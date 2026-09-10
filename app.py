"""Library attendance app. Python 3.11+. Run: streamlit run app.py."""
import csv
import hashlib
import hmac
import io
import json
import math
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, date, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

KST = ZoneInfo('Asia/Seoul')
DB_PATH = Path(os.environ.get('ATTENDANCE_DB', str(Path(__file__).parent / 'data' / 'attendance.db')))
DEFAULT = dict(start='08:00', end='08:10', late=1000, absent=3000,
               lat=37.5665, lon=126.9780, radius=200, accuracy=100, configured=False)

# Invoke geolocation from a real browser click, not a Streamlit rerun.
GEO_REQUEST_JS = '''new Promise((resolve) => {
  const box = document.createElement('div');
  const button = document.createElement('button');
  const message = document.createElement('p');
  button.textContent = '위치 권한 요청하고 출석하기';
  button.style.cssText = 'width:100%;min-height:52px;background:#176b46;color:white;border:0;border-radius:8px;font-size:17px;cursor:pointer';
  message.style.cssText = 'font:14px sans-serif;color:#555';
  message.textContent = '버튼을 누른 뒤 브라우저의 위치 요청에서 허용을 선택하세요.';
  box.append(button,message); document.body.append(box); setFrameHeight(150);
  let done = false;
  let timer;
  const finish = (value) => {
    if (done) return;
    done = true; clearTimeout(timer); button.disabled = true;
    message.textContent = value.error ? '위치 확인 실패. 아래 안내를 확인하세요.' : '위치 확인 완료. 출석 기록을 저장합니다.';
    resolve(value);
  };
  button.addEventListener('click', () => {
    button.disabled = true;
    message.textContent = '위치 권한을 허용해 주세요. 최대 20초 동안 확인합니다.';
    if (!window.isSecureContext) {finish({error:{code:4}}); return;}
    const policy = document.permissionsPolicy || document.featurePolicy;
    if (policy && !policy.allowsFeature('geolocation')) {finish({error:{code:5}}); return;}
    if (!navigator.geolocation) {finish({error:{code:0}}); return;}
    timer = setTimeout(() => finish({error:{code:3}}),20000);
    try {
      navigator.geolocation.getCurrentPosition(p => finish({coords:{
        latitude:p.coords.latitude,longitude:p.coords.longitude,accuracy:p.coords.accuracy},
        timestamp:p.timestamp}),e => finish({error:{code:e.code}}),
        {enableHighAccuracy:true,timeout:15000,maximumAge:0});
    } catch (e) {finish({error:{code:0}});}
  },{once:true});
})'''

@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS members(id INTEGER PRIMARY KEY, name TEXT NOT NULL,
          code TEXT UNIQUE NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(day TEXT PRIMARY KEY, policy TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attendance(member INTEGER REFERENCES members(id),
          day TEXT REFERENCES sessions(day), status TEXT NOT NULL, fine INTEGER NOT NULL CHECK(fine>=0),
          checked_at TEXT, distance REAL, note TEXT NOT NULL DEFAULT '', PRIMARY KEY(member,day));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, member INTEGER NOT NULL REFERENCES members(id),
          amount INTEGER NOT NULL CHECK(amount != 0), at TEXT NOT NULL, note TEXT NOT NULL);
        ''')
        c.execute('INSERT OR IGNORE INTO settings VALUES(1,?)', (json.dumps(DEFAULT),))

def rows(sql, args=()):
    with db() as c:
        return [dict(r) for r in c.execute(sql, args)]

def password_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', value.encode(), bytes.fromhex(salt), 200000).hex()

def verify(value, stored):
    return hmac.compare_digest(password_hash(value, stored.split(':')[0]), stored)

def audit(c, detail):
    c.execute('INSERT INTO audit(at,detail) VALUES(?,?)', (datetime.now(KST).isoformat(), detail))

def member_summary(member):
    with db() as c:
        counts = {r['status']: r['n'] for r in c.execute('SELECT status,COUNT(*) n FROM attendance WHERE member=? GROUP BY status',(member,))}
        fine = c.execute('SELECT COALESCE(SUM(fine),0) FROM attendance WHERE member=?',(member,)).fetchone()[0]
        paid = c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE member=?',(member,)).fetchone()[0]
    total = sum(counts.get(s,0) for s in ('정상','지각','결석'))
    attended = counts.get('정상',0) + counts.get('지각',0)
    return dict(counts=counts,rate=100*attended/total if total else None,fine=fine,paid=paid,
                unpaid=max(0,fine-paid),credit=max(0,paid-fine))

def record_payment(member, amount, note, token):
    if type(amount) is not int or amount == 0 or abs(amount)>10000000 or not note.strip():
        raise ValueError('유효한 정산 금액과 사유를 입력하세요.')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT 1 FROM payments WHERE id=?',(token,)).fetchone():
            return False
        if not c.execute('SELECT 1 FROM members WHERE id=?',(member,)).fetchone():
            raise ValueError('등록된 회원을 선택하세요.')
        fine = c.execute('SELECT COALESCE(SUM(fine),0) FROM attendance WHERE member=?',(member,)).fetchone()[0]
        paid = c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE member=?',(member,)).fetchone()[0]
        if amount>0 and amount>max(0,fine-paid):
            raise ValueError('납부액은 현재 미납액을 초과할 수 없습니다.')
        if amount<0 and -amount>paid:
            raise ValueError('환불/납부 취소액은 누적 납부액을 초과할 수 없습니다.')
        c.execute('INSERT INTO payments VALUES(?,?,?,?,?)',(token,member,amount,datetime.now(KST).isoformat(),note.strip()))
        audit(c,f'벌금 정산: 회원 {member}, 금액 {amount}, 사유 {note.strip()}')
        return True

def classify(at, policy):
    t = at.astimezone(KST).time().replace(tzinfo=None)
    if t < time.fromisoformat(policy['start']):
        return '정상', 0
    if t <= time.fromisoformat(policy['end']):
        return '지각', policy['late']
    return '결석', policy['absent']

def distance_m(lat, lon, target_lat, target_lon):
    a, b = map(math.radians, (lat, target_lat))
    dlat, dlon = math.radians(target_lat-lat), math.radians(target_lon-lon)
    v = math.sin(dlat/2)**2 + math.cos(a)*math.cos(b)*math.sin(dlon/2)**2
    return 6371000 * 2 * math.asin(math.sqrt(min(1, max(0, v))))

def validate_location(location, policy, now):
    if isinstance(location,dict) and 'error' in location:
        code = location['error'].get('code') if isinstance(location['error'],dict) else None
        messages = {1:'위치 권한이 거부되었습니다. 브라우저 설정에서 위치를 허용한 뒤 다시 측정하세요.',
                    2:'현재 위치를 찾을 수 없습니다. GPS를 켜고 창가나 야외에서 다시 측정하세요.',
                    3:'위치 확인 시간이 초과되었습니다. 기기 위치 서비스를 켠 뒤 이름을 다시 눌러 시도하세요.',
                    4:'위치는 HTTPS 또는 localhost에서만 확인할 수 있습니다. 배포된 https:// 주소를 열어 주세요.',
                    5:'현재 화면의 브라우저 정책이 위치 요청을 차단했습니다. 미리보기·메신저 내장 브라우저 대신 배포된 앱 주소를 Safari 또는 Chrome에서 직접 여세요.'}
        raise ValueError(messages.get(code,'이 브라우저에서 위치를 확인할 수 없습니다. HTTPS 주소와 위치 설정을 확인하세요.'))
    try:
        coords = location['coords']
        lat, lon, accuracy = (float(coords[k]) for k in ('latitude', 'longitude', 'accuracy'))
        age = now.timestamp() - float(location['timestamp']) / 1000
        if not all(math.isfinite(x) for x in (lat, lon, accuracy, age)):
            raise ValueError
        if not (-90 <= lat <= 90 and -180 <= lon <= 180 and 0 <= accuracy <= policy['accuracy']):
            raise ValueError
        if not -10 <= age <= 120:
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError('위치가 없거나 오래되었거나 정확도가 부족합니다. 위치를 다시 확인해 주세요.')
    distance = distance_m(lat, lon, policy['lat'], policy['lon'])
    if distance > policy['radius']:
        raise ValueError(f'허용 반경 밖입니다. 도서관까지 약 {distance:.0f}m입니다.')
    return distance

def create_sessions(days, policy):
    if not policy['configured']:
        raise ValueError('실제 도서관 위치를 먼저 설정해 주세요.')
    with db() as c:
        for day in days:
            cur = c.execute('INSERT OR IGNORE INTO sessions VALUES(?,?)', (day, json.dumps(policy)))
            if cur.rowcount:
                c.execute("INSERT INTO attendance(member,day,status,fine) SELECT id,?,'대기',0 FROM members WHERE active=1", (day,))
        audit(c, f'일정 등록: {", ".join(days)}')

def finalize(now):
    # Runs on app access; backfills every scheduled day even after downtime.
    with db() as c:
        for r in c.execute('SELECT * FROM sessions').fetchall():
            p = json.loads(r['policy'])
            deadline = datetime.combine(date.fromisoformat(r['day']), time.fromisoformat(p['end']), KST)
            if now > deadline:
                c.execute("UPDATE attendance SET status='결석',fine=? WHERE day=? AND status='대기'", (p['absent'], r['day']))

def check_in(member, location, now):
    day = now.astimezone(KST).date().isoformat()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        r = c.execute('SELECT policy FROM sessions WHERE day=?', (day,)).fetchone()
        if not r:
            raise ValueError('오늘은 등록된 스터디 일정이 없습니다.')
        p = json.loads(r['policy'])
        distance = validate_location(location, p, now)
        status, fine = classify(now, p)
        cur = c.execute('''UPDATE attendance SET status=?,fine=?,checked_at=?,distance=?
          WHERE member=? AND day=? AND checked_at IS NULL
          AND status IN ('대기','결석') AND note='' AND EXISTS
          (SELECT 1 FROM members WHERE id=? AND active=1)''',
          (status, fine, now.isoformat(), distance, member, day, member))
        if not cur.rowcount:
            raise ValueError('이미 인증했거나, 출석 대상이 아니거나, 관리자가 확정한 기록입니다.')
        return status, fine, distance

def restore_backup(payload):
    if len(payload) > 20 * 1024 * 1024:
        raise ValueError('백업은 20MB 이하여야 합니다.')
    source = sqlite3.connect(':memory:')
    try:
        source.deserialize(payload)
        if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('손상된 백업입니다.')
        if source.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('백업의 회원/일정 참조가 올바르지 않습니다.')
        with db() as c:
            # Earlier releases had no payments table; migrate their backup in memory.
            if not source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='payments'").fetchone():
                source.execute(c.execute("SELECT sql FROM sqlite_master WHERE name='payments'").fetchone()[0])
            schema = "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            if [tuple(r) for r in c.execute(schema)] != source.execute(schema).fetchall():
                raise ValueError('이 앱에서 만든 백업만 복원할 수 있습니다.')
            for item in source.execute('SELECT policy FROM sessions'):
                p = json.loads(item[0])
                if set(p) != set(DEFAULT):
                    raise ValueError('백업의 출석 기준이 올바르지 않습니다.')
                time.fromisoformat(p['start'])
                time.fromisoformat(p['end'])
            c.execute('BEGIN IMMEDIATE')
            for table in ('payments','attendance','sessions','members','settings','audit'):
                c.execute(f'DELETE FROM {table}')
            for table in ('settings','members','sessions','attendance','audit','payments'):
                entries = source.execute(f'SELECT * FROM {table}').fetchall()
                if entries:
                    marks = ','.join('?' for _ in entries[0])
                    c.executemany(f'INSERT INTO {table} VALUES({marks})', entries)
            audit(c,'관리자 SQLite 백업 복원')
    finally:
        source.close()

def main():
    import streamlit as st
    from streamlit_js_eval import streamlit_js_eval
    st.set_page_config(page_title='도서관 아침 스터디', page_icon='📚', layout='centered')
    st.markdown('<style>.stButton button{min-height:48px;width:100%}div.block-container{max-width:920px;padding-top:2rem}</style>', unsafe_allow_html=True)
    st.title('📚 도서관 아침 스터디')
    st.caption('출석부터 벌금 확인까지 · 모든 시간은 한국 시간')
    with st.sidebar.expander('ChatGPT API Key (선택)'):
        st.text_input('OpenAI API Key',type='password',key='api_key')
        st.caption('현재 출석·정산 기능에는 AI 호출이 필요하지 않습니다. 입력한 키는 현재 세션에서만 유지하며 DB·백업에 저장하거나 외부로 전송하지 않습니다.')
        st.button('API Key 지우기',on_click=lambda: st.session_state.pop('api_key',None))
    init_db()
    finalize(datetime.now(KST))
    page = st.radio('메뉴', ['출석 / 개인 기록', '전체 현황', '관리'], horizontal=True)
    st.caption('비밀번호 없는 공유 앱 · 링크를 가진 사람은 기록 조회와 관리가 가능합니다.')
    now = datetime.now(KST)
    today = now.date().isoformat()
    st.caption(now.strftime('%Y년 %m월 %d일 %H:%M'))
    def table(records):
        if records:
            st.dataframe(records, hide_index=True, width='stretch')
        else:
            st.info('표시할 기록이 없습니다.')
    if page == '전체 현황':
        data = rows('SELECT status,COUNT(*) AS n FROM attendance WHERE day=? GROUP BY status', (today,))
        counts = {r['status']: r['n'] for r in data}
        st.subheader('오늘의 출석 현황')
        for col, status in zip(st.columns(4), ['정상', '지각', '결석', '대기']):
            col.metric(status, f"{counts.get(status, 0)}명")
        st.metric('활성 스터디원', f"{rows('SELECT COUNT(*) AS n FROM members WHERE active=1')[0]['n']}명")
        summaries = [member_summary(m['id']) for m in rows('SELECT id FROM members')]
        for col,label,field in zip(st.columns(3),['누적 부과 벌금','누적 납부액','미납액'],['fine','paid','unpaid']):
            col.metric(label,f"{sum(s[field] for s in summaries):,}원")
        st.caption('대기는 마감 전 미인증자입니다. 이름을 선택하면 개인 기록도 확인할 수 있습니다.')
    elif page == '출석 / 개인 기록':
        members = rows('SELECT id,name,code FROM members WHERE active=1 ORDER BY name,code')
        names = {m['id']:f"{m['name']} ({m['code']})" if m['code'] != m['name'] else m['name'] for m in members}
        if not members:
            st.info('위의 관리 메뉴에서 스터디원 이름을 먼저 등록하세요.')
            return
        query = st.text_input('내 이름 검색',placeholder='이름을 입력하세요',max_chars=50).strip()
        st.caption('이름 선택 → 위치 권한 요청하고 출석하기 → 허용. 위치가 확인되면 자동으로 출석됩니다. 거리만 저장합니다.')
        matches = {mid:label for mid,label in names.items() if query.casefold() in label.casefold()}
        if query:
            if not matches:
                st.info('검색된 이름이 없습니다.')
            for mid,label in matches.items():
                if st.button(label,key=f'checkin_name_{mid}',type='primary'):
                    st.session_state.selected_attendee = mid
                    st.session_state.pending_checkin = (mid,secrets.token_hex(8))
                    st.session_state.pop('checkin_feedback',None)
        else:
            st.info('이름을 검색한 뒤 검색 결과에서 본인 이름을 누르세요.')
        member = st.session_state.get('selected_attendee')
        if member not in names:
            st.session_state.pop('pending_checkin',None)
            return
        st.subheader(f"{names[member]}님의 출석")
        session = rows('SELECT policy FROM sessions WHERE day=?', (today,))
        if session:
            p = json.loads(session[0]['policy'])
            st.info(f"정상: {p['start']} 미만 / 지각: {p['start']}~{p['end']} 포함 / 이후: 결석\n\n지각 {p['late']:,}원 · 결석 {p['absent']:,}원 · 반경 {p['radius']}m")
            pending = st.session_state.get('pending_checkin')
            if pending and pending[0] == member:
                location = streamlit_js_eval(js_expressions=GEO_REQUEST_JS,key='geo_' + pending[1])
                if location is None:
                    st.info('위의 초록색 버튼을 눌러 위치 권한을 요청하세요. 이미 권한을 차단했다면 주소창의 사이트 설정에서 위치를 허용해야 합니다.')
                else:
                    try:
                        status,fine,distance = check_in(member,location,datetime.now(KST))
                        st.session_state.checkin_feedback = ('success',f'{names[member]}님 {status} 인증 완료 · 벌금 {fine:,}원 · 도서관까지 {distance:.0f}m')
                    except ValueError as e:
                        st.session_state.checkin_feedback = ('warning',str(e))
                    finally:
                        st.session_state.pop('pending_checkin',None)
            feedback = st.session_state.get('checkin_feedback')
            if feedback:
                getattr(st,feedback[0])(feedback[1])
            st.caption('위치 확인에 실패했다면 브라우저 위치 설정을 확인한 뒤 이름을 다시 누르세요.')
        else:
            st.session_state.pop('pending_checkin',None)
            st.info('오늘 등록된 스터디 일정이 없습니다.')
        st.subheader('나의 기록')
        records = rows('SELECT day AS 날짜,status AS 상태,fine AS 벌금,checked_at AS 인증시간,note AS 관리자메모 FROM attendance WHERE member=? ORDER BY day DESC', (member,))
        summary = member_summary(member)
        st.metric('출석률 (정상 + 지각)',f"{summary['rate']:.1f}%" if summary['rate'] is not None else '집계 전')
        st.caption('출석률 = (정상 + 지각) ÷ (정상 + 지각 + 결석). 대기·면제는 제외합니다.')
        for col,label,field in zip(st.columns(3),['누적 부과액','납부액','미납액'],['fine','paid','unpaid']):
            col.metric(label,f"{summary[field]:,}원")
        if summary['credit']:
            st.info(f"벌금 정정 후 초과 납부액: {summary['credit']:,}원. 관리자에게 환불 또는 차감을 요청하세요.")
        st.write(' · '.join(f"{s} {sum(r['상태']==s for r in records)}회" for s in ['정상','지각','결석']))
        table(records)
        with st.expander('나의 납부·환불 내역'):
            table(rows('SELECT at AS 처리시간,amount AS 금액,note AS 사유 FROM payments WHERE member=? ORDER BY at DESC',(member,)))
    else:
        tabs = st.tabs(['스터디원', '기준 / 일정', '기록 관리', '백업', '벌금 정산'])
        with tabs[0]:
            with st.form('add_member', clear_on_submit=True):
                name = st.text_input('이름', max_chars=50)
                code = st.text_input('동명이인 구분 이름 (선택)', max_chars=50, help='같은 이름이 있을 때만 입력하세요. 예: 민지A')
                if st.form_submit_button('스터디원 추가'):
                    if not name.strip():
                        st.error('이름을 입력하세요.')
                    else:
                        with db() as c:
                            cur = c.execute('INSERT INTO members(name,code,password) VALUES(?,?,?)', (name.strip(), code.strip() or name.strip(), ''))
                            # New members join future sessions; today requires explicit admin review.
                            c.execute("INSERT INTO attendance(member,day,status,fine) SELECT ?,day,'대기',0 FROM sessions WHERE day>?", (cur.lastrowid,today))
                            audit(c, f'회원 추가: {code.strip()}')
                        st.success('등록했습니다. 오늘 일정은 기록 관리에서 대상자를 추가할 수 있습니다.')
            members = rows('SELECT id,name,code,active FROM members ORDER BY name')
            table(members)
            if members:
                ids = {m['id']: f"{m['name']} ({m['code']})" for m in members}
                selected = st.selectbox('관리할 회원', list(ids), format_func=ids.get)
                active = st.checkbox('활성 상태', value=bool(next(m['active'] for m in members if m['id']==selected)), key=f'active_{selected}')
                if st.button('상태 저장 (삭제는 비활성화)'):
                    with db() as c:
                        c.execute('UPDATE members SET active=? WHERE id=?', (int(active),selected))
                        if not active:
                            c.execute("DELETE FROM attendance WHERE member=? AND day>? AND status='대기'", (selected,today))
                        else:
                            c.execute("INSERT OR IGNORE INTO attendance(member,day,status,fine) SELECT ?,day,'대기',0 FROM sessions WHERE day>?", (selected,today))
                        audit(c, f'회원 상태 변경: {selected} / {active}')
                    st.rerun()
        with tabs[1]:
            p = json.loads(rows('SELECT value FROM settings WHERE id=1')[0]['value'])
            with st.form('policy'):
                start = st.time_input('정상 출석 종료 (이 시각부터 지각)', time.fromisoformat(p['start']))
                end = st.time_input('지각 종료 (이 시각까지 지각)', time.fromisoformat(p['end']))
                late = st.number_input('지각 벌금',0,1000000,p['late'],100)
                absent = st.number_input('결석 벌금',0,1000000,p['absent'],100)
                lat = st.number_input('도서관 위도',-90.0,90.0,float(p['lat']),format='%.6f')
                lon = st.number_input('도서관 경도',-180.0,180.0,float(p['lon']),format='%.6f')
                radius = st.number_input('허용 반경 (m)',10,5000,p['radius'])
                accuracy = st.number_input('허용 GPS 오차 (m)',5,1000,p['accuracy'])
                confirmed = st.checkbox('실제 도서관 좌표를 확인했습니다',value=p['configured'])
                if st.form_submit_button('기준 저장'):
                    if start >= end or not confirmed:
                        st.error('종료 시각은 시작보다 늦어야 하며 실제 좌표 확인이 필요합니다.')
                    else:
                        p = dict(start=start.isoformat(),end=end.isoformat(),late=late,absent=absent,lat=lat,lon=lon,radius=radius,accuracy=accuracy,configured=True)
                        with db() as c:
                            c.execute('UPDATE settings SET value=? WHERE id=1',(json.dumps(p),))
                            audit(c,'출석 기준 변경')
                        st.success('저장했습니다. 새 일정에만 적용됩니다.')
            st.caption('일정 생성 시 기준과 대상 회원을 고정합니다. 기존 일정은 기준 변경의 영향을 받지 않습니다.')
            with st.form('schedule'):
                begin = st.date_input('시작일',now.date(),min_value=now.date())
                finish = st.date_input('종료일',now.date()+timedelta(days=7),min_value=now.date())
                weekdays = st.multiselect('진행 요일',list(range(7)),default=[0,1,2,3,4],format_func=lambda x:['월','화','수','목','금','토','일'][x])
                if st.form_submit_button('스터디 일정 생성'):
                    if finish < begin or (finish-begin).days>366 or not weekdays:
                        st.error('요일을 선택하고 1년 이내의 날짜 범위를 지정하세요.')
                    else:
                        days = [(begin+timedelta(days=i)).isoformat() for i in range((finish-begin).days+1) if (begin+timedelta(days=i)).weekday() in weekdays]
                        create_sessions(days,p)
                        st.success(f'{len(days)}일을 처리했습니다. 기존 일정은 유지됩니다.')
            table(rows('SELECT day AS 스터디날짜 FROM sessions ORDER BY day DESC LIMIT 60'))
        with tabs[2]:
            chosen = st.date_input('조회 / 수정 날짜',now.date()).isoformat()
            records = rows('''SELECT m.id,m.name AS 이름,m.code AS 닉네임,a.status AS 상태,a.fine AS 벌금,
                a.checked_at AS 인증시간,a.distance AS 거리m,a.note AS 메모
                FROM attendance a JOIN members m ON m.id=a.member WHERE a.day=?''',(chosen,))
            table(records)
            if rows('SELECT day FROM sessions WHERE day=?',(chosen,)):
                all_members = rows('SELECT id,name,code FROM members WHERE active=1')
                if all_members:
                    names = {r['id']:f"{r['name']} ({r['code']})" for r in all_members}
                    add_id = st.selectbox('누락된 일정 대상자 추가',list(names),format_func=names.get)
                    if st.button('이 날짜 대상자로 추가'):
                        with db() as c:
                            c.execute("INSERT OR IGNORE INTO attendance(member,day,status,fine) VALUES(?,?,'대기',0)",(add_id,chosen))
                            audit(c,f'대상자 추가: {add_id} {chosen}')
                        st.rerun()
            if records:
                names = {r['id']:f"{r['이름']} ({r['닉네임']})" for r in records}
                with st.form('correct'):
                    mid = st.selectbox('수정 대상',list(names),format_func=names.get)
                    status = st.selectbox('수정 상태',['정상','지각','결석','면제'])
                    fine = st.number_input('최종 부과 벌금 (자동 누적 합계에 반영)',0,1000000,0,100)
                    note = st.text_input('수정 사유 (필수)')
                    if st.form_submit_button('기록 정정'):
                        if not note.strip():
                            st.error('사유를 입력하세요.')
                        else:
                            with db() as c:
                                before = dict(c.execute('SELECT * FROM attendance WHERE member=? AND day=?',(mid,chosen)).fetchone())
                                c.execute('UPDATE attendance SET status=?,fine=?,note=? WHERE member=? AND day=?',(status,fine,note.strip(),mid,chosen))
                                audit(c,json.dumps(dict(before=before,after=dict(status=status,fine=fine,note=note)),ensure_ascii=False))
                            st.rerun()
            totals = rows('''SELECT m.name AS 이름,m.code AS 닉네임,
              SUM(a.status='정상') AS 정상,SUM(a.status='지각') AS 지각,SUM(a.status='결석') AS 결석,
              COALESCE(SUM(a.fine),0) AS 누적벌금 FROM members m LEFT JOIN attendance a ON m.id=a.member GROUP BY m.id ORDER BY m.id''')
            st.subheader('전체 개인별 누계')
            for record,m in zip(totals,rows('SELECT id FROM members ORDER BY id')):
                summary=member_summary(m['id'])
                record.update(출석률=f"{summary['rate']:.1f}%" if summary['rate'] is not None else '집계 전',납부액=summary['paid'],미납액=summary['unpaid'])
            table(totals)
            export = rows('SELECT m.name,m.code,a.* FROM attendance a JOIN members m ON m.id=a.member ORDER BY day DESC')
            if export:
                buf = io.StringIO()
                writer = csv.DictWriter(buf,fieldnames=export[0].keys())
                writer.writeheader()
                writer.writerows({k:("'"+v if isinstance(v,str) and v.startswith(('=','+','-','@')) else v) for k,v in r.items()} for r in export)
                st.download_button('전체 기록 CSV 다운로드',buf.getvalue().encode('utf-8-sig'),'attendance.csv','text/csv')
            with st.expander('관리자 변경 이력'):
                table(rows('SELECT * FROM audit ORDER BY id DESC LIMIT 100'))
        with tabs[3]:
            st.warning('Community Cloud는 로컬 파일의 영구 보존을 보장하지 않습니다. 운영 후 반드시 백업을 내려받으세요. 복원 방법은 README에 있습니다.')
            if st.button('현재 SQLite 백업 만들기'):
                with db() as c:
                    memory = sqlite3.connect(':memory:')
                    c.backup(memory)
                    st.session_state.backup = memory.serialize()
                    memory.close()
            if st.session_state.get('backup'):
                st.download_button('SQLite 백업 다운로드',st.session_state.backup,f'attendance-{today}.db','application/octet-stream')
            st.caption('백업에는 회원 이름과 출석·정산 기록이 포함됩니다. 안전한 곳에 보관하세요. 새 변경 이후에는 백업을 다시 만드세요.')
            uploaded = st.file_uploader('이 앱에서 만든 SQLite 백업 복원',type=['db'])
            agreed = st.checkbox('현재 전체 데이터가 백업 내용으로 교체됨을 확인했습니다. 먼저 최신 백업을 다운로드했습니다.')
            if st.button('백업으로 복원',disabled=not (uploaded and agreed)):
                restore_backup(uploaded.getvalue())
                st.session_state.clear()
                st.rerun()
        with tabs[4]:
            members = rows('SELECT id,name,code FROM members ORDER BY name,code')
            names = {m['id']:f"{m['name']} ({m['code']})" for m in members}
            if not members:
                st.info('먼저 회원을 등록하세요.')
            else:
                mid = st.selectbox('정산 대상',list(names),format_func=names.get)
                summary=member_summary(mid)
                st.write(f"부과 {summary['fine']:,}원 · 납부 {summary['paid']:,}원 · 미납 {summary['unpaid']:,}원 · 초과납부 {summary['credit']:,}원")
                with st.form('settle',clear_on_submit=True):
                    operation=st.selectbox('처리 구분',['납부','환불 / 납부 취소'])
                    amount=st.number_input('정산 금액 (원)',min_value=1,max_value=10000000,value=1000,step=100)
                    reason=st.text_input('납부 방법 / 정산 사유 (필수)',max_chars=300)
                    token=st.session_state.setdefault('payment_token',secrets.token_hex(16))
                    if st.form_submit_button('정산 기록 저장'):
                        record_payment(mid,amount if operation=='납부' else -amount,reason,token)
                        st.session_state.payment_token=secrets.token_hex(16)
                        st.rerun()
                st.caption('실제 송금·환불은 별도로 진행하고 이곳에 처리 내역을 기록합니다. 정산 내역은 삭제하지 않고 반대 금액으로 취소합니다.')
                table(rows('SELECT at AS 처리시간,amount AS 금액,note AS 사유 FROM payments WHERE member=? ORDER BY at DESC',(mid,)))

if __name__ == '__main__':
    import streamlit as st
    try:
        main()
    except sqlite3.IntegrityError:
        st.error('중복된 닉네임 또는 허용되지 않는 데이터입니다. 입력을 확인해 주세요.')
    except sqlite3.Error:
        st.error('저장소 작업에 실패했습니다. 잠시 후 다시 시도하고 지속되면 관리자에게 문의하세요.')
    except ValueError as e:
        st.error(str(e))
    except OSError:
        st.error('저장 파일에 접근할 수 없습니다. 데이터 폴더의 쓰기 권한을 확인해 주세요.')
