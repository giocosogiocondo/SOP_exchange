"""
SOP Review Web Application (FastAPI Version)
Refactored for better maintenance and readability.
"""

import os
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

# ==========================================
# 1. 설정 및 상수 (Configuration & Constants)
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'sop_review_fast.db')

# 중복 제거: 전공 및 학위 리스트를 한곳에서 관리합니다.
MAJORS = [
    'Computer Science', 'Electrical Engineering', 'Mechanical Engineering',
    'Chemistry', 'Physics', 'Biology', 'Mathematics', 'Economics', 'Business',
    'Psychology', 'Sociology', 'History', 'Art', 'Music', 'Education', 'Architecture', 'Civil and Environmental Engineering', 'Etc.'
]

DEGREES = ['Bachelor', 'Master', 'PhD', 'MD', 'MBA']

app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, 'templates'))


# ==========================================
# 2. 데이터베이스 헬퍼 (Database Helpers)
# ==========================================

def get_db_connection():
    """DB 연결 객체를 반환합니다 (Row Factory 적용)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    """sqlite3.Row 객체를 일반 딕셔너리로 변환합니다."""
    return {k: row[k] for k in row.keys()}

def init_db():
    """앱 시작 시 테이블이 없으면 생성합니다."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        
        # 유저 테이블
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            nickname TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            major TEXT NOT NULL,
            detailed_major TEXT,
            degree TEXT NOT NULL,
            blocked_until TEXT
        )''')
        
        # Check for detailed_major column and add if missing (Migration)
        c.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in c.fetchall()]
        if 'detailed_major' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN detailed_major TEXT")

        
        # 리뷰 요청 테이블
        c.execute('''CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            requester_sop TEXT,
            recipient_sop TEXT,
            status TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            accepted_at TEXT,
            deadline TEXT,
            requester_review TEXT,
            recipient_review TEXT,
            requester_reviewed_at TEXT,
            recipient_reviewed_at TEXT
        )''')
        conn.commit()

@app.on_event('startup')
def startup():
    init_db()


# ==========================================
# 3. 인증 및 유틸리티 (Auth & Utils)
# ==========================================

def hash_password(password: str) -> str:
    """SHA256을 사용한 간단한 비밀번호 해싱"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """쿠키에서 사용자 정보를 가져옵니다."""
    user_id = request.cookies.get('user_id')
    if not user_id:
        return None
    try:
        uid = int(user_id)
    except ValueError:
        return None
        
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (uid,))
        row = c.fetchone()
        if row:
            return dict_from_row(row)
    return None

def require_login(request: Request) -> Dict[str, Any]:
    """로그인이 필요한 페이지에서 사용. 비로그인 시 메인으로 리다이렉트(예외 발생)."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={'Location': '/'})
    return user

def check_expired_requests_for_user(user_id: int):
    """마감기한이 지난 요청을 확인하고 패널티를 부여합니다."""
    now = datetime.utcnow()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE status = ? AND deadline < ?', ('accepted', now.isoformat()))
        expired = c.fetchall()
        
        for row in expired:
            req = dict_from_row(row)
            failed_user_id = None
            
            # 리뷰를 안 쓴 사람 찾기
            if not req['requester_review']:
                failed_user_id = req['requester_id']
            elif not req['recipient_review']:
                failed_user_id = req['recipient_id']
            
            if failed_user_id:
                # 48시간 블락 적용
                unblock_time = (now + timedelta(hours=48)).isoformat()
                c.execute('UPDATE users SET blocked_until = ? WHERE id = ?', (unblock_time, failed_user_id))
            
            # 요청 만료 처리
            c.execute('UPDATE requests SET status = ? WHERE id = ?', ('expired', req['id']))
        conn.commit()


# ==========================================
# 4. 라우트 핸들러 (Routes)
# ==========================================

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse('/dashboard')
    return templates.TemplateResponse('index.html', {'request': request, 'user': None})


@app.get('/register', response_class=HTMLResponse)
async def register_form(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse('/dashboard')
    
    # 리팩토링: 전역 상수 사용
    return templates.TemplateResponse('register.html', {
        'request': request, 
        'majors': MAJORS, 
        'degrees': DEGREES, 
        'user': None
    })


@app.post('/register')
async def register(request: Request):
    """회원가입 처리"""
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    
    username = data.get('username', [''])[0]
    nickname = data.get('nickname', [''])[0]
    password = data.get('password', [''])[0]
    major = data.get('major', [''])[0]
    degree = data.get('degree', [''])[0]

    # 입력값 검증 실패 시 다시 폼 보여주기 (전역 상수 사용)
    if not (username and nickname and password and major and degree):
        return templates.TemplateResponse('register.html', {
            'request': request,
            'error': 'All fields are required.',
            'majors': MAJORS,
            'degrees': DEGREES,
            'user': None
        }, status_code=400)

    password_hash = hash_password(password)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, nickname, password_hash, major, degree) VALUES (?, ?, ?, ?, ?)',
                      (username, nickname, password_hash, major, degree))
            conn.commit()
    except sqlite3.IntegrityError:
        # 중복 아이디 에러 처리 (전역 상수 사용)
        return templates.TemplateResponse('register.html', {
            'request': request,
            'error': 'Username already exists.',
            'majors': MAJORS,   # 수정됨
            'degrees': DEGREES, # 수정됨
            'user': None
        }, status_code=400)

    return RedirectResponse(url='/login', status_code=302)


@app.get('/login', response_class=HTMLResponse)
async def login_form(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse('/dashboard')
    return templates.TemplateResponse('login.html', {'request': request, 'user': None})


@app.post('/login')
async def login(request: Request):
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    username = data.get('username', [''])[0]
    password = data.get('password', [''])[0]
    
    password_hash = hash_password(password)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
        row = c.fetchone()
        
        if row:
            user = dict_from_row(row)
            response = RedirectResponse(url='/dashboard', status_code=302)
            # 쿠키 설정 (7일)
            response.set_cookie(key='user_id', value=str(user['id']), max_age=7*24*60*60, httponly=True)
            return response
            
    return templates.TemplateResponse('login.html', {
        'request': request, 
        'error': 'Invalid credentials.', 
        'user': None
    }, status_code=400)


@app.get('/logout')
async def logout(request: Request):
    response = RedirectResponse('/', status_code=302)
    response.delete_cookie('user_id')
    return response


@app.get('/profile', response_class=HTMLResponse)
async def profile_form(request: Request):
    user = require_login(request)
    return templates.TemplateResponse('profile.html', {
        'request': request,
        'user': user,
        'majors': MAJORS,
        'degrees': DEGREES
    })


@app.post('/profile')
async def update_profile(request: Request):
    user = require_login(request)
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    
    nickname = data.get('nickname', [''])[0]
    major = data.get('major', [''])[0]
    detailed_major = data.get('detailed_major', [''])[0]
    degree = data.get('degree', [''])[0]
    
    # Update user info
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('UPDATE users SET nickname = ?, major = ?, detailed_major = ?, degree = ? WHERE id = ?',
                  (nickname, major, detailed_major, degree, user['id']))
        conn.commit()
        
    return RedirectResponse('/profile', status_code=302)



@app.get('/dashboard', response_class=HTMLResponse)
async def dashboard(request: Request):
    user = require_login(request)
    check_expired_requests_for_user(user['id'])
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # 1. 내가 받은 대기중인 요청 (Pending)
        c.execute('SELECT * FROM requests WHERE recipient_id = ? AND status = ?', (user['id'], 'pending'))
        pending_rows = c.fetchall()
        pending = []
        for r in pending_rows:
            rr = dict_from_row(r)
            c.execute('SELECT nickname FROM users WHERE id = ?', (rr['requester_id'],))
            nick_row = c.fetchone()
            rr['requester_nickname'] = nick_row['nickname'] if nick_row else 'Unknown'
            pending.append(rr)
            
        # 2. 진행 중인 요청 (Accepted) - 내가 보냈거나 받은 것
        c.execute('SELECT * FROM requests WHERE (requester_id = ? OR recipient_id = ?) AND status = ?', 
                  (user['id'], user['id'], 'accepted'))
        accepted_rows = c.fetchall()
        accepted = []
        for r in accepted_rows:
            rr = dict_from_row(r)
            partner_id = rr['recipient_id'] if rr['requester_id'] == user['id'] else rr['requester_id']
            c.execute('SELECT nickname FROM users WHERE id = ?', (partner_id,))
            nick_row = c.fetchone()
            rr['partner_nickname'] = nick_row['nickname'] if nick_row else 'Unknown'
            accepted.append(rr)
            
        # 3. 완료된 요청 (Completed)
        c.execute('SELECT * FROM requests WHERE (requester_id = ? OR recipient_id = ?) AND status = ?', 
                  (user['id'], user['id'], 'completed'))
        completed_rows = c.fetchall()
        completed = []
        for r in completed_rows:
            rr = dict_from_row(r)
            partner_id = rr['recipient_id'] if rr['requester_id'] == user['id'] else rr['requester_id']
            c.execute('SELECT nickname FROM users WHERE id = ?', (partner_id,))
            nick_row = c.fetchone()
            rr['partner_nickname'] = nick_row['nickname'] if nick_row else 'Unknown'
            completed.append(rr)

    return templates.TemplateResponse('dashboard.html', {
        'request': request,
        'user': user,
        'pending_requests': pending,
        'accepted_requests': accepted,
        'completed_requests': completed
    })


@app.get('/same_major', response_class=HTMLResponse)
async def same_major(request: Request):
    user = require_login(request)
    now = datetime.utcnow()
    
    blocked_until = user['blocked_until']
    users = []
    message = None
    
    if blocked_until:
        try:
            blocked_dt = datetime.fromisoformat(blocked_until)
        except ValueError:
            blocked_dt = None
            
        if blocked_dt and blocked_dt > now:
            message = f'You are temporarily blocked until {blocked_dt.strftime("%Y-%m-%d %H:%M UTC")} and cannot send review requests.'
        else:
            # 시간 지났으면 블락 해제
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('UPDATE users SET blocked_until = NULL WHERE id = ?', (user['id'],))
                conn.commit()
                
    if not message:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE major = ? AND id != ?', (user['major'], user['id']))
            users = [dict_from_row(r) for r in c.fetchall()]
            
    return templates.TemplateResponse('same_major.html', {
        'request': request, 
        'user': user, 
        'users': users, 
        'message': message
    })


@app.get('/send_request/{recipient_id}', response_class=HTMLResponse)
async def send_request_form(request: Request, recipient_id: int):
    user = require_login(request)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (recipient_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='User not found')
        recipient = dict_from_row(row)
        
    now = datetime.utcnow()
    blocked_current = user['blocked_until'] and datetime.fromisoformat(user['blocked_until']) > now
    blocked_recipient = recipient['blocked_until'] and datetime.fromisoformat(recipient['blocked_until']) > now
    
    if blocked_current or blocked_recipient:
        return templates.TemplateResponse('same_major.html', {
            'request': request, 
            'user': user, 
            'users': [], 
            'message': 'One of the users is currently blocked from sending or receiving requests.'
        })
        
    return templates.TemplateResponse('send_request.html', {
        'request': request, 
        'user': user, 
        'recipient': recipient
    })


@app.post('/send_request/{recipient_id}')
async def send_request_action(request: Request, recipient_id: int):
    user = require_login(request)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (recipient_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='User not found')
        recipient = dict_from_row(row)

    now = datetime.utcnow()
    blocked_current = user['blocked_until'] and datetime.fromisoformat(user['blocked_until']) > now
    blocked_recipient = recipient['blocked_until'] and datetime.fromisoformat(recipient['blocked_until']) > now
    
    if blocked_current or blocked_recipient:
        return templates.TemplateResponse('same_major.html', {
            'request': request, 
            'user': user, 
            'users': [], 
            'message': 'One of the users is currently blocked.'
        })
        
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    sop_text = data.get('sop', [''])[0]
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('INSERT INTO requests (requester_id, recipient_id, requester_sop, status, sent_at) VALUES (?, ?, ?, ?, ?)',
                  (user['id'], recipient_id, sop_text, 'pending', datetime.utcnow().isoformat()))
        conn.commit()
        
    return RedirectResponse('/dashboard', status_code=302)


@app.get('/request/{req_id}', response_class=HTMLResponse)
async def request_detail(request: Request, req_id: int):
    user = require_login(request)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Request not found')
        req_row = dict_from_row(row)
        
        # 권한 확인
        if req_row['recipient_id'] != user['id']:
            raise HTTPException(status_code=403, detail='Not authorized')
        
        if req_row['status'] != 'pending':
            return RedirectResponse('/dashboard', status_code=302)
            
        # 요청자 정보 가져오기
        c.execute('SELECT * FROM users WHERE id = ?', (req_row['requester_id'],))
        requester = dict_from_row(c.fetchone())
        
    return templates.TemplateResponse('request_detail.html', {
        'request': request, 
        'user': user, 
        'rr': req_row, 
        'requester': requester
    })


@app.post('/request/{req_id}')
async def request_action(request: Request, req_id: int):
    user = require_login(request)
    
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    action = data.get('action', [''])[0]
    sop_text = data.get('sop', [''])[0] if 'sop' in data else None
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Request not found')
        req_row = dict_from_row(row)
        
        if req_row['recipient_id'] != user['id']:
            raise HTTPException(status_code=403, detail='Not authorized')
            
        if req_row['status'] != 'pending':
            return RedirectResponse('/dashboard', status_code=302)
            
        if action == 'accept':
            if not sop_text:
                # 에러 발생 시 정보 재조회 필요
                c.execute('SELECT * FROM users WHERE id = ?', (req_row['requester_id'],))
                requester = dict_from_row(c.fetchone())
                return templates.TemplateResponse('request_detail.html', {
                    'request': request,
                    'user': user,
                    'rr': req_row,
                    'requester': requester,
                    'error': 'SOP is required to accept.'
                }, status_code=400)
                
            accepted_at = datetime.utcnow()
            deadline = accepted_at + timedelta(hours=24)
            c.execute('UPDATE requests SET recipient_sop = ?, status = ?, accepted_at = ?, deadline = ? WHERE id = ?',
                      (sop_text, 'accepted', accepted_at.isoformat(), deadline.isoformat(), req_id))
            conn.commit()
        else:
            # 거절 (삭제)
            c.execute('DELETE FROM requests WHERE id = ?', (req_id,))
            conn.commit()
            
    return RedirectResponse('/dashboard', status_code=302)


@app.get('/review/{req_id}', response_class=HTMLResponse)
async def review_form(request: Request, req_id: int):
    user = require_login(request)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Request not found')
        rr = dict_from_row(row)
        
    if rr['status'] != 'accepted':
        return RedirectResponse('/dashboard', status_code=302)
        
    deadline = datetime.fromisoformat(rr['deadline']) if rr['deadline'] else None
    if deadline and datetime.utcnow() > deadline:
        return RedirectResponse('/dashboard', status_code=302)
        
    # 나의 역할 확인 (요청자 or 수신자)
    if user['id'] == rr['requester_id']:
        my_sop = rr['requester_sop']
        other_sop = rr['recipient_sop']
        my_review = rr['requester_review']
    elif user['id'] == rr['recipient_id']:
        my_sop = rr['recipient_sop']
        other_sop = rr['requester_sop']
        my_review = rr['recipient_review']
    else:
        raise HTTPException(status_code=403, detail='Not authorized')
        
    return templates.TemplateResponse('review_form.html', {
        'request': request, 
        'user': user, 
        'rr': rr, 
        'my_sop': my_sop, 
        'other_sop': other_sop, 
        'my_review': my_review
    })


@app.post('/review/{req_id}')
async def submit_review(request: Request, req_id: int):
    user = require_login(request)
    
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    review_text = data.get('review_text', [''])[0]
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Request not found')
        rr = dict_from_row(row)
        
        if rr['status'] != 'accepted':
            return RedirectResponse('/dashboard', status_code=302)
            
        deadline = datetime.fromisoformat(rr['deadline']) if rr['deadline'] else None
        if deadline and datetime.utcnow() > deadline:
            return RedirectResponse('/dashboard', status_code=302)
            
        if user['id'] == rr['requester_id']:
            c.execute('UPDATE requests SET requester_review = ?, requester_reviewed_at = ? WHERE id = ?',
                      (review_text, datetime.utcnow().isoformat(), req_id))
        elif user['id'] == rr['recipient_id']:
            c.execute('UPDATE requests SET recipient_review = ?, recipient_reviewed_at = ? WHERE id = ?',
                      (review_text, datetime.utcnow().isoformat(), req_id))
        else:
            raise HTTPException(status_code=403, detail='Not authorized')
            
        # 양쪽 다 완료되었는지 체크
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        updated = dict_from_row(c.fetchone())
        if updated['requester_review'] and updated['recipient_review']:
            c.execute('UPDATE requests SET status = ? WHERE id = ?', ('completed', req_id))
        conn.commit()
        
    return RedirectResponse('/dashboard', status_code=302)


@app.get('/results/{req_id}', response_class=HTMLResponse)
async def review_results(request: Request, req_id: int):
    user = require_login(request)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Request not found')
        rr = dict_from_row(row)
        
    if rr['status'] != 'completed':
        return RedirectResponse('/dashboard', status_code=302)
        
    if user['id'] not in (rr['requester_id'], rr['recipient_id']):
        raise HTTPException(status_code=403, detail='Not authorized')
        
    return templates.TemplateResponse('review_results.html', {
        'request': request, 
        'user': user, 
        'rr': rr
    })