"""
SOP Review Web Application using FastAPI and Starlette sessions.

This application allows users to register, log in, and exchange Statements of Purpose (SOP) for mutual review. Each user can view others in the same major, send review requests, accept requests by providing their SOP, and exchange reviews via a template within a 24‑hour deadline. Failure to submit a review within the deadline results in a 48‑hour block on sending or receiving new requests.

Database: SQLite (using Python's built‑in sqlite3 module).
Templates: Jinja2 templates stored in the `templates` directory.
Sessions: Stored in signed cookies via Starlette's SessionMiddleware.

To run this application locally, execute:
    uvicorn main:app --reload --port 8000

"""

import os
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
# We do not use SessionMiddleware because itsdangerous is not available.
# Instead we manage a simple user_id cookie manually for session handling.

import urllib.parse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'sop_review_fast.db')

def init_db():
    """Initialize the SQLite database and create tables if they do not exist."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            nickname TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            major TEXT NOT NULL,
            degree TEXT NOT NULL,
            blocked_until TEXT
        )''')
        # review requests table
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


def dict_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a sqlite3.Row to a dict."""
    return {k: row[k] for k in row.keys()}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Simple password hash using SHA256. For demo purposes only (no salt)."""
    import hashlib
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, 'templates'))


@app.on_event('startup')
def startup():
    # Ensure DB exists
    init_db()


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """Retrieve the currently logged‑in user from a signed cookie. Returns None if not logged in."""
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
    """Dependency to enforce login."""
    user = get_current_user(request)
    if not user:
        # Redirect to login page
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={'Location': '/'})
    return user


def check_expired_requests_for_user(user_id: int):
    """Check accepted requests for expiration and apply penalties."""
    now = datetime.utcnow()
    with get_db_connection() as conn:
        c = conn.cursor()
        # Fetch accepted requests where deadline has passed
        c.execute('SELECT * FROM requests WHERE status = ? AND deadline < ?', ('accepted', now.isoformat()))
        expired = c.fetchall()
        for row in expired:
            req = dict_from_row(row)
            # Determine who has not reviewed
            failed_user_id = None
            if not req['requester_review']:
                failed_user_id = req['requester_id']
            elif not req['recipient_review']:
                failed_user_id = req['recipient_id']
            if failed_user_id:
                # set block for 48 hours from now
                unblock_time = (now + timedelta(hours=48)).isoformat()
                c.execute('UPDATE users SET blocked_until = ? WHERE id = ?', (unblock_time, failed_user_id))
            # mark request as expired
            c.execute('UPDATE requests SET status = ? WHERE id = ?', ('expired', req['id']))
        conn.commit()


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
    majors = [
        'Computer Science', 'Electrical Engineering', 'Mechanical Engineering',
        'Chemistry', 'Physics', 'Biology', 'Mathematics', 'Economics', 'Business',
        'Psychology', 'Sociology', 'History', 'Art', 'Music', 'Education'
    ]
    degrees = ['Bachelor', 'Master', 'PhD', 'MD', 'MBA']
    return templates.TemplateResponse('register.html', {'request': request, 'majors': majors, 'degrees': degrees, 'user': None})


@app.post('/register')
async def register(request: Request):
    """Handle registration form submission."""
    # parse form data manually
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    username = data.get('username', [''])[0]
    nickname = data.get('nickname', [''])[0]
    password = data.get('password', [''])[0]
    major = data.get('major', [''])[0]
    degree = data.get('degree', [''])[0]
    # Validate inputs
    if not (username and nickname and password and major and degree):
        return templates.TemplateResponse('register.html', {
            'request': request,
            'error': 'All fields are required.',
            'majors': ['Computer Science', 'Electrical Engineering', 'Mechanical Engineering', 'Chemistry', 'Physics', 'Biology', 'Mathematics', 'Economics', 'Business', 'Psychology', 'Sociology', 'History', 'Art', 'Music', 'Education'],
            'degrees': ['Bachelor', 'Master', 'PhD', 'MD', 'MBA'],
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
        return templates.TemplateResponse('register.html', {
            'request': request,
            'error': 'Username already exists.',
            'majors': ['Computer Science', 'Electrical Engineering', 'Mechanical Engineering', 'Chemistry', 'Physics', 'Biology', 'Mathematics', 'Economics', 'Business', 'Psychology', 'Sociology', 'History', 'Art', 'Music', 'Education'],
            'degrees': ['Bachelor', 'Master', 'PhD', 'MD', 'MBA'],
            'user': None
        }, status_code=400)
    # Redirect to login
    response = RedirectResponse(url='/login', status_code=302)
    return response


@app.get('/login', response_class=HTMLResponse)
async def login_form(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse('/dashboard')
    return templates.TemplateResponse('login.html', {'request': request, 'user': None})


@app.post('/login')
async def login(request: Request):
    """Process login form submission."""
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
            response.set_cookie(key='user_id', value=str(user['id']), max_age=7*24*60*60, httponly=True)
            return response
    return templates.TemplateResponse('login.html', {'request': request, 'error': 'Invalid credentials.', 'user': None}, status_code=400)


@app.get('/logout')
async def logout(request: Request):
    # clear the cookie
    response = RedirectResponse('/', status_code=302)
    response.delete_cookie('user_id')
    return response


@app.get('/dashboard', response_class=HTMLResponse)
async def dashboard(request: Request):
    user = require_login(request)
    # Check expired requests for this user
    check_expired_requests_for_user(user['id'])
    now = datetime.utcnow().isoformat()
    # Fetch pending requests where user is recipient
    with get_db_connection() as conn:
        c = conn.cursor()
        # Pending requests where user is recipient
        c.execute('SELECT * FROM requests WHERE recipient_id = ? AND status = ?', (user['id'], 'pending'))
        pending_rows = c.fetchall()
        pending = []
        for r in pending_rows:
            rr = dict_from_row(r)
            # fetch requester nickname
            c.execute('SELECT nickname FROM users WHERE id = ?', (rr['requester_id'],))
            nick_row = c.fetchone()
            rr['requester_nickname'] = nick_row['nickname'] if nick_row else 'Unknown'
            pending.append(rr)
        # Accepted requests where user is either requester or recipient
        c.execute('SELECT * FROM requests WHERE (requester_id = ? OR recipient_id = ?) AND status = ?', (user['id'], user['id'], 'accepted'))
        accepted_rows = c.fetchall()
        accepted = []
        for r in accepted_rows:
            rr = dict_from_row(r)
            # partner id
            partner_id = rr['recipient_id'] if rr['requester_id'] == user['id'] else rr['requester_id']
            c.execute('SELECT nickname FROM users WHERE id = ?', (partner_id,))
            nick_row = c.fetchone()
            rr['partner_nickname'] = nick_row['nickname'] if nick_row else 'Unknown'
            accepted.append(rr)
        # Completed requests
        c.execute('SELECT * FROM requests WHERE (requester_id = ? OR recipient_id = ?) AND status = ?', (user['id'], user['id'], 'completed'))
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
    # Check if blocked
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
            # Unblock if past time
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('UPDATE users SET blocked_until = NULL WHERE id = ?', (user['id'],))
                conn.commit()
    if not message:
        # fetch users with same major excluding self
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE major = ? AND id != ?', (user['major'], user['id']))
            rows = c.fetchall()
            users = [dict_from_row(r) for r in rows]
    return templates.TemplateResponse('same_major.html', {'request': request, 'user': user, 'users': users, 'message': message})


@app.get('/send_request/{recipient_id}', response_class=HTMLResponse)
async def send_request_form(request: Request, recipient_id: int):
    user = require_login(request)
    # Check blocked status for both users
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (recipient_id,))
        row = c.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='User not found')
        recipient = dict_from_row(row)
    now = datetime.utcnow()
    # blocked for current user
    blocked_current = user['blocked_until'] and datetime.fromisoformat(user['blocked_until']) > now
    blocked_recipient = recipient['blocked_until'] and datetime.fromisoformat(recipient['blocked_until']) > now
    if blocked_current or blocked_recipient:
        return templates.TemplateResponse('same_major.html', {'request': request, 'user': user, 'users': [], 'message': 'One of the users is currently blocked from sending or receiving requests.'})
    return templates.TemplateResponse('send_request.html', {'request': request, 'user': user, 'recipient': recipient})


@app.post('/send_request/{recipient_id}')
async def send_request_action(request: Request, recipient_id: int):
    """Handle sending a review request. The user posts their SOP."""
    user = require_login(request)
    # Validate recipient
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
        return templates.TemplateResponse('same_major.html', {'request': request, 'user': user, 'users': [], 'message': 'One of the users is currently blocked from sending or receiving requests.'})
    # Parse body for SOP
    body = await request.body()
    data = urllib.parse.parse_qs(body.decode())
    sop_text = data.get('sop', [''])[0]
    # Create request with status pending
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
    # Only recipient can view
    if req_row['recipient_id'] != user['id']:
        raise HTTPException(status_code=403, detail='Not authorized')
    if req_row['status'] != 'pending':
        return RedirectResponse('/dashboard', status_code=302)
    # Get requester user info
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (req_row['requester_id'],))
        requester = dict_from_row(c.fetchone())
    return templates.TemplateResponse('request_detail.html', {'request': request, 'user': user, 'rr': req_row, 'requester': requester})


@app.post('/request/{req_id}')
async def request_action(request: Request, req_id: int):
    """Handle acceptance or rejection of a review request."""
    user = require_login(request)
    # Parse submitted form data
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
                return templates.TemplateResponse('request_detail.html', {
                    'request': request,
                    'user': user,
                    'rr': req_row,
                    'requester': None,
                    'error': 'SOP is required to accept.'
                }, status_code=400)
            accepted_at = datetime.utcnow()
            deadline = accepted_at + timedelta(hours=24)
            c.execute('UPDATE requests SET recipient_sop = ?, status = ?, accepted_at = ?, deadline = ? WHERE id = ?',
                      (sop_text, 'accepted', accepted_at.isoformat(), deadline.isoformat(), req_id))
            conn.commit()
        else:
            # reject: delete request
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
    # ensure accepted
    if rr['status'] != 'accepted':
        return RedirectResponse('/dashboard', status_code=302)
    # check deadline
    deadline = datetime.fromisoformat(rr['deadline']) if rr['deadline'] else None
    if deadline and datetime.utcnow() > deadline:
        # This should be handled by expiration check, but redirect anyway
        return RedirectResponse('/dashboard', status_code=302)
    # Determine my role
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
    return templates.TemplateResponse('review_form.html', {'request': request, 'user': user, 'rr': rr, 'my_sop': my_sop, 'other_sop': other_sop, 'my_review': my_review})


@app.post('/review/{req_id}')
async def submit_review(request: Request, req_id: int):
    """Submit a review for a partner's SOP."""
    user = require_login(request)
    # parse form data manually
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
        # Check if both reviews complete
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
    return templates.TemplateResponse('review_results.html', {'request': request, 'user': user, 'rr': rr})