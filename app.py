import os
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # You should replace this with a secure random value in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sop_review.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    nickname = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    major = db.Column(db.String(80), nullable=False)
    degree = db.Column(db.String(80), nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ReviewRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requester_sop = db.Column(db.Text, nullable=True)
    recipient_sop = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, completed, expired
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime, nullable=True)
    deadline = db.Column(db.DateTime, nullable=True)
    requester_review = db.Column(db.Text, nullable=True)
    recipient_review = db.Column(db.Text, nullable=True)
    requester_reviewed_at = db.Column(db.DateTime, nullable=True)
    recipient_reviewed_at = db.Column(db.DateTime, nullable=True)

    def requester(self):
        return User.query.get(self.requester_id)

    def recipient(self):
        return User.query.get(self.recipient_id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables():
    db.create_all()


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        nickname = request.form['nickname']
        password = request.form['password']
        major = request.form['major']
        degree = request.form['degree']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=username, nickname=nickname, major=major, degree=degree)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    majors = [
        'Computer Science', 'Electrical Engineering', 'Mechanical Engineering',
        'Chemistry', 'Physics', 'Biology', 'Mathematics', 'Economics', 'Business',
        'Psychology', 'Sociology', 'History', 'Art', 'Music', 'Education'
    ]
    degrees = [
        'Bachelor', 'Master', 'PhD', 'MD', 'MBA'
    ]
    return render_template('register.html', majors=majors, degrees=degrees)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Show overview: pending requests, accepted and awaiting review, completed
    # Check for expired reviews and apply penalties
    now = datetime.utcnow()
    # Evaluate expired requests for current user as requester or recipient
    expired_requests = ReviewRequest.query.filter(
        (ReviewRequest.status == 'accepted') & (ReviewRequest.deadline < now)
    ).all()
    for req in expired_requests:
        # Determine who failed to review
        if req.requester_review is None:
            failed_user = req.requester()
        elif req.recipient_review is None:
            failed_user = req.recipient()
        else:
            continue
        # apply penalty if not already applied
        if not failed_user.blocked_until or failed_user.blocked_until < now:
            failed_user.blocked_until = now + timedelta(hours=48)
            db.session.commit()
        # mark request as expired
        req.status = 'expired'
        db.session.commit()
    # Get all review requests involving current user
    pending_requests = ReviewRequest.query.filter(
        (ReviewRequest.recipient_id == current_user.id) & (ReviewRequest.status == 'pending')
    ).all()
    accepted_requests = ReviewRequest.query.filter(
        ((ReviewRequest.requester_id == current_user.id) | (ReviewRequest.recipient_id == current_user.id)) &
        (ReviewRequest.status == 'accepted')
    ).all()
    completed_requests = ReviewRequest.query.filter(
        ((ReviewRequest.requester_id == current_user.id) | (ReviewRequest.recipient_id == current_user.id)) &
        (ReviewRequest.status == 'completed')
    ).all()
    return render_template('dashboard.html', pending_requests=pending_requests, accepted_requests=accepted_requests, completed_requests=completed_requests)


@app.route('/same_major')
@login_required
def same_major():
    # Check if user is blocked
    now = datetime.utcnow()
    if current_user.blocked_until and current_user.blocked_until > now:
        flash(f'You are temporarily blocked until {current_user.blocked_until} and cannot send review requests.')
        users = []
    else:
        users = User.query.filter_by(major=current_user.major).filter(User.id != current_user.id).all()
    return render_template('same_major.html', users=users)


@app.route('/send_request/<int:user_id>', methods=['GET', 'POST'])
@login_required
def send_request(user_id):
    recipient = User.query.get_or_404(user_id)
    now = datetime.utcnow()
    # Check if either user is blocked
    if (current_user.blocked_until and current_user.blocked_until > now) or (recipient.blocked_until and recipient.blocked_until > now):
        flash('One of the users is currently blocked from sending/receiving requests.')
        return redirect(url_for('same_major'))
    if request.method == 'POST':
        sop_text = request.form['sop']
        # create review request
        rr = ReviewRequest(
            requester_id=current_user.id,
            recipient_id=recipient.id,
            requester_sop=sop_text
        )
        db.session.add(rr)
        db.session.commit()
        flash('Review request sent.')
        return redirect(url_for('dashboard'))
    return render_template('send_request.html', recipient=recipient)


@app.route('/request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def request_detail(request_id):
    rr = ReviewRequest.query.get_or_404(request_id)
    # Only recipient can accept / reject
    if current_user.id != rr.recipient_id:
        flash('You are not authorized to view this request.')
        return redirect(url_for('dashboard'))
    if rr.status != 'pending':
        flash('This request is no longer pending.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'accept':
            sop_text = request.form['sop']
            rr.recipient_sop = sop_text
            rr.status = 'accepted'
            rr.accepted_at = datetime.utcnow()
            rr.deadline = rr.accepted_at + timedelta(hours=24)
            db.session.commit()
            flash('Review request accepted. Please complete your review within 24 hours.')
        else:
            # reject
            db.session.delete(rr)
            db.session.commit()
            flash('Review request rejected.')
        return redirect(url_for('dashboard'))
    return render_template('request_detail.html', rr=rr)


@app.route('/review/<int:request_id>', methods=['GET', 'POST'])
@login_required
def review(request_id):
    rr = ReviewRequest.query.get_or_404(request_id)
    if rr.status != 'accepted':
        flash('This review request is not in a state to be reviewed.')
        return redirect(url_for('dashboard'))
    now = datetime.utcnow()
    # check deadline
    if rr.deadline < now:
        flash('The review deadline has passed.')
        return redirect(url_for('dashboard'))
    # Determine which side user is
    if current_user.id == rr.requester_id:
        my_sop = rr.requester_sop
        other_sop = rr.recipient_sop
        my_review = rr.requester_review
    elif current_user.id == rr.recipient_id:
        my_sop = rr.recipient_sop
        other_sop = rr.requester_sop
        my_review = rr.recipient_review
    else:
        flash('You are not part of this review.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Save review
        review_text = request.form['review_text']
        if current_user.id == rr.requester_id:
            rr.requester_review = review_text
            rr.requester_reviewed_at = datetime.utcnow()
        else:
            rr.recipient_review = review_text
            rr.recipient_reviewed_at = datetime.utcnow()
        # If both reviews are completed, mark as completed
        if rr.requester_review and rr.recipient_review:
            rr.status = 'completed'
        db.session.commit()
        flash('Review submitted.')
        return redirect(url_for('dashboard'))
    return render_template('review_form.html', rr=rr, my_sop=my_sop, other_sop=other_sop, my_review=my_review)


@app.route('/results/<int:request_id>')
@login_required
def results(request_id):
    rr = ReviewRequest.query.get_or_404(request_id)
    if rr.status != 'completed':
        flash('Results are not available yet.')
        return redirect(url_for('dashboard'))
    # Check user is participant
    if current_user.id != rr.requester_id and current_user.id != rr.recipient_id:
        flash('You are not part of this review.')
        return redirect(url_for('dashboard'))
    return render_template('review_results.html', rr=rr)


if __name__ == '__main__':
    app.run(debug=True, port=5000)