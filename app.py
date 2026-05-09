from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

ENCRYPTION_KEY_FILE = 'encryption.key'
def load_or_create_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f: return f.read()
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as f: f.write(key)
    return key
fernet = Fernet(load_or_create_key())

def encrypt_data(p):
    return fernet.encrypt(p.encode()).decode() if p else ''
def decrypt_data(c):
    try: return fernet.decrypt(c.encode()).decode() if c else ''
    except: return '[error]'

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role          = db.Column(db.String(20), default='user')
    email_enc     = db.Column(db.Text, default='')
    phone_enc     = db.Column(db.Text, default='')
    grades        = db.relationship('Grade', backref='user', lazy=True, cascade='all, delete-orphan')

    @property
    def email(self): return decrypt_data(self.email_enc)
    @email.setter
    def email(self, v): self.email_enc = encrypt_data(v)
    @property
    def phone(self): return decrypt_data(self.phone_enc)
    @phone.setter
    def phone(self, v): self.phone_enc = encrypt_data(v)

    def get_gpa(self):
        if not self.grades: return 0.0
        tp = sum(g.grade_points() * g.credits for g in self.grades)
        tc = sum(g.credits for g in self.grades)
        return round(tp / tc, 2) if tc > 0 else 0.0

    def total_credits(self): return sum(g.credits for g in self.grades)

class Grade(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    user_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject  = db.Column(db.String(100), nullable=False)
    credits  = db.Column(db.Integer, nullable=False, default=3)
    score    = db.Column(db.Float, nullable=False)
    semester = db.Column(db.String(50), default='')

    def letter_grade(self):
        s = self.score
        if s>=90: return 'A+'
        if s>=85: return 'A'
        if s>=80: return 'A-'
        if s>=75: return 'B+'
        if s>=70: return 'B'
        if s>=65: return 'B-'
        if s>=60: return 'C+'
        if s>=55: return 'C'
        if s>=50: return 'C-'
        if s>=45: return 'D'
        return 'F'

    def grade_points(self):
        s = self.score
        if s>=90: return 4.0
        if s>=85: return 3.7
        if s>=80: return 3.3
        if s>=75: return 3.0
        if s>=70: return 2.7
        if s>=65: return 2.3
        if s>=60: return 2.0
        if s>=55: return 1.7
        if s>=50: return 1.3
        if s>=45: return 1.0
        return 0.0

    def status(self): return 'Pass' if self.score >= 50 else 'Fail'

def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        u = User.query.get(session['user_id'])
        if not u or u.role != 'admin': abort(403)
        return f(*a, **k)
    return d

@app.route('/')
def index(): return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        email    = request.form.get('email','').strip()
        phone    = request.form.get('phone','').strip()
        if not username or not password:
            flash('Username and password required.','danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username taken.','danger')
            return render_template('register.html')
        u = User(username=username, password_hash=generate_password_hash(password))
        u.email = email; u.phone = phone
        db.session.add(u); db.session.commit()
        flash('Account created! Please log in.','success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form.get('username','').strip()).first()
        if u and check_password_hash(u.password_hash, request.form.get('password','')):
            session['user_id'] = u.id
            session['username'] = u.username
            session['role'] = u.role
            flash(f'Welcome back, {u.username}!','success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.','danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out.','info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/grades')
@login_required
def grades():
    user = User.query.get(session['user_id'])
    return render_template('grades.html', user=user)

@app.route('/manage_grades')
@admin_required
def manage_grades():
    students = User.query.filter_by(role='user').all()
    return render_template('manage_grades.html', students=students)

@app.route('/grades/delete/<int:gid>', methods=['POST'])
@admin_required
def delete_grade(gid):
    g = Grade.query.get_or_404(gid)
    uid = g.user_id
    db.session.delete(g); db.session.commit()
    flash('Grade deleted.','info')
    return redirect(url_for('admin_view_grades', uid=uid))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.email = request.form.get('email','').strip()
        user.phone = request.form.get('phone','').strip()
        db.session.commit()
        flash('Profile updated.','success')
    return render_template('profile.html', user=user)

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', users=User.query.all())

@app.route('/admin/delete/<int:uid>', methods=['POST'])
@admin_required
def delete_user(uid):
    u = User.query.get_or_404(uid)
    if u.role == 'admin':
        flash("Cannot delete admin accounts.",'danger')
        return redirect(url_for('admin_panel'))
    db.session.delete(u); db.session.commit()
    flash(f'User {u.username} deleted.','success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/promote/<int:uid>', methods=['POST'])
@admin_required
def promote_user(uid):
    u = User.query.get_or_404(uid)
    u.role = 'admin'; db.session.commit()
    flash(f'{u.username} promoted to admin.','success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/grades/<int:uid>')
@admin_required
def admin_view_grades(uid):
    user = User.query.get_or_404(uid)
    return render_template('admin_grades.html', user=user)

@app.route('/admin/grades/<int:uid>/add', methods=['POST'])
@admin_required
def admin_add_grade(uid):
    user = User.query.get_or_404(uid)
    subject  = request.form.get('subject','').strip()
    credits  = request.form.get('credits','3')
    score    = request.form.get('score','')
    semester = request.form.get('semester','').strip()
    if not subject or not score:
        flash('Subject and score required.','danger')
        return redirect(url_for('admin_view_grades', uid=uid))
    try:
        sf = float(score); ci = int(credits)
        if not (0 <= sf <= 100) or not (1 <= ci <= 6): raise ValueError
    except ValueError:
        flash('Score must be 0-100, credits 1-6.','danger')
        return redirect(url_for('admin_view_grades', uid=uid))
    db.session.add(Grade(user_id=uid, subject=subject, credits=ci, score=sf, semester=semester))
    db.session.commit()
    flash(f'"{subject}" added to {user.username}!','success')
    return redirect(url_for('admin_view_grades', uid=uid))

@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403
@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404

def create_tables():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            a = User(username='admin', password_hash=generate_password_hash('Admin@1234'), role='admin')
            a.email = 'admin@secureapp.com'; a.phone = '+1-000-000-0000'
            db.session.add(a); db.session.commit()
            print("✓ Admin created → username: admin | password: Admin@1234")

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
