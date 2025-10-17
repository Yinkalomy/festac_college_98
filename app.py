import os
import uuid
import hmac
import hashlib
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import csv, io, datetime, base64, secrets
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///instance/votes.db')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
ADMIN_REGISTER_CODE = os.getenv('ADMIN_REGISTER_CODE', 'admincode123')

load_dotenv()  # take environment variables from .env.

# server salt for HMAC (base64 in env or local file)
_SERVER_SALT_B64 = os.getenv('SERVER_SALT')
if _SERVER_SALT_B64:
    SERVER_SALT = base64.b64decode(_SERVER_SALT_B64)
else:
    SALT_PATH = 'server_salt.bin'
    if os.path.exists(SALT_PATH):
        SERVER_SALT = open(SALT_PATH, 'rb').read()
    else:
        s = secrets.token_bytes(32)
        open(SALT_PATH, 'wb').write(s)
        SERVER_SALT = s

db = SQLAlchemy(app)

# Models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    email = db.Column(db.String(254), nullable=True)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Ballot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), nullable=False)
    choice = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def token_hmac(token: str) -> str:
    return hmac.new(SERVER_SALT, token.encode('utf-8'), hashlib.sha256).hexdigest()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin_id'):
            return redirect(url_for('admin_login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# Create tables before starting the app
with app.app_context():
    db.create_all()

# Public pages
@app.route('/')
def index():
    return render_template('index.html', association_name=os.getenv('ASSOCIATION_NAME', 'Festac College 1998 Set'))

@app.route('/vote/<token>', methods=['GET','POST'])
def vote_with_token(token):
    t = Token.query.filter_by(token=token).first()
    if not t or t.used:
        return render_template('vote_invalid.html')
    if request.method == 'POST':
        choice = request.form.get('choice')
        if not choice:
            return render_template('vote.html', token=token, error="Please enter a choice.")
        th = token_hmac(token)
        b = Ballot(token_hash=th, choice=choice)
        t.used = True
        # blank plaintext token for privacy
        t.token = ''
        db.session.add(b)
        db.session.commit()
        return render_template('thanks.html')
    return render_template('vote.html', token=token)

# Admin auth
@app.route('/admin/register', methods=['GET','POST'])
def admin_register():
    if request.method == 'POST':
        code = request.form.get('code','')
        if ADMIN_REGISTER_CODE and code != ADMIN_REGISTER_CODE:
            return "Invalid registration code.", 403
        email = request.form.get('email')
        pwd = request.form.get('password')
        if not email or not pwd:
            return "Missing fields", 400
        if Admin.query.filter_by(email=email).first():
            return "Admin already exists", 400
        adm = Admin(email=email)
        adm.set_password(pwd)
        db.session.add(adm)
        db.session.commit()
        return redirect(url_for('admin_login'))
    return render_template('register.html', require_code=bool(ADMIN_REGISTER_CODE))

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        pwd = request.form.get('password')
        adm = Admin.query.filter_by(email=email).first()
        if not adm or not adm.check_password(pwd):
            return render_template('login.html', error="Invalid credentials")
        session['admin_id'] = adm.id
        session['admin_email'] = adm.email
        return redirect(url_for('admin_dashboard'))
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    return redirect(url_for('admin_login'))

# Admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html', email=session.get('admin_email'))

@app.route('/admin/generate', methods=['GET','POST'])
@login_required
def admin_generate():
    if request.method == 'POST':
        emails_raw = request.form.get('emails','').strip()
        count = request.form.get('count')
        emails = []
        if emails_raw:
            emails = [e.strip() for e in emails_raw.splitlines() if e.strip()]
        anon_count = int(count) if count and count.isdigit() else 0
        created = []
        for e in emails:
            token_val = str(uuid.uuid4())
            t = Token(token=token_val, email=e)
            db.session.add(t)
            db.session.flush()
            created.append((e, url_for('vote_with_token', token=token_val, _external=True)))
        for i in range(anon_count):
            token_val = str(uuid.uuid4())
            t = Token(token=token_val, email=None)
            db.session.add(t)
            db.session.flush()
            created.append((None, url_for('vote_with_token', token=token_val, _external=True)))
        db.session.commit()
        return render_template('generated.html', created=created)
    return render_template('generate.html')

@app.route('/admin/tally')
@login_required
def admin_tally():
    rows = db.session.query(Ballot.choice, db.func.count(Ballot.id)).group_by(Ballot.choice).all()
    total = sum([r[1] for r in rows])
    return render_template('tally.html', rows=rows, total=total)

@app.route('/admin/export-audit')
@login_required
def admin_export_audit():
    ballots = Ballot.query.order_by(Ballot.created_at.asc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['token_hash','choice','created_at'])
    for b in ballots:
        writer.writerow([b.token_hash, b.choice, b.created_at.isoformat()])
    csv_bytes = buf.getvalue().encode('utf-8')
    signature = hmac.new(SERVER_SALT, csv_bytes, hashlib.sha256).hexdigest()
    out = io.BytesIO(csv_bytes)
    out.seek(0)
    headers = {'X-Audit-Signature': signature}
    return send_file(out, mimetype='text/csv', as_attachment=True, download_name='audit_ballots.csv', headers=headers)

if __name__ == '__main__':
    app.run(debug=True)
