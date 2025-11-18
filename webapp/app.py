from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import pyotp, os, json, datetime, subprocess
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.environ.get('BASE_PATH', '/opt/security-audit')
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me')
database_path = os.environ.get('DATABASE_PATH', os.path.join(BASE, 'data', 'webapp.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{database_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login = LoginManager(app)

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True)
    password_hash=db.Column(db.String(200))
    role=db.Column(db.String(20),"user")
    mfa_secret=db.Column(db.String(32), nullable=True)
    mfa_enabled=db.Column(db.Boolean, default=False)
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)
    def get_id(self): return str(self.id)

@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

@app.before_first_request
def create_admin():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        u=User(username='admin', role='admin')
        u.set_password('ChangeMeNow!')
        u.mfa_secret=pyotp.random_base32()
        u.mfa_enabled=True
        db.session.add(u); db.session.commit()

# Alternative approach for Flask 2.3+ compatibility
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        u=User(username='admin', role='admin')
        u.set_password('ChangeMeNow!')
        u.mfa_secret=pyotp.random_base32()
        u.mfa_enabled=True
        db.session.add(u); db.session.commit()

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and u.check_password(request.form['password']):
            if u.mfa_enabled:
                token = request.form.get('token','')
                if not pyotp.TOTP(u.mfa_secret).verify(token):
                    flash('Invalid MFA token'); return redirect(url_for('login'))
            login_user(u)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    scans = sorted(os.listdir(base)) if os.path.isdir(base) else []
    return render_template('index.html', scans=scans)

@app.route('/run_scan', methods=['POST'])
@login_required
def run_scan():
    # trigger scan via Docker exec (in scanner container)
    config_path = os.environ.get('CONFIG_PATH', os.path.join(BASE, 'config.json'))
    scan_script = os.path.join(BASE, 'reporting', 'run_full_scan.py')
    # Run scan in scanner container
    try:
        # Check if we're in Docker, use docker exec to run in scanner container
        if os.path.exists('/.dockerenv'):
            # We're in Docker, try to run in scanner container via docker
            docker_cmd = ['docker', 'exec', '-d', 'security-audit-scanner', 
                         'python3', scan_script, '--config', config_path]
            subprocess.Popen(docker_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Direct Python call if not in Docker
            subprocess.Popen([
                'python3', scan_script, 
                '--config', config_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        # Fallback: try direct execution
        subprocess.Popen([
            'python3', scan_script, 
            '--config', config_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    flash('Scan started')
    return redirect(url_for('index'))

@app.route('/reports/<scan>')
@login_required
def reports(scan):
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    path = os.path.join(base, scan, 'final_report')
    if not os.path.isdir(path): return "Not found", 404
    files = [f for f in os.listdir(path) if f.endswith('.html') or f.endswith('.pdf')]
    return render_template('reports.html', files=files, scan=scan)

@app.route('/download/<scan>/<fn>')
@login_required
def download(scan, fn):
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    p = os.path.join(base, scan, 'final_report', fn)
    if os.path.exists(p): return send_file(p)
    return "Not found", 404

if __name__=='__main__':
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5005))
    app.run(host=host, port=port)
