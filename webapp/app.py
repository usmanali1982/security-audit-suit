from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import traceback
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
login.login_view = 'login'
login.login_message = 'Please log in to access this page.'

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True)
    password_hash=db.Column(db.String(200))
    role=db.Column(db.String(20), default="user")
    mfa_secret=db.Column(db.String(32), nullable=True)
    mfa_enabled=db.Column(db.Boolean, default=False)
    is_active=db.Column(db.Boolean, default=True)  # Required by Flask-Login
    
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)
    def get_id(self): return str(self.id)
    
    # Flask-Login compatibility methods
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False

@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# Initialize database and create admin user (Flask 2.3+ compatible)
# @app.before_first_request is deprecated in Flask 2.2+, removed in Flask 2.3+
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        u=User(username='admin', role='admin', is_active=True)
        u.set_password('ChangeMeNow!')
        u.mfa_secret=pyotp.random_base32()
        u.mfa_enabled=True
        db.session.add(u)
        db.session.commit()
    else:
        # Update existing admin user to ensure is_active is set
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            if not hasattr(admin_user, 'is_active') or admin_user.is_active is None:
                admin_user.is_active = True
                db.session.commit()

@app.route('/login', methods=['GET','POST'])
def login():
    # If user is already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method=='POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        token = request.form.get('token', '')
        
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            if u.mfa_enabled:
                if not token:
                    flash('MFA is enabled. Please enter your MFA token.')
                    return render_template('login.html', username=username)
                try:
                    if not pyotp.TOTP(u.mfa_secret).verify(token, valid_window=1):
                        flash('Invalid MFA token. Please try again.')
                        return render_template('login.html', username=username)
                except Exception as e:
                    flash(f'MFA verification error: {str(e)}')
                    return render_template('login.html', username=username)
            login_user(u, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password')
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
    scans = []
    try:
        # Create directory if it doesn't exist
        os.makedirs(base, exist_ok=True)
        # Get list of scans with error handling
        if os.path.isdir(base):
            try:
                all_items = os.listdir(base)
                # Filter only directories, exclude files
                scans = [s for s in all_items if os.path.isdir(os.path.join(base, s))]
                # Sort by name (timestamp) descending - most recent first
                scans = sorted(scans, reverse=True)
            except PermissionError:
                flash('Permission denied: Cannot read scan directory', 'error')
            except Exception as e:
                flash(f'Error listing scans: {str(e)}', 'error')
    except Exception as e:
        app.logger.error(f'Error in index route: {traceback.format_exc()}')
        flash(f'Error accessing scan directory: {str(e)}', 'error')
    return render_template('index.html', scans=scans, current_user=current_user)

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

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    error_msg = traceback.format_exc()
    app.logger.error(f'Internal server error: {error_msg}')
    return f'<h1>Internal Server Error</h1><p>An error occurred. Please check the logs.</p><pre style="background:#f0f0f0;padding:10px;border-radius:5px;">{error_msg}</pre><br><a href="/">Go to Dashboard</a>', 500

@app.errorhandler(404)
def not_found(error):
    return '<h1>Page Not Found</h1><p>The page you are looking for does not exist.</p><br><a href="/">Go to Dashboard</a>', 404

if __name__=='__main__':
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5005))
    app.run(host=host, port=port)
