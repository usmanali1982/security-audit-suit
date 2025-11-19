from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, stream_with_context
import traceback
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as db_text
from sqlalchemy.exc import OperationalError
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from functools import wraps
from collections import defaultdict
from queue import Queue, Empty
import uuid, sys
import pyotp, os, json, datetime, subprocess, threading, time, shutil, io, base64
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from webapp.services import (
    ScriptRegistry,
    SSHConnectivityService,
    OrchestratorService,
    RunRequest,
)

# --- App Initialization ---
BASE = os.environ.get('BASE_PATH', '/opt/security-audit')
PROJECT_ROOT = os.environ.get('PROJECT_ROOT', os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
SCRIPTS_BASE = os.environ.get('SCRIPTS_BASE', PROJECT_ROOT)
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me')

# Ensure data directory exists
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE, 'data'))
os.makedirs(DATA_DIR, exist_ok=True)
REPORTS_DIR = os.path.join(DATA_DIR, 'reports')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Set database path
database_path = os.path.join(DATA_DIR, 'webapp.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{database_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
login.login_message = 'Please log in to access this page.'

script_registry = ScriptRegistry(SCRIPTS_BASE)
connectivity_service = SSHConnectivityService()
RUN_LOG_STREAMS = defaultdict(list)
orchestrator = None
# --- End App Initialization ---
# Models
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True, nullable=False)
    password_hash=db.Column(db.String(200))
    role=db.Column(db.String(20), default="user")
    mfa_secret=db.Column(db.String(32), nullable=True)
    mfa_enabled=db.Column(db.Boolean, default=False)
    is_active=db.Column(db.Boolean, default=True)
    created_at=db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)
    def get_id(self): return str(self.id)
    
    @property
    def is_authenticated(self): return True
    @property
    def is_anonymous(self): return False
    def is_admin(self): return self.role == 'admin'

class Host(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    hostname=db.Column(db.String(255), nullable=False)
    ip_address=db.Column(db.String(45), nullable=False)
    ssh_user=db.Column(db.String(100), default="root")
    ssh_port=db.Column(db.Integer, default=22)
    ssh_key_path=db.Column(db.String(500), nullable=True)
    description=db.Column(db.Text, nullable=True)
    is_active=db.Column(db.Boolean, default=True)
    created_at=db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at=db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    bastion_host=db.Column(db.String(255), nullable=True)
    bastion_user=db.Column(db.String(100), nullable=True)
    bastion_port=db.Column(db.Integer, nullable=True)
    bastion_key_path=db.Column(db.String(500), nullable=True)
    last_check_status=db.Column(db.String(20), nullable=True)
    last_check_message=db.Column(db.String(255), nullable=True)
    last_check_at=db.Column(db.DateTime, nullable=True)
    last_latency_ms=db.Column(db.Float, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id, 'hostname': self.hostname, 'ip_address': self.ip_address,
            'ssh_user': self.ssh_user, 'ssh_port': self.ssh_port,
            'ssh_key_path': self.ssh_key_path, 'description': self.description,
            'is_active': self.is_active,
            'bastion_host': self.bastion_host,
            'bastion_user': self.bastion_user,
            'bastion_port': self.bastion_port,
            'bastion_key_path': self.bastion_key_path,
            'last_check_status': self.last_check_status,
            'last_check_message': self.last_check_message,
            'last_check_at': self.last_check_at.isoformat() if self.last_check_at else None,
            'last_latency_ms': self.last_latency_ms,
        }

class Scan(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    scan_type=db.Column(db.String(50), nullable=False)
    host_id=db.Column(db.Integer, db.ForeignKey('host.id'), nullable=True)
    status=db.Column(db.String(20), default='pending')
    progress=db.Column(db.Integer, default=0)
    current_task=db.Column(db.String(255), nullable=True)
    output_dir=db.Column(db.String(500), nullable=True)
    started_at=db.Column(db.DateTime, nullable=True)
    completed_at=db.Column(db.DateTime, nullable=True)
    created_by=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at=db.Column(db.DateTime, default=db.func.current_timestamp())
    error_message=db.Column(db.Text, nullable=True)
    
    host = db.relationship('Host', backref='scans')
    creator = db.relationship('User', backref='scans')

class ScanLog(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    scan_id=db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    log_level=db.Column(db.String(20), default='info')
    message=db.Column(db.Text, nullable=False)
    timestamp=db.Column(db.DateTime, default=db.func.current_timestamp())
    
    scan = db.relationship('Scan', backref='scan_logs')

class Run(db.Model):
    run_id=db.Column(db.String(64), primary_key=True)
    run_type=db.Column(db.String(50), nullable=False)
    status=db.Column(db.String(20), default='pending')
    scripts=db.Column(db.Text, nullable=False)
    tools=db.Column(db.Text, nullable=True)
    run_metadata=db.Column(db.Text, nullable=True)
    created_by=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at=db.Column(db.DateTime, default=db.func.current_timestamp())
    started_at=db.Column(db.DateTime, nullable=True)
    completed_at=db.Column(db.DateTime, nullable=True)
    progress=db.Column(db.Integer, default=0)
    error_message=db.Column(db.Text, nullable=True)
    report_path=db.Column(db.String(500), nullable=True)
    
    creator = db.relationship('User', backref='runs')

    def to_dict(self):
        return {
            'run_id': self.run_id,
            'run_type': self.run_type,
            'status': self.status,
            'scripts': json.loads(self.scripts or '[]'),
            'run_metadata': json.loads(self.run_metadata or '{}'),
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'error_message': self.error_message,
            'report_path': self.report_path,
        }

class RunHost(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    run_id=db.Column(db.String(64), db.ForeignKey('run.run_id'), nullable=False)
    host_id=db.Column(db.Integer, db.ForeignKey('host.id'), nullable=True)
    hostname=db.Column(db.String(255), nullable=False)
    ip_address=db.Column(db.String(45), nullable=False)
    status=db.Column(db.String(20), default='pending')
    last_message=db.Column(db.Text, nullable=True)
    latency_ms=db.Column(db.Float, nullable=True)

    run = db.relationship('Run', backref='hosts')

    def to_dict(self):
        return {
            'run_id': self.run_id,
            'host_id': self.host_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'status': self.status,
            'last_message': self.last_message,
            'latency_ms': self.latency_ms,
        }

class RunLog(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    run_id=db.Column(db.String(64), db.ForeignKey('run.run_id'), nullable=False)
    level=db.Column(db.String(20), default='info')
    message=db.Column(db.Text, nullable=False)
    created_at=db.Column(db.DateTime, default=db.func.current_timestamp())

    run = db.relationship('Run', backref='logs')

    def to_dict(self):
        return {
            'run_id': self.run_id,
            'level': self.level,
            'message': self.message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

# --- Real-time Logging & Status Updates ---
def broadcast_run_log(run_id: str, level: str, message: str):
    with app.app_context():
        log = RunLog(run_id=run_id, level=level, message=message)
        db.session.add(log)
        db.session.commit()
        payload = {'run_id': run_id, 'level': level, 'message': message, 'created_at': log.created_at.isoformat() if log.created_at else None}
    for queue in RUN_LOG_STREAMS.get(run_id, []):
        try:
            queue.put(payload)
        except Exception:
            continue


def update_run_status(run_id: str, status: str, message: str = "", success: bool = True):
    with app.app_context():
        run = Run.query.get(run_id)
        if not run:
            return
        run.status = status
        run.completed_at = datetime.datetime.utcnow() if status in ('completed', 'failed') else run.completed_at
        run.progress = 100 if status == 'completed' else run.progress
        run.error_message = None if success else message
        db.session.commit()


def orchestrator_log_callback(run_id: str, line: str):
    broadcast_run_log(run_id, 'info', line)


def orchestrator_status_callback(run_id: str, success: bool, message: str):
    status = 'completed' if success else 'failed'
    if not success:
        broadcast_run_log(run_id, 'error', message)
    update_run_status(run_id, status, message=message, success=success)


def initialize_orchestrator():
    global orchestrator
    orchestrator = OrchestratorService(
        base_path=PROJECT_ROOT,
        scripts_root=SCRIPTS_BASE,
        log_callback=orchestrator_log_callback,
        status_callback=orchestrator_status_callback,
    )


def register_log_stream(run_id: str) -> Queue:
    q = Queue()
    RUN_LOG_STREAMS[run_id].append(q)
    return q


def unregister_log_stream(run_id: str, queue: Queue):
    if run_id in RUN_LOG_STREAMS and queue in RUN_LOG_STREAMS[run_id]:
        RUN_LOG_STREAMS[run_id].remove(queue)
    if run_id in RUN_LOG_STREAMS and not RUN_LOG_STREAMS[run_id]:
        del RUN_LOG_STREAMS[run_id]

# --- Orchestration Logic ---
def start_security_run(run_type: str, host_ids, script_ids, created_by: int, metadata: dict | None = None):
    metadata = metadata or {}
    scripts = []
    for script_id in script_ids:
        info = script_registry.get(script_id)
        if not info:
            raise ValueError(f"Script {script_id} not found")
        scripts.append(info)
    hosts = Host.query.filter(Host.id.in_(host_ids), Host.is_active == True).all()
    if not hosts:
        raise ValueError("No valid hosts selected")
    run_id = uuid.uuid4().hex
    run = Run(
        run_id=run_id,
        run_type=run_type,
        status='queued',
        scripts=json.dumps([s.to_dict() for s in scripts]),
        run_metadata=json.dumps(metadata),
        created_by=created_by,
        started_at=datetime.datetime.utcnow(),
    )
    db.session.add(run)
    for host in hosts:
        snapshot = host.to_dict()
        db.session.add(RunHost(
            run_id=run_id,
            host_id=host.id,
            hostname=snapshot['hostname'],
            ip_address=snapshot['ip_address'],
            status='pending',
        ))
    db.session.commit()
    hosts_payload = []
    for host in hosts:
        hosts_payload.append({
            'hostname': host.hostname,
            'ip_address': host.ip_address,
            'ssh_user': host.ssh_user,
            'ssh_port': host.ssh_port,
            'ssh_key_path': host.ssh_key_path,
        })
    request = RunRequest(
        run_type=run_type,
        hosts=hosts_payload,
        scripts=[s.relative_path for s in scripts],
        created_by=created_by,
        extra_vars=metadata.get('extra_vars', {}),
    )
    orchestrator.run(request, run_id=run_id)
    update_run_status(run_id, 'running')
    broadcast_run_log(run_id, 'info', f"Run {run_id} started for {len(hosts)} host(s)")
    return run_id


# --- End Orchestration Logic ---

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

def check_disk_space(path):
    """Check available disk space for a given path"""
    try:
        stat = shutil.disk_usage(path)
        total_gb = stat.total / (1024**3)
        free_gb = stat.free / (1024**3)
        used_gb = stat.used / (1024**3)
        free_percent = (stat.free / stat.total) * 100
        return {
            'total_gb': round(total_gb, 2),
            'free_gb': round(free_gb, 2),
            'used_gb': round(used_gb, 2),
            'free_percent': round(free_percent, 2),
            'is_low': free_percent < 5.0
        }
    except Exception as e:
        app.logger.error(f"Error checking disk space: {e}")
        return None

# Initialize database and create admin user (Flask 2.3+ compatible)
# @app.before_first_request is deprecated in Flask 2.2+, removed in Flask 2.3+
initialize_orchestrator()

with app.app_context():
    db.create_all()
    
    # Migrate existing database: Add new columns and tables
    try:
        # Check if user table exists
        result = db.session.execute(db_text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'"))
        user_table_exists = result.fetchone() is not None
        
        if user_table_exists:
            # Check and add missing columns to user table
            try:
                # Get current table info
                columns = db.session.execute(db_text("PRAGMA table_info(user)")).fetchall()
                column_names = [col[1] for col in columns]
                
                # List of required columns and their definitions
                required_columns = {
                    'is_active': 'BOOLEAN DEFAULT 1',
                    'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP'
                }
                
                # Check for missing columns
                migrations = []
                for col, col_type in required_columns.items():
                    if col not in column_names:
                        migrations.append(f"ADD COLUMN {col} {col_type}")
                
                # Apply migrations if needed
                if migrations:
                    print(f"Migrating user table: {', '.join(migrations)}")
                    for migration in migrations:
                        try:
                            db.session.execute(db_text(f"ALTER TABLE user {migration}"))
                            db.session.commit()
                            print(f"Successfully added column: {migration.split()[2]}")
                        except Exception as e:
                            print(f"Error adding column: {migration}. Error: {e}")
                            db.session.rollback()
                            raise
                else:
                    print("User table schema is up to date")
                    
            except Exception as e:
                print(f"User table migration error: {e}")
                db.session.rollback()
        
        # Check for new tables
        tables_result = db.session.execute(db_text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
        existing_tables = [t[0] for t in tables_result]
        
        if 'host' not in existing_tables:
            print("Creating host table...")
        if 'scan' not in existing_tables:
            print("Creating scan table...")
        if 'scan_log' not in existing_tables:
            print("Creating scan_log table...")
            
    except Exception as e:
        print(f"Database migration error: {e}")
        db.session.rollback()
    
    # Create or update admin user (AFTER migration)
    try:
        # Use raw SQL to check if admin exists (safer than ORM if schema changed)
        try:
            result = db.session.execute(db_text("SELECT COUNT(*) FROM user WHERE username = 'admin'"))
            admin_exists = result.scalar() > 0
        except Exception:
            admin_exists = False
        
        if not admin_exists:
            # Create new admin user
            db.session.execute(db_text(
                "INSERT INTO user (username, password_hash, role, mfa_secret, mfa_enabled, is_active) "
                "VALUES ('admin', :pwd, 'admin', :secret, 1, 1)"
            ), {
                'pwd': generate_password_hash('ChangeMeNow!'),
                'secret': pyotp.random_base32()
            })
            db.session.commit()
            print("Created admin user")
        else:
            # Update existing admin user to ensure is_active is set
            try:
                db.session.execute(db_text("UPDATE user SET is_active = 1 WHERE username = 'admin' AND (is_active IS NULL OR is_active = 0)"))
                db.session.commit()
            except Exception as e:
                print(f"Note: Could not update admin user is_active: {e}")
                # If update fails, continue anyway - might already be set
    except Exception as e:
        print(f"Error creating/updating admin user: {e}")
        db.session.rollback()

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
    """Enhanced dashboard with statistics and host-based reports"""
    # Get scans from database
    if current_user.is_admin():
        scans = Scan.query.order_by(Scan.created_at.desc()).limit(100).all()
    else:
        scans = Scan.query.filter_by(created_by=current_user.id).order_by(Scan.created_at.desc()).limit(100).all()
    
    # Get hosts (admin only for management)
    hosts = Host.query.filter_by(is_active=True).all() if current_user.is_admin() else []
    
    # Statistics
    if current_user.is_admin():
        stats = {
            'total_scans': Scan.query.count(),
            'completed_scans': Scan.query.filter_by(status='completed').count(),
            'running_scans': Scan.query.filter_by(status='running').count(),
            'failed_scans': Scan.query.filter_by(status='failed').count(),
            'total_hosts': Host.query.filter_by(is_active=True).count(),
            'pending_scans': Scan.query.filter_by(status='pending').count()
        }
    else:
        stats = {
            'total_scans': Scan.query.filter_by(created_by=current_user.id).count(),
            'completed_scans': Scan.query.filter_by(status='completed', created_by=current_user.id).count(),
            'running_scans': Scan.query.filter_by(status='running', created_by=current_user.id).count(),
            'failed_scans': Scan.query.filter_by(status='failed', created_by=current_user.id).count(),
            'total_hosts': 0,
            'pending_scans': Scan.query.filter_by(status='pending', created_by=current_user.id).count()
        }
    
    return render_template('dashboard.html', scans=scans, hosts=hosts, stats=stats, current_user=current_user)

@app.route('/run_scan', methods=['POST'])
@login_required
def run_scan():
    """Run security scan via Ansible on selected hosts"""
    if not current_user.is_admin():
        flash('Admin access required to run scans', 'error')
        return redirect(url_for('index'))
    
    scan_type = request.form.get('scan_type', 'full')
    host_ids = request.form.getlist('host_ids')
    
    # Get hosts to scan
    if host_ids:
        hosts_to_scan = Host.query.filter(Host.id.in_(host_ids), Host.is_active == True).all()
    else:
        # If no hosts selected, scan all active hosts
        hosts_to_scan = Host.query.filter_by(is_active=True).all()
    
    if not hosts_to_scan:
        flash('No active hosts selected. Please add hosts first.', 'error')
        return redirect(url_for('index'))
    
    # Create scan record
    scan = Scan(
        scan_type=scan_type,
        status='pending',
        progress=0,
        current_task='Initializing scan...',
        created_by=current_user.id
    )
    db.session.add(scan)
    db.session.commit()
    
    scan_id = scan.id
    
    # Run scan in background thread
    def run_ansible_scan():
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return
            
            scan.status = 'running'
            scan.started_at = datetime.datetime.utcnow()
            scan.progress = 10
            scan.current_task = f'Starting scan on {len(hosts_to_scan)} host(s)...'
            db.session.commit()
            
            # Import AnsibleRunner
            sys_path = os.path.join(BASE, 'ansible_runner.py')
            if os.path.exists(sys_path):
                import sys
                if BASE not in sys.path:
                    sys.path.insert(0, BASE)
                from ansible_runner import AnsibleRunner
                
                runner = AnsibleRunner(BASE)
                hosts_data = [h.to_dict() for h in hosts_to_scan]
                
                # Step 1: Setup tools
                scan.progress = 20
                scan.current_task = 'Setting up security tools on hosts...'
                db.session.commit()
                
                setup_result = runner.setup_tools(hosts_data)
                if not setup_result['success']:
                    scan.status = 'failed'
                    scan.error_message = f"Tool setup failed: {setup_result.get('error', 'Unknown error')}"
                    scan.current_task = 'Setup failed'
                    db.session.commit()
                    return
                
                # Step 2: Setup web security
                scan.progress = 40
                scan.current_task = 'Configuring web server security...'
                db.session.commit()
                
                web_result = runner.setup_web_security(hosts_data)
                
                # Step 3: Run scan
                scan.progress = 50
                scan.current_task = f'Running {scan_type} security scan...'
                db.session.commit()
                
                scan_result = runner.run_scan(hosts_data, scan_type=scan_type, scan_id=str(scan_id))
                
                if scan_result['success']:
                    scan.status = 'completed'
                    scan.progress = 100
                    scan.current_task = 'Scan completed successfully'
                    scan.completed_at = datetime.datetime.utcnow()
                    scan.output_dir = f"/var/security-scans/ansible/{scan_id}"
                else:
                    scan.status = 'failed'
                    scan.error_message = scan_result.get('error', 'Unknown error')
                    scan.current_task = 'Scan failed'
                    scan.progress = 50
            else:
                # Fallback: Direct scan without Ansible (for testing)
                scan.progress = 30
                scan.current_task = 'Running direct scan (Ansible not configured)...'
                db.session.commit()
                
                config_path = os.environ.get('CONFIG_PATH', os.path.join(BASE, 'config.json'))
                scan_script = os.path.join(BASE, 'reporting', 'run_full_scan.py')
                
                if os.path.exists('/.dockerenv'):
                    docker_cmd = ['docker', 'exec', '-d', 'security-audit-scanner', 
                                 'python3', scan_script, '--config', config_path]
                    subprocess.Popen(docker_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.Popen(['python3', scan_script, '--config', config_path],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                scan.status = 'running'
                scan.current_task = 'Direct scan initiated (check logs for progress)'
                scan.output_dir = os.path.join(os.environ.get('SCAN_BASE_DIR', '/var/security-scans'),
                                              datetime.datetime.utcnow().strftime("%Y-%m-%d_%H%M%S"))
            
            db.session.commit()
        except Exception as e:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'failed'
                scan.error_message = str(e)
                scan.current_task = f'Error: {str(e)}'
                db.session.commit()
            app.logger.error(f'Scan error: {traceback.format_exc()}')
    
    thread = threading.Thread(target=run_ansible_scan, daemon=True)
    thread.start()
    
    flash(f'Scan #{scan_id} started for {len(hosts_to_scan)} host(s)', 'success')
    return redirect(url_for('index'))

@app.route('/api/scan/status/<int:scan_id>')
@login_required
def scan_status_api(scan_id):
    """Get scan status (JSON API for AJAX polling)"""
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.created_by != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'progress': scan.progress,
        'current_task': scan.current_task,
        'hostname': scan.host.hostname if scan.host else 'All Hosts',
        'error_message': scan.error_message,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })

@app.route('/api/scan/stream/<int:scan_id>')
@login_required
def scan_stream(scan_id):
    """Server-Sent Events stream for real-time scan status"""
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.created_by != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    def generate():
        last_status = None
        while True:
            scan = Scan.query.get(scan_id)
            if not scan:
                break
            
            current_status = {
                'status': scan.status,
                'progress': scan.progress,
                'current_task': scan.current_task,
                'error_message': scan.error_message
            }
            
            if current_status != last_status:
                yield f"data: {json.dumps(current_status)}\n\n"
                last_status = current_status
            
            if scan.status in ['completed', 'failed']:
                yield f"data: {json.dumps({'status': 'completed', 'progress': scan.progress})}\n\n"
                break
            
            time.sleep(2)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

# User Management Routes
@app.route('/users')
@admin_required
def users():
    """List all users"""
    users_list = User.query.order_by(User.created_at.desc()).all()
    return render_template('users/list.html', users=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    """Create new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')
        mfa_enabled = request.form.get('mfa_enabled') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('users/create.html')
        
        try:
            user = User(username=username, role=role, mfa_enabled=mfa_enabled, is_active=True)
            user.set_password(password)
            if mfa_enabled:
                user.mfa_secret = pyotp.random_base32()
            db.session.add(user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('users'))
        except OperationalError as e:
            db.session.rollback()
            error_msg = str(e)
            app.logger.error(f"Database error creating user: {error_msg}")
            
            # Check disk space
            disk_info = check_disk_space(DATA_DIR)
            if disk_info:
                if disk_info['is_low']:
                    flash(f"Database error: Disk space is critically low ({disk_info['free_percent']}% free, {disk_info['free_gb']} GB available). Please free up space and try again.", 'error')
                else:
                    flash(f"Database error: {error_msg}. Disk space: {disk_info['free_gb']} GB free ({disk_info['free_percent']}%).", 'error')
            else:
                if 'full' in error_msg.lower() or 'disk' in error_msg.lower():
                    flash(f"Database error: Disk or database is full. Please check available disk space and database file size.", 'error')
                else:
                    flash(f"Database error: {error_msg}. Please check logs for details.", 'error')
            return render_template('users/create.html')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Unexpected error creating user: {traceback.format_exc()}")
            flash(f"Error creating user: {str(e)}", 'error')
            return render_template('users/create.html')
    
    return render_template('users/create.html')

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user"""
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('users'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('users'))

# MFA Management Routes
@app.route('/users/<int:user_id>/mfa/setup')
@login_required
def mfa_setup(user_id):
    """Display MFA QR code for setup"""
    user = User.query.get_or_404(user_id)
    
    # Users can only view their own MFA, admins can view any user's
    if not current_user.is_admin() and user.id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Generate secret if not exists
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
        name=user.username,
        issuer_name='Security Audit Portal'
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for display
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    img_data = base64.b64encode(img_buffer.read()).decode()
    
    return render_template('users/mfa_setup.html', 
                         user=user, 
                         qr_code=img_data,
                         secret=user.mfa_secret,
                         totp_uri=totp_uri)

@app.route('/users/<int:user_id>/mfa/regenerate', methods=['POST'])
@login_required
def mfa_regenerate(user_id):
    """Regenerate MFA secret"""
    user = User.query.get_or_404(user_id)
    
    # Users can only regenerate their own MFA, admins can regenerate any user's
    if not current_user.is_admin() and user.id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Generate new secret
    user.mfa_secret = pyotp.random_base32()
    # Disable MFA until user sets it up again
    user.mfa_enabled = False
    db.session.commit()
    
    flash('MFA secret regenerated. Please set up MFA again with the new QR code.', 'success')
    return redirect(url_for('mfa_setup', user_id=user.id))

@app.route('/users/<int:user_id>/mfa/verify', methods=['POST'])
@login_required
def mfa_verify(user_id):
    """Verify MFA token and enable MFA"""
    user = User.query.get_or_404(user_id)
    
    # Users can only verify their own MFA, admins can verify any user's
    if not current_user.is_admin() and user.id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    token = request.form.get('token', '').strip()
    
    if not token:
        flash('Please enter the verification code from your authenticator app', 'error')
        return redirect(url_for('mfa_setup', user_id=user.id))
    
    if not user.mfa_secret:
        flash('MFA secret not found. Please regenerate.', 'error')
        return redirect(url_for('mfa_setup', user_id=user.id))
    
    # Verify token
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(token, valid_window=1):
        user.mfa_enabled = True
        db.session.commit()
        flash('MFA verified and enabled successfully!', 'success')
        if current_user.is_admin():
            return redirect(url_for('users'))
        else:
            return redirect(url_for('index'))
    else:
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('mfa_setup', user_id=user.id))

@app.route('/profile/mfa')
@login_required
def profile_mfa():
    """User's own MFA management page"""
    return redirect(url_for('mfa_setup', user_id=current_user.id))

# Host Management Routes
@app.route('/hosts')
@login_required
def hosts():
    """List all hosts"""
    if current_user.is_admin():
        hosts_list = Host.query.order_by(Host.created_at.desc()).all()
    else:
        hosts_list = []  # Regular users can't manage hosts
    return render_template('hosts/list.html', hosts=hosts_list)

@app.route('/hosts/create', methods=['GET', 'POST'])
@admin_required
def create_host():
    """Create new host"""
    if request.method == 'POST':
        host = Host(
            hostname=request.form.get('hostname', '').strip(),
            ip_address=request.form.get('ip_address', '').strip(),
            ssh_user=request.form.get('ssh_user', 'root').strip(),
            ssh_port=int(request.form.get('ssh_port', 22)),
            ssh_key_path=request.form.get('ssh_key_path', '').strip() or None,
            description=request.form.get('description', '').strip() or None,
            is_active=True
        )
        db.session.add(host)
        db.session.commit()
        flash('Host added successfully', 'success')
        return redirect(url_for('hosts'))
    return render_template('hosts/create.html')

@app.route('/hosts/<int:host_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_host(host_id):
    """Edit host"""
    host = Host.query.get_or_404(host_id)
    if request.method == 'POST':
        host.hostname = request.form.get('hostname', '').strip()
        host.ip_address = request.form.get('ip_address', '').strip()
        host.ssh_user = request.form.get('ssh_user', 'root').strip()
        host.ssh_port = int(request.form.get('ssh_port', 22))
        host.ssh_key_path = request.form.get('ssh_key_path', '').strip() or None
        host.description = request.form.get('description', '').strip() or None
        host.is_active = request.form.get('is_active') == 'on'
        db.session.commit()
        flash('Host updated successfully', 'success')
        return redirect(url_for('hosts'))
    return render_template('hosts/edit.html', host=host)

@app.route('/hosts/<int:host_id>/delete', methods=['POST'])
@admin_required
def delete_host(host_id):
    """Delete host"""
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    flash('Host deleted successfully', 'success')
    return redirect(url_for('hosts'))

@app.route('/reports/<int:scan_id>')
@login_required
def view_report(scan_id):
    """View scan report"""
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.created_by != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    report_root = scan.output_dir or os.path.join(base, 'ansible', str(scan_id))
    report_path = os.path.join(report_root, 'final_report')
    
    files = []
    download_subdir = None
    
    if not os.path.isdir(report_path) and os.path.isdir(report_root):
        # Some older scans stored artifacts directly under output_dir
        report_path = report_root
    
    if os.path.isdir(report_path):
        files = [f for f in os.listdir(report_path) if f.endswith(('.html', '.pdf', '.json'))]
        if report_root.startswith(base):
            download_subdir = os.path.relpath(report_root, base)
        else:
            download_subdir = report_root
    
    return render_template('reports/view.html', scan=scan, files=files, report_subdir=download_subdir)

# Legacy reports route for backward compatibility
@app.route('/reports/<scan>')
@login_required
def reports(scan):
    """Legacy reports route"""
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    path = os.path.join(base, scan, 'final_report')
    if not os.path.isdir(path): return "Not found", 404
    files = [f for f in os.listdir(path) if f.endswith('.html') or f.endswith('.pdf')]
    return render_template('reports.html', files=files, scan=scan)

@app.route('/logs')
@login_required
def logs():
    """Log viewer"""
    hosts_list = Host.query.filter_by(is_active=True).all() if current_user.is_admin() else []
    log_types = ['nginx', 'laravel', 'golang', 'mongodb', 'react']
    return render_template('logs/viewer.html', hosts=hosts_list, log_types=log_types)

@app.route('/api/logs/stream')
@login_required
def log_stream():
    """Stream logs via SSE"""
    host_id = request.args.get('host_id')
    log_type = request.args.get('log_type', 'nginx')
    critical_only = request.args.get('critical_only', 'false') == 'true'
    
    host = Host.query.get(host_id) if host_id else None
    if not host and host_id:
        return jsonify({'error': 'Host not found'}), 404
    
    # Log file paths mapping
    log_paths = {
        'nginx': '/var/log/nginx/error.log',
        'laravel': '/var/www/laravel/storage/logs/laravel.log',
        'golang': '/var/log/golang/app.log',
        'mongodb': '/var/log/mongodb/mongod.log',
        'react': '/var/log/react/app.log'
    }
    
    def generate():
        yield f"data: {json.dumps({'message': 'Use /api/runs/<id>/logs/stream for live execution logs', 'type': 'info'})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

# --- API Endpoints for new features ---
@app.route('/api/scripts', methods=['GET'])
@login_required
def list_scripts():
    category = request.args.get('category') # e.g., 'setup', 'scan/baseline'
    scripts = [s.to_dict() for s in script_registry.list(category)]
    return jsonify({'scripts': scripts})


@app.route('/api/scripts/refresh', methods=['POST'])
@admin_required
def refresh_scripts():
    script_registry.refresh()
    return jsonify({'scripts': [s.to_dict() for s in script_registry.list()]})

@app.route('/api/hosts/status', methods=['POST'])
@login_required
def host_status():
    data = request.get_json(force=True)
    host_ids = data.get('host_ids', [])
    if not host_ids:
        return jsonify({'error': 'host_ids required'}), 400
    hosts = Host.query.filter(Host.id.in_(host_ids)).all()
    results = []
    for host in hosts:
        result = connectivity_service.check_host(host.ssh_user, host.ip_address, host.ssh_port, host.ssh_key_path)
        result.host_id = host.id
        result.hostname = host.hostname
        host.last_check_status = 'online' if result.ok else 'offline'
        host.last_check_message = result.message
        host.last_latency_ms = result.latency_ms
        host.last_check_at = datetime.datetime.utcnow()
        payload = result.to_dict()
        results.append(payload)
    db.session.commit()
    return jsonify({'results': results})

@app.route('/api/runs', methods=['POST'])
@login_required
def create_run_api():
    data = request.get_json(force=True)
    run_type = data.get('run_type')
    host_ids = data.get('host_ids', [])
    script_ids = data.get('script_ids', [])
    metadata = data.get('metadata', {})
    if not run_type or not host_ids or not script_ids:
        return jsonify({'error': 'run_type, host_ids, script_ids are required'}), 400
    try:
        run_id = start_security_run(run_type, host_ids, script_ids, current_user.id, metadata)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'run_id': run_id}), 201

@app.route('/api/runs/<run_id>', methods=['GET'])
@login_required
def get_run(run_id):
    run = Run.query.get_or_404(run_id)
    hosts = [host.to_dict() for host in run.hosts]
    return jsonify({'run': run.to_dict(), 'hosts': hosts})

@app.route('/api/runs/<run_id>/logs/stream')
@login_required
def stream_run_logs(run_id):
    run = Run.query.get_or_404(run_id)
    queue = register_log_stream(run_id)

    def generate_logs():
        # First, stream existing logs from the database
        existing = RunLog.query.filter_by(run_id=run_id).order_by(RunLog.created_at.asc()).all()
        for log in existing:
            yield f"data: {json.dumps(log.to_dict())}\n\n"
        # Then, listen for new logs from the queue
        try:
            while True:
                try:
                    payload = queue.get(timeout=30)
                    yield f"data: {json.dumps(payload)}\n\n"
                except Empty:
                    yield 'data: {"heartbeat": true}\n\n'
        finally:
            unregister_log_stream(run_id, queue)

    return Response(stream_with_context(generate_logs()), mimetype='text/event-stream')
    
@app.route('/api/security-suite')
@login_required
def security_suite_details():
    details = {
        'tools': [
            {
                'name': 'OWASP ZAP',
                'description': 'Active and passive web application scanning to detect vulnerabilities based on real server_names discovered on remote hosts.',
            },
            {
                'name': 'Wazuh',
                'description': 'Host-based intrusion detection and compliance monitoring; collects events from remote hosts via agents or SSH.',
            },
            {
                'name': 'OpenVAS / Greenbone',
                'description': 'Network vulnerability scanning for servers and services exposed on remote hosts.',
            },
            {
                'name': 'Custom setup scripts',
                'description': 'Hardening and configuration scripts found under scripts/setup to bootstrap remote servers.',
            },
        ],
        'usage': 'Select hosts, validate connectivity, choose setup/baseline/pentest scripts, then run orchestrations that chain Ansible scripts and security tools. Reports are stored per host/run in data/reports.',
    }
    return jsonify(details)

# --- End API Endpoints ---

@app.route('/download/<path:scan>/<fn>')
@login_required
def download(scan, fn):
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    p = os.path.join(base, scan, 'final_report', fn)
    if os.path.exists(p): return send_file(p)
    return "Not found", 404

@app.route('/health')
def health():
    """Health check endpoint for Docker"""
    try:
        # Quick database check
        db.session.execute(db_text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    disk_info = check_disk_space(DATA_DIR)
    health_data = {
        'status': 'healthy' if db_status == 'ok' else 'unhealthy',
        'database': db_status,
        'disk': disk_info
    }
    
    status_code = 200 if db_status == 'ok' else 503
    return jsonify(health_data), status_code

@app.route('/admin/diagnostics')
@admin_required
def diagnostics():
    """Database and system diagnostics for admins"""
    diagnostics_data = {
        'database': {},
        'disk': {},
        'database_file': {}
    }
    
    # Database file info
    db_file = os.path.join(DATA_DIR, 'webapp.db')
    if os.path.exists(db_file):
        try:
            db_size = os.path.getsize(db_file)
            db_size_mb = db_size / (1024 * 1024)
            diagnostics_data['database_file'] = {
                'path': db_file,
                'size_mb': round(db_size_mb, 2),
                'exists': True
            }
        except Exception as e:
            diagnostics_data['database_file'] = {'error': str(e)}
    else:
        diagnostics_data['database_file'] = {'exists': False, 'path': db_file}
    
    # Database connection test
    try:
        result = db.session.execute(db_text("SELECT COUNT(*) FROM user"))
        user_count = result.scalar()
        diagnostics_data['database'] = {
            'status': 'connected',
            'user_count': user_count,
            'test_query': 'success'
        }
    except Exception as e:
        diagnostics_data['database'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Disk space
    diagnostics_data['disk'] = check_disk_space(DATA_DIR)
    
    return jsonify(diagnostics_data)

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
