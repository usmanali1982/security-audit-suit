from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, stream_with_context
import traceback
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as db_text, or_
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from functools import wraps
import pyotp, os, json, datetime, subprocess, threading, time
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
    
    def to_dict(self):
        return {
            'id': self.id, 'hostname': self.hostname, 'ip_address': self.ip_address,
            'ssh_user': self.ssh_user, 'ssh_port': self.ssh_port,
            'ssh_key_path': self.ssh_key_path, 'description': self.description,
            'is_active': self.is_active
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

# Initialize database and create admin user (Flask 2.3+ compatible)
# @app.before_first_request is deprecated in Flask 2.2+, removed in Flask 2.3+
with app.app_context():
    db.create_all()
    
    # Migrate existing database: Add new columns and tables
    try:
        # Check if user table exists
        result = db.session.execute(db_text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'"))
        user_table_exists = result.fetchone() is not None
        
        if user_table_exists:
            # Migrate user table
            try:
                db.session.execute(db_text("SELECT is_active FROM user LIMIT 1"))
                print("User table schema up to date")
            except Exception:
                try:
                    print("Migrating user table...")
                    db.session.execute(db_text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                    db.session.execute(db_text("ALTER TABLE user ADD COLUMN created_at DATETIME"))
                    db.session.commit()
                    print("User table migration complete")
                except Exception as e:
                    print(f"User migration error: {e}")
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
        
        user = User(username=username, role=role, mfa_enabled=mfa_enabled, is_active=True)
        user.set_password(password)
        if mfa_enabled:
            user.mfa_secret = pyotp.random_base32()
        db.session.add(user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('users'))
    
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
    report_path = scan.output_dir or os.path.join(base, 'ansible', str(scan_id), 'final_report')
    
    files = []
    if os.path.isdir(report_path):
        files = [f for f in os.listdir(report_path) if f.endswith(('.html', '.pdf', '.json'))]
    
    return render_template('reports/view.html', scan=scan, files=files)

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
        log_file = log_paths.get(log_type, log_paths['nginx'])
        try:
            # Placeholder for SSH-based log tailing
            # In production, use paramiko to SSH and tail logs
            yield f"data: {json.dumps({'message': 'Log streaming implementation needed', 'type': 'info'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'message': str(e), 'type': 'error'})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

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
