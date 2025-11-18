"""
Enhanced Security Audit Suite Web Application
Features:
- User management with role-based access
- Host management with Ansible integration
- Real-time scan status
- Enhanced dashboard
- Log viewer
"""
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as db_text, or_, and_
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from functools import wraps
import pyotp, os, json, datetime, subprocess, threading, queue, time
from werkzeug.security import generate_password_hash, check_password_hash
import traceback

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

# Import models
from webapp.models import User, Host, Scan, ScanLog

@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize database and models
with app.app_context():
    db.create_all()
    
    # Migrate existing database
    try:
        result = db.session.execute(db_text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'"))
        table_exists = result.fetchone() is not None
        
        if table_exists:
            try:
                db.session.execute(db_text("SELECT is_active FROM user LIMIT 1"))
                print("is_active column exists")
            except Exception:
                try:
                    print("Adding is_active column to user table...")
                    db.session.execute(db_text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                    db.session.execute(db_text("ALTER TABLE user ADD COLUMN created_at DATETIME"))
                    db.session.commit()
                    print("Successfully migrated user table")
                except Exception as e:
                    print(f"Error migrating user table: {e}")
                    db.session.rollback()
    except Exception as e:
        print(f"Error checking database: {e}")
        db.session.rollback()
    
    # Create admin user if not exists
    try:
        admin_exists = db.session.execute(db_text("SELECT COUNT(*) FROM user WHERE username = 'admin'")).scalar() > 0
        if not admin_exists:
            admin = User(username='admin', role='admin', is_active=True)
            admin.set_password('ChangeMeNow!')
            admin.mfa_secret = pyotp.random_base32()
            admin.mfa_enabled = True
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")
    except Exception as e:
        print(f"Error creating admin user: {e}")
        db.session.rollback()

# Scan status tracking
scan_status_queue = queue.Queue()
active_scans = {}

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method=='POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        token = request.form.get('token', '')
        
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password) and u.is_active:
            if u.mfa_enabled:
                if not token:
                    flash('MFA is enabled. Please enter your MFA token.', 'error')
                    return render_template('login.html', username=username)
                try:
                    if not pyotp.TOTP(u.mfa_secret).verify(token, valid_window=1):
                        flash('Invalid MFA token. Please try again.', 'error')
                        return render_template('login.html', username=username)
                except Exception as e:
                    flash(f'MFA verification error: {str(e)}', 'error')
                    return render_template('login.html', username=username)
            login_user(u, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Enhanced dashboard with host-based reports"""
    # Get all scans ordered by date
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(50).all()
    
    # Get active hosts
    hosts = Host.query.filter_by(is_active=True).all()
    
    # Get scan statistics
    stats = {
        'total_scans': Scan.query.count(),
        'completed_scans': Scan.query.filter_by(status='completed').count(),
        'running_scans': Scan.query.filter_by(status='running').count(),
        'failed_scans': Scan.query.filter_by(status='failed').count(),
        'total_hosts': Host.query.filter_by(is_active=True).count()
    }
    
    return render_template('dashboard.html', 
                         scans=scans, 
                         hosts=hosts, 
                         stats=stats,
                         current_user=current_user)

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
    hosts_list = Host.query.order_by(Host.created_at.desc()).all()
    return render_template('hosts/list.html', hosts=hosts_list)

@app.route('/hosts/create', methods=['GET', 'POST'])
@admin_required
def create_host():
    """Create new host"""
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        ssh_user = request.form.get('ssh_user', 'root').strip()
        ssh_port = int(request.form.get('ssh_port', 22))
        ssh_key_path = request.form.get('ssh_key_path', '').strip()
        description = request.form.get('description', '').strip()
        
        host = Host(
            hostname=hostname,
            ip_address=ip_address,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key_path=ssh_key_path if ssh_key_path else None,
            description=description if description else None,
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

# Scan Management Routes
@app.route('/api/scan/status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    """Get scan status (for AJAX polling)"""
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.created_by != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(scan.to_dict())

@app.route('/api/scan/stream/<int:scan_id>')
@login_required
def scan_stream(scan_id):
    """Server-Sent Events stream for scan status"""
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
                break
            
            time.sleep(2)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/run_scan', methods=['POST'])
@login_required
def run_scan():
    """Run security scan via Ansible"""
    if not current_user.is_admin():
        flash('Admin access required to run scans', 'error')
        return redirect(url_for('index'))
    
    scan_type = request.form.get('scan_type', 'full')
    host_ids = request.form.getlist('host_ids')
    
    # Get hosts to scan
    if host_ids:
        hosts = Host.query.filter(Host.id.in_(host_ids), Host.is_active == True).all()
    else:
        hosts = Host.query.filter_by(is_active=True).all()
    
    if not hosts:
        flash('No active hosts selected', 'error')
        return redirect(url_for('index'))
    
    # Create scan record
    scan = Scan(
        scan_type=scan_type,
        status='pending',
        progress=0,
        current_task='Initializing...',
        created_by=current_user.id
    )
    db.session.add(scan)
    db.session.commit()
    
    # Run scan in background thread
    def run_ansible_scan():
        try:
            from ansible_runner import AnsibleRunner
            runner = AnsibleRunner(BASE)
            
            scan.status = 'running'
            scan.started_at = datetime.datetime.utcnow()
            scan.current_task = 'Starting Ansible playbook...'
            scan.progress = 10
            db.session.commit()
            
            # Update scan status
            scan.current_task = f'Scanning {len(hosts)} host(s)...'
            scan.progress = 20
            db.session.commit()
            
            # Run Ansible playbook
            hosts_data = [h.to_dict() for h in hosts]
            result = runner.run_scan(hosts_data, scan_type=scan_type, scan_id=str(scan.id))
            
            if result['success']:
                scan.status = 'completed'
                scan.progress = 100
                scan.current_task = 'Scan completed successfully'
                scan.completed_at = datetime.datetime.utcnow()
                scan.output_dir = result.get('output_dir', '')
            else:
                scan.status = 'failed'
                scan.error_message = result.get('error', 'Unknown error')
                scan.current_task = 'Scan failed'
            
            db.session.commit()
        except Exception as e:
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.current_task = f'Error: {str(e)}'
            db.session.commit()
    
    thread = threading.Thread(target=run_ansible_scan, daemon=True)
    thread.start()
    
    flash(f'Scan started for {len(hosts)} host(s)', 'success')
    return redirect(url_for('index'))

@app.route('/reports/<int:scan_id>')
@login_required
def view_report(scan_id):
    """View scan report"""
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.created_by != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Get report files
    base = os.environ.get('SCAN_BASE_DIR', '/var/security-scans')
    report_path = scan.output_dir or os.path.join(base, str(scan.id), 'final_report')
    
    files = []
    if os.path.isdir(report_path):
        files = [f for f in os.listdir(report_path) 
                if f.endswith(('.html', '.pdf', '.json'))]
    
    return render_template('reports/view.html', scan=scan, files=files)

@app.route('/logs')
@login_required
def logs():
    """Log viewer"""
    hosts_list = Host.query.filter_by(is_active=True).all()
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
    if not host and not host_id:
        return jsonify({'error': 'Host required'}), 400
    
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
            # In real implementation, SSH to host and tail log file
            # For now, placeholder
            yield f"data: {json.dumps({'message': 'Log streaming not yet implemented', 'type': 'info'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'message': str(e), 'type': 'error'})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

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

