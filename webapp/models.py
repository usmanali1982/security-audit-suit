from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")  # 'admin' or 'user'
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def set_password(self, p):
        self.password_hash = generate_password_hash(p)
    
    def check_password(self, p):
        return check_password_hash(self.password_hash, p)
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def is_admin(self):
        return self.role == 'admin'

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    ssh_user = db.Column(db.String(100), default="root")
    ssh_port = db.Column(db.Integer, default=22)
    ssh_key_path = db.Column(db.String(500), nullable=True)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'ssh_user': self.ssh_user,
            'ssh_port': self.ssh_port,
            'ssh_key_path': self.ssh_key_path,
            'description': self.description,
            'is_active': self.is_active
        }

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)  # 'full', 'linux', 'nginx', 'web'
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)
    current_task = db.Column(db.String(255), nullable=True)
    output_dir = db.Column(db.String(500), nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    error_message = db.Column(db.Text, nullable=True)
    
    host = db.relationship('Host', backref='scans')
    creator = db.relationship('User', backref='scans')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'host_id': self.host_id,
            'hostname': self.host.hostname if self.host else 'All Hosts',
            'status': self.status,
            'progress': self.progress,
            'current_task': self.current_task,
            'output_dir': self.output_dir,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    log_level = db.Column(db.String(20), default='info')  # info, warning, error, critical
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    scan = db.relationship('Scan', backref='logs')

