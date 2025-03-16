from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
import json

@login_manager.user_loader
def load_user(id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    """User model for authentication and scan ownership"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    packet_captures = db.relationship('PacketCapture', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the user's password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Scan(db.Model):
    """Scan model to store NMAP scan details and results"""
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(120))  # Target IP or range
    scan_type = db.Column(db.String(64))  # Type of scan (simple, comprehensive, etc.)
    arguments = db.Column(db.String(256))  # NMAP command arguments
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed, stopped
    task_id = db.Column(db.String(36), index=True)  # Celery task ID
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Float)  # Duration in seconds
    host_count = db.Column(db.Integer, default=0)  # Number of hosts discovered
    result_json = db.Column(db.Text)  # Raw scan results in JSON format
    command_output = db.Column(db.Text)  # Raw command output for display
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    hosts = db.relationship('Host', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_result(self, result_dict):
        """Store scan results as JSON"""
        self.result_json = json.dumps(result_dict)
    
    def get_result(self):
        """Retrieve scan results as a dictionary"""
        if self.result_json:
            return json.loads(self.result_json)
        return {}
    
    def __repr__(self):
        return f'<Scan {self.id} {self.target}>'

class Host(db.Model):
    """Host model to store discovered hosts from scans"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64))
    hostname = db.Column(db.String(120))
    mac_address = db.Column(db.String(64))
    os = db.Column(db.String(120))
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    ports = db.relationship('Port', backref='host', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Host {self.ip_address}>'

class Port(db.Model):
    """Port model to store open ports on hosts"""
    id = db.Column(db.Integer, primary_key=True)
    port_number = db.Column(db.Integer)
    protocol = db.Column(db.String(10))  # tcp, udp, etc.
    service = db.Column(db.String(64))  # Service name if identified
    state = db.Column(db.String(20))  # open, closed, filtered
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    
    def __repr__(self):
        return f'<Port {self.port_number}/{self.protocol}>'

# Add this to models.py

class PacketCapture(db.Model):
    """PacketCapture model to store tcpdump capture details and results"""
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(64))  # Network interface (eth0, wlan0, etc.)
    protocol = db.Column(db.String(20))   # Protocol (tcp, udp, icmp, etc.)
    port = db.Column(db.Integer)          # Port number
    host = db.Column(db.String(120))      # Host IP address
    packet_count = db.Column(db.Integer)  # Number of packets to capture (0 for unlimited)
    verbose = db.Column(db.Boolean, default=False)  # Verbose output
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed, stopped
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Float)        # Duration in seconds
    filename = db.Column(db.String(256))  # Path to the pcap file
    command = db.Column(db.String(512))   # Full tcpdump command
    command_output = db.Column(db.Text)   # Raw command output for display
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<PacketCapture {self.id} {self.interface}>'

class NetworkCommand(db.Model):
    """NetworkCommand model to store network command details and results"""
    id = db.Column(db.Integer, primary_key=True)
    tool = db.Column(db.String(64))  # ping, traceroute, dig, etc.
    command_text = db.Column(db.String(512))  # Full command that was executed
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed, stopped, timeout
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    duration = db.Column(db.Float)  # Duration in seconds
    command_output = db.Column(db.Text)  # Raw command output
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<NetworkCommand {self.id} {self.tool}>'
