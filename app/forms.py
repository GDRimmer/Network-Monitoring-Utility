from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Regexp, Length, NumberRange, Optional
from app.models import User

class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """Form for user registration with password requirements"""
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=10, message="Password must be at least 10 characters long"),
        Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
               message="Password must include at least one uppercase letter, one number, and one special character")
    ])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        """Check if username is already in use"""
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Username already in use. Please choose a different one.')
    
    def validate_email(self, email):
        """Check if email is already in use"""
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email address already registered. Please use a different one.')

class ScanForm(FlaskForm):
    """Form for configuring NMAP scans"""
    target = StringField('Target IP/Range', validators=[DataRequired()])
    scan_type = SelectField('Scan Type', choices=[
        ('simple', 'Simple Scan (Common ports only)'),
        ('comprehensive', 'Comprehensive Scan (Full port range with OS detection)'),
        ('os', 'OS Detection Scan'),
        ('service', 'Service Version Scan'),
        ('custom', 'Custom Scan (Specify arguments)')
    ])
    custom_args = StringField('Custom NMAP Arguments')
    submit = SubmitField('Start Scan')

class UploadForm(FlaskForm):
    """Form for uploading existing NMAP scan results"""
    file = FileField('NMAP Scan Results File', validators=[
        FileRequired(),
        FileAllowed(['txt', 'xml'], 'Only text (.txt) or XML (.xml) files are allowed.')
    ])
    submit = SubmitField('Upload and Analyze')

# Add this to forms.py

class PacketCaptureForm(FlaskForm):
    """Form for configuring tcpdump packet captures"""
    interface = SelectField('Network Interface', validators=[DataRequired()])
    packet_count = IntegerField('Number of Packets (0 for unlimited)', default=0, validators=[NumberRange(min=0)])
    protocol = SelectField('Protocol', choices=[
        ('', 'All Protocols'),
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
        ('arp', 'ARP')
    ])
    port = IntegerField('Port Number (0 for all ports)', default=0, validators=[NumberRange(min=0, max=65535)])
    host = StringField('Host IP Address (Optional)')
    verbose = BooleanField('Verbose Output', default=False)
    submit = SubmitField('Start Capture')
    
    def __init__(self, *args, **kwargs):
        super(PacketCaptureForm, self).__init__(*args, **kwargs)
        # Populate interface choices
        self.populate_interfaces()
    
    def populate_interfaces(self):
        """Populate network interface choices dynamically"""
        try:
            # Get list of network interfaces
            import netifaces
            interfaces = netifaces.interfaces()
            self.interface.choices = [(iface, iface) for iface in interfaces]
        except ImportError:
            # Fallback to common interfaces if netifaces is not available
            self.interface.choices = [
                ('eth0', 'eth0'), 
                ('wlan0', 'wlan0'),
                ('lo', 'lo (Loopback)'),
                ('any', 'any (All interfaces)')
            ]

class PingForm(FlaskForm):
    """Form for ping tool"""
    host = StringField('Host/IP Address', validators=[DataRequired()])
    count = IntegerField('Number of Packets', default=4, validators=[NumberRange(min=1, max=100)])
    timeout = IntegerField('Timeout (seconds)', default=5, validators=[NumberRange(min=1, max=60)])
    submit = SubmitField('Start Ping')

class TracerouteForm(FlaskForm):
    """Form for traceroute tool"""
    host = StringField('Host/IP Address', validators=[DataRequired()])
    max_hops = IntegerField('Maximum Hops', default=30, validators=[NumberRange(min=1, max=100)])
    timeout = IntegerField('Timeout (seconds)', default=5, validators=[NumberRange(min=1, max=60)])
    submit = SubmitField('Start Traceroute')

class DigForm(FlaskForm):
    """Form for dig DNS lookup"""
    domain = StringField('Domain Name', validators=[DataRequired()])
    record_type = SelectField('Record Type', choices=[
        ('A', 'A - IPv4 Address'),
        ('AAAA', 'AAAA - IPv6 Address'),
        ('MX', 'MX - Mail Exchange'),
        ('NS', 'NS - Name Server'),
        ('TXT', 'TXT - Text Record'),
        ('SOA', 'SOA - Start of Authority'),
        ('ANY', 'ANY - All Records')
    ])
    submit = SubmitField('Start DNS Lookup')

class IperfForm(FlaskForm):
    """Form for iperf network performance test"""
    server = StringField('Server IP/Hostname', validators=[DataRequired()])
    port = IntegerField('Port', default=5201, validators=[NumberRange(min=1024, max=65535)])
    duration = IntegerField('Test Duration (seconds)', default=10, validators=[NumberRange(min=1, max=300)])
    protocol = SelectField('Protocol', choices=[
        ('tcp', 'TCP'),
        ('udp', 'UDP')
    ])
    bandwidth = StringField('Bandwidth Limit (for UDP)', validators=[Optional()], 
                           description='e.g., 100M for 100 Mbits/sec')
    submit = SubmitField('Start Performance Test')

class IpRouteForm(FlaskForm):
    """Form for ip route commands"""
    action = SelectField('Action', choices=[
        ('show', 'Show Routes'),
        ('get', 'Get Route for Destination')
    ])
    destination = StringField('Destination IP (for Get)', validators=[Optional()])
    submit = SubmitField('Execute Command')

class IptablesForm(FlaskForm):
    """Form for iptables commands"""
    action = SelectField('Action', choices=[
        ('list', 'List Rules'),
        ('list_nat', 'List NAT Rules'),
        ('list_mangle', 'List Mangle Rules')
    ])
    submit = SubmitField('Execute Command')
