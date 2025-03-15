from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Regexp, Length, NumberRange
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
