import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Security configurations
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secure-key-for-nmap-scanner-app'
    
    # Database configurations
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Celery configurations
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True  # Retry connecting to broker on startup
    
    # Upload configurations
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Authentication configurations
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    
    # Rate limiting
    SCAN_RATE_LIMIT = 5  # Maximum number of scans per hour per user
