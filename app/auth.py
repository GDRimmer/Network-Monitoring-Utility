from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm
from urllib.parse import urlparse
import re

# Create authentication Blueprint
bp = Blueprint('auth', __name__)

def is_safe_url(url):
    """Check if URL is safe to redirect to (doesn't contain a netloc)"""
    if not url:
        return False
    
    # Parse the URL using urllib's reliable parser
    parsed_url = urlparse(url)
    
    # A URL is safe if it doesn't have a network location (domain) or scheme
    # This ensures it's a relative URL that stays on the same site
    return not (parsed_url.netloc or parsed_url.scheme)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Find the user
        user = User.query.filter_by(username=form.username.data).first()
        
        # Check if user exists and password is correct
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))
        
        # Log the user in
        login_user(user, remember=form.remember_me.data)
        
        # Redirect to requested page or default to home
        next_page = request.args.get('next')
        if not next_page or not is_safe_url(next_page):
            next_page = url_for('main.index')
        
        flash('Login successful', 'success')
        return redirect(next_page)
    
    return render_template('login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    """Handle user logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        # Add to database
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html', title='Register', form=form)
