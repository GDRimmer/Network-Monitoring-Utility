import os
import uuid
import re
from app.models import Scan, Host, Port
from flask import current_app
from PIL import Image, ImageDraw, ImageFont

def is_valid_ip(ip_str):
    """
    Check if a string is a valid IP address
    
    Args:
        ip_str: String to check
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip_str):
        return False
    
    # Check each octet is between 0 and 255
    octets = ip_str.split('.')
    for octet in octets:
        if int(octet) < 0 or int(octet) > 255:
            return False
    
    return True

def is_valid_ip_range(range_str):
    """
    Check if a string is a valid IP range or CIDR notation
    
    Args:
        range_str: String to check
        
    Returns:
        bool: True if valid IP range, False otherwise
    """
    # Check CIDR notation (e.g., 192.168.1.0/24)
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if re.match(cidr_pattern, range_str):
        ip_part, prefix = range_str.split('/')
        if not is_valid_ip(ip_part) or int(prefix) < 0 or int(prefix) > 32:
            return False
        return True
    
    # Check hyphenated range (e.g., 192.168.1.1-192.168.1.254)
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'
    if re.match(range_pattern, range_str):
        start_ip, end_ip = range_str.split('-')
        return is_valid_ip(start_ip) and is_valid_ip(end_ip)
    
    # Check if it's a simple IP (also valid as a range)
    return is_valid_ip(range_str)

def sanitize_nmap_args(args):
    """
    Sanitize NMAP arguments to prevent command injection
    
    Args:
        args: NMAP arguments string
        
    Returns:
        str: Sanitized arguments string
    """
    # Disallow potentially dangerous flags
    dangerous_flags = ['-iR', '--script', '--script-args', '--script-help', 
                      '--script-trace', '-e', '--datadir', '--servicedb',
                      '--send-ip', '--send-eth', '--spoof-mac', '--proxies',
                      '--unprivileged', '-b', '-R', '--dns-servers', '--traceroute',
                      '-oN', '-oX', '-oS', '-oG', '-oA', '--log-errors',
                      '--bpf-script', '--ip-options', '--ttl', '-f', '--badsum',
                      '--adler32', '--data', '--data-string', '--data-length',
                      '--source-port', '--mtu', '--scanflags']
    
    # Remove unsafe flags
    sanitized_args = args
    for flag in dangerous_flags:
        sanitized_args = re.sub(r'\s*' + flag + r'\s+[^\s]*', '', sanitized_args)
    
    # Remove shell command operators
    sanitized_args = re.sub(r'[;&|<>]', '', sanitized_args)
    
    # Allow only alphanumeric, dash, underscore, space, comma, period, and slash
    sanitized_args = re.sub(r'[^\w\-\s,\.\/]', '', sanitized_args)
    
    return sanitized_args.strip()

def create_host_map(scan_id):
    """
    Create a basic host map image showing discovered hosts
    
    Args:
        scan_id: ID of the scan to visualize
        
    Returns:
        str: Path to the generated image file, or None on failure
    """
    try:
        # Get scan and host data
        scan = Scan.query.get(scan_id)
        if not scan or scan.hosts.count() == 0:
            return None
        
        # Set up the image
        width, height = 800, 600
        img = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(img)
        
        # Try to load a font, fall back to default if not available
        try:
            font = ImageFont.truetype("arial.ttf", 14)
            title_font = ImageFont.truetype("arial.ttf", 18)
        except IOError:
            font = ImageFont.load_default()
            title_font = ImageFont.load_default()
        
        # Draw title
        title = f"Network Scan: {scan.target}"
        draw.text((width//2 - 150, 20), title, fill="black", font=title_font)
        
        # Calculate positions for hosts
        hosts = list(scan.hosts.all())
        max_hosts = min(24, len(hosts))  # Limit displayed hosts
        
        # Grid layout
        cols = 4
        rows = (max_hosts + cols - 1) // cols
        cell_width = width // cols
        cell_height = (height - 80) // rows
        
        # Draw hosts
        for i, host in enumerate(hosts[:max_hosts]):
            row = i // cols
            col = i % cols
            
            x = col * cell_width + 40
            y = row * cell_height + 80
            
            # Draw computer icon (simple rectangle)
            draw.rectangle([x, y, x+60, y+40], outline="black", fill="lightblue")
            
            # Draw text information
            ip_text = host.ip_address
            draw.text((x+70, y), f"IP: {ip_text}", fill="black", font=font)
            
            if host.hostname:
                draw.text((x+70, y+20), f"Name: {host.hostname[:15]}", fill="black", font=font)
            
            if host.mac_address:
                draw.text((x+70, y+40), f"MAC: {host.mac_address}", fill="black", font=font)
        
        # Generate a unique filename
        filename = f"host_map_{scan_id}_{uuid.uuid4().hex[:8]}.png"
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image
        img.save(filepath)
        
        # Return the relative path to the file
        return os.path.basename(filepath)
    
    except Exception as e:
        current_app.logger.error(f"Error creating host map: {str(e)}")
        return None
