from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, send_from_directory, make_response
from flask_login import login_required, current_user
from app.utils_tcpdump import run_tcpdump_in_thread, active_captures
from datetime import datetime
import os
import uuid
import threading
import time
import subprocess
from werkzeug.utils import secure_filename
import shlex
import time
import re

# Create main Blueprint
bp = Blueprint('main', __name__)

from app import db
from app.models import Scan, Host, Port, PacketCapture, NetworkCommand
from app.forms import (
    ScanForm, UploadForm, PingForm, TracerouteForm, 
    DigForm, IperfForm, IpRouteForm, IptablesForm, PacketCaptureForm
)
from app.scanner import NmapScanner, parse_nmap_file, parse_scan_result
from app.utils import is_valid_ip_range, sanitize_nmap_args, create_host_map

# Dictionary to keep track of running scans
active_scans = {}

# Dictionary to keep track of running network utilities
active_network_utils = {}

def run_scan_in_thread(app, scan_id):
    """Run a scan in a background thread using a simpler, more direct approach"""
    # Create application context for the thread
    from flask import current_app
    with app.app_context():
        try:
            print(f"Starting scan thread for scan_id {scan_id}")
            scan = Scan.query.get(scan_id)
            if not scan:
                print(f"Scan {scan_id} not found")
                return
            
            # Update scan status
            scan.status = 'running'
            scan.command_output = "Initializing scan...\n"
            db.session.commit()
            
            # Import necessary modules
            import subprocess, time, os
            from pathlib import Path
            
            # Get arguments based on scan type
            if scan.scan_type == 'simple':
                args = '-sT -F -T4 -v'
            elif scan.scan_type == 'comprehensive':
                args = '-sT -p- -T4 -A -v'
            elif scan.scan_type == 'os':
                args = '-sT -O -T4 -v'
            elif scan.scan_type == 'service':
                args = '-sT -sV -T4 -v'
            elif scan.scan_type == 'custom' and scan.arguments:
                args = scan.arguments
                if '-v' not in args:
                    args += ' -v'
                # Replace SYN scan with TCP scan if present
                args = args.replace(' -sS ', ' -sT ')
            else:
                args = '-sT -T4 -v'
                
            # Prepare command
            command = f"nmap {args} {scan.target}"
            print(f"Will execute: {command}")
            
            # Update database with command
            scan.command_output += f"Executing: {command}\n\n"
            db.session.commit()
            
            # DIRECT APPROACH: Run nmap and capture output directly
            start_time = time.time()
            
            # Run process with output capture
            try:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # Capture all output
                all_output = ""
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    
                    print(f"NMAP OUTPUT: {line.strip()}")
                    all_output += line
                    
                    # Update database periodically with new output
                    scan.command_output = "Executing: " + command + "\n\n" + all_output
                    db.session.commit()
                
                # Wait for process to complete
                return_code = process.wait()
                end_time = time.time()
                duration = end_time - start_time
                
                # Final output update
                scan.command_output = "Executing: " + command + "\n\n" + all_output
                
                # Check return code
                if return_code != 0:
                    scan.command_output += f"\nNMAP exited with code {return_code}\n"
                    scan.status = 'failed'
                    scan.end_time = datetime.utcnow()
                    db.session.commit()
                    print(f"NMAP failed with return code {return_code}")
                    return
                
                # Process scan results directly from the output
                try:
                    # We'll use the internal python-nmap parser to process the results
                    # Create a temporary file to hold the XML output for parsing
                    home_dir = str(Path.home())
                    temp_dir = os.path.join(home_dir, 'nmap_temp')
                    os.makedirs(temp_dir, exist_ok=True)
                    
                    # Run the scan again but with XML output (quick and dirty solution)
                    xml_file = os.path.join(temp_dir, f"nmap_scan_{scan_id}.xml")
                    xml_command = f"{command} -oX {xml_file}"
                    subprocess.run(xml_command, shell=True, check=True)
                    
                    if os.path.exists(xml_file):
                        # Parse the XML output
                        with open(xml_file, "r") as xml_f:
                            xml_output = xml_f.read()
                            
                        from app.scanner import NmapScanner
                        scanner = NmapScanner(scan.target)
                        result = scanner.scanner.analyse_nmap_xml_scan(xml_output)
                        
                        # Add elapsed time
                        if 'nmap' not in result:
                            result['nmap'] = {}
                        if 'scanstats' not in result['nmap']:
                            result['nmap']['scanstats'] = {}
                        result['nmap']['scanstats']['elapsed'] = duration
                        
                        # Parse and save results
                        from app.scanner import parse_scan_result
                        parse_scan_result(scan, result)
                        
                        # Try to clean up the XML file
                        try:
                            os.remove(xml_file)
                        except:
                            pass
                    else:
                        # If XML parsing fails, manually update the scan status
                        scan.status = 'completed'
                        scan.end_time = datetime.utcnow()
                        scan.duration = duration
                        db.session.commit()
                        
                    # Add completion message
                    scan.command_output += f"\nScan completed successfully in {duration:.2f} seconds.\n"
                    db.session.commit()
                    
                except Exception as result_error:
                    print(f"Error processing results: {str(result_error)}")
                    scan.command_output += f"\nError processing results: {str(result_error)}\n"
                    scan.status = 'failed'
                    scan.end_time = datetime.utcnow()
                    db.session.commit()
            
            except Exception as cmd_error:
                print(f"Error executing NMAP: {str(cmd_error)}")
                scan.command_output += f"\nError executing NMAP: {str(cmd_error)}\n"
                scan.status = 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()
            
            # Remove from active scans
            if scan_id in active_scans:
                del active_scans[scan_id]
                
        except Exception as e:
            print(f"Thread error for scan {scan_id}: {str(e)}")
            try:
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = 'failed'
                    scan.end_time = datetime.utcnow()
                    scan.command_output += f"\nError: {str(e)}\n"
                    db.session.commit()
            except Exception as db_error:
                print(f"Failed to update scan status: {str(db_error)}")
            
            # Remove from active scans
            if scan_id in active_scans:
                del active_scans[scan_id]

def run_network_command(app, command_id, command, timeout=None):
    """Run a network command in a background thread"""
    with app.app_context():
        try:
            from app import db
            from app.models import NetworkCommand
            
            print(f"Starting network command thread for command_id {command_id}")
            network_cmd = NetworkCommand.query.get(command_id)
            if not network_cmd:
                print(f"Command {command_id} not found")
                return
            
            # Update command status
            network_cmd.status = 'running'
            network_cmd.command_output = "Initializing command...\n"
            db.session.commit()
            
            # Convert command to args list if it's a string
            if isinstance(command, str):
                command = shlex.split(command)
            
            print(f"Will execute: {' '.join(command)}")
            
            # Update database with command
            network_cmd.command_text = ' '.join(command)
            network_cmd.command_output += f"Executing: {' '.join(command)}\n\n"
            db.session.commit()
            
            # Start the command
            start_time = time.time()
            
            try:
                # Use Popen to start the process
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1  # Line buffered
                )
                
                # Add the process to active commands
                active_network_utils[command_id] = process
                
                # Capture output with timeout handling
                output_lines = []
                error_lines = []
                
                # Helper function for non-blocking reads
                def read_stream(stream, lines_list):
                    line = stream.readline()
                    if line:
                        lines_list.append(line)
                        return line
                    return None
                
                # Set end time if timeout provided
                end_time = None
                if timeout:
                    end_time = start_time + timeout
                
                # Read output while process is running
                while process.poll() is None:
                    # Check timeout
                    if end_time and time.time() > end_time:
                        process.terminate()
                        break
                    
                    # Read from stdout
                    stdout_line = read_stream(process.stdout, output_lines)
                    if stdout_line:
                        network_cmd.command_output += stdout_line
                        db.session.commit()
                    
                    # Read from stderr
                    stderr_line = read_stream(process.stderr, error_lines)
                    if stderr_line:
                        network_cmd.command_output += "ERROR: " + stderr_line
                        db.session.commit()
                    
                    # If no new output, sleep briefly
                    if not stdout_line and not stderr_line:
                        time.sleep(0.1)
                
                # Get any remaining output
                remaining_out, remaining_err = process.communicate()
                if remaining_out:
                    network_cmd.command_output += remaining_out
                if remaining_err:
                    network_cmd.command_output += "ERROR: " + remaining_err
                
                # Process is finished
                return_code = process.returncode
                end_time = time.time()
                duration = end_time - start_time
                
                # Check return code for timeout
                if timeout and time.time() - start_time >= timeout:
                    network_cmd.command_output += f"\nCommand timed out after {timeout} seconds.\n"
                    network_cmd.status = 'timeout'
                # Check for other return codes
                elif return_code != 0 and return_code != -15:  # -15 is SIGTERM, used when stopping manually
                    network_cmd.command_output += f"\nCommand exited with code {return_code}\n"
                    network_cmd.status = 'failed'
                else:
                    network_cmd.status = 'completed'
                
                network_cmd.end_time = datetime.utcnow()
                network_cmd.duration = duration
                db.session.commit()
                
            except Exception as cmd_error:
                print(f"Error executing command: {str(cmd_error)}")
                network_cmd.command_output += f"\nError executing command: {str(cmd_error)}\n"
                network_cmd.status = 'failed'
                network_cmd.end_time = datetime.utcnow()
                db.session.commit()
            
            # Remove from active commands
            if command_id in active_network_utils:
                del active_network_utils[command_id]
                
        except Exception as e:
            print(f"Thread error for command {command_id}: {str(e)}")
            try:
                network_cmd = NetworkCommand.query.get(command_id)
                if network_cmd:
                    network_cmd.status = 'failed'
                    network_cmd.end_time = datetime.utcnow()
                    network_cmd.command_output += f"\nError: {str(e)}\n"
                    db.session.commit()
            except Exception as db_error:
                print(f"Failed to update command status: {str(db_error)}")
            
            # Remove from active commands
            if command_id in active_network_utils:
                del active_network_utils[command_id]

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    """Main application page"""
    form = ScanForm()
    return render_template('index.html', title='Home', form=form)

@bp.route('/scan/new')
@login_required
def scan_new():
    form = ScanForm()
    return render_template('scan_new.html', title='New Scan', form=form)

@bp.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new NMAP scan"""
    form = ScanForm()
    if form.validate_on_submit():
        # Validate target input
        target = form.target.data
        if not is_valid_ip_range(target):
            flash('Invalid IP address or range format', 'danger')
            return redirect(url_for('main.index'))
        
        # Get scan type and arguments
        scan_type = form.scan_type.data
        arguments = form.custom_args.data if scan_type == 'custom' else None
        
        # Sanitize custom arguments if provided
        if arguments:
            arguments = sanitize_nmap_args(arguments)
        
        # Create new scan record
        scan = Scan(
            target=target,
            scan_type=scan_type,
            arguments=arguments,
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan_in_thread, args=(current_app._get_current_object(),scan.id))
        thread.daemon = True
        thread.start()
        
        # Mark as active immediately so the UI knows it's running
        active_scans[scan.id] = True
        
        # Immediately update status to running (this helps the UI)
        scan.status = 'running'
        db.session.commit()
        
        flash(f'Scan started for {target}', 'success')
        return redirect(url_for('main.scan_results', scan_id=scan.id))
    
    # If form validation fails
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", 'danger')
    
    return redirect(url_for('main.index'))

@bp.route('/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    """Display results of a specific scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if scan belongs to current user
    if scan.user_id != current_user.id:
        flash('Access to the requested scan is restricted', 'danger')
        return redirect(url_for('main.index'))
    
    # Check if host map can be created
    host_map = None
    if scan.status == 'completed' and scan.hosts.count() > 0:
        # Generate host visualization
        host_map = create_host_map(scan_id)
    
    return render_template('scan_results.html', 
                          title='Scan Results', 
                          scan=scan, 
                          host_map=host_map)

@bp.route('/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    """AJAX endpoint to check scan status"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if scan belongs to current user
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if we have an active scanner for this scan
    is_active = scan_id in active_scans
    
    # Force a fresh query to get the latest status
    db.session.refresh(scan)
    
    data = {
        'status': scan.status,
        'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else None,
        'duration': scan.duration if scan.duration else None,
        'host_count': scan.host_count,
        'is_active': is_active
    }
    
    print(f"Status update for scan {scan_id}: {data}")
    return jsonify(data)

@bp.route('/scan_output/<int:scan_id>')
@login_required
def scan_output(scan_id):
    """Get the raw command output for a scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if scan belongs to current user
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Force refresh to get the latest output
    db.session.refresh(scan)
    
    return jsonify({
        'output': scan.command_output or 'No output available',
        'status': scan.status
    })

@bp.route('/stop_scan/<int:scan_id>')
@login_required
def stop_scan(scan_id):
    """Stop a running scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if scan belongs to current user
    if scan.user_id != current_user.id:
        flash('Access to the requested scan is restricted', 'danger')
        return redirect(url_for('main.index'))
    
    # Check if scan is running
    if scan.status != 'running':
        flash('Scan is not currently running', 'warning')
        return redirect(url_for('main.scan_results', scan_id=scan.id))
    
    # Try to stop the scan
    if scan_id in active_scans:
        # Find any nmap processes running for this scan and kill them
        import subprocess
        try:
            # Use pkill to find and kill nmap processes (requires sudo if launched with sudo)
            subprocess.run("pkill -f nmap", shell=True)
            flash('Scan process terminated', 'info')
        except Exception as e:
            flash(f'Error stopping scan process: {str(e)}', 'warning')
        
        # Remove from active scans
        del active_scans[scan_id]
    
    # Update scan status
    scan.status = 'stopped'
    scan.end_time = datetime.utcnow()
    scan.command_output += "\nScan was manually stopped by user.\n"
    db.session.commit()
    
    flash('Scan stopped', 'info')
    return redirect(url_for('main.scan_results', scan_id=scan.id))

@bp.route('/scan_history')
@login_required
def scan_history():
    """Display scan history for the current user"""
    from datetime import timedelta
    
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.start_time.desc()).all()
    
    # Count failed and old scans for UI decisions
    failed_count = sum(1 for scan in scans if scan.status == 'failed')
    
    # Calculate cutoff date for old scans
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    old_count = sum(1 for scan in scans if scan.start_time and scan.start_time < cutoff_date)
    
    return render_template('scan_history.html', 
                           title='Scan History', 
                           scans=scans,
                           failed_count=failed_count,
                           old_count=old_count,
                           now=datetime.utcnow(),
                           timedelta=timedelta)

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Handle upload of NMAP scan results files"""
    form = UploadForm()
    if form.validate_on_submit():
        # Save uploaded file
        file = form.file.data
        filename = secure_filename(file.filename)
        # Add unique identifier to filename to prevent overwrites
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        
        # Parse the file
        scan_id = parse_nmap_file(file_path, current_user.id)
        
        if scan_id:
            flash('File uploaded and processed successfully', 'success')
            return redirect(url_for('main.scan_results', scan_id=scan_id))
        else:
            flash('Error processing file', 'danger')
    
    return render_template('upload.html', title='Upload Scan', form=form)

@bp.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Serve files from the upload directory"""
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@bp.route('/host_details/<int:host_id>')
@login_required
def host_details(host_id):
    """Display detailed information about a specific host"""
    host = Host.query.get_or_404(host_id)
    
    # Check if host's scan belongs to current user
    scan = Scan.query.get(host.scan_id)
    if scan.user_id != current_user.id:
        flash('Access to the requested host is restricted', 'danger')
        return redirect(url_for('main.index'))
    
    return render_template('host_details.html', title='Host Details', host=host, scan=scan)

@bp.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Delete a scan from the database"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check if scan belongs to current user
    if scan.user_id != current_user.id:
        flash('Access to the requested scan is restricted', 'danger')
        return redirect(url_for('main.index'))
    
    # Get scan info for flash message before deletion
    scan_info = f"Scan #{scan.id} ({scan.target})"
    
    # Delete the scan (cascade will handle hosts and ports)
    db.session.delete(scan)
    db.session.commit()
    
    flash(f'{scan_info} has been deleted', 'success')
    return redirect(url_for('main.scan_history'))

@bp.route('/delete_failed_scans', methods=['POST'])
@login_required
def delete_failed_scans():
    """Delete all failed scans for the current user"""
    # Find all failed scans for the current user
    failed_scans = Scan.query.filter_by(user_id=current_user.id, status='failed').all()
    
    # Delete each scan
    count = 0
    for scan in failed_scans:
        db.session.delete(scan)
        count += 1
    
    # Commit the changes
    db.session.commit()
    
    flash(f'Deleted {count} failed scans', 'success')
    return redirect(url_for('main.scan_history'))

@bp.route('/delete_old_scans', methods=['POST'])
@login_required
def delete_old_scans():
    """Delete all scans older than 30 days for the current user"""
    # Calculate the cutoff date (30 days ago)
    from datetime import timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    
    # Find all scans older than the cutoff date for the current user
    old_scans = Scan.query.filter(
        Scan.user_id == current_user.id,
        Scan.start_time < cutoff_date
    ).all()
    
    # Delete each scan
    count = 0
    for scan in old_scans:
        db.session.delete(scan)
        count += 1
    
    # Commit the changes
    db.session.commit()
    
    flash(f'Deleted {count} scans older than 30 days', 'success')
    return redirect(url_for('main.scan_history'))

# These routes should be added to main.py
# Make sure to add these imports at the top of the file:
# import subprocess
# from flask import make_response

@bp.route('/arp_table')
@login_required
def arp_table():
    """Display the current ARP table"""
    from app.utils_arp import get_arp_table, get_vendor_from_mac
    
    # Get the current ARP table
    arp_entries = get_arp_table()
    
    # Add vendor information
    for entry in arp_entries:
        entry['vendor'] = get_vendor_from_mac(entry['mac'])
    
    return render_template('arp_table.html', 
                          title='ARP Table', 
                          arp_entries=arp_entries,
                          last_updated=datetime.utcnow())

@bp.route('/refresh_arp_table')
@login_required
def refresh_arp_table():
    """Refresh the ARP table by running arp -a command"""
    try:
        # Run arp -a to update the ARP cache
        subprocess.run(['arp', '-a'], check=True)
        flash('ARP table refreshed successfully', 'success')
    except Exception as e:
        flash(f'Error refreshing ARP table: {str(e)}', 'danger')
    
    return redirect(url_for('main.arp_table'))

@bp.route('/update_arp_table', methods=['POST'])
@login_required
def update_arp_table():
    """Manually update the ARP table by pinging a specific target"""
    target = request.form.get('target', '')
    
    if not target:
        flash('Please provide a target IP address', 'warning')
        return redirect(url_for('main.arp_table'))
    
    try:
        # Ping the target to update the ARP cache
        subprocess.run(['ping', '-c', '1', target], check=True)
        flash(f'Successfully pinged {target} to update ARP cache', 'success')
    except Exception as e:
        flash(f'Error pinging target {target}: {str(e)}', 'danger')
    
    return redirect(url_for('main.arp_table'))

@bp.route('/export_arp_table/<format>')
@login_required
def export_arp_table(format):
    """Export the ARP table in various formats"""
    from app.utils_arp import get_arp_table, get_vendor_from_mac, export_arp_table_csv, export_arp_table_json
    
    # Get the current ARP table
    arp_entries = get_arp_table()
    
    # Add vendor information
    for entry in arp_entries:
        entry['vendor'] = get_vendor_from_mac(entry['mac'])
    
    # Generate timestamp for filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    if format == 'csv':
        # Export as CSV
        csv_content = export_arp_table_csv(arp_entries)
        
        # Create response with CSV content
        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename=arp_table_{timestamp}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
        
    elif format == 'json':
        # Export as JSON
        json_content = export_arp_table_json(arp_entries)
        
        # Create response with JSON content
        response = make_response(json_content)
        response.headers["Content-Disposition"] = f"attachment; filename=arp_table_{timestamp}.json"
        response.headers["Content-Type"] = "application/json"
        return response
        
    else:
        flash(f'Unsupported export format: {format}', 'danger')
        return redirect(url_for('main.arp_table'))

@bp.route('/packet_captures')
@login_required
def packet_captures():
    """Display packet capture page and list of captures"""
    form = PacketCaptureForm()
    
    # Get all captures for the current user
    captures = PacketCapture.query.filter_by(user_id=current_user.id).order_by(PacketCapture.start_time.desc()).all()
    
    return render_template('packet_captures.html', 
                           title='Packet Captures', 
                           form=form, 
                           captures=captures)

@bp.route('/start_capture', methods=['POST'])
@login_required
def start_capture():
    """Start a new packet capture"""
    form = PacketCaptureForm()
    
    if form.validate_on_submit():
        # Create new packet capture record
        capture = PacketCapture(
            interface=form.interface.data,
            protocol=form.protocol.data,
            port=form.port.data if form.port.data > 0 else None,
            host=form.host.data if form.host.data else None,
            packet_count=form.packet_count.data,
            verbose=form.verbose.data,
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(capture)
        db.session.commit()
        
        # Start capture in background thread
        thread = threading.Thread(target=run_tcpdump_in_thread, args=(current_app._get_current_object(), capture.id))
        thread.daemon = True
        thread.start()
        
        flash(f'Packet capture started on {capture.interface}', 'success')
        return redirect(url_for('main.capture_details', capture_id=capture.id))
    
    # If form validation fails
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", 'danger')
    
    return redirect(url_for('main.packet_captures'))

@bp.route('/capture_details/<int:capture_id>')
@login_required
def capture_details(capture_id):
    """Display details of a specific capture"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        flash('Access to the requested capture is restricted', 'danger')
        return redirect(url_for('main.packet_captures'))
    
    return render_template('capture_details.html', 
                          title='Capture Details', 
                          capture=capture)

@bp.route('/capture_status/<int:capture_id>')
@login_required
def capture_status(capture_id):
    """AJAX endpoint to check capture status"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if we have an active process for this capture
    is_active = capture_id in active_captures
    
    # Force a fresh query to get the latest status
    db.session.refresh(capture)
    
    data = {
        'status': capture.status,
        'start_time': capture.start_time.strftime('%Y-%m-%d %H:%M:%S') if capture.start_time else None,
        'duration': capture.duration if capture.duration else None,
        'is_active': is_active
    }
    
    return jsonify(data)

@bp.route('/capture_output/<int:capture_id>')
@login_required
def capture_output(capture_id):
    """Get the raw command output for a capture"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Force refresh to get the latest output
    db.session.refresh(capture)
    
    return jsonify({
        'output': capture.command_output or 'No output available',
        'status': capture.status
    })

@bp.route('/stop_capture/<int:capture_id>')
@login_required
def stop_capture(capture_id):
    """Stop a running capture"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        flash('Access to the requested capture is restricted', 'danger')
        return redirect(url_for('main.packet_captures'))
    
    # Check if capture is running
    if capture.status != 'running':
        flash('Capture is not currently running', 'warning')
        return redirect(url_for('main.capture_details', capture_id=capture.id))
    
    # Try to stop the capture
    if capture_id in active_captures:
        process = active_captures[capture_id]
        try:
            process.terminate()
            flash('Capture process terminated', 'info')
        except Exception as e:
            flash(f'Error stopping capture process: {str(e)}', 'warning')
        
        # Remove from active captures
        del active_captures[capture_id]
    
    # Update capture status
    capture.status = 'stopped'
    capture.end_time = datetime.utcnow()
    capture.command_output += "\nCapture was manually stopped by user.\n"
    db.session.commit()
    
    flash('Capture stopped', 'info')
    return redirect(url_for('main.capture_details', capture_id=capture.id))

@bp.route('/download_capture/<int:capture_id>')
@login_required
def download_capture(capture_id):
    """Download a capture file"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        flash('Access to the requested capture is restricted', 'danger')
        return redirect(url_for('main.packet_captures'))
    
    # Check if file exists
    if not capture.filename:
        flash('Capture file not found', 'danger')
        return redirect(url_for('main.capture_details', capture_id=capture.id))
    
    # Directory for packet captures
    captures_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'captures')
    
    # Return the file
    return send_from_directory(captures_dir, capture.filename)

@bp.route('/delete_capture/<int:capture_id>', methods=['POST'])
@login_required
def delete_capture(capture_id):
    """Delete a capture and its file"""
    capture = PacketCapture.query.get_or_404(capture_id)
    
    # Check if capture belongs to current user
    if capture.user_id != current_user.id:
        flash('Access to the requested capture is restricted', 'danger')
        return redirect(url_for('main.packet_captures'))
    
    # If capture is running, stop it first
    if capture.status == 'running' and capture_id in active_captures:
        process = active_captures[capture_id]
        try:
            process.terminate()
        except Exception:
            pass
        
        # Remove from active captures
        if capture_id in active_captures:
            del active_captures[capture_id]
    
    # Delete the capture file if it exists
    if capture.filename:
        captures_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'captures')
        file_path = os.path.join(captures_dir, capture.filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                flash(f'Error deleting file: {str(e)}', 'warning')
    
    # Delete the capture record
    db.session.delete(capture)
    db.session.commit()
    
    flash('Capture deleted', 'success')
    return redirect(url_for('main.packet_captures'))

@bp.route('/network_utilities')
@login_required
def network_utilities():
    """Main network utilities page showing available tools"""
    return render_template('network_utilities.html', title='Network Utilities')

@bp.route('/network_utilities/ping', methods=['GET', 'POST'])
@login_required
def network_ping():
    """Ping utility page"""
    form = PingForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='ping',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build ping command
        ping_command = [
            'ping',
            '-c', str(form.count.data),
            '-W', str(form.timeout.data),
            form.host.data
        ]
        
        # Start command in background thread
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, ping_command)
        )
        thread.daemon = True
        thread.start()
        
        flash(f'Ping started for {form.host.data}', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past ping commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='ping'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_ping.html', 
        title='Ping Tool', 
        form=form, 
        past_commands=past_commands
    )

@bp.route('/network_utilities/traceroute', methods=['GET', 'POST'])
@login_required
def network_traceroute():
    """Traceroute utility page"""
    form = TracerouteForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='traceroute',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build traceroute command
        traceroute_command = [
            'traceroute',
            '-m', str(form.max_hops.data),
            '-w', str(form.timeout.data),
            form.host.data
        ]
        
        # Start command in background thread
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, traceroute_command)
        )
        thread.daemon = True
        thread.start()
        
        flash(f'Traceroute started for {form.host.data}', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past traceroute commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='traceroute'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_traceroute.html', 
        title='Traceroute Tool', 
        form=form,
        past_commands=past_commands
    )

@bp.route('/network_utilities/dig', methods=['GET', 'POST'])
@login_required
def network_dig():
    """Dig DNS lookup utility page"""
    form = DigForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='dig',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build dig command
        dig_command = [
            'dig',
            '+noall', '+answer', '+stats',
            form.domain.data, form.record_type.data
        ]
        
        # Start command in background thread
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, dig_command)
        )
        thread.daemon = True
        thread.start()
        
        flash(f'DNS lookup started for {form.domain.data}', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past dig commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='dig'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_dig.html', 
        title='Dig DNS Lookup Tool', 
        form=form,
        past_commands=past_commands
    )

@bp.route('/network_utilities/iperf', methods=['GET', 'POST'])
@login_required
def network_iperf():
    """Iperf network performance test utility page"""
    form = IperfForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='iperf',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build iperf command
        iperf_command = [
            'iperf3',
            '-c', form.server.data,
            '-p', str(form.port.data),
            '-t', str(form.duration.data)
        ]
        
        # Add protocol-specific options
        if form.protocol.data == 'udp':
            iperf_command.append('-u')
            if form.bandwidth.data:
                iperf_command.extend(['-b', form.bandwidth.data])
        
        # Start command in background thread with timeout
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, iperf_command, form.duration.data + 10)
        )
        thread.daemon = True
        thread.start()
        
        flash(f'Performance test started to {form.server.data}', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past iperf commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='iperf'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_iperf.html', 
        title='Iperf Performance Test Tool', 
        form=form,
        past_commands=past_commands
    )

@bp.route('/network_utilities/iproute', methods=['GET', 'POST'])
@login_required
def network_iproute():
    """IP route utility page"""
    form = IpRouteForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='iproute',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build ip route command
        if form.action.data == 'show':
            iproute_command = ['ip', 'route', 'show']
        elif form.action.data == 'get' and form.destination.data:
            iproute_command = ['ip', 'route', 'get', form.destination.data]
        else:
            flash('Invalid action or missing destination', 'danger')
            return redirect(url_for('main.network_iproute'))
        
        # Start command in background thread
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, iproute_command)
        )
        thread.daemon = True
        thread.start()
        
        flash('IP route command started', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past iproute commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='iproute'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_iproute.html', 
        title='IP Route Tool', 
        form=form,
        past_commands=past_commands
    )

@bp.route('/network_utilities/iptables', methods=['GET', 'POST'])
@login_required
def network_iptables():
    """IPtables firewall utility page"""
    form = IptablesForm()
    
    if form.validate_on_submit():
        # Create new network command record
        command = NetworkCommand(
            tool='iptables',
            status='pending',
            user_id=current_user.id,
            start_time=datetime.utcnow()
        )
        db.session.add(command)
        db.session.commit()
        
        # Build iptables command
        if form.action.data == 'list':
            iptables_command = ['sudo', 'iptables', '-L', '-v', '--line-numbers']
        elif form.action.data == 'list_nat':
            iptables_command = ['sudo', 'iptables', '-t', 'nat', '-L', '-v', '--line-numbers']
        elif form.action.data == 'list_mangle':
            iptables_command = ['sudo', 'iptables', '-t', 'mangle', '-L', '-v', '--line-numbers']
        else:
            flash('Invalid action', 'danger')
            return redirect(url_for('main.network_iptables'))
        
        # Start command in background thread
        thread = threading.Thread(
            target=run_network_command, 
            args=(current_app._get_current_object(), command.id, iptables_command)
        )
        thread.daemon = True
        thread.start()
        
        flash('IPtables command started', 'success')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Get past iptables commands for this user
    past_commands = NetworkCommand.query.filter_by(
        user_id=current_user.id, 
        tool='iptables'
    ).order_by(NetworkCommand.start_time.desc()).limit(10).all()
    
    return render_template(
        'network_iptables.html', 
        title='IPtables Firewall Tool', 
        form=form,
        past_commands=past_commands
    )

@bp.route('/network_command/<int:command_id>')
@login_required
def network_command_results(command_id):
    """Display results of a specific network command"""
    command = NetworkCommand.query.get_or_404(command_id)
    
    # Check if command belongs to current user
    if command.user_id != current_user.id:
        flash('Access to the requested command is restricted', 'danger')
        return redirect(url_for('main.network_utilities'))
    
    # Determine which template to use based on the tool
    template = f'network_{command.tool}_results.html'
    
    return render_template(
        template,
        title=f'{command.tool.capitalize()} Results',
        command=command
    )

@bp.route('/network_command_status/<int:command_id>')
@login_required
def network_command_status(command_id):
    """AJAX endpoint to check command status"""
    command = NetworkCommand.query.get_or_404(command_id)
    
    # Check if command belongs to current user
    if command.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if we have an active process for this command
    is_active = command_id in active_network_utils
    
    # Force a fresh query to get the latest status
    db.session.refresh(command)
    
    data = {
        'status': command.status,
        'start_time': command.start_time.strftime('%Y-%m-%d %H:%M:%S') if command.start_time else None,
        'duration': command.duration if command.duration else None,
        'is_active': is_active
    }
    
    return jsonify(data)

@bp.route('/network_command_output/<int:command_id>')
@login_required
def network_command_output(command_id):
    """AJAX endpoint to get command output"""
    command = NetworkCommand.query.get_or_404(command_id)
    
    # Check if command belongs to current user
    if command.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Force refresh to get the latest output
    db.session.refresh(command)
    
    return jsonify({
        'output': command.command_output or 'No output available',
        'status': command.status
    })

@bp.route('/stop_network_command/<int:command_id>')
@login_required
def stop_network_command(command_id):
    """Stop a running network command"""
    command = NetworkCommand.query.get_or_404(command_id)
    
    # Check if command belongs to current user
    if command.user_id != current_user.id:
        flash('Access to the requested command is restricted', 'danger')
        return redirect(url_for('main.network_utilities'))
    
    # Check if command is running
    if command.status != 'running':
        flash('Command is not currently running', 'warning')
        return redirect(url_for('main.network_command_results', command_id=command.id))
    
    # Try to stop the command
    if command_id in active_network_utils:
        process = active_network_utils[command_id]
        try:
            process.terminate()
            flash('Command terminated', 'info')
        except Exception as e:
            flash(f'Error stopping command: {str(e)}', 'warning')
        
        # Remove from active commands
        del active_network_utils[command_id]
    
    # Update command status
    command.status = 'stopped'
    command.end_time = datetime.utcnow()
    command.command_output += "\nCommand was manually stopped by user.\n"
    db.session.commit()
    
    flash('Command stopped', 'info')
    return redirect(url_for('main.network_command_results', command_id=command.id))
