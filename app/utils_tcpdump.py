# Add this to a new file: utils_tcpdump.py

import subprocess
import os
import time
from datetime import datetime
from flask import current_app

# Dictionary to keep track of running captures
active_captures = {}

def run_tcpdump_in_thread(app, capture_id):
    """Run a tcpdump capture in a background thread"""
    with app.app_context():
        try:
            from app import db
            from app.models import PacketCapture
            
            print(f"Starting tcpdump thread for capture_id {capture_id}")
            capture = PacketCapture.query.get(capture_id)
            if not capture:
                print(f"Capture {capture_id} not found")
                return
            
            # Update capture status
            capture.status = 'running'
            capture.command_output = "Initializing packet capture...\n"
            db.session.commit()
            
            # Create directory for packet captures if it doesn't exist
            captures_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'captures')
            os.makedirs(captures_dir, exist_ok=True)
            
            # Prepare the output filename
            filename = f"capture_{capture_id}_{int(time.time())}.pcap"
            filepath = os.path.join(captures_dir, filename)
            capture.filename = filename
            
            # Build tcpdump command
            command = ["tcpdump", "-i", capture.interface]
            
            # Add options based on capture configuration
            if capture.verbose:
                command.append("-v")
            
            if capture.packet_count is not None and capture.packet_count > 0:
    	        command.extend(["-c", str(capture.packet_count)])
            
	    # Add protocol filter if specified
            filter_parts = []
            if capture.protocol:
                filter_parts.append(capture.protocol)
            
            # Add port filter if specified
            if capture.port is not None and capture.port > 0:
    	        filter_parts.append(f"port {capture.port}")
            
            # Add host filter if specified
            if capture.host:
                filter_parts.append(f"host {capture.host}")
            
            # Combine filter parts with 'and'
            if filter_parts:
                filter_expr = " and ".join(filter_parts)
                command.append(filter_expr)
            
            # Add output file
            command.extend(["-w", filepath])
            
            # Convert command list to string for display
            command_str = " ".join(command)
            capture.command = command_str
            
            # Update database with command
            capture.command_output += f"Executing: {command_str}\n\n"
            db.session.commit()
            
            print(f"Will execute: {command_str}")
            
            # Start the capture
            start_time = time.time()
            
            try:
                # Use Popen to start the process
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Add the process to active captures
                active_captures[capture_id] = process
                
                # Check process status periodically
                while process.poll() is None:
                    # Read from stderr (tcpdump outputs status to stderr)
                    stderr_data = process.stderr.readline()
                    if stderr_data:
                        capture.command_output += stderr_data
                        db.session.commit()
                    
                    # Sleep briefly to avoid hammering the database
                    time.sleep(0.5)
                
                # Process has finished
                return_code = process.returncode
                end_time = time.time()
                duration = end_time - start_time
                
                # Get remaining output
                out, err = process.communicate()
                if err:
                    capture.command_output += err
                
                # Check return code
                if return_code != 0 and return_code != -15:  # -15 is SIGTERM, used when stopping
                    capture.command_output += f"\ntcpdump exited with code {return_code}\n"
                    capture.status = 'failed'
                else:
                    capture.status = 'completed'
                
                capture.end_time = datetime.utcnow()
                capture.duration = duration
                db.session.commit()
                
            except Exception as cmd_error:
                print(f"Error executing tcpdump: {str(cmd_error)}")
                capture.command_output += f"\nError executing tcpdump: {str(cmd_error)}\n"
                capture.status = 'failed'
                capture.end_time = datetime.utcnow()
                db.session.commit()
            
            # Remove from active captures
            if capture_id in active_captures:
                del active_captures[capture_id]
                
        except Exception as e:
            print(f"Thread error for capture {capture_id}: {str(e)}")
            try:
                capture = PacketCapture.query.get(capture_id)
                if capture:
                    capture.status = 'failed'
                    capture.end_time = datetime.utcnow()
                    capture.command_output += f"\nError: {str(e)}\n"
                    db.session.commit()
            except Exception as db_error:
                print(f"Failed to update capture status: {str(db_error)}")
            
            # Remove from active captures
            if capture_id in active_captures:
                del active_captures[capture_id]
