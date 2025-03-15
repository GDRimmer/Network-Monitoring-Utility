import subprocess
import time
import os
import tempfile
from pathlib import Path

def run_test():
    print("Starting NMAP test...")
    
    # Create temporary directory in user's home
    home_dir = str(Path.home())
    temp_dir = os.path.join(home_dir, 'nmap_temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create output file paths
    output_file = os.path.join(temp_dir, "nmap_test_output.txt")
    xml_file = os.path.join(temp_dir, "nmap_test.xml")
    
    # Try to remove files if they exist, but continue if we can't
    for file_path in [output_file, xml_file]:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Removed existing file: {file_path}")
            except PermissionError:
                print(f"Warning: Could not remove existing file: {file_path}")
    
    # NMAP command to run - using -sT (TCP Connect) instead of -sS (SYN)
    command = f"nmap -sT -F -T4 -v 127.0.0.1 -oX {xml_file}"
    print(f"Running command: {command}")
    
    try:
        # Run command and tee output to both console and file
        full_command = f"{command} | tee {output_file}"
        print(f"Full command with output redirect: {full_command}")
        
        process = subprocess.Popen(
            full_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Read and print output in real time
        for line in iter(process.stdout.readline, ''):
            print(f"OUTPUT: {line.strip()}")
        
        # Wait for process to complete
        process.wait()
        
        print(f"Process exited with code: {process.returncode}")
        
        # Check if output files were created
        xml_exists = os.path.exists(xml_file)
        output_exists = os.path.exists(output_file)
        
        print(f"XML output file exists: {xml_exists}")
        print(f"Text output file exists: {output_exists}")
        
        # Read file content if it exists
        if output_exists:
            with open(output_file, 'r') as f:
                content = f.read()
                content_size = len(content)
                print(f"Output file size: {content_size} bytes")
                print("First 200 characters of output:")
                print(content[:200])
        
    except Exception as e:
        print(f"Error running NMAP: {str(e)}")

if __name__ == "__main__":
    run_test()
