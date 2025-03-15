import nmap
import threading
import time
import json
from datetime import datetime
from app.models import Scan, Host, Port
from app import db


class NmapScanner:
    """Class to handle NMAP scanning operations"""

    def __init__(self, target, scan_type='simple', args=None):
        self.target = target
        self.scan_type = scan_type
        self.args = args
        self.scanner = nmap.PortScanner()
        self.running = False
        self.result = None
        print(f"NmapScanner initialized for target: {target}, type: {scan_type}")

    def get_scan_args(self):
        """Return appropriate nmap arguments based on scan_type"""
        if self.scan_type == 'simple':
            return '-sS -F -T4'  # SYN scan, fast mode (fewer ports), aggressive timing
        elif self.scan_type == 'comprehensive':
            return '-sS -p- -T4 -A -v'  # SYN scan, all ports, aggressive timing, OS & version detection
        elif self.scan_type == 'os':
            return '-sS -O -T4'  # SYN scan with OS detection
        elif self.scan_type == 'service':
            return '-sS -sV -T4'  # SYN scan with service version detection
        elif self.scan_type == 'custom' and self.args:
            return self.args  # Custom arguments provided by user
        else:
            return '-sS -T4'  # Default to SYN scan with aggressive timing

    def run_scan(self):
        """Run the scan and return the results directly"""
        try:
            self.running = True
            args = self.get_scan_args()
            print(f"Running nmap synchronously with args: {args}")
            start_time = time.time()
            result = self.scanner.scan(self.target, arguments=args)
            end_time = time.time()
            result['nmap']['scanstats']['elapsed'] = end_time - start_time
            print(f"Scan completed in {end_time - start_time} seconds")
            return result
        except Exception as e:
            print(f"Error during scan: {str(e)}")
            return {'error': str(e)}
        finally:
            self.running = False

    def start_scan(self):
        """Start the scan and set the result"""
        if not self.running:
            self.result = self.run_scan()
            return True
        return False

    def stop_scan(self):
        """Stop the running scan - Note: this doesn't actually stop nmap, just marks it as stopped"""
        self.running = False
        return True

    def get_result(self):
        """Return the scan result"""
        return self.result

    def is_running(self):
        """Check if scan is still running"""
        return self.running


def parse_scan_result(scan_obj, result):
    """Parse nmap scan result and update the database with the findings"""
    try:
        print(f"Parsing scan results: {result}")
        if not result or 'nmap' not in result or 'scanstats' not in result['nmap']:
            scan_obj.status = 'failed'
            db.session.commit()
            print("Failed to find expected result structure")
            return

        # Update scan object with basic stats
        scan_obj.status = 'completed'
        scan_obj.end_time = datetime.utcnow()
        scan_obj.duration = float(result['nmap']['scanstats'].get('elapsed', 0))
        scan_obj.host_count = int(result['nmap']['scanstats'].get('uphosts', 0))
        scan_obj.set_result(result)

        print(f"Found {scan_obj.host_count} hosts")

        # Process hosts and their details
        if 'scan' in result:
            for ip, host_data in result['scan'].items():
                print(f"Processing host: {ip}")
                # Create host record
                host = Host(
                    ip_address=ip,
                    scan=scan_obj
                )

                # Extract hostname if available
                if 'hostnames' in host_data and host_data['hostnames']:
                    for hostname_entry in host_data['hostnames']:
                        if 'name' in hostname_entry and hostname_entry['name']:
                            host.hostname = hostname_entry['name']
                            break

                # Extract MAC address if available
                if 'addresses' in host_data and 'mac' in host_data['addresses']:
                    host.mac_address = host_data['addresses']['mac']

                # Extract OS details if available
                if 'osmatch' in host_data and host_data['osmatch']:
                    host.os = host_data['osmatch'][0]['name']

                db.session.add(host)

                # Process TCP ports
                if 'tcp' in host_data:
                    for port_num, port_data in host_data['tcp'].items():
                        print(f"Found TCP port: {port_num}")
                        port = Port(
                            port_number=port_num,
                            protocol='tcp',
                            service=port_data.get('name', ''),
                            state=port_data.get('state', ''),
                            host=host
                        )
                        db.session.add(port)

                # Process UDP ports if available
                if 'udp' in host_data:
                    for port_num, port_data in host_data['udp'].items():
                        print(f"Found UDP port: {port_num}")
                        port = Port(
                            port_number=port_num,
                            protocol='udp',
                            service=port_data.get('name', ''),
                            state=port_data.get('state', ''),
                            host=host
                        )
                        db.session.add(port)

        db.session.commit()
        print("Scan results successfully saved to database")
    except Exception as e:
        print(f"Error parsing scan results: {str(e)}")
        db.session.rollback()
        scan_obj.status = 'failed'
        scan_obj.result_json = '{"error": "' + str(e) + '"}'
        db.session.commit()


def parse_nmap_file(file_path, user_id):
    """Parse an uploaded nmap file and store results in the database"""
    try:
        # Create a new scan record for the uploaded file
        scan = Scan(
            target='Uploaded File',
            scan_type='upload',
            arguments='N/A',
            status='processing',
            user_id=user_id,
            start_time=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()

        # Parse file based on format (XML or text)
        if file_path.endswith('.xml'):
            # Parse XML file using nmap's built-in XML parser
            nm = nmap.PortScanner()
            with open(file_path, 'r') as f:
                content = f.read()
            nm.analyse_nmap_xml_scan(content)
            result = nm._scan_result
            parse_scan_result(scan, result)
        else:
            # Basic parsing for text output (limited functionality)
            with open(file_path, 'r') as f:
                content = f.read()

            # Create a simple result structure
            result = {
                'nmap': {
                    'scanstats': {
                        'elapsed': 0,
                        'uphosts': 0,
                        'downhosts': 0,
                        'totalhosts': 0
                    }
                },
                'scan': {}
            }

            # Simple text parsing logic
            hosts = {}
            current_host = None

            for line in content.splitlines():
                # Look for host lines
                if 'Nmap scan report for' in line:
                    ip = line.split('for ')[1].strip()
                    current_host = ip
                    hosts[current_host] = {
                        'addresses': {'ipv4': current_host},
                        'tcp': {},
                        'hostnames': []
                    }
                    result['nmap']['scanstats']['uphosts'] += 1
                    result['nmap']['scanstats']['totalhosts'] += 1

                # Look for MAC addresses
                elif 'MAC Address:' in line and current_host:
                    parts = line.split('MAC Address:')
                    if len(parts) > 1:
                        mac_parts = parts[1].split('(')
                        if len(mac_parts) > 0:
                            mac = mac_parts[0].strip()
                            hosts[current_host]['addresses']['mac'] = mac

                # Look for open ports
                elif current_host and '/tcp' in line and 'open' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        port_num = int(parts[0].split('/')[0])
                        state = parts[1]
                        service = ' '.join(parts[2:])
                        hosts[current_host]['tcp'][port_num] = {
                            'state': state,
                            'name': service
                        }

            result['scan'] = hosts
            scan.set_result(result)
            parse_scan_result(scan, result)

        return scan.id
    except Exception as e:
        if 'scan' in locals():
            scan.status = 'failed'
            scan.result_json = json.dumps({'error': str(e)})
            db.session.commit()
        return None
