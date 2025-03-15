import subprocess
from datetime import datetime
import re
import json
import csv
import io
import os


def get_arp_table():
    """
    Get the current ARP table from the system

    Returns:
        list: List of dictionaries containing IP, MAC, and interface information
    """
    try:
        # Run the arp -a command
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)

        # Parse the output
        arp_entries = []

        for line in result.stdout.splitlines():
            # Skip empty lines
            if not line.strip():
                continue

            # Parse the line - typical format: hostname (ip) at mac on interface
            match = re.search(r'(.*) \(([0-9\.]+)\) at ([0-9a-f:]+) \[(\w+)\] on ([^\s]+)', line)
            if match:
                hostname, ip, mac, hw_type, interface = match.groups()
                arp_entries.append({
                    'hostname': hostname.strip(),
                    'ip': ip,
                    'mac': mac,
                    'hw_type': hw_type,
                    'interface': interface,
                    'timestamp': datetime.now()
                })
            else:
                # Alternative format (varies by system): hostname (ip) at mac on interface
                match = re.search(r'(.*) \(([0-9\.]+)\) at ([0-9a-f:]+) on ([^\s]+)', line)
                if match:
                    hostname, ip, mac, interface = match.groups()
                    arp_entries.append({
                        'hostname': hostname.strip(),
                        'ip': ip,
                        'mac': mac,
                        'hw_type': 'ether',  # Assuming ether as default
                        'interface': interface,
                        'timestamp': datetime.now()
                    })
                # Handle cases where MAC address is reported as incomplete
                elif "incomplete" in line.lower():
                    match = re.search(r'(.*) \(([0-9\.]+)\) at incomplete', line)
                    if match:
                        hostname, ip = match.groups()
                        arp_entries.append({
                            'hostname': hostname.strip(),
                            'ip': ip,
                            'mac': 'incomplete',
                            'hw_type': 'unknown',
                            'interface': 'unknown',
                            'timestamp': datetime.now()
                        })

        return arp_entries
    except Exception as e:
        print(f"Error getting ARP table: {str(e)}")
        return []


def clear_arp_cache():
    """
    Clear the ARP cache

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # This requires root privileges, often used with sudo
        # Using IP command as it's more modern and available on most systems
        subprocess.run(['ip', 'neigh', 'flush', 'all'], check=True)
        return True
    except Exception as e:
        print(f"Error clearing ARP cache: {str(e)}")
        return False


def get_vendor_from_mac(mac_address):
    """
    Get vendor information from MAC address (first 3 octets)
    Uses an expanded OUI (Organizationally Unique Identifier) database

    Args:
        mac_address: MAC address string

    Returns:
        str: Vendor name or unknown
    """
    if mac_address == 'incomplete':
        return 'Unknown'

    # Normalize MAC address format (supports both : and - separators)
    normalized_mac = mac_address.lower().replace('-', ':')
    prefix = ':'.join(normalized_mac.split(':')[:3])

    return MAC_VENDORS.get(prefix, 'Unknown')


def export_arp_table_json(arp_entries):
    """
    Export the ARP table as JSON

    Args:
        arp_entries: List of dictionaries containing ARP entries

    Returns:
        str: JSON string
    """
    # Create a copy to avoid modifying the original data
    export_data = []

    for entry in arp_entries:
        # Create a copy of the entry without the timestamp (which is not JSON serializable)
        export_entry = {
            'hostname': entry['hostname'],
            'ip_address': entry['ip'],
            'mac_address': entry['mac'],
            'vendor': get_vendor_from_mac(entry['mac']),
            'interface': entry['interface'],
            'hw_type': entry['hw_type'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        export_data.append(export_entry)

    return json.dumps(export_data, indent=4)


def export_arp_table_csv(arp_entries):
    """
    Export the ARP table as CSV

    Args:
        arp_entries: List of dictionaries containing ARP entries

    Returns:
        str: CSV string
    """
    # Create a string buffer to write CSV data to
    output = io.StringIO()

    # Define CSV fields
    fieldnames = ['hostname', 'ip_address', 'mac_address', 'vendor', 'interface', 'hw_type', 'timestamp']

    # Create CSV writer
    writer = csv.DictWriter(output, fieldnames=fieldnames)

    # Write header
    writer.writeheader()

    # Write data
    for entry in arp_entries:
        writer.writerow({
            'hostname': entry['hostname'],
            'ip_address': entry['ip'],
            'mac_address': entry['mac'],
            'vendor': get_vendor_from_mac(entry['mac']),
            'interface': entry['interface'],
            'hw_type': entry['hw_type'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    # Get the CSV content
    csv_content = output.getvalue()
    output.close()

    return csv_content


# Expanded MAC Vendor Database
# Source: Common OUI prefixes from IEEE registry (abbreviated for code simplicity)
MAC_VENDORS = {
    # Apple devices
    '00:03:93': 'Apple',
    '00:0a:27': 'Apple',
    '00:0a:95': 'Apple',
    '00:0d:93': 'Apple',
    '00:11:24': 'Apple',
    '00:14:51': 'Apple',
    '00:16:cb': 'Apple',
    '00:17:f2': 'Apple',
    '00:19:e3': 'Apple',
    '00:1b:63': 'Apple',
    '00:1d:4f': 'Apple',
    '00:1e:52': 'Apple',
    '00:1e:c2': 'Apple',
    '00:1f:5b': 'Apple',
    '00:1f:f3': 'Apple',
    '00:21:e9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:12': 'Apple',
    '00:23:32': 'Apple',
    '00:23:6c': 'Apple',
    '00:23:df': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:bc': 'Apple',
    '00:26:08': 'Apple',
    '00:26:4a': 'Apple',
    '00:26:b0': 'Apple',
    '00:26:bb': 'Apple',
    '00:30:65': 'Apple',
    '00:3e:e1': 'Apple',
    '04:0c:ce': 'Apple',
    '04:15:52': 'Apple',
    '04:1e:64': 'Apple',
    '04:26:65': 'Apple',
    '04:54:53': 'Apple',
    '04:69:f8': 'Apple',
    '04:d3:cf': 'Apple',
    '04:db:56': 'Apple',
    '04:e5:36': 'Apple',
    '04:f1:3e': 'Apple',
    '04:f7:e4': 'Apple',
    '08:66:98': 'Apple',
    '08:70:45': 'Apple',
    '18:af:61': 'Apple',
    '28:cf:da': 'Apple',
    '34:12:98': 'Apple',
    '34:15:9e': 'Apple',
    '3c:07:54': 'Apple',
    '3c:d0:f8': 'Apple',
    '40:a6:d9': 'Apple',
    '44:2a:60': 'Apple',
    '5c:f9:38': 'Apple',
    '60:fa:cd': 'Apple',
    '64:b9:e8': 'Apple',
    '7c:6d:62': 'Apple',
    '7c:d1:c3': 'Apple',
    '88:c6:63': 'Apple',
    '8c:2d:aa': 'Apple',
    '98:03:d8': 'Apple',
    '98:fe:94': 'Apple',
    'a8:fa:d8': 'Apple',
    'ac:cf:5c': 'Apple',
    'b8:c7:5d': 'Apple',
    'b8:f6:b1': 'Apple',
    'c8:2a:14': 'Apple',
    'c8:6f:1d': 'Apple',
    'cc:08:8d': 'Apple',
    'd0:23:db': 'Apple',
    'e0:b9:ba': 'Apple',
    'e0:f8:47': 'Apple',
    'e8:04:0b': 'Apple',
    'f0:18:98': 'Apple',
    'f8:1e:df': 'Apple',

    # Cisco devices
    '00:00:0c': 'Cisco',
    '00:01:42': 'Cisco',
    '00:01:43': 'Cisco',
    '00:01:97': 'Cisco',
    '00:02:4a': 'Cisco',
    '00:02:4b': 'Cisco',
    '00:02:7d': 'Cisco',
    '00:02:b9': 'Cisco',
    '00:03:31': 'Cisco',
    '00:03:32': 'Cisco',
    '00:03:fe': 'Cisco',
    '00:03:ff': 'Cisco',
    '00:04:9a': 'Cisco',
    '00:04:c0': 'Cisco',
    '00:05:9a': 'Cisco',
    '00:05:dc': 'Cisco',
    '00:06:28': 'Cisco',
    '00:06:7c': 'Cisco',
    '00:07:0d': 'Cisco',
    '00:07:0e': 'Cisco',
    '00:07:eb': 'Cisco',
    '00:07:ec': 'Cisco',
    '00:08:7c': 'Cisco',
    '00:08:7d': 'Cisco',
    '00:0a:41': 'Cisco',
    '00:0a:42': 'Cisco',
    '00:0a:8a': 'Cisco',
    '00:0a:b7': 'Cisco',
    '00:0a:b8': 'Cisco',
    '00:0a:f3': 'Cisco',
    '00:0a:f4': 'Cisco',
    '00:0b:45': 'Cisco',
    '00:0b:46': 'Cisco',
    '00:0b:fd': 'Cisco',
    '00:0b:fe': 'Cisco',
    '00:0c:30': 'Cisco',
    '00:0c:31': 'Cisco',
    '00:0c:85': 'Cisco',
    '00:0c:86': 'Cisco',
    '00:0d:28': 'Cisco',
    '00:0d:29': 'Cisco',
    '00:0d:65': 'Cisco',
    '00:0d:66': 'Cisco',
    '00:0e:38': 'Cisco',
    '00:0e:39': 'Cisco',
    '00:0e:83': 'Cisco',
    '00:0e:84': 'Cisco',

    # Microsoft devices
    '00:03:ff': 'Microsoft',
    '00:0d:3a': 'Microsoft',
    '00:12:5a': 'Microsoft',
    '00:15:5d': 'Microsoft',
    '00:17:fa': 'Microsoft',
    '00:1d:d8': 'Microsoft',
    '00:22:48': 'Microsoft',
    '00:50:f2': 'Microsoft',
    '00:bd:3a': 'Microsoft',
    '28:18:78': 'Microsoft',
    '3c:83:75': 'Microsoft',
    '48:50:73': 'Microsoft',
    '50:1a:c5': 'Microsoft',
    '58:82:a8': 'Microsoft',
    '60:45:bd': 'Microsoft',
    '7c:1e:52': 'Microsoft',
    '7c:ed:8d': 'Microsoft',

    # Intel devices
    '00:02:b3': 'Intel',
    '00:03:47': 'Intel',
    '00:04:23': 'Intel',
    '00:07:e9': 'Intel',
    '00:0c:f1': 'Intel',
    '00:0e:0c': 'Intel',
    '00:0e:35': 'Intel',
    '00:11:11': 'Intel',
    '00:11:75': 'Intel',
    '00:12:f0': 'Intel',
    '00:13:02': 'Intel',
    '00:13:20': 'Intel',
    '00:13:ce': 'Intel',
    '00:13:e8': 'Intel',
    '00:15:00': 'Intel',
    '00:15:17': 'Intel',
    '00:16:6f': 'Intel',
    '00:16:76': 'Intel',
    '00:16:ea': 'Intel',
    '00:16:eb': 'Intel',
    '00:18:de': 'Intel',
    '00:19:d1': 'Intel',
    '00:19:d2': 'Intel',
    '00:1b:21': 'Intel',
    '00:1b:77': 'Intel',
    '00:1c:bf': 'Intel',
    '00:1c:c0': 'Intel',
    '00:1d:e0': 'Intel',
    '00:1d:e1': 'Intel',
    '00:1e:64': 'Intel',
    '00:1e:65': 'Intel',
    '00:1e:67': 'Intel',
    '00:1f:3b': 'Intel',
    '00:1f:3c': 'Intel',
    '00:21:5c': 'Intel',
    '00:21:5d': 'Intel',
    '00:21:6a': 'Intel',
    '00:21:6b': 'Intel',
    '00:22:fa': 'Intel',
    '00:22:fb': 'Intel',
    '00:24:d6': 'Intel',
    '00:24:d7': 'Intel',
    '00:26:c6': 'Intel',
    '00:26:c7': 'Intel',

    # Dell devices
    '00:06:5b': 'Dell',
    '00:08:74': 'Dell',
    '00:0b:db': 'Dell',
    '00:0d:56': 'Dell',
    '00:0f:1f': 'Dell',
    '00:11:43': 'Dell',
    '00:12:3f': 'Dell',
    '00:13:72': 'Dell',
    '00:14:22': 'Dell',
    '00:15:c5': 'Dell',
    '00:16:f0': 'Dell',
    '00:18:8b': 'Dell',
    '00:19:b9': 'Dell',
    '00:1a:a0': 'Dell',
    '00:1c:23': 'Dell',
    '00:1d:09': 'Dell',
    '00:1e:4f': 'Dell',
    '00:21:70': 'Dell',
    '00:21:9b': 'Dell',
    '00:22:19': 'Dell',
    '00:23:ae': 'Dell',
    '00:24:e8': 'Dell',
    '00:25:64': 'Dell',
    '00:26:37': 'Dell',

    # Samsung devices
    '00:00:f0': 'Samsung',
    '00:02:78': 'Samsung',
    '00:07:ab': 'Samsung',
    '00:12:47': 'Samsung',
    '00:12:fb': 'Samsung',
    '00:15:99': 'Samsung',
    '00:16:32': 'Samsung',
    '00:16:6b': 'Samsung',
    '00:16:db': 'Samsung',
    '00:17:c9': 'Samsung',
    '00:17:d5': 'Samsung',
    '00:18:af': 'Samsung',
    '00:1a:8a': 'Samsung',
    '00:1b:98': 'Samsung',
    '00:1c:43': 'Samsung',
    '00:1d:25': 'Samsung',
    '00:1d:f6': 'Samsung',
    '00:1e:7d': 'Samsung',
    '00:1f:cc': 'Samsung',
    '00:1f:cd': 'Samsung',
    '00:21:19': 'Samsung',
    '00:21:4c': 'Samsung',
    '00:21:d1': 'Samsung',
    '00:21:d2': 'Samsung',
    '00:23:39': 'Samsung',
    '00:23:3a': 'Samsung',
    '00:23:99': 'Samsung',
    '00:23:d6': 'Samsung',
    '00:23:d7': 'Samsung',
    '00:24:54': 'Samsung',
    '00:24:90': 'Samsung',
    '00:24:91': 'Samsung',
    '00:24:e9': 'Samsung',
    '00:25:38': 'Samsung',
    '00:25:66': 'Samsung',
    '00:25:67': 'Samsung',
    '00:26:37': 'Samsung',
    '00:26:5d': 'Samsung',
    '00:26:5f': 'Samsung',

    # VM/Hypervisor software
    '00:0c:29': 'VMware',
    '00:50:56': 'VMware',
    '00:05:69': 'VMware',
    '00:1c:14': 'VMware',
    '00:0f:4b': 'Oracle VM',
    '08:00:27': 'VirtualBox',
    '52:54:00': 'QEMU/KVM',
    '00:16:3e': 'Xen',

    # Network equipment manufacturers
    '00:30:f1': 'Accton',
    '00:01:38': 'Netgear',
    '00:09:5b': 'Netgear',
    '00:0f:b5': 'Netgear',
    '00:14:6c': 'Netgear',
    '00:18:4d': 'Netgear',
    '00:1b:2f': 'Netgear',
    '00:1e:2a': 'Netgear',
    '00:1f:33': 'Netgear',
    '00:22:3f': 'Netgear',
    '00:24:b2': 'Netgear',
    '00:26:f2': 'Netgear',
    '20:4e:7f': 'Netgear',
    '84:1b:5e': 'Netgear',
    'c0:3f:0e': 'Netgear',
    'e0:91:f5': 'Netgear',
    '00:01:5c': 'Linksys',
    '00:04:5a': 'Linksys',
    '00:06:25': 'Linksys',
    '00:0c:41': 'Linksys',
    '00:0e:08': 'Linksys',
    '00:0f:66': 'Linksys',
    '00:12:17': 'Linksys',
    '00:13:10': 'Linksys',
    '00:14:bf': 'Linksys',
    '00:16:b6': 'Linksys',
    '00:18:f8': 'Linksys',
    '00:1a:70': 'Linksys',
    '00:1c:10': 'Linksys',
    '00:1d:7e': 'Linksys',
    '00:1e:e5': 'Linksys',
    '00:21:29': 'Linksys',
    '00:22:6b': 'Linksys',
    '00:22:75': 'Linksys',
    '00:23:69': 'Linksys',
    '00:25:9c': 'Linksys',
    '00:06:cc': 'JMicron',
    '00:50:43': 'Marvell',
    '00:04:9f': 'Freescale',
    '00:60:6e': 'Davicom',
    '00:a0:24': '3COM',
    '00:0d:88': 'D-Link',
    '00:05:5d': 'D-Link',
    '00:17:9a': 'D-Link',
    '00:1b:11': 'D-Link',
    '00:1c:f0': 'D-Link',
    '00:1e:58': 'D-Link',
    '00:21:91': 'D-Link',
    '00:22:b0': 'D-Link',
    '00:24:01': 'D-Link',
    '00:26:5a': 'D-Link',
    '18:0f:76': 'D-Link',
    '1c:bd:b9': 'D-Link',
    '1c:af:f7': 'D-Link',
    '28:10:7b': 'D-Link',
    '3c:1e:04': 'D-Link',
    '00:05:1c': 'Edimax',
    '00:0e:2e': 'Edimax',
    '00:1f:1f': 'Edimax',
    '00:80:48': 'Compex',
    '00:90:d8': 'Whitecross',

    # IoT devices
    'b8:27:eb': 'Raspberry Pi Foundation',
    'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi',
    'b8:27:eb': 'Raspberry Pi',
    '00:13:ef': 'Nest Labs',
    '18:b4:30': 'Nest Labs',
    '64:16:66': 'Nest Labs',
    '30:8c:fb': 'Dropcam',
    '90:4c:e5': 'Hon Hai / Foxconn (for many IoT)',
    '44:65:0d': 'Amazon',
    '74:c2:46': 'Amazon',
    'a0:02:dc': 'Amazon',
    'ac:63:be': 'Amazon',
    'fc:a6:67': 'Amazon',
    '40:b4:cd': 'Amazon',
    'f0:d2:f1': 'Amazon',

    # Mobile devices
    '00:23:76': 'HTC',
    '00:ee:bd': 'HTC',
    '04:c2:3e': 'HTC',
    '18:87:96': 'HTC',
    '1c:b0:94': 'HTC',
    '2c:8a:72': 'HTC',
    '38:e7:d8': 'HTC',
    '7c:61:93': 'HTC',
    '80:01:84': 'HTC',
    '84:7a:88': 'HTC',
    '90:21:55': 'HTC',
    '98:0d:2e': 'HTC',
    'a0:f4:50': 'HTC',
    'd8:b3:77': 'HTC',
    'e8:99:c4': 'HTC',
    'f8:db:7f': 'HTC',
    '00:1b:63': 'Apple',
    '00:1e:52': 'Apple',
    '00:1f:f3': 'Apple',
    '00:21:e9': 'Apple',
    '00:23:df': 'Apple',
    '00:25:bc': 'Apple',
    '00:26:08': 'Apple',
    '00:26:bb': 'Apple',
    '04:0c:ce': 'Apple',
    '04:26:65': 'Apple',
    '04:54:53': 'Apple',
    '04:db:56': 'Apple',
    '04:e5:36': 'Apple',
    '04:f1:3e': 'Apple',
    '14:8f:c6': 'Apple',
    '24:ab:81': 'Apple',
    '28:37:37': 'Apple',
    '3c:07:54': 'Apple',
    '3c:d0:f8': 'Apple',
    '58:55:ca': 'Apple',
    '58:b0:35': 'Apple',
    '60:c5:47': 'Apple',
    '64:76:ba': 'Apple',
    '64:a3:cb': 'Apple',
    '68:09:27': 'Apple',
    '68:a8:6d': 'Apple',
    '6c:c2:6b': 'Apple',
    '00:18:82': 'Huawei',
    '00:25:9e': 'Huawei',
    '00:25:68': 'Huawei',
    '00:25:9e': 'Huawei',
    '00:e0:fc': 'Huawei',
    '04:25:c5': 'Huawei',
    '04:bd:70': 'Huawei',
    '04:c0:6f': 'Huawei',
    '04:f9:38': 'Huawei',
    '08:19:a6': 'Huawei',
    '08:63:61': 'Huawei',
    '0c:37:dc': 'Huawei',
    '0c:96:bf': 'Huawei',
    '10:1b:54': 'Huawei',
    '10:47:80': 'Huawei',
    '10:c6:1f': 'Huawei',
    '14:30:04': 'Huawei',
    '14:b9:68': 'Huawei',
    '18:c5:8a': 'Huawei',
    '18:d2:76': 'Huawei',
    '1c:15:1f': 'Huawei',
    '1c:1d:67': 'Huawei',
    '1c:59:9b': 'Huawei',
    '1c:8e:5c': 'Huawei',
    '20:08:ed': 'Huawei',
    '20:2b:c1': 'Huawei',
    '20:f3:a3': 'Huawei',
    '24:4c:07': 'Huawei',
    '24:69:a5': 'Huawei',
    '24:7f:3c': 'Huawei',
    '24:9e:ab': 'Huawei',
    '24:db:ac': 'Huawei',
    '28:31:52': 'Huawei',
    '28:5f:db': 'Huawei',
    '28:a6:db': 'Huawei',
    '2c:55:d3': 'Huawei',
    '2c:ab:00': 'Huawei',
    '2c:cf:58': 'Huawei',
    '30:87:30': 'Huawei',
    '30:d1:7e': 'Huawei',
    '34:00:a3': 'Huawei',
    '34:1e:6b': 'Huawei',
    '34:6b:d3': 'Huawei',
    '34:cd:be': 'Huawei',
    '38:37:8b': 'Huawei',
    '38:4c:4f': 'Huawei',
    '38:bc:01': 'Huawei',
    '3c:47:11': 'Huawei',
    '3c:67:8c': 'Huawei',
    'c8:d1:5e': 'Xiaomi',
    'd4:97:0b': 'Xiaomi',
    'f0:b4:29': 'Xiaomi',
    'f8:a4:5f': 'Xiaomi',
    '00:24:54': 'Samsung',
    '08:08:c2': 'Samsung',
    '08:37:3d': 'Samsung',
    '08:d4:2b': 'Samsung',
    '0c:14:20': 'Samsung',
    '0c:71:5d': 'Samsung',
    '0c:89:10': 'Samsung',
    '10:1d:c0': 'Samsung',
    '10:30:47': 'Samsung',
    '10:d5:42': 'Samsung',
    '14:49:e0': 'Samsung',
    '14:89:fd': 'Samsung',
    '14:a3:64': 'Samsung',
    '18:16:c9': 'Samsung',
    '18:26:66': 'Samsung',
    '18:e2:c2': 'Samsung',
    '1c:62:b8': 'Samsung',
    '1c:66:aa': 'Samsung',
    '1c:af:05': 'Samsung',
    '20:13:e0': 'Samsung',
    '20:64:32': 'Samsung',
    '20:d3:90': 'Samsung',
    '20:d5:bf': 'Samsung',
    '24:4b:81': 'Samsung',
    '24:c6:96': 'Samsung',
    '28:98:7b': 'Samsung',
    '28:ba:b5': 'Samsung',
    '28:cc:01': 'Samsung',
    '2c:ae:2b': 'Samsung',
    '30:cd:a7': 'Samsung',
    '34:23:ba': 'Samsung',
    '34:c3:ac': 'Samsung',
    '38:01:97': 'Samsung',
    '38:16:d1': 'Samsung',
    '38:aa:3c': 'Samsung',
    '3c:5a:37': 'Samsung',
    '3c:62:00': 'Samsung',
    '3c:8b:fe': 'Samsung',
    '40:0e:85': 'Samsung',
    '44:4e:1a': 'Samsung',
    '44:f4:59': 'Samsung',
    '48:44:f7': 'Samsung',
    '48:49:c7': 'Samsung',
    '50:01:bb': 'Samsung',
    '50:f0:d3': 'Samsung',
    '54:9b:12': 'Samsung',
    '54:fa:3e': 'Samsung',
    '58:c3:8b': 'Samsung',
    '5c:2e:59': 'Samsung',
    '5c:3c:27': 'Samsung',
    '5c:aa:fd': 'Samsung',
    '60:6b:bd': 'Samsung',
    '60:8f:5c': 'Samsung',
    '60:a1:0a': 'Samsung',
    '60:d0:a9': 'Samsung',
    '64:1c:b0': 'Samsung',
    '64:77:91': 'Samsung',
    '64:b3:10': 'Samsung',
    '68:27:37': 'Samsung',
    '68:48:98': 'Samsung',
    '68:e7:c2': 'Samsung',
    '6c:f3:73': 'Samsung',
    '94:35:0a': 'Samsung',
    '98:52:b1': 'Samsung',
    '9c:e6:e7': 'Samsung',
    'a8:06:00': 'Samsung',
    'a8:16:d0': 'Samsung',
    'ac:5f:3e': 'Samsung',
    'ac:ee:9e': 'Samsung',
    'b0:df:3a': 'Samsung',
    'b0:ec:71': 'Samsung',
    'b4:07:f9': 'Samsung',
    'b8:5e:7b': 'Samsung',
    'bc:20:a4': 'Samsung',
    'bc:44:86': 'Samsung',
    'bc:54:51': 'Samsung',
    'bc:72:b1': 'Samsung',
    'bc:79:ad': 'Samsung',
    'c4:73:1e': 'Samsung',
    'c8:19:f7': 'Samsung',
    'cc:07:ab': 'Samsung',
    'cc:3a:61': 'Samsung',
    'd0:22:be': 'Samsung',
    'd0:59:e4': 'Samsung',
    'd0:66:7b': 'Samsung',
    'd4:87:d8': 'Samsung',
    'd4:88:90': 'Samsung',
    'd8:57:ef': 'Samsung',
    'd8:90:e8': 'Samsung',
    'dc:66:72': 'Samsung',
    'e4:12:1d': 'Samsung',
    'e4:40:e2': 'Samsung',
    'e4:7c:f9': 'Samsung',
    'e4:b0:21': 'Samsung',
    'e4:e0:c5': 'Samsung',
    'e8:03:9a': 'Samsung',
    'e8:4e:84': 'Samsung',
    'ec:1f:72': 'Samsung',
    'ec:9b:5b': 'Samsung',
    'f0:5a:09': 'Samsung',
    'f0:6b:ca': 'Samsung',
    'f0:72:8c': 'Samsung',
    'f0:e7:7e': 'Samsung',
    'f4:42:8f': 'Samsung',
    'f4:7b:5e': 'Samsung',
    'f4:9f:54': 'Samsung',
    '00:bb:3a': 'Amazon',
    '40:b4:cd': 'Amazon',
    '44:65:0d': 'Amazon',
    '74:75:48': 'Amazon',
    '74:c2:46': 'Amazon',
    '84:d6:d0': 'Amazon',
    'a0:02:dc': 'Amazon',
    'ac:63:be': 'Amazon',
    'b4:7c:9c': 'Amazon',
    'f0:27:2d': 'Amazon',
    'fc:65:de': 'Amazon',
    'fc:a6:67': 'Amazon'
}