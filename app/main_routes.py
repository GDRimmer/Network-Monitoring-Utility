# These routes should be added to main.py
# Make sure to import subprocess at the top of the file

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
