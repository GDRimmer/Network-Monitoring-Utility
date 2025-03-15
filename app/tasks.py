from celery import shared_task
from datetime import datetime
import time
from flask import current_app

def get_db():
    """Get the database instance in the application context"""
    from app import db
    return db

@shared_task
def run_nmap_scan(scan_id):
    """
    Celery task to run an NMAP scan asynchronously
    
    Args:
        scan_id: ID of the scan record in the database
    """
    try:
        # Import here to avoid circular imports
        from app.models import Scan
        from app.scanner import NmapScanner, parse_scan_result
        
        # Get database
        db = get_db()
        
        # Get the scan record from database
        scan = Scan.query.get(scan_id)
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        
        # Update scan status
        scan.status = 'running'
        scan.task_id = run_nmap_scan.request.id
        db.session.commit()
        
        # Create and start scanner
        scanner = NmapScanner(scan.target, scan.scan_type, scan.arguments)
        scanner.start_scan()
        
        # Wait for scan to complete, with status updates
        while scanner.is_running():
            run_nmap_scan.update_state(state='PROGRESS', meta={'status': 'running'})
            time.sleep(5)
        
        # Get scan results
        result = scanner.get_result()
        if not result:
            scan.status = 'failed'
            scan.end_time = datetime.utcnow()
            db.session.commit()
            return {'status': 'error', 'message': 'Scan failed to produce results'}
        
        # Parse and store scan results
        parse_scan_result(scan, result)
        
        return {'status': 'completed', 'scan_id': scan_id}
    
    except Exception as e:
        # Handle exceptions
        db = get_db()
        if 'scan' in locals():
            scan.status = 'failed'
            scan.end_time = datetime.utcnow()
            db.session.commit()
        return {'status': 'error', 'message': str(e)}

@shared_task
def clean_up_stalled_scans():
    """
    Periodic task to clean up scans that may have stalled
    Marks scans as failed if they have been running for more than 2 hours
    """
    try:
        # Import here to avoid circular imports
        from app.models import Scan
        
        # Get database
        db = get_db()
        
        # Find all scans still marked as running or pending
        stalled_scans = Scan.query.filter(Scan.status.in_(['running', 'pending'])).all()
        now = datetime.utcnow()
        
        for scan in stalled_scans:
            # If scan has been running for more than 2 hours, mark as failed
            time_diff = now - scan.start_time
            if time_diff.total_seconds() > 7200:  # 2 hours in seconds
                scan.status = 'failed'
                scan.end_time = now
                scan.result_json = '{"error": "Scan timed out after 2 hours"}'
        
        db.session.commit()
        return {'status': 'success', 'cleaned_scans': len(stalled_scans)}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
