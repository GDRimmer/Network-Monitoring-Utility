// Main JavaScript for NMAP Scanner App

document.addEventListener('DOMContentLoaded', function() {
    // Auto-close alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const closeButton = alert.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });

    // Handle custom NMAP arguments visibility
    const scanTypeSelect = document.getElementById('scan_type');
    const customArgsContainer = document.getElementById('custom-args-container');
    
    if (scanTypeSelect && customArgsContainer) {
        scanTypeSelect.addEventListener('change', function() {
            if (this.value === 'custom') {
                customArgsContainer.style.display = 'block';
            } else {
                customArgsContainer.style.display = 'none';
            }
        });
        
        // Set initial state
        if (scanTypeSelect.value === 'custom') {
            customArgsContainer.style.display = 'block';
        } else {
            customArgsContainer.style.display = 'none';
        }
    }

    // File upload name display
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name;
            const fileLabel = this.nextElementSibling;
            if (fileLabel && fileName) {
                fileLabel.textContent = fileName;
            }
        });
    }

    // Add search functionality to tables
    const searchInput = document.getElementById('table-search');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const tableId = this.getAttribute('data-table');
            const table = document.getElementById(tableId);
            
            if (table) {
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(function(row) {
                    const text = row.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            }
        });
    }

    // Form validation for IP input
    const ipInput = document.getElementById('target');
    if (ipInput) {
        ipInput.addEventListener('blur', function() {
            const ipValue = this.value.trim();
            const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
            
            if (ipValue && !ipPattern.test(ipValue)) {
                this.classList.add('is-invalid');
                
                // Create or update feedback message
                let feedback = this.nextElementSibling;
                if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                    feedback = document.createElement('div');
                    feedback.classList.add('invalid-feedback', 'd-block');
                    this.parentNode.insertBefore(feedback, this.nextSibling);
                }
                feedback.textContent = 'Please enter a valid IP address, CIDR range, or IP range.';
            } else {
                this.classList.remove('is-invalid');
                
                // Remove feedback if it exists
                const feedback = this.nextElementSibling;
                if (feedback && feedback.classList.contains('invalid-feedback')) {
                    feedback.remove();
                }
            }
        });
    }
    
    // Enable tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Function to confirm scan abort
function confirmStopScan() {
    return confirm('Are you sure you want to stop this scan? This action cannot be undone.');
}

// Function to format time duration
function formatDuration(seconds) {
    if (seconds < 60) {
        return seconds.toFixed(2) + ' seconds';
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return minutes + ' min ' + remainingSeconds.toFixed(0) + ' sec';
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return hours + ' hr ' + minutes + ' min';
    }
}

/**
 * Functions for packet capture operations
 */
document.addEventListener('DOMContentLoaded', function() {
    // Format packet capture duration
    function formatDuration(seconds) {
        if (!seconds) return "0s";
        
        const hrs = Math.floor(seconds / 3600);
        seconds %= 3600;
        const mins = Math.floor(seconds / 60);
        seconds = Math.floor(seconds % 60);
        
        let result = "";
        if (hrs > 0) result += `${hrs}h `;
        if (mins > 0) result += `${mins}m `;
        result += `${seconds}s`;
        
        return result;
    }
    
    // Auto-refresh capture table
    function refreshCaptureStatus() {
        const statusCells = document.querySelectorAll('.capture-status');
        if (statusCells.length === 0) return;
        
        statusCells.forEach(cell => {
            const captureId = cell.dataset.captureId;
            if (!captureId) return;
            
            fetch(`/capture_status/${captureId}`)
                .then(response => response.json())
                .then(data => {
                    // Update status badge
                    const statusBadge = cell.querySelector('.badge');
                    if (statusBadge) {
                        statusBadge.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
                        
                        // Update badge class
                        statusBadge.className = 'badge';
                        if (data.status === 'completed') {
                            statusBadge.classList.add('bg-success');
                        } else if (data.status === 'running') {
                            statusBadge.classList.add('bg-primary');
                        } else if (data.status === 'failed') {
                            statusBadge.classList.add('bg-danger');
                        } else if (data.status === 'stopped') {
                            statusBadge.classList.add('bg-warning');
                        } else {
                            statusBadge.classList.add('bg-secondary');
                        }
                    }
                    
                    // Update duration cell if it exists
                    const durationCell = document.querySelector(`.capture-duration[data-capture-id="${captureId}"]`);
                    if (durationCell && data.duration) {
                        durationCell.textContent = formatDuration(data.duration);
                    }
                    
                    // Update action buttons if status changed
                    const actionCell = document.querySelector(`.capture-actions[data-capture-id="${captureId}"]`);
                    if (actionCell) {
                        // Show/hide stop button based on status
                        const stopButton = actionCell.querySelector('.btn-warning');
                        if (stopButton) {
                            stopButton.style.display = data.status === 'running' ? 'inline-block' : 'none';
                        }
                        
                        // Show/hide download button based on status
                        const downloadButton = actionCell.querySelector('.btn-success');
                        if (downloadButton) {
                            downloadButton.style.display = 
                                (data.status === 'completed' || data.status === 'stopped') ? 'inline-block' : 'none';
                        }
                    }
                })
                .catch(error => {
                    console.error(`Error updating capture status for ID ${captureId}:`, error);
                });
        });
    }
    
    // Check if we're on the captures page
    if (document.querySelector('#captures-table')) {
        // Initial refresh
        refreshCaptureStatus();
        
        // Set up interval for refreshing status
        setInterval(refreshCaptureStatus, 5000);
    }
    
    // Interface selection form handler
    const interfaceSelect = document.getElementById('interface');
    const protocolSelect = document.getElementById('protocol');
    const portInput = document.getElementById('port');
    const hostInput = document.getElementById('host');
    const captureForm = document.getElementById('capture-form');
    
    if (captureForm) {
        captureForm.addEventListener('submit', function(e) {
            // Validate that at least interface is selected
            if (!interfaceSelect.value) {
                e.preventDefault();
                alert('Please select a network interface');
                return false;
            }
            
            // If port is specified, validate it's in range
            if (portInput.value) {
                const port = parseInt(portInput.value, 10);
                if (isNaN(port) || port < 0 || port > 65535) {
                    e.preventDefault();
                    alert('Port must be between 0 and 65535');
                    return false;
                }
            }
            
            // If host is specified, validate it looks like an IP address
            if (hostInput.value) {
                const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
                if (!ipPattern.test(hostInput.value)) {
                    e.preventDefault();
                    alert('Please enter a valid IP address');
                    return false;
                }
            }
            
            return true;
        });
    }
});
