// Dark Mode Toggle Functionality

document.addEventListener('DOMContentLoaded', function() {
    // Get theme toggle checkbox and icon elements
    const toggleSwitch = document.getElementById('theme-switch');
    
    // Check for saved theme preference or use prefer-color-scheme
    const currentTheme = localStorage.getItem('theme') || 
                          (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    
    // Apply the theme when the page loads
    document.documentElement.setAttribute('data-theme', currentTheme);
    
    // Update the toggle switch if dark mode is active
    if (currentTheme === 'dark') {
        toggleSwitch.checked = true;
    }
    
    // Function to switch themes
    function switchTheme(e) {
        if (e.target.checked) {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
        } else {
            document.documentElement.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
        }
    }
    
    // Event listener for theme switch
    toggleSwitch.addEventListener('change', switchTheme);
});