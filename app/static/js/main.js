// SecureHide Main JavaScript

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add fade-out to alert messages
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    });

    // Dynamic file input label update
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'No file chosen';
            const label = input.nextElementSibling;
            if (label && label.classList.contains('form-file-label')) {
                label.textContent = fileName;
            }
        });
    });
    
    // Password visibility toggle functionality
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const passwordField = document.querySelector(this.getAttribute('data-target'));
            if (passwordField) {
                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    this.innerHTML = '<i class="fas fa-eye-slash"></i>';
                } else {
                    passwordField.type = 'password';
                    this.innerHTML = '<i class="fas fa-eye"></i>';
                }
            }
        });
    });
    
    // Media type detection for file uploads
    const mediaFileInputs = document.querySelectorAll('.media-file-input');
    mediaFileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const fileName = this.value.toLowerCase();
            const mediaTypeIndicator = document.getElementById(this.getAttribute('data-indicator'));
            
            if (mediaTypeIndicator) {
                if (fileName.match(/\.(jpg|jpeg|png|gif|bmp)$/)) {
                    mediaTypeIndicator.textContent = 'Image';
                    mediaTypeIndicator.className = 'badge bg-primary';
                } else if (fileName.match(/\.(wav|mp3)$/)) {
                    mediaTypeIndicator.textContent = 'Audio';
                    mediaTypeIndicator.className = 'badge bg-success';
                } else if (fileName.match(/\.(mp4|avi|mov)$/)) {
                    mediaTypeIndicator.textContent = 'Video';
                    mediaTypeIndicator.className = 'badge bg-danger';
                } else {
                    mediaTypeIndicator.textContent = 'Unknown';
                    mediaTypeIndicator.className = 'badge bg-secondary';
                }
            }
            
            // Check file size
            if (this.files[0]) {
                const fileSize = this.files[0].size / 1024 / 1024; // Convert to MB
                if (fileSize > 16) { // Limit to 16MB
                    alert('File size exceeds the 16MB limit. Please choose a smaller file.');
                    this.value = ''; // Clear the input
                }
            }
        });
    });
    
    // Text area character count
    const messageTextareas = document.querySelectorAll('.message-textarea');
    messageTextareas.forEach(textarea => {
        const counterElement = document.getElementById(textarea.getAttribute('data-counter'));
        if (counterElement) {
            textarea.addEventListener('input', function() {
                const currentLength = this.value.length;
                counterElement.textContent = `${currentLength} characters`;
            });
        }
    });
    
    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
});