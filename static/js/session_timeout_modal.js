function showSessionExpiredModal() {
    var modal = document.getElementById('session-expired-modal');
    modal.style.display = 'block';

    // Close the modal and redirect when the user clicks the close (x) button
    var closeButton = modal.querySelector('.close');
    closeButton.onclick = function() {
        modal.style.display = 'none';
        window.location.href = '/login';  // Adjust URL as per your routes
    }
}

// Function to check session status
function checkSession() {
    fetch('/check_session')
        .then(response => response.json())
        .then(data => {
            if (data.expired) {
                showSessionExpiredModal();
            }
        })
        .catch(error => {
            console.error('Error checking session status:', error);
        });
}

// Polling to check session status periodically
setInterval(checkSession, 60000);
