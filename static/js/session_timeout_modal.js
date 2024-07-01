function showSessionExpiredModal() {
    var modal = document.getElementById('session-expired-modal');
    modal.style.display = 'block';

    var closeButton = modal.querySelector('.close');
    closeButton.onclick = function() {
        modal.style.display = 'none';
        window.location.href = '/login';
    }
}

function checkSession() {
    fetch('/check_session', {
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Check-Session': 'True'
        }
    })
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
