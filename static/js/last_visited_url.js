document.addEventListener("DOMContentLoaded", function() {
    console.log("DOMContentLoaded event fired");

    let currentUrl = window.location.href;
    console.log("Current URL:", currentUrl);

    // Get the CSRF token from the hidden input in the form
    let csrfToken = document.querySelector('input[name="csrf_token"]').value;
    console.log("CSRF token:", csrfToken);

    fetch('/visit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken // Include the CSRF token in the headers
        },
        body: JSON.stringify({
            url: currentUrl,
            csrf_token: csrfToken // Include the CSRF token in the request body
        })
    })
    .then(response => {
        console.log("Response status:", response.status);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log(`Visited: ${data.message}`);
        if (data.error) {
            console.error(data.error);
        } else {
            console.log(`Visit recorded: ${data.urls}`);
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});
