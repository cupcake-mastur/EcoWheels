document.addEventListener("DOMContentLoaded", function() {
    console.log("DOMContentLoaded event fired");

    let currentUrl = window.location.href;
    console.log("Current URL:", currentUrl);

    // Check if the CSRF token element exists
    let csrfTokenElement = document.querySelector('input[name="csrf_token"]');
    let csrfToken = csrfTokenElement ? csrfTokenElement.value : null;
    console.log("CSRF token:", csrfToken);

    // Create the headers object
    let headers = {
        'Content-Type': 'application/json'
    };

    // Add the CSRF token to headers if it exists
    if (csrfToken) {
        headers['X-CSRFToken'] = csrfToken;
    }

    fetch('/visit', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({
            url: currentUrl,
            csrf_token: csrfToken // Include the CSRF token in the request body if it exists
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
