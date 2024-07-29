document.addEventListener("DOMContentLoaded", function() {
    let currentUrl = window.location.href;

    // Check if the CSRF token element exists
    let csrfTokenElement = document.querySelector('input[name="csrf_token"]');
    let csrfToken = csrfTokenElement ? csrfTokenElement.value : null;

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
    });
});
