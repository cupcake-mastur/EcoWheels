$(document).ready(function() {
    var lastVisitedUrl = window.location.href;  // Capture the current URL

    $('a.nav-link').on('click', function(event) {
        event.preventDefault();  // Prevent default action to ensure AJAX completes before navigation
        var targetUrl = $(this).attr('href');  // Get the target URL of the link

        $.ajax({
            type: 'POST',
            url: '/update_last_visited_url',
            data: {'last_visited_url': lastVisitedUrl},
            success: function(response) {
                console.log('Last visited URL updated successfully.');
                window.location.href = targetUrl;  // Proceed to the target URL
            },
            error: function(error) {
                console.error('Error updating last visited URL:', error);
                window.location.href = targetUrl;  // Proceed to the target URL even if AJAX fails
            }
        });
    });
});
