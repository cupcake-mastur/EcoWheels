$(document).ready(function() {
  function checkSession() {
    $.ajax({
      type: 'GET',
      url: '/check_session',
      dataType: 'json',
      success: function(data) {
        if (data.expired) {
          $('#sessionExpiredModal').modal('show');
        }
      },
      error: function(xhr, status, error) {
        console.error('Error checking session:', error);
      }
    });
  }

  // Set the interval to check the session status every 10 seconds
  setInterval(checkSession, 10000);
});
