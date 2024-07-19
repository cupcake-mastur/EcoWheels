let formType = '';

    function showPasswordModal(type) {
        formType = type;
        $('#passwordModal').modal('show');
    }

    $('#passwordForm').on('submit', function(event) {
        event.preventDefault();
        const currentPassword = $('#current_pass_modal').val();
        if (currentPassword && formType) {
            const form = $(`form[data-form-type=${formType}]`);
            $('<input>').attr({
                type: 'hidden',
                name: 'current_password',
                value: currentPassword
            }).appendTo(form);
            form.submit();
        }
    });

    $(document).ready(function () {
        $('#myTab a').on('click', function (e) {
            e.preventDefault();
            $(this).tab('show');
        });
    });

document.addEventListener('DOMContentLoaded', function() {
    var policyModal = document.getElementById("policyModal");
    var policyLink = document.getElementById("policyLink");
    var closeButton = document.querySelector("#policyModal .close");

    policyLink.onclick = function(event) {
        event.preventDefault();
        policyModal.style.display = "flex"; // Show modal
    }

    closeButton.addEventListener("click", function() {
        policyModal.style.display = "none";  // Hide the modal
    });

    window.addEventListener("click", function(event) {
        if (event.target === policyModal) {
            policyModal.style.display = "none";  // Hide the modal
        }
    });
});
