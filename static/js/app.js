/* BlindBit SSE — Global JS */

// Auto-dismiss alerts after 4 seconds
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.alert').forEach(a => {
        setTimeout(() => {
            a.style.opacity = '0';
            a.style.transform = 'translateY(-10px)';
            setTimeout(() => a.remove(), 300);
        }, 4000);
    });

    const logoutForm = document.getElementById('logout-form');
    if (logoutForm) {
        logoutForm.addEventListener('submit', (event) => {
            const shouldSignOut = window.confirm('Are you sure you want to sign out?');
            if (!shouldSignOut) {
                event.preventDefault();
            }
        });
    }

    const recoverySavedLink = document.getElementById('recovery-saved-link');
    if (recoverySavedLink) {
        recoverySavedLink.addEventListener('click', (event) => {
            const confirmed = window.confirm(
                'Please confirm: have you downloaded and safely stored your recovery codes? These codes may be required to regain access.'
            );
            if (!confirmed) {
                event.preventDefault();
            }
        });
    }
});
