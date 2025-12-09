// Modal utility functions for Terms and Conditions
window.modalHelper = {
    showModal: function (modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
            modal.setAttribute('aria-hidden', 'false');
            document.body.style.overflow = 'hidden'; // Prevent body scroll when modal is open
            
            // Add smooth fade-in animation
            setTimeout(() => {
                modal.classList.add('opacity-100');
            }, 10);
        }
    },

    hideModal: function (modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
            modal.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = ''; // Restore body scroll
            modal.classList.remove('opacity-100');
        }
    }
};