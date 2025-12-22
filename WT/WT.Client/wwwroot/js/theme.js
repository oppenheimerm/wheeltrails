// Dark Mode & Contrast Management
window.themeManager = {
    // Toggle dark mode
    toggleDarkMode: function () {
        const html = document.documentElement;
        const isDark = html.classList.toggle('dark');
        localStorage.setItem('theme-mode', isDark ? 'dark' : 'light');
        return isDark;
    },

    // Set contrast level (standard, medium, high)
    setContrast: function (level) {
        const html = document.documentElement;
        html.setAttribute('data-md-contrast', level);
        localStorage.setItem('theme-contrast', level);
    },

    // Toggle password visibility by element id. Returns the new state (true = visible/text).
    togglePasswordVisibility: function (elementId) {
        try {
            const el = document.getElementById(elementId);
            if (!el) return false;
            const isText = el.type === 'text';
            el.type = isText ? 'password' : 'text';
            return !isText;
        } catch (e) {
            console.error('togglePasswordVisibility error', e);
            return false;
        }
    },

    // Initialize theme from localStorage or system preference
    init: function () {
        const savedMode = localStorage.getItem('theme-mode');
        const savedContrast = localStorage.getItem('theme-contrast') || 'standard';
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        // Apply dark mode
        if (savedMode === 'dark' || (!savedMode && prefersDark)) {
            document.documentElement.classList.add('dark');
        }

        // Apply contrast level
        if (savedContrast !== 'standard') {
            document.documentElement.setAttribute('data-md-contrast', savedContrast);
        }
    }
};

// Auto-initialize on page load
themeManager.init();