module.exports = {
    content: [
        "./**/*.razor",
        "./wwwroot/index.html"
    ],
    darkMode: 'class', // Enable dark mode with .dark class
    theme: {
        extend: {
            colors: {
                // Material 3 Color System - Uses CSS Variables
                'md-primary': 'var(--md-sys-color-primary)',
                'md-on-primary': 'var(--md-sys-color-on-primary)',
                'md-primary-container': 'var(--md-sys-color-primary-container)',
                'md-on-primary-container': 'var(--md-sys-color-on-primary-container)',
                
                'md-secondary': 'var(--md-sys-color-secondary)',
                'md-on-secondary': 'var(--md-sys-color-on-secondary)',
                'md-secondary-container': 'var(--md-sys-color-secondary-container)',
                'md-on-secondary-container': 'var(--md-sys-color-on-secondary-container)',
                
                'md-tertiary': 'var(--md-sys-color-tertiary)',
                'md-on-tertiary': 'var(--md-sys-color-on-tertiary)',
                'md-tertiary-container': 'var(--md-sys-color-tertiary-container)',
                'md-on-tertiary-container': 'var(--md-sys-color-on-tertiary-container)',
                
                'md-error': 'var(--md-sys-color-error)',
                'md-on-error': 'var(--md-sys-color-on-error)',
                'md-error-container': 'var(--md-sys-color-error-container)',
                'md-on-error-container': 'var(--md-sys-color-on-error-container)',
                
                'md-background': 'var(--md-sys-color-background)',
                'md-on-background': 'var(--md-sys-color-on-background)',
                
                'md-surface': 'var(--md-sys-color-surface)',
                'md-on-surface': 'var(--md-sys-color-on-surface)',
                'md-surface-variant': 'var(--md-sys-color-surface-variant)',
                'md-on-surface-variant': 'var(--md-sys-color-on-surface-variant)',
                
                'md-outline': 'var(--md-sys-color-outline)',
                'md-outline-variant': 'var(--md-sys-color-outline-variant)',
                
                'md-shadow': 'var(--md-sys-color-shadow)',
                'md-scrim': 'var(--md-sys-color-scrim)',
                
                'md-inverse-surface': 'var(--md-sys-color-inverse-surface)',
                'md-inverse-on-surface': 'var(--md-sys-color-inverse-on-surface)',
                'md-inverse-primary': 'var(--md-sys-color-inverse-primary)',
                
                // Surface container levels
                'md-surface-dim': 'var(--md-sys-color-surface-dim)',
                'md-surface-bright': 'var(--md-sys-color-surface-bright)',
                'md-surface-container-lowest': 'var(--md-sys-color-surface-container-lowest)',
                'md-surface-container-low': 'var(--md-sys-color-surface-container-low)',
                'md-surface-container': 'var(--md-sys-color-surface-container)',
                'md-surface-container-high': 'var(--md-sys-color-surface-container-high)',
                'md-surface-container-highest': 'var(--md-sys-color-surface-container-highest)',
            },
            fontFamily: {
                'sans': ['Roboto', 'system-ui', 'sans-serif'],
            },
        },
    },
    plugins: [],
}