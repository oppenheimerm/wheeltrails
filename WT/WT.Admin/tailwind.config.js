module.exports = {
    content: [
        "./**/*.razor"
    ],
    darkMode: 'class',
    theme: {
        extend: {
            animation: {
                rise: 'rise 2s ease-out forwards',
            },
            keyframes: {
                rise: {
                    '0%': { transform: 'translateY(100%)' },
                    '100%': { transform: 'translateY(0)' },
                },
            },
            colors: {
                // ✅ Material 3 Color System (NEW)
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

                // ✅ Keep your existing harp colors for backwards compatibility
                'harp': {
                    50: '#f4f9f4',
                    100: '#e5f0e5',
                    200: '#cfe3cf',
                    300: '#aacbab',
                    400: '#7cac7e',
                    500: '#5a8d5b',
                    600: '#467348',
                    700: '#395c3a',
                    800: '#314a31',
                    900: '#293e2a',
                    950: '#132014'
                },
                'wt-black': {
                    50: '#f6f6f6',
                    100: '#e7e7e7',
                    200: '#d1d1d1',
                    300: '#b0b0b0',
                    400: '#888888',
                    500: '#6d6d6d',
                    600: '#5d5d5d',
                    700: '#4f4f4f',
                    800: '#454545',
                    900: '#3d3d3d',
                    950: '#010101',
                }
            },
            fontFamily: {
                // Make Figtree the primary sans font for the site
                'sans': ['Figtree', 'Roboto', 'system-ui', 'sans-serif'],
                'figtree': ['Figtree', 'serif'],
                'playfair': ['Playfair Display', 'serif']
            }
        },
    },
    plugins: [],
}