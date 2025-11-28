module.exports = {
    content: [
        "./**/*.razor",
        "./wwwroot/index.html"
    ],
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
                'harp': {
                    50: '#f4f9f4',//light mode bg option 1  
                    100: '#e5f0e5',//light mode bg option 2 - base color
                    200: '#cfe3cf',
                    300: '#aacbab',
                    400: '#7cac7e',
                    500: '#5a8d5b',
                    600: '#467348',
                    700: '#395c3a',
                    800: '#314a31',
                    900: '#293e2a', //dark mode bg option 1
                    950: '#132014'//dark mode bg option 2
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
                    950: '#010101',//base colour

                }
            },
        },
        fontFamily: {
            'playfair': ["Playfair Display", "serif"]
        }
    },
    plugins: [],
}