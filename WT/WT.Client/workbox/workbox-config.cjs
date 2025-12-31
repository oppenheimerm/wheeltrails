module.exports = {
    swSrc: 'workbox/service-worker.src.js',
    swDest: 'wwwroot/service-worker.published.js',
    globDirectory: 'wwwroot',
    globPatterns: [
        '**/*.{html,js,css,png,svg,wasm,woff2,woff,eot,ttf,dll}'
    ],
    // avoid accidentally precaching the generated sw
    globIgnores: [
        'service-worker.published.js'
    ],
    maximumFileSizeToCacheInBytes: 5 * 1024 * 1024 //5MB
};
