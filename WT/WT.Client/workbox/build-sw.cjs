const { generateSW } = require('workbox-build');
const path = require('path');

(async () => {
    try {
        // Allow overriding target publish directory via --publishDir or PUBLISH_DIR env var
        const args = process.argv.slice(2);
        let publishDirArgIndex = args.findIndex(a => a === '--publishDir');
        let publishDir = process.env.PUBLISH_DIR || null;
        if (publishDirArgIndex >= 0 && args.length > publishDirArgIndex + 1) {
            publishDir = args[publishDirArgIndex + 1];
        }

        const root = path.resolve(__dirname, '..'); // WT.Client

        let targetWWWRoot;
        if (publishDir) {
            // If a publish output folder was provided, expect it to contain a wwwroot subfolder
            targetWWWRoot = path.isAbsolute(publishDir) ? path.join(publishDir, 'wwwroot') : path.join(path.resolve(publishDir), 'wwwroot');
        } else {
            // Default to the project's wwwroot (useful for local dev)
            targetWWWRoot = path.join(root, 'wwwroot');
        }

        const swDest = path.join(targetWWWRoot, 'service-worker.published.js');
        const globDirectory = targetWWWRoot;

        console.log('generateSW with:');
        console.log({ swDest, globDirectory });

        const result = await generateSW({
            swDest,
            globDirectory,
            globPatterns: ['**/*.{html,js,css,png,svg,wasm,woff2,woff,eot,ttf,dll}'],
            globIgnores: ['service-worker.published.js'],
            maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
            runtimeCaching: [
                // API routes: network-first with short TTL and small cache size
                {
                    urlPattern: /\/api\//,
                    handler: 'NetworkFirst',
                    options: {
                        cacheName: 'wt-runtime-api',
                        networkTimeoutSeconds: 3,
                        expiration: { maxEntries: 50, maxAgeSeconds: 5 * 60 }, //5 minutes
                        cacheableResponse: { statuses: [0, 200] }
                    }
                },
                // Images: cache-first with expiration limits
                {
                    urlPattern: /\.(?:png|jpg|jpeg|svg|gif)$/,
                    handler: 'CacheFirst',
                    options: {
                        cacheName: 'wt-images',
                        expiration: { maxEntries: 100, maxAgeSeconds: 30 * 24 * 60 * 60 }, //30 days
                        cacheableResponse: { statuses: [0, 200] }
                    }
                },
                // Framework files: stale-while-revalidate for fast boot and updates
                {
                    urlPattern: /\/_framework\//,
                    handler: 'StaleWhileRevalidate',
                    options: { cacheName: 'wt-framework', cacheableResponse: { statuses: [0, 200] } }
                },
                // Google Maps (external) - network-first with short timeout (will be ignored by scope if cross-origin), keep small cache
                {
                    urlPattern: /https:\/\/maps\.googleapis\.com|https:\/\/maps\.gstatic\.com/,
                    handler: 'NetworkFirst',
                    options: {
                        cacheName: 'wt-google-maps',
                        networkTimeoutSeconds: 3,
                        expiration: { maxEntries: 50, maxAgeSeconds: 24 * 60 * 60 }, //1 day
                        cacheableResponse: { statuses: [0, 200] }
                    }
                }
            ]
        });

        console.log(`Generated ${swDest}, which will precache ${result.count} files, totaling ${result.size} bytes.`);
    } catch (err) {
        console.error('Workbox generateSW failed:', err);
        process.exitCode = 1;
    }
})();
