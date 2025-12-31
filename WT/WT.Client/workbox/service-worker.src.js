/* Workbox service worker template (uses Workbox CDN globals)
 This file will be processed by workbox injectManifest which will replace
 self.__WB_MANIFEST with the list of files to precache.
*/

// Use Workbox CDN (no bundler). When injected, precache manifest will be available.
importScripts('https://storage.googleapis.com/workbox-cdn/releases/6.5.4/workbox-sw.js');

// Ensure workbox is available
if (typeof workbox === 'undefined') {
    console.error('Workbox failed to load.');
} else {
    // Precaching placeholder - workbox injectManifest will replace this single token
    workbox.precaching.precacheAndRoute(self.__WB_MANIFEST);

    // Navigation: network-first for SPA
    workbox.routing.registerRoute(
        ({ request }) => request.mode === 'navigate',
        new workbox.strategies.NetworkFirst({
            cacheName: 'wt-runtime-navigation',
            plugins: [new workbox.expiration.ExpirationPlugin({ maxEntries: 50 })]
        })
    );

    // API: network-first
    workbox.routing.registerRoute(
        ({ url }) => url.pathname.startsWith('/api/'),
        new workbox.strategies.NetworkFirst({
            cacheName: 'wt-runtime-api',
            networkTimeoutSeconds: 5
        })
    );

    // Images: cache-first with expiration
    workbox.routing.registerRoute(
        ({ request }) => request.destination === 'image',
        new workbox.strategies.CacheFirst({
            cacheName: 'wt-images',
            plugins: [new workbox.expiration.ExpirationPlugin({ maxEntries: 100, maxAgeSeconds: 30 * 24 * 60 * 60 })]
        })
    );
}
