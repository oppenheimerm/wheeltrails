/*
When using Workbox in injectManifest mode without bundling, you must manually import 
the Workbox runtime library at the top of your service worker.
Otherwise, the browser has no idea what workbox refers to.
 */
importScripts('https://storage.googleapis.com/workbox-cdn/releases/6.5.4/workbox-sw.js');

self.skipWaiting();
workbox.core.clientsClaim();

// Precache manifest injected by Workbox
workbox.precaching.precacheAndRoute(self.__WB_MANIFEST);

// ⭐ Modern navigation fallback for Workbox v6+
workbox.routing.registerRoute(
    ({ request }) => request.mode === 'navigate',
    workbox.precaching.createHandlerBoundToURL('index.html')
);

// ⭐ Offline fallback page (offline.html)
workbox.routing.setCatchHandler(({ event }) => {
    if (event.request.mode === 'navigate') {
        return workbox.precaching.matchPrecache('offline.html');
    }
    return Response.error();
});



// Runtime caching for API calls
workbox.routing.registerRoute(
    ({ url }) => url.pathname.startsWith('/api'),
    new workbox.strategies.StaleWhileRevalidate()
);


/*
Workbox’s "Workbox’s injectManifest"  does not bundle your imports.
It expects you to bundle your service worker before running.

In other words: 
    "service-worker-src.js" can use imports
    "service-worker.published.js" must not contain imports 
In other words:
• 	 can use imports
• 	 must not contain imports

We must use Workbox without ES module imports, we will use Workbox’s 
global build instead of ES module imports. That means:
    No import statements
   Use workbox.* globals instead
This avoids bundling entirely and works perfectly with Blazor.


*/