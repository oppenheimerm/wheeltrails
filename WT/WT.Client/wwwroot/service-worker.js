// Minimal development service worker — avoids published precache and AOT wasm references.
// Purpose: allow local registration during development without failing on missing publish-only assets.
self.addEventListener('install', (event) => {
 // Activate immediately
 self.skipWaiting();
});

self.addEventListener('activate', (event) => {
 // Take control of uncontrolled clients as soon as possible
 event.waitUntil(self.clients.claim());
});

// Simple network-first fetch handler with a cache fallback for offline
self.addEventListener('fetch', (event) => {
 // Ignore non-GET requests
 if (event.request.method !== 'GET') return;

 // For navigation requests, prefer network but fallback to cache if offline
 if (event.request.mode === 'navigate') {
 event.respondWith(
 fetch(event.request).catch(() => caches.match('offline-fallback') )
 );
 return;
 }

 // For other requests, attempt network then fallback to cache
 event.respondWith(
 fetch(event.request).then((response) => {
 return response;
 }).catch(() => caches.match(event.request))
 );
});

// Note: This dev worker intentionally does NOT perform precaching of the
// production/_framework assets. For full PWA precaching, build/publish the
// client and register the generated `service-worker.published.js` instead.
