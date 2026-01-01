/*
When using Workbox in injectManifest mode without bundling, you must manually import 
the Workbox runtime library at the top of your service worker.
Otherwise, the browser has no idea what workbox refers to.
 */
importScripts('https://storage.googleapis.com/workbox-cdn/releases/6.5.4/workbox-sw.js');

self.skipWaiting();
workbox.core.clientsClaim();

// Precache manifest injected by Workbox
workbox.precaching.precacheAndRoute([{"revision":"34f608b809dfa9fef5efcbcc25ca0109","url":"manifest.json"},{"revision":"435ab12f532c62e2a20cc79128588c70","url":"index.html"},{"revision":"acc23e1f035b250c39fa0c38e4155709","url":"icon-96.png"},{"revision":"7b0bed15acfbee64f06eadb5f7af4ef4","url":"icon-72.png"},{"revision":"3750ab6d80cb43fa6c8f506c4f6a287f","url":"icon-512.png"},{"revision":"450bf4cee5dd9e0c2a9774a8716a7190","url":"icon-512-maskable.png"},{"revision":"34942b9414f6c08ab4f17dc4eddf9dcf","url":"icon-384.png"},{"revision":"3b5a93a9ffa0913cc9b3ad99651b331c","url":"icon-256.png"},{"revision":"5cc7bdd5607e3d997e3b53196d0cc574","url":"icon-192.png"},{"revision":"8126472dd8f006e46ca70d8c955bc5d5","url":"icon-192-maskable.png"},{"revision":"48f73c8b4bc755c1454814b14ba6d591","url":"icon-152.png"},{"revision":"ddfb3c3ad8eec5913b6a8cc7bbadd107","url":"icon-144.png"},{"revision":"f75abe764facf8f5ee24bb79a9685b7e","url":"icon-128.png"},{"revision":"eab4f24ab5ff80be586dcdab8e87dc9c","url":"favicon.png"},{"revision":"fefaeec6ddf8d22321e2fe6a589f34d1","url":"appsettings.json"},{"revision":"cf25c6403bf7de9c49838804f28e2ac9","url":"appsettings.Development.json"},{"revision":"fee50fa5c1dd9bae58d08442e9954fd4","url":"sample-data/weather.json"},{"revision":"3cfceb68a23416bd6f61467961a3e2b3","url":"js/trailRecorder.js"},{"revision":"239107ed14cedf2604e478b6b04e94e0","url":"js/theme.js"},{"revision":"c9aa4024c16945ea1be11e49d224800a","url":"js/modal.js"},{"revision":"37818f9bb5d871f1d148a58ad9d78bc6","url":"js/fabInterop.js"},{"revision":"e8326633556267d18cfdfb9cac8a3e26","url":"img/assets/logo-light.png"},{"revision":"aaae543d097b8438f525602379436191","url":"img/assets/logo-dark.png"},{"revision":"2919cb41225a054e4b42557ecf5b8aa3","url":"css/tailwind.css"},{"revision":"61f4f28152ba12eb87baf62b20c567d3","url":"css/input.css"},{"revision":"b81345d94f5f11e4b527f8f8f992e86f","url":"css/app.css"},{"revision":"cca6db5a694579411abc05f24df60482","url":"css/material-theme/theme.css"},{"revision":"fcc6afb8acba07c45f15fdaaf58588cd","url":"css/material-theme/light.css"},{"revision":"a04a3b10be1104d7de169f2f8cfaba20","url":"css/material-theme/light-mc.css"},{"revision":"2ab0a55f5f1fc9192a0f65ff6384796d","url":"css/material-theme/light-hc.css"},{"revision":"d01e7ceff7cdb2cfc4022ac9cf062a05","url":"css/material-theme/dark.css"},{"revision":"6d4bde9dc348de2e050c5b6a2b08a166","url":"css/material-theme/dark-mc.css"},{"revision":"a33c00c59b9b3082fc9ca2a568602865","url":"css/material-theme/dark-hc.css"}]);

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