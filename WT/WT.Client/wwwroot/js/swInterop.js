// JS interop for service worker update detection and activation
window.wtSwInterop = {
    addServiceWorkerUpdateListener: function (dotNetRef) {
        console.log('[wtSwInterop] addServiceWorkerUpdateListener called');
        if (!('serviceWorker' in navigator)) {
            console.warn('[wtSwInterop] Service Worker not supported');
            return;
        }

        // Helper to check registration and notify if waiting
        function checkRegistrationAndNotify() {
            return navigator.serviceWorker.getRegistration().then(function (reg) {
                if (!reg) {
                    console.log('[wtSwInterop] no registration found');
                    return false;
                }
                console.log('[wtSwInterop] registration found', reg);

                // If there's already a waiting worker, notify immediately
                if (reg.waiting) {
                    console.log('[wtSwInterop] worker waiting -> notify .NET');
                    try { dotNetRef.invokeMethodAsync('NotifyUpdateAvailable'); } catch (e) { console.error(e); }
                    return true;
                }

                // Listen for updatefound (new installing worker)
                reg.addEventListener('updatefound', function () {
                    console.log('[wtSwInterop] updatefound event');
                    const newWorker = reg.installing;
                    if (!newWorker) return;
                    newWorker.addEventListener('statechange', function () {
                        console.log('[wtSwInterop] newWorker state:', newWorker.state);
                        if (newWorker.state === 'installed' && reg.waiting) {
                            console.log('[wtSwInterop] new worker installed and waiting -> notify .NET');
                            try { dotNetRef.invokeMethodAsync('NotifyUpdateAvailable'); } catch (e) { console.error(e); }
                        }
                    });
                });
                return false;
            }).catch(function (err) { console.warn('wtSwInterop getRegistration failed', err); return false; });
        }

        // Try immediate check, then poll a few times (handles timing races)
        checkRegistrationAndNotify().then(function(found){
            if (found) return;
            // Poll up to6 times with1s interval
            let attempts =0;
            const maxAttempts =6;
            const timer = setInterval(() => {
                attempts++;
                checkRegistrationAndNotify().then(foundNow => {
                    if (foundNow || attempts >= maxAttempts) {
                        clearInterval(timer);
                    }
                });
            },1000);
        });
    },

    skipWaitingAndReload: function () {
        console.log('[wtSwInterop] skipWaitingAndReload called');
        if (!('serviceWorker' in navigator)) return;
        navigator.serviceWorker.getRegistration().then(function (reg) {
            if (!reg || !reg.waiting) {
                console.log('[wtSwInterop] no waiting worker to skipWaiting');
                return;
            }

            // Listen for controllerchange and reload when it happens
            function onControllerChange() {
                console.log('[wtSwInterop] controllerchange detected, reloading');
                window.location.reload();
            }

            navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);

            // Send the message to instruct the waiting worker to skip waiting
            try {
                reg.waiting.postMessage('SKIP_WAITING');
            } catch (e) {
                console.error('Failed to post message to waiting service worker', e);
            }
        }).catch(function(err){ console.error('getRegistration failed', err); });
    }
};
