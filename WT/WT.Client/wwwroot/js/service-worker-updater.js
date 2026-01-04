window.wheelyTrailsSW = {
    register: function (dotnetRef) {
        if (!('serviceWorker' in navigator)) {
            return;
        }

        navigator.serviceWorker.register('service-worker.published.js')
            .then(reg => {
                // Fired when a new service worker is found
                reg.onupdatefound = () => {
                    const newWorker = reg.installing;

                    newWorker.onstatechange = () => {
                        if (newWorker.state === 'installed') {
                            // If there's an existing controller, this is an update
                            if (navigator.serviceWorker.controller) {
                                dotnetRef.invokeMethodAsync('NotifyUpdateAvailable');
                            }
                        }
                    };
                };
            });
    },

    // Called by Blazor when user clicks "Update"
    applyUpdate: function () {
        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ action: 'skipWaiting' });
        }
        window.location.reload();
    }
};