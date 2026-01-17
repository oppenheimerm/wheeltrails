window.offlineInterop = (() => {
    const listeners = new Map();

    // More reliable than navigator.onLine - actually try to fetch something
    async function checkOnline() {
        // If navigator says offline, trust it (saves a request)
        if (!navigator.onLine) return false;
        
        // Otherwise verify with a small fetch
        try {
            // Use a tiny endpoint or external resource; HEAD to minimize payload
            const response = await fetch('/favicon.png', { 
                method: 'HEAD', 
                cache: 'no-store',
                mode: 'same-origin'
            });
            return response.ok;
        } catch {
            return false;
        }
    }

    function isOnline() {
        // Synchronous check - falls back to navigator.onLine
        return navigator.onLine;
    }

    async function isOnlineAsync() {
        return await checkOnline();
    }

    function registerStatusChanged(dotnetRef) {
        if (!dotnetRef) return;

        const onOnline = () => dotnetRef.invokeMethodAsync('UpdateOnlineStatus', true).catch(() => {});
        const onOffline = () => dotnetRef.invokeMethodAsync('UpdateOnlineStatus', false).catch(() => {});

        window.addEventListener('online', onOnline);
        window.addEventListener('offline', onOffline);

        listeners.set(dotnetRef, { onOnline, onOffline });

        // Immediately notify .NET of current status using async check
        checkOnline().then(online => {
            dotnetRef.invokeMethodAsync('UpdateOnlineStatus', online).catch(() => {});
        });
    }

    function unregisterStatusChanged(dotnetRef) {
        const entry = listeners.get(dotnetRef);
        if (!entry) return;
        try {
            window.removeEventListener('online', entry.onOnline);
            window.removeEventListener('offline', entry.onOffline);
        } catch (e) {}
        listeners.delete(dotnetRef);
    }

    return { isOnline, isOnlineAsync, registerStatusChanged, unregisterStatusChanged };
})();