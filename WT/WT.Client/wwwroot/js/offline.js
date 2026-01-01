window.offlineInterop = (() => {
    const listeners = new Map();

    function isOnline() {
        return navigator.onLine;
    }

    function registerStatusChanged(dotnetRef) {
        if (!dotnetRef) return;
        const onOnline = () => dotnetRef.invokeMethodAsync('UpdateOnlineStatus', true).catch(()=>{});
        const onOffline = () => dotnetRef.invokeMethodAsync('UpdateOnlineStatus', false).catch(()=>{});
        window.addEventListener('online', onOnline);
        window.addEventListener('offline', onOffline);
        listeners.set(dotnetRef, { onOnline, onOffline });
    }

    function unregisterStatusChanged(dotnetRef) {
        const entry = listeners.get(dotnetRef);
        if (!entry) return;
        try {
            window.removeEventListener('online', entry.onOnline);
            window.removeEventListener('offline', entry.onOffline);
        } catch (e) { /* ignore */ }
        listeners.delete(dotnetRef);
    }

    return {
        isOnline,
        registerStatusChanged,
        unregisterStatusChanged
    };
})();