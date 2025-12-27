(function () {
    // Simple helper to add/remove a document-level keydown listener that notifies .NET when Escape is pressed.
    const handlers = {
        dotNetRef: null,
        listener: null
    };

    window.fabInterop = {
        addEscapeHandler: function (dotNetRef) {
            // remove existing first
            if (handlers.listener) {
                document.removeEventListener('keydown', handlers.listener);
                handlers.listener = null;
            }
            handlers.dotNetRef = dotNetRef;
            handlers.listener = function (ev) {
                if (ev.key === 'Escape' || ev.key === 'Esc') {
                    // notify .NET - instance method CloseFabFromJs
                    if (handlers.dotNetRef) {
                        handlers.dotNetRef.invokeMethodAsync('CloseFabFromJs');
                    }
                }
            };
            document.addEventListener('keydown', handlers.listener);
        },
        removeEscapeHandler: function () {
            if (handlers.listener) {
                document.removeEventListener('keydown', handlers.listener);
                handlers.listener = null;
            }
            if (handlers.dotNetRef) {
                try { handlers.dotNetRef.dispose(); } catch { }
                handlers.dotNetRef = null;
            }
        }
    };
})();
