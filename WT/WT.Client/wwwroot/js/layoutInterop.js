window.layoutInterop = (() => {
    let mo = null;

    function updateHeaderHeight() {
        try {
            // Defensive guards for non-browser or early-execution environments
            if (typeof document === 'undefined' || typeof document.documentElement === 'undefined') return;

            const header = document.querySelector('header');
            if (!header) {
                // Remove the custom property if header is not present
                document.documentElement.style.removeProperty('--header-height');
                return;
            }

            const h = Math.ceil(header.getBoundingClientRect().height || 0);
            document.documentElement.style.setProperty('--header-height', `${h}px`);
        } catch (ex) {
            // Fail silently but log for diagnostics (avoids unhandled exceptions that trigger VS script debugger)
            try { console.warn('layoutInterop.updateHeaderHeight failed:', ex); } catch { /* noop */ }
        }
    }

    function startAutoUpdate() {
        try {
            updateHeaderHeight();

            if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return;

            // Use passive resize listener when available
            try { window.addEventListener('resize', updateHeaderHeight, { passive: true }); } catch {
                // Some older environments may not support options object
                window.addEventListener('resize', updateHeaderHeight);
            }

            const header = (typeof document !== 'undefined') ? document.querySelector('header') : null;
            if (header && !mo && typeof MutationObserver !== 'undefined') {
                mo = new MutationObserver(updateHeaderHeight);
                mo.observe(header, { attributes: true, childList: true, subtree: true });
            }
        } catch (ex) {
            try { console.warn('layoutInterop.startAutoUpdate failed:', ex); } catch { /* noop */ }
        }
    }

    function stopAutoUpdate() {
        try {
            if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
                try { window.removeEventListener('resize', updateHeaderHeight); } catch { /* ignore */ }
            }
            if (mo) {
                try { mo.disconnect(); } catch { /* ignore */ }
                mo = null;
            }
        } catch (ex) {
            try { console.warn('layoutInterop.stopAutoUpdate failed:', ex); } catch { /* noop */ }
        }
    }

    return { updateHeaderHeight, startAutoUpdate, stopAutoUpdate };
})();
