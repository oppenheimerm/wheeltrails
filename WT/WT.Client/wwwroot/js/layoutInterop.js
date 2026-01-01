window.layoutInterop = (() => {
    let mo = null;
    function updateHeaderHeight() {
        const header = document.querySelector('header');
        if (!header) return;
        const h = Math.ceil(header.getBoundingClientRect().height);
        document.documentElement.style.setProperty('--header-height', `${h}px`);
    }

    function startAutoUpdate() {
        updateHeaderHeight();
        window.addEventListener('resize', updateHeaderHeight, { passive: true });
        const header = document.querySelector('header');
        if (header && !mo) {
            mo = new MutationObserver(updateHeaderHeight);
            mo.observe(header, { attributes: true, childList: true, subtree: true });
        }
    }

    function stopAutoUpdate() {
        window.removeEventListener('resize', updateHeaderHeight);
        if (mo) {
            mo.disconnect();
            mo = null;
        }
    }

    return { updateHeaderHeight, startAutoUpdate, stopAutoUpdate };
})();
