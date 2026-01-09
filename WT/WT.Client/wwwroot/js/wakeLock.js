/*
 * wakeLock.js
 *-----------
 * Provides Screen Wake Lock API functionality to prevent the device screen
 * from turning off during GPS recording sessions. This is critical for
 * continuous location tracking in the WT.Client trail recording feature.
 *
 * Public API (attached to window):
 * - requestWakeLock() => Promise<boolean>
 *   Requests a wake lock to keep the screen awake. Returns true if successful,
 *   false if not supported or failed. Automatically handles visibility changes
 *   to re-acquire lock when page becomes visible again.
 *
 * - releaseWakeLock() => Promise<void>
 *Releases the current wake lock, allowing the screen to sleep normally.
 *
 * - isWakeLockSupported() => boolean
 *   Returns true if the Screen Wake Lock API is supported in this browser.
 *
 * - isWakeLockActive() => boolean
 *   Returns true if a wake lock is currently active.
 *
 * Browser Support:
 * - Chrome/Edge 84+
 * - Safari 16.4+ (iOS/iPadOS 16.4+)
 * - Opera 70+
 * - Not supported: Firefox (as of 2024)
 *
 * Security Requirements:
 * - HTTPS required (or localhost for development)
 * - Page must be visible (active tab)
 * - User interaction required for first acquisition
 *
 * Usage Example from Blazor:
 * var supported = await JS.InvokeAsync<bool>("isWakeLockSupported");
 * if (supported) {
 *     var acquired = await JS.InvokeAsync<bool>("requestWakeLock");
 *     // ... do GPS recording ...
 *     await JS.InvokeVoidAsync("releaseWakeLock");
 * }
 */

let wakeLock = null;
let isAcquiring = false;

/**
 * Check if Screen Wake Lock API is supported in this browser
 * @returns {boolean} True if supported, false otherwise
 */
function isWakeLockSupported() {
    return 'wakeLock' in navigator;
}

/**
 * Check if a wake lock is currently active
 * @returns {boolean} True if wake lock is active, false otherwise
 */
function isWakeLockActive() {
    return wakeLock !== null && !wakeLock.released;
}

/**
 * Request a screen wake lock to prevent the device from sleeping
 * @returns {Promise<boolean>} True if wake lock acquired, false if failed or unsupported
 */
async function requestWakeLock() {
    // Check browser support
    if (!isWakeLockSupported()) {
        console.warn('Wake Lock API is not supported in this browser');
     return false;
    }

    // Prevent multiple simultaneous acquisition attempts
    if (isAcquiring) {
        console.log('Wake lock acquisition already in progress');
        return false;
    }

    // If already active, return success
    if (isWakeLockActive()) {
        console.log('Wake lock is already active');
        return true;
    }

    try {
        isAcquiring = true;
      wakeLock = await navigator.wakeLock.request('screen');
        
      console.log('Wake lock acquired successfully');

        // Listen for release event (can happen when tab is hidden, minimized, etc.)
        wakeLock.addEventListener('release', () => {
            console.log('Wake lock was released');
    wakeLock = null;
        });

        return true;
    } catch (err) {
  // Common errors:
     // - NotAllowedError: User didn't interact with page, or permission denied
        // - NotSupportedError: Not supported on this device
        console.error('Failed to acquire wake lock:', err.name, err.message);
        wakeLock = null;
        return false;
    } finally {
        isAcquiring = false;
    }
}

/**
 * Release the current wake lock, allowing the screen to sleep
 * @returns {Promise<void>}
 */
async function releaseWakeLock() {
    if (wakeLock !== null && !wakeLock.released) {
        try {
            await wakeLock.release();
            console.log('Wake lock released successfully');
        } catch (err) {
        console.error('Failed to release wake lock:', err);
        }
        wakeLock = null;
    }
}

/**
 * Handle page visibility changes to re-acquire wake lock when page becomes visible
 * This is important because wake locks are automatically released when the page is hidden
 */
async function handleVisibilityChange() {
    if (document.visibilityState === 'visible' && wakeLock !== null && wakeLock.released) {
     console.log('Page became visible, attempting to re-acquire wake lock');
        await requestWakeLock();
    }
}

// Set up automatic re-acquisition when page becomes visible again
if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', handleVisibilityChange);
}

// Expose functions to global window for Blazor JSInterop
if (typeof window !== 'undefined') {
    window.isWakeLockSupported = isWakeLockSupported;
    window.isWakeLockActive = isWakeLockActive;
    window.requestWakeLock = requestWakeLock;
    window.releaseWakeLock = releaseWakeLock;
}
