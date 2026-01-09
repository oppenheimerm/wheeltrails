# Screen Wake Lock - Quick Start Guide

## What Was Implemented

The Screen Wake Lock API keeps your device screen awake during GPS trail recording, ensuring continuous location data collection.

## Quick Test

1. **Open the trail creation page**: Navigate to `/trails/new`
2. **Check console**: Look for "Wake Lock API is supported" message
3. **Start recording**: Click "Start recording" button
4. **Verify**: Banner should show "Screen wake lock active"
5. **Leave screen idle**: Screen should NOT dim/sleep
6. **Stop recording**: Click "Stop recording"
7. **Verify**: Wake lock released, screen can sleep normally

## Browser Compatibility

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome/Edge 84+ | ? Full support | Recommended |
| Safari 16.4+ | ? Full support | iOS/iPadOS 16.4+ |
| Firefox | ? Not supported | Falls back gracefully |
| Opera 70+ | ? Full support | - |

## Key Features

? **Automatic**: Requests wake lock when recording starts  
? **Smart**: Re-acquires lock when returning to tab  
? **Clean**: Releases lock when recording stops  
? **Safe**: Fallback for unsupported browsers  
? **Visible**: Shows status in recording banner  

## Code Changes

### 1. New JavaScript Module
- **File**: `WT.Client/wwwroot/js/wakeLock.js`
- **Purpose**: Wake Lock API wrapper with auto re-acquisition

### 2. Updated Page
- **File**: `WT.Client/Pages/Trails/TrailCreate.razor`
- **Changes**:
  - Added wake lock state tracking
  - Requests lock on recording start
  - Releases lock on recording stop
  - Shows status in UI

### 3. Script Reference
- **File**: `WT.Client/wwwroot/index.html`
- **Change**: Added `<script src="js/wakeLock.js"></script>`

## Usage Pattern

```csharp
// On recording start
if (isWakeLockSupported)
{
    var acquired = await JS.InvokeAsync<bool>("requestWakeLock");
    if (acquired) { isWakeLockActive = true; }
}

// On recording stop
if (isWakeLockActive)
{
    await JS.InvokeVoidAsync("releaseWakeLock");
    isWakeLockActive = false;
}
```

## Testing Checklist

- [ ] Wake lock acquired when recording starts
- [ ] Screen doesn't dim during recording
- [ ] Wake lock released when recording stops
- [ ] Wake lock re-acquired when switching back to tab
- [ ] Works on mobile devices (Chrome/Safari)
- [ ] Graceful fallback on Firefox
- [ ] Status shown in recording banner

## HTTPS Requirement

?? **Important**: Wake Lock API requires HTTPS in production
- ? Works on `localhost` for development
- ? Works on `https://` domains
- ? Won't work on `http://` (except localhost)

## Battery Impact

?? **User Communication**:
- Recording banner shows wake lock status
- Users informed that screen staying on uses more battery
- Wake lock only active during GPS recording (not all the time)

## Troubleshooting

### Wake lock not working?
1. Check browser compatibility (Chrome/Edge/Safari recommended)
2. Verify HTTPS is used (or localhost for dev)
3. Check console for error messages
4. Ensure page is visible (active tab)

### Testing visibility change behavior
```javascript
// In browser console:
window.isWakeLockActive() // Check status
```

## Next Steps

Consider adding these enhancements:
1. User setting to enable/disable wake lock
2. Battery level indicator
3. Low power mode detection
4. Usage analytics

## Support Resources

- Full documentation: `WAKE_LOCK_IMPLEMENTATION.md`
- MDN Docs: https://developer.mozilla.org/en-US/docs/Web/API/Screen_Wake_Lock_API
- Can I Use: https://caniuse.com/wake-lock
