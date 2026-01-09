# Screen Wake Lock API Implementation Guide

## Overview
The Screen Wake Lock API has been integrated into the WheelyTrails project to prevent the device screen from turning off during GPS trail recording. This ensures continuous location data collection without interruption.

## Files Modified/Created

### New Files
1. **`WT.Client/wwwroot/js/wakeLock.js`**
   - JavaScript module providing Wake Lock API functionality
   - Handles wake lock acquisition, release, and automatic re-acquisition
   - Includes browser support detection

### Modified Files
1. **`WT.Client/wwwroot/index.html`**
   - Added script reference to `wakeLock.js`

2. **`WT.Client/Pages/Trails/TrailCreate.razor`**
   - Added wake lock state tracking
   - Integrated wake lock requests/releases with GPS recording lifecycle
   - Updated UI to show wake lock status

## How It Works

### 1. Initialization
When the TrailCreate page loads, it checks if the browser supports the Wake Lock API:

```csharp
isWakeLockSupported = await JS.InvokeAsync<bool>("isWakeLockSupported");
```

### 2. Starting Recording
When the user starts GPS recording:
- A wake lock is requested via `requestWakeLock()`
- The screen is prevented from sleeping
- Status is tracked in `isWakeLockActive`

```csharp
var wakeLockAcquired = await JS.InvokeAsync<bool>("requestWakeLock");
if (wakeLockAcquired)
{
    isWakeLockActive = true;
}
```

### 3. Stopping Recording
When recording stops:
- The wake lock is released via `releaseWakeLock()`
- The screen can sleep normally again

```csharp
await JS.InvokeVoidAsync("releaseWakeLock");
isWakeLockActive = false;
```

### 4. Automatic Re-acquisition
If the user switches tabs or minimizes the browser:
- The wake lock is automatically released by the browser
- When the page becomes visible again, the wake lock is automatically re-acquired
- This is handled by the `visibilitychange` event listener in `wakeLock.js`

## Browser Support

### Supported Browsers
- ? Chrome/Edge 84+ (Desktop & Mobile)
- ? Safari 16.4+ (iOS/iPadOS 16.4+)
- ? Opera 70+
- ? Samsung Internet 14+

### Not Supported
- ? Firefox (as of 2024) - Feature request open
- ? Older browsers (IE, old Safari versions)

### Fallback Behavior
When Wake Lock API is not supported:
- GPS recording still works normally
- The screen may sleep according to device settings
- Users are notified in the recording banner: "Screen may sleep (wake lock unavailable)"

## Security Requirements

The Wake Lock API has strict security requirements:

1. **HTTPS Required**
   - Must be served over HTTPS in production
   - `localhost` is allowed for development

2. **Active Tab/Visible Page**
   - Page must be visible (active tab)
   - Wake lock is automatically released when tab is hidden

3. **User Interaction**
   - First wake lock request requires user interaction
   - This is handled by the "Start recording" button click

## User Experience

### Visual Indicators
The recording banner now shows wake lock status:

- **Wake lock active**: "Screen wake lock active"
- **Wake lock unavailable**: "Screen may sleep (wake lock unavailable)"
- **Not supported**: "May affect battery"

### Best Practices
1. Wake lock is only requested during active GPS recording
2. Wake lock is automatically released when recording stops
3. Wake lock is released when component is disposed
4. Status is clearly communicated to users

## API Reference

### JavaScript Functions (in `wakeLock.js`)

#### `isWakeLockSupported()`
```javascript
// Returns: boolean
// Check if Wake Lock API is supported
const supported = window.isWakeLockSupported();
```

#### `requestWakeLock()`
```javascript
// Returns: Promise<boolean>
// Request a wake lock (true if successful)
const acquired = await window.requestWakeLock();
```

#### `releaseWakeLock()`
```javascript
// Returns: Promise<void>
// Release the current wake lock
await window.releaseWakeLock();
```

#### `isWakeLockActive()`
```javascript
// Returns: boolean
// Check if a wake lock is currently active
const active = window.isWakeLockActive();
```

### Blazor Integration Example

```csharp
// Check support
var supported = await JS.InvokeAsync<bool>("isWakeLockSupported");

if (supported)
{
    // Request wake lock
    var acquired = await JS.InvokeAsync<bool>("requestWakeLock");
    
    if (acquired)
    {
 // GPS recording with wake lock active
        // ...
        
        // Release when done
        await JS.InvokeVoidAsync("releaseWakeLock");
    }
}
```

## Testing

### Test Scenarios

1. **Desktop Browser**
   ```
   - Start recording ? screen should not dim
   - Switch tabs ? wake lock released automatically
   - Return to tab ? wake lock re-acquired
   - Stop recording ? wake lock released
   ```

2. **Mobile Device**
   ```
   - Start recording ? screen stays on
   - Lock device ? wake lock released
- Unlock device ? wake lock re-acquired if still recording
   - Stop recording ? screen can sleep normally
   ```

3. **Unsupported Browser**
   ```
   - Recording works normally
   - No wake lock acquired
   - Appropriate message shown to user
   ```

### Testing Tips

1. Use Chrome DevTools to simulate visibility changes:
   - Open DevTools
   - Application tab ? Background Services ? Background Sync
   - Toggle "Emulate page focus"

2. Check wake lock status in console:
   ```javascript
   console.log('Wake Lock Active:', window.isWakeLockActive());
   ```

3. Test on actual mobile devices for accurate battery impact assessment

## Performance & Battery Impact

### Battery Considerations
- Wake locks prevent screen from sleeping ? higher battery usage
- Only active during GPS recording (not all the time)
- Automatically released when not needed
- Users are informed about battery impact

### Best Practices
1. Only request wake lock when actively recording GPS
2. Release immediately when recording stops
3. Let users know wake lock is active
4. Consider adding a user preference to disable wake lock

## Troubleshooting

### Wake Lock Not Acquired
**Problem**: `requestWakeLock()` returns `false`

**Possible Causes**:
1. Browser doesn't support Wake Lock API
2. Page not served over HTTPS (except localhost)
3. Page not visible (hidden tab)
4. Permission denied by browser

**Solution**: Check console for error messages and verify HTTPS is used

### Wake Lock Released Unexpectedly
**Problem**: Wake lock released while recording

**Possible Causes**:
1. User switched tabs
2. User minimized browser
3. Device went to sleep

**Solution**: Wake lock will automatically re-acquire when page becomes visible again (handled by `visibilitychange` listener)

### Memory Leak Concerns
**Problem**: Wake lock not released

**Solution**: Wake lock is released in multiple places:
- When recording stops
- When component is disposed
- Automatically by browser when tab is hidden

## Future Enhancements

Potential improvements:
1. **User Preference**: Add setting to enable/disable wake lock
2. **Battery Status**: Show estimated battery impact
3. **Partial Wake Lock**: Use lower power wake lock mode if available
4. **Analytics**: Track wake lock usage for optimization
5. **Notification**: Alert user if wake lock is lost during recording

## References

- [Screen Wake Lock API Specification](https://w3c.github.io/screen-wake-lock/)
- [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Screen_Wake_Lock_API)
- [Can I Use - Wake Lock](https://caniuse.com/wake-lock)

## Support

For issues or questions:
1. Check browser console for error messages
2. Verify browser compatibility
3. Ensure HTTPS is used (production)
4. Test with Chrome/Edge 84+ for best support
