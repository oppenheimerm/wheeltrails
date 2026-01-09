/**
 * Wake Lock API Testing & Debug Utilities
 * 
 * Open browser console and use these functions to test wake lock behavior
 * during development. Paste into console or save as a bookmarklet.
 */

// Test 1: Check if Wake Lock is supported
function testWakeLockSupport() {
    const supported = window.isWakeLockSupported();
    console.log(`%c Wake Lock Support: ${supported ? '? YES' : '? NO'}`, 
        `font-size: 14px; font-weight: bold; color: ${supported ? '#4CAF50' : '#F44336'}`);
    
    if (!supported) {
  console.log('%c Try Chrome 84+, Edge 84+, or Safari 16.4+', 'color: #FF9800');
    }
    return supported;
}

// Test 2: Check current wake lock status
function testWakeLockStatus() {
    const active = window.isWakeLockActive();
    console.log(`%c Wake Lock Status: ${active ? '?? ACTIVE' : '?? INACTIVE'}`, 
   `font-size: 14px; font-weight: bold; color: ${active ? '#4CAF50' : '#9E9E9E'}`);
    return active;
}

// Test 3: Request wake lock manually
async function testRequestWakeLock() {
    console.log('%c Requesting wake lock...', 'color: #2196F3');
    try {
      const acquired = await window.requestWakeLock();
     if (acquired) {
        console.log('%c ? Wake lock acquired successfully!', 'color: #4CAF50; font-weight: bold');
          console.log('%c Screen should stay awake now', 'color: #4CAF50');
        } else {
       console.log('%c ? Failed to acquire wake lock', 'color: #F44336; font-weight: bold');
        }
        return acquired;
    } catch (err) {
        console.error('Error requesting wake lock:', err);
 return false;
    }
}

// Test 4: Release wake lock manually
async function testReleaseWakeLock() {
    console.log('%c Releasing wake lock...', 'color: #2196F3');
    try {
    await window.releaseWakeLock();
        console.log('%c ? Wake lock released successfully!', 'color: #4CAF50; font-weight: bold');
      console.log('%c Screen can sleep normally now', 'color: #4CAF50');
    } catch (err) {
        console.error('Error releasing wake lock:', err);
    }
}

// Test 5: Full cycle test
async function testFullWakeLockCycle() {
    console.log('%c === Starting Wake Lock Full Cycle Test ===', 'color: #9C27B0; font-weight: bold; font-size: 16px');
    
    // Step 1: Check support
    console.log('\n%c Step 1: Checking support...', 'color: #2196F3; font-weight: bold');
    const supported = testWakeLockSupport();
    if (!supported) {
        console.log('%c Test aborted: Wake Lock not supported', 'color: #F44336; font-weight: bold');
        return;
    }
    
    await sleep(1000);
    
    // Step 2: Check initial status
    console.log('\n%c Step 2: Checking initial status...', 'color: #2196F3; font-weight: bold');
    testWakeLockStatus();
    
    await sleep(1000);
    
    // Step 3: Request wake lock
    console.log('\n%c Step 3: Requesting wake lock...', 'color: #2196F3; font-weight: bold');
    const acquired = await testRequestWakeLock();
    
 if (!acquired) {
        console.log('%c Test failed: Could not acquire wake lock', 'color: #F44336; font-weight: bold');
        return;
    }
    
    await sleep(2000);
    
    // Step 4: Verify active
    console.log('\n%c Step 4: Verifying wake lock is active...', 'color: #2196F3; font-weight: bold');
    testWakeLockStatus();
    
    await sleep(2000);
    
    // Step 5: Release wake lock
    console.log('\n%c Step 5: Releasing wake lock...', 'color: #2196F3; font-weight: bold');
    await testReleaseWakeLock();
    
    await sleep(1000);
  
    // Step 6: Verify released
    console.log('\n%c Step 6: Verifying wake lock is released...', 'color: #2196F3; font-weight: bold');
    testWakeLockStatus();
    
    console.log('\n%c === Test Complete ===', 'color: #4CAF50; font-weight: bold; font-size: 16px');
}

// Test 6: Monitor wake lock state
function monitorWakeLock(durationSeconds = 30) {
    console.log(`%c ?? Monitoring wake lock state for ${durationSeconds} seconds...`, 'color: #2196F3; font-weight: bold');
    console.log('%c Switch tabs, minimize browser, or lock device to test behavior', 'color: #FF9800');
    
    let counter = 0;
    const interval = setInterval(() => {
        counter++;
 const active = window.isWakeLockActive();
        const status = active ? '?? ACTIVE' : '?? INACTIVE';
  const color = active ? '#4CAF50' : '#9E9E9E';
        
      console.log(`%c [${counter}s] ${status}`, `color: ${color}`);
        
        if (counter >= durationSeconds) {
   clearInterval(interval);
       console.log('%c Monitoring complete', 'color: #2196F3; font-weight: bold');
        }
    }, 1000);
    
    return interval;
}

// Test 7: Visibility change test
function testVisibilityBehavior() {
    console.log('%c === Testing Visibility Change Behavior ===', 'color: #9C27B0; font-weight: bold; font-size: 16px');
    console.log('%c 1. Wake lock will be requested', 'color: #2196F3');
    console.log('%c 2. Switch to another tab or minimize browser', 'color: #2196F3');
    console.log('%c 3. Come back to this tab', 'color: #2196F3');
    console.log('%c 4. Check console - wake lock should re-acquire automatically', 'color: #2196F3');
  
    // Add temporary visibility listener for logging
    const listener = () => {
    if (document.visibilityState === 'visible') {
            console.log('%c ??? Page became VISIBLE', 'color: #4CAF50; font-weight: bold');
      setTimeout(() => testWakeLockStatus(), 500);
        } else {
            console.log('%c ?? Page became HIDDEN', 'color: #9E9E9E; font-weight: bold');
 setTimeout(() => testWakeLockStatus(), 500);
   }
    };
    
    document.addEventListener('visibilitychange', listener);
    
    // Request initial wake lock
    testRequestWakeLock();
    
    // Clean up after 60 seconds
    setTimeout(() => {
        document.removeEventListener('visibilitychange', listener);
        console.log('%c Visibility test listener removed', 'color: #9E9E9E');
    }, 60000);
}

// Helper function
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Run all tests
async function runAllTests() {
    console.clear();
    console.log('%c ?? Running All Wake Lock Tests ??', 'color: #9C27B0; font-weight: bold; font-size: 18px');
    console.log('?'.repeat(50));
    
    await testFullWakeLockCycle();
    
    console.log('\n' + '?'.repeat(50));
    console.log('%c Additional Tests Available:', 'color: #2196F3; font-weight: bold');
    console.log('  • testVisibilityBehavior() - Test tab switching');
    console.log('  • monitorWakeLock(30) - Monitor for 30 seconds');
    console.log('  • testWakeLockSupport() - Check support only');
  console.log('  • testWakeLockStatus() - Check current status');
}

// Export test functions to window
if (typeof window !== 'undefined') {
    window.wakeLockTests = {
        support: testWakeLockSupport,
        status: testWakeLockStatus,
      request: testRequestWakeLock,
        release: testReleaseWakeLock,
        fullCycle: testFullWakeLockCycle,
        monitor: monitorWakeLock,
        visibility: testVisibilityBehavior,
        runAll: runAllTests
    };
    
    console.log('%c Wake Lock Test Utilities Loaded!', 'color: #4CAF50; font-weight: bold; font-size: 16px');
    console.log('%c Usage:', 'color: #2196F3; font-weight: bold');
    console.log('  wakeLockTests.runAll()     - Run all tests');
    console.log('  wakeLockTests.support()    - Check browser support');
    console.log('  wakeLockTests.status()       - Check current status');
    console.log('  wakeLockTests.request()      - Request wake lock');
    console.log('  wakeLockTests.release()      - Release wake lock');
    console.log('  wakeLockTests.fullCycle()    - Full test cycle');
    console.log('  wakeLockTests.monitor(30)    - Monitor for 30s');
    console.log('  wakeLockTests.visibility()   - Test tab switching');
}
