/*
 * trailRecorder.js
 *---------------
 * Helpers for map initialization and geolocation tracking used by the Blazor
 * client (WT.Client). Exposed functions are attached to `window` so Blazor
 * can call them via JS interop.
 *
 * Public API (attached to window):
 * - initMap(dotNetRef, mapElementId, centerLat, centerLng, zoom)
 * Initialize Google Maps on the specified element id. `dotNetRef` is
 * optional here but kept for parity with previous API.
 *
 * - getCurrentPosition(options) => Promise<{lat:number, lng:number}>
 * One-shot geolocation lookup. Resolves with `{lat,lng}` or rejects
 * with an error message. Uses navigator.geolocation.getCurrentPosition.
 *
 * - startWatchPosition(dotNetRef, options) => watchId
 * Starts a geolocation watch. On each position update the function will
 * invoke `dotNetRef.invokeMethodAsync('OnPositionUpdate', { lat, lng })`
 * so the Blazor component can receive updates. Returns the watchId used
 * by the browser API or null if geolocation unsupported.
 *
 * - stopWatchPosition()
 * Stops a previously started watch (clears watchId).
 *
 * - startRecording(dotNetRef) / stopRecording()
 * Backwards-compatible convenience wrappers that call startWatchPosition
 * / stopWatchPosition. startRecording returns the watchId.
 *
 * - updateTrailPath(waypoints)
 * Expects an array of waypoints [{ lat, lng }, ...] and updates an
 * existing Google Maps Polyline with the given path.
 *
 * - addPoiMarker(poi)
 * Adds a Google Maps Marker for a POI object. Expected POI shape:
 * { location: { lat: number, lng: number }, type?: string }
 *
 * Notes & Blazor integration
 * --------------------------
 * - The Blazor page should provide a DotNetObjectReference with a public
 * JSInvokable method named `OnPositionUpdate` that accepts an object with
 * `lat` and `lng` numeric properties. Example in C#:
 *
 * [JSInvokable]
 * public Task OnPositionUpdate(WTLatLng point) { ... }
 *
 * - All functions gracefully handle lack of geolocation support in the
 * browser and log or reject accordingly.
 *
 * - The `initMap` function waits for the Google Maps API to be available and
 * retries a few times before failing to make initialization more robust
 * in page load scenarios where the maps script may load asynchronously.
 *
 * Example usage from Blazor (pseudo):
 * await JS.InvokeVoidAsync("initMap", dotNetRef, "map", lat, lng,14);
 * var pos = await JS.InvokeAsync<Position>("getCurrentPosition");
 * var watchId = await JS.InvokeAsync<int?>("startWatchPosition", dotNetRef);
 * await JS.InvokeVoidAsync("stopWatchPosition");
 */

let map;
let polyline;
let watchId = null;

function initMap(dotNetRef, mapElementId, centerLat, centerLng, zoom) {
    // If Google Maps hasn't loaded yet, retry a few times before throwing.
    if (typeof google === 'undefined' || typeof google.maps === 'undefined') {
        // Try again in250ms (up to ~2.5s)
        let attempts =0;
        const tryInit = () => {
            attempts++;
            if (typeof google !== 'undefined' && typeof google.maps !== 'undefined') {
                initMap(dotNetRef, mapElementId, centerLat, centerLng, zoom);
                return;
            }
            if (attempts <10) {
                setTimeout(tryInit,250);
            } else {
                console.error('Google Maps API not loaded; cannot initialize map.');
            }
        };
        setTimeout(tryInit,250);
        return;
    }

    map = new google.maps.Map(document.getElementById(mapElementId), {
        center: { lat: centerLat, lng: centerLng },
        zoom: zoom
    });

    polyline = new google.maps.Polyline({
        map: map,
        geodesic: true,
        strokeColor: "#FF0000",
        strokeOpacity: 1.0,
        strokeWeight: 4
    });
}

function startRecording(dotNetRef) {
    if (!navigator.geolocation) {
        alert("Geolocation is not supported by this browser.");
        return;
    }

    watchId = navigator.geolocation.watchPosition(
        (pos) => {
            dotNetRef.invokeMethodAsync("OnPositionUpdate", {
                lat: pos.coords.latitude,
                lng: pos.coords.longitude
            });
        },
        (err) => {
            console.error(err);
        },
        {
            enableHighAccuracy: true,
            maximumAge: 0,
            timeout: 5000
        }
    );
    return watchId;
}

function stopRecording() {
    if (watchId !== null) {
        navigator.geolocation.clearWatch(watchId);
        watchId = null;
    }
}

function updateTrailPath(waypoints) {
    if (!polyline || !map) return;

    const path = waypoints.map(p => ({ lat: p.lat, lng: p.lng }));
    polyline.setPath(path);
}

function addPoiMarker(poi) {
    if (!map) return;

    new google.maps.Marker({
        position: { lat: poi.location.lat, lng: poi.location.lng },
        map: map,
        title: poi.type
    });
}

// New helper: get current position (one-shot) - returns a Promise resolving {lat,lng}
function getCurrentPosition(options) {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject('Geolocation not supported');
            return;
        }

        navigator.geolocation.getCurrentPosition(
            (pos) => {
                resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude });
            },
            (err) => {
                reject(err.message || err.code || 'Error getting position');
            },
            options || { maximumAge:60000, timeout:5000, enableHighAccuracy: false }
        );
    });
}

// New helper: start watch with same behavior as startRecording but return watchId
function startWatchPosition(dotNetRef, options) {
    if (!navigator.geolocation) {
        console.error('Geolocation not supported');
        return null;
    }

    watchId = navigator.geolocation.watchPosition(
        (pos) => {
            if (dotNetRef && typeof dotNetRef.invokeMethodAsync === 'function') {
                dotNetRef.invokeMethodAsync("OnPositionUpdate", {
                    lat: pos.coords.latitude,
                    lng: pos.coords.longitude
                });
            }
        },
        (err) => {
            console.error(err);
        },
        options || { enableHighAccuracy: true, maximumAge:0, timeout:5000 }
    );

    return watchId;
}

function stopWatchPosition() {
    stopRecording();
}

// expose to global window for Blazor JSInterop
if (typeof window !== 'undefined') {
    window.initMap = initMap;
    window.startRecording = startRecording;
    window.stopRecording = stopRecording;
    window.updateTrailPath = updateTrailPath;
    window.addPoiMarker = addPoiMarker;
    window.getCurrentPosition = getCurrentPosition;
    window.startWatchPosition = startWatchPosition;
    window.stopWatchPosition = stopWatchPosition;
}