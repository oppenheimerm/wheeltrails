// uploader.js - simple XHR uploader with progress reporting
//
// Public API:
// - window.uploadWithProgress(inputId, url, dotNetRef, bearer)
// Starts a single-file upload taken from the file input element with id `inputId`.
// Sends a multipart/form-data POST to `url` and reports progress back to the
// provided Blazor DotNet object reference via invokable methods.
//
// - window.abortUpload()
// Aborts the currently running upload (if any).
//
// DotNet interop (expected methods on the supplied dotNetRef):
// - NotifySelectedFileName(string fileName)
// Optional: called once when a file is selected to notify client code of the file name.
// - ReportUploadProgress(int percent)
// Optional: called repeatedly with0-100 progress percentages.
// - UploadFinished(string responseText)
// Optional: called when the server responds with2xx. `responseText` is the raw XHR response.
// - UploadFailed(string message)
// Optional: called when upload fails, is aborted, or an XHR/network error occurs.
//
// Notes & behavior:
// - The function uses XMLHttpRequest to enable accurate upload progress events.
// - The FormData key for the file is `file`. Adjust server-side binding if different.
// - If a bearer token string is provided it will be set as an Authorization header
// ("Bearer <token>"). Be sure tokens are handled securely on the client.
// - Only a single file (the first file in the input.files list) is uploaded.
// - The current XHR instance is stored in `window._currentUploadXhr` to allow aborting.
// - Aborting an XHR triggers the XHR `onerror` handler in some browsers; both
// `onerror` and `onload` contain logic to clean up and notify the DotNet reference.
// - This file intentionally avoids Promise-based fetch() because fetch upload
// progress events are not widely supported; XHR remains the most reliable cross-browser choice.
//
// Browser compatibility:
// - Works in modern browsers (Chrome, Edge, Firefox, Safari).
// - For very large files consider chunked uploads or server endpoint that supports streaming.
//
// Security:
// - Never embed long-lived secrets in client-side JS. Only short-lived tokens from secure flows should be used.
// - Sanitize/validate any incoming file server-side (size, content-type, magic-bytes) before persisting.

window.uploadWithProgress = function (inputId, url, dotNetRef, bearer) {
    try {
        const input = document.getElementById(inputId);
        if (!input || !input.files || input.files.length === 0) {
            // Notify .NET that no file was selected
            if (dotNetRef) dotNetRef.invokeMethodAsync('UploadFailed', 'No file selected');
            return;
        }

        // Use only the first file for this uploader helper
        const file = input.files[0];

        if (dotNetRef) {
            // Optional: notify .NET of selected filename for UI updates
            try { dotNetRef.invokeMethodAsync('NotifySelectedFileName', file.name); } catch (e) { }
        }

        const xhr = new XMLHttpRequest();
        const fd = new FormData();
        // Server expects field name `file` for the uploaded file
        fd.append('file', file, file.name);

        xhr.open('POST', url, true);

        if (bearer) {
            // If a bearer token is supplied, attach it to the Authorization header
            // Ensure the token originates from a secure source and has appropriate scope/expiry.
            try { xhr.setRequestHeader('Authorization', 'Bearer ' + bearer); } catch (e) { }
        }

        // Upload progress event. e.lengthComputable may be false in some cases.
        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                if (dotNetRef) dotNetRef.invokeMethodAsync('ReportUploadProgress', percent);
            }
        };

        // Load handler: called on completion regardless of HTTP status
        xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                // Success: forward raw response text to .NET for parsing
                if (dotNetRef) dotNetRef.invokeMethodAsync('UploadFinished', xhr.responseText);
            } else {
                // Non-success HTTP status
                if (dotNetRef) dotNetRef.invokeMethodAsync('UploadFailed', `Upload failed with status ${xhr.status}`);
            }
            // cleanup current xhr reference
            try { delete window._currentUploadXhr; } catch (e) { }
        };

        // Error handler: network errors, CORS, or aborts may trigger this
        xhr.onerror = function () {
            if (dotNetRef) dotNetRef.invokeMethodAsync('UploadFailed', 'Upload error');
            try { delete window._currentUploadXhr; } catch (e) { }
        };

        // store for abort so other code (e.g., Cancel button) can call window.abortUpload()
        window._currentUploadXhr = xhr;
        xhr.send(fd);
    }
    catch (ex) {
        // Unexpected exception in the uploader helper
        if (dotNetRef) dotNetRef.invokeMethodAsync('UploadFailed', ex?.message ?? 'Upload exception');
    }
};

/**
 * Abort the current upload in progress (if any).
 * This will call XHR.abort() on the stored instance and remove the global reference.
 * Caller should listen for the UploadFailed callback to react to the cancellation.
 */
window.abortUpload = function () {
    try {
        if (window._currentUploadXhr) {
            try { window._currentUploadXhr.abort(); } catch (e) { }
            delete window._currentUploadXhr;
        }
    }
    catch (ex) { }
};
