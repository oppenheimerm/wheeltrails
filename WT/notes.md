
## Google Maps API Key — Runtime config (Implemented)

This project uses a simple, low-friction runtime-config approach so developers can keep local keys out of source control while CI injects the production key into the published artifact automatically.

Why this approach
- Browser-loaded Google Maps keys are public by design. Storing them in source is risky.
- This approach requires one small, one-time local setup per developer and one automatic CI step on deployment. No per-deploy manual work required.
- CI writes the production key into the published `wwwroot` only. Your local dev key stays uncommitted.

What was changed
- `WT/WT.Client/wwwroot/index.html` now loads `js/config.js` and creates the Maps <script> at runtime from `window.__WT_CONFIG__.GOOGLE_MAPS_API_KEY`.
- `WT/WT.Client/wwwroot/js/config.example.js` was added as a template for developers.
- `WT/WT.Client/.gitignore` updated to ignore `WT.Client/wwwroot/js/config.js` (local untracked file).
- Repository workflow `.github/workflows/deploy.yml` now generates `wwwroot/js/config.js` in the published output using the `GOOGLE_MAPS_API_KEY` secret.

Local developer setup (one-time)
1. Copy the example to create a local config (do NOT commit):
 - PowerShell:
 ```powershell
 Copy-Item WT/WT.Client/wwwroot/js/config.example.js WT/WT.Client/wwwroot/js/config.js
 notepad WT/WT.Client/wwwroot/js/config.js
 # replace '__GOOGLE_MAPS_API_KEY__' with your local key
 ```
 - Bash:
 ```bash
 cp WT/WT.Client/wwwroot/js/config.example.js WT/WT.Client/wwwroot/js/config.js
 sed -i "s/__GOOGLE_MAPS_API_KEY__/YOUR_LOCAL_KEY/" WT/WT.Client/wwwroot/js/config.js
 ```
2. Confirm `WT/WT.Client/wwwroot/js/config.js` is listed in `WT/WT.Client/.gitignore` so it won't be committed.
3. Run the client for local dev as before: `dotnet run --project WT/WT.Client` or run the full solution. The app will load the Maps script using your local key.

CI / Production deployment
1. Add the production Maps key to the repository Secrets:
 - Repository ? Settings ? Secrets and variables ? Actions ? New repository secret
 - Name: `GOOGLE_MAPS_API_KEY`
 - Value: (your production Maps API key)
2. The workflow `.github/workflows/deploy.yml` will:
 - `dotnet publish` the client project
 - create `WT/WT.Client/bin/Release/net9.0/publish/wwwroot/js/config.js` containing:
 ```js
 window.__WT_CONFIG__ = { GOOGLE_MAPS_API_KEY: "<your-secret>" };
 ```
 - upload the entire `publish/wwwroot` to Cloudflare Pages
3. No source files are changed by CI; the secret exists only in the publish artifact.

How to test the CI injection
- Trigger a run (push to `main` or use the Actions UI `Run workflow` for `workflow_dispatch`).
- In the Actions run logs, confirm the step `Create runtime config with Google Maps API Key in publish output` prints `Wrote runtime config to .../wwwroot/js/config.js`.
- After deployment, open the site and verify maps load. You can also inspect the published `js/config.js` file via the site or by downloading the published artifact from the workflow run (if needed).

Security notes
- Google Maps JS API keys are public to the browser. Restrict the key in Google Cloud Console by HTTP referrers (add exact allowed domains, including protocol and any hostnames).
- Use separate keys for local dev, staging, and production and rotate keys if they are exposed.
- Never commit secrets to source control.

If you want, I can also:
- Add a short smoke-test step in the workflow that checks `js/config.js` exists in the publish folder and prints a masked confirmation (it will not print the secret).
- Add a one-line PowerShell helper script under `scripts/` to help new devs create `js/config.js` from the example.

---

(End of Google Maps runtime config documentation)
