Dev injector usage

This folder contains a simple PowerShell helper to inject the Google Maps API key into the Blazor client `index.html` from a committed template.

scripts/dev-inject.ps1
- Purpose: make it trivial to generate `WT.Client/wwwroot/index.html` from `index.html.template` without committing secrets.
- Usage examples (from `src/WT`):
 - One-off injection in current shell:
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE"
 - Persist env var for future shells and inject:
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE" -Persist
 - Force git index changes (stop tracking) without prompts:
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE" -ForceGitChanges

Notes:
- Only `index.html.template` is committed to the repo. `index.html` is generated locally and is ignored via `.gitignore`.
- The script will attempt to replace any literal key in the template with the placeholder `__GOOGLE_MAPS_API_KEY__` once.
- If you need a non-interactive CI injector use the repository workflow to run a Node or PowerShell injector that reads the secret from `secrets.GOOGLE_MAPS_API_KEY`.

Security:
- Do NOT commit `index.html` with a real key. If a key was pushed, rotate it immediately as you did.
- Use restricted API key with HTTP referrers in Google Cloud Console.
