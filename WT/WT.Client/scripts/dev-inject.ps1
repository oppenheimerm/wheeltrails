Param(
 [Parameter(Mandatory=$true, Position=0)]
 [string]$Key,

 [switch]$Persist,
 [switch]$ForceGitChanges
)

# Repeatable helper to generate WT.Client/wwwroot/index.html from index.html.template
# Usage examples:
# pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY"
# pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY" -Persist
# pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY" -ForceGitChanges

try {
 $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
 $templatePath = Join-Path $scriptDir '..\wwwroot\index.html.template' | Resolve-Path -ErrorAction Stop
} catch {
 Write-Error "Cannot locate index.html.template. Expected near: '$scriptDir\..\wwwroot\index.html.template'"
 exit1
}

$outPath = Join-Path $scriptDir '..\wwwroot\index.html'

Write-Host "Template: $($templatePath)"
Write-Host "Output: $outPath"

$templateContent = Get-Content -Raw -Path $templatePath
if ($templateContent -notmatch '__GOOGLE_MAPS_API_KEY__') {
 Write-Warning "Template does not contain the placeholder '__GOOGLE_MAPS_API_KEY__'. The file will still be written with no replacement."
}

# Perform a literal replacement (not regex) so API keys with symbols are preserved
$generated = $templateContent.Replace('__GOOGLE_MAPS_API_KEY__', $Key)

# Ensure directory exists
$outDir = Split-Path -Parent $outPath
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Write file as UTF8 without BOM
Set-Content -Path $outPath -Value $generated -Encoding utf8
Write-Host "Generated: $outPath"

if ($Persist) {
 try {
 # Persist environment variable for current user
 Write-Host "Persisting environment variable GOOGLE_MAPS_API_KEY for current user (requires new shells to see it)."
 & setx GOOGLE_MAPS_API_KEY "$Key" | Out-Null
 Write-Host "Persisted. Restart any open shells to see the variable." 
 } catch {
 Write-Warning "Failed to persist env var via setx: $_"
 }
}

if ($ForceGitChanges) {
 # Attempt to add index.html to .gitignore and stop tracking generated file
 $repoRoot = (git rev-parse --show-toplevel)2>$null
 if (-not $repoRoot) {
 Write-Warning "Git not available or this folder is not inside a git repo. Skipping git changes."
 } else {
 $gitignore = Join-Path $repoRoot '.gitignore'
 $relPath = 'WT.Client/wwwroot/index.html'
 if (-not (Test-Path $gitignore)) { New-Item -Path $gitignore -ItemType File -Force | Out-Null }
 $gitignoreContent = Get-Content -Raw -Path $gitignore -ErrorAction SilentlyContinue
 if ($gitignoreContent -notmatch [regex]::Escape($relPath)) {
 Add-Content -Path $gitignore -Value "`n$relPath"
 Write-Host "Appended $relPath to .gitignore"
 } else {
 Write-Host ".gitignore already contains $relPath"
 }

 # Remove from index (stop tracking) but keep file
 try {
 git rm --cached --quiet -- "$relPath"2>$null
 Write-Host "Removed $relPath from git index (if it was tracked)."
 } catch {
 Write-Warning "Failed to run 'git rm --cached' — ensure git is available and you have permissions."
 }

 # Stage .gitignore change
 try { git add .gitignore; git commit -m "Ignore generated WT.Client/wwwroot/index.html" -q } catch { Write-Host "Committed .gitignore or already committed." }
 }
}

Write-Host "Done. Verify: open $outPath and confirm the Google Maps API key was injected."