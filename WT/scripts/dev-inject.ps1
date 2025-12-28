<#
Simple PowerShell helper to manage Google Maps API key injection for WT.Client
Usage (from repository folder `src/WT`):
 # one-off inject (current shell)
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE"

 # persist environment variable (setx) and inject
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE" -Persist

 # force git index changes (will run git rm --cached and commit .gitignore when file is tracked)
 pwsh -ExecutionPolicy Bypass -File .\scripts\dev-inject.ps1 -Key "YOUR_KEY_HERE" -ForceGitChanges

This script does the following (safe defaults):
 - Ensures `WT.Client/wwwroot/index.html.template` exists and contains the placeholder `__GOOGLE_MAPS_API_KEY__` (fixes template if needed)
 - Writes `WT.Client/wwwroot/index.html` by replacing the placeholder with the provided key (or $env:GOOGLE_MAPS_API_KEY if not provided)
 - Adds `WT.Client/wwwroot/index.html` to .gitignore if missing
 - Optionally stops tracking `index.html` in git (asks for confirmation or uses `-ForceGitChanges`)
#>
param(
 [string]$Key,
 [switch]$Persist,
 [switch]$ForceGitChanges
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# repo root for this script is parent of scripts directory
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')
$templatePath = Join-Path $repoRoot 'WT.Client\wwwroot\index.html.template'
$outPath = Join-Path $repoRoot 'WT.Client\wwwroot\index.html'
$gitignorePath = Join-Path $repoRoot '.gitignore'

if (-not (Test-Path $templatePath)) {
 Write-Error "Template not found: $templatePath"
 exit1
}

# If Key not provided, read from current shell env
if (-not $Key -or $Key -eq '') {
 if ($env:GOOGLE_MAPS_API_KEY) {
 $Key = $env:GOOGLE_MAPS_API_KEY
 Write-Host "Using GOOGLE_MAPS_API_KEY from current environment (session)"
 }
}

if (-not $Key -or $Key -eq '') {
 $Key = Read-Host "Enter Google Maps API key (input will be visible)"
}

if (-not $Key -or $Key -eq '') {
 Write-Error "No key provided. Exiting."
 exit2
}

if ($Persist) {
 try {
 setx GOOGLE_MAPS_API_KEY $Key | Out-Null
 Write-Host "Persisted GOOGLE_MAPS_API_KEY for current user (you must re-open shells to see it)."
 } catch {
 Write-Warning "Failed to persist env var with setx: $_"
 }
}

# Read template
$template = Get-Content $templatePath -Raw

# Ensure template contains placeholder; if not, attempt safe replacement of any literal key
if ($template -notmatch '__GOOGLE_MAPS_API_KEY__') {
 Write-Host "Placeholder not found in template — attempting to replace any literal key with placeholder."
 # Replace the value after key= up to & or quote or whitespace
 $updated = $template -replace '(?<=key=)[^&"''\s]+', '__GOOGLE_MAPS_API_KEY__'
 if ($updated -ne $template) {
 $updated | Out-File $templatePath -Encoding utf8
 Write-Host "Updated template to include placeholder: $templatePath"
 $template = $updated
 } else {
 Write-Warning "Could not find a key pattern to replace in template. Please open $templatePath and add '__GOOGLE_MAPS_API_KEY__' manually."
 exit3
 }
}

# Produce output by replacing placeholder
$outContent = $template -replace '__GOOGLE_MAPS_API_KEY__', [System.Text.RegularExpressions.Regex]::Escape($Key)
$outContent | Out-File $outPath -Encoding utf8
Write-Host "Wrote generated file: $outPath"

# Ensure .gitignore contains ignore entry
$ignoreLine = 'WT.Client/wwwroot/index.html'
if (-not (Test-Path $gitignorePath)) { New-Item -Path $gitignorePath -ItemType File -Force | Out-Null }
$gitIgnoreText = Get-Content $gitignorePath -Raw
if ($gitIgnoreText -notmatch [System.Text.RegularExpressions.Regex]::Escape($ignoreLine)) {
 Add-Content -Path $gitignorePath -Value $ignoreLine
 Write-Host "Appended ignore rule to .gitignore"
} else {
 Write-Host ".gitignore already contains ignore rule"
}

# Git operations: stop tracking index.html if currently tracked
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
 Push-Location $repoRoot
 try {
 $isTracked = $false
 try {
 git ls-files --error-unmatch $outPath2>$null | Out-Null
 $isTracked = $true
 } catch {
 $isTracked = $false
 }

 if ($isTracked) {
 if ($ForceGitChanges) {
 git rm --cached --quiet $outPath
 git add .gitignore > $null2>&1
 git commit -m "Stop tracking generated index.html; add template-based injection" --quiet
 Write-Host "Removed index.html from git index and committed .gitignore"
 } else {
 $resp = Read-Host "index.html is currently tracked. Run 'git rm --cached' and commit now? (y/n)"
 if ($resp -eq 'y') {
 git rm --cached $outPath
 git add .gitignore
 git commit -m "Stop tracking generated index.html; add template-based injection"
 Write-Host "Removed index.html from git index and committed .gitignore"
 } else {
 Write-Host "Skipped git index removal. Remember to run: git rm --cached $outPath && git add .gitignore && git commit -m 'Stop tracking generated index.html'"
 }
 }
 } else {
 Write-Host "index.html not tracked by git (or already removed)"
 }
 } finally {
 Pop-Location
 }
} else {
 Write-Host "git not found on PATH; skipping git index checks. Ensure .gitignore and index.html status are correct." 
}

Write-Host "Done. index.html generated locally and will be ignored by git going forward."