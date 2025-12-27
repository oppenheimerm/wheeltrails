# PowerShell helper to inject Google Maps API key into wwwroot/index.html from an environment variable
# Usage: .\inject-google-key.ps1 -Key $env:GOOGLE_MAPS_API_KEY -TemplatePath "wwwroot/index.html.template" -OutPath "wwwroot/index.html"
param(
 [Parameter(Mandatory=$true)]
 [string]$Key,

 [Parameter(Mandatory=$false)]
 [string]$TemplatePath = "wwwroot/index.html.template",

 [Parameter(Mandatory=$false)]
 [string]$OutPath = "wwwroot/index.html"
)

if (-not (Test-Path $TemplatePath)) {
 Write-Error "Template file not found: $TemplatePath"
 exit1
}

(Get-Content $TemplatePath) -replace '__GOOGLE_MAPS_API_KEY__', [RegEx]::Escape($Key) | Set-Content $OutPath -Encoding UTF8
Write-Host "Injected Google Maps API key into $OutPath"