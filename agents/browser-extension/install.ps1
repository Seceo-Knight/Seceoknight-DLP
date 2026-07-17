<#
  SeceoKnight DLP - Cloud Upload Guard : Windows install helper.

  Configures the native-messaging host: writes the host manifest, registers it
  for Chrome/Edge, and writes the host's server/agent config. Run this AFTER you
  have loaded the extension (you need its Extension ID) and placed the host
  executable/launcher on disk.

  Run in an ELEVATED PowerShell (Run as administrator) for machine scope.

  Example:
    .\install.ps1 `
        -ExtensionId  ppkk...your-extension-id... `
        -ServerUrl    https://dlp.example.com/api/v1 `
        -AgentId      win-ws-01 `
        -AgentKey     0f3a...agent-api-key... `
        -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"
#>
param(
  [Parameter(Mandatory = $true)][string]$ExtensionId,
  [Parameter(Mandatory = $true)][string]$ServerUrl,
  [Parameter(Mandatory = $true)][string]$AgentId,
  [Parameter(Mandatory = $true)][string]$AgentKey,
  # Full path to the host executable: a PyInstaller skdlp_host.exe (recommended)
  # or a .bat launcher that runs the Python script.
  [Parameter(Mandatory = $true)][string]$HostCommand,
  [ValidateSet('chrome', 'edge', 'both')][string]$Browser = 'both',
  [ValidateSet('user', 'machine')][string]$Scope = 'machine'
)
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:ProgramData 'SeceoKnight'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# 1) Native-messaging host manifest ------------------------------------------
$manifestPath = Join-Path $dir 'com.seceoknightdlp.dlp.json'
[ordered]@{
  name            = 'com.seceoknightdlp.dlp'
  description     = 'SeceoKnight DLP native messaging host (cloud upload guard)'
  path            = $HostCommand
  type            = 'stdio'
  allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII -Path $manifestPath
Write-Host "[+] Host manifest : $manifestPath"

# 2) Registry registration ----------------------------------------------------
$root = if ($Scope -eq 'machine') { 'HKLM:' } else { 'HKCU:' }
$keys = @()
if ($Browser -in 'chrome', 'both') { $keys += "$root\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.seceoknightdlp.dlp" }
if ($Browser -in 'edge',   'both') { $keys += "$root\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.seceoknightdlp.dlp" }
foreach ($k in $keys) {
  New-Item -Path $k -Force | Out-Null
  Set-ItemProperty -Path $k -Name '(Default)' -Value $manifestPath
  Write-Host "[+] Registered    : $k"
}

# 3) Host config (server URL + agent credentials) -----------------------------
$cfgPath = Join-Path $dir 'dlp-host.json'
[ordered]@{
  server_url = $ServerUrl
  agent_id   = $AgentId
  agent_key  = $AgentKey
} | ConvertTo-Json | Set-Content -Encoding ASCII -Path $cfgPath
Write-Host "[+] Host config   : $cfgPath"

Write-Host ""
Write-Host "Done. Fully close and reopen the browser, then test an upload." -ForegroundColor Green
Write-Host "Host log will appear at: $(Join-Path $dir 'dlp-host.log')"
