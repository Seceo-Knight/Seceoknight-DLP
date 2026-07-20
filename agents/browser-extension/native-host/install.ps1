<#
  SeceoKnight DLP - Cloud Upload Guard : Windows install helper.

  Configures the native-messaging host: writes the host manifest, registers it
  for Chrome/Edge, and writes the host's server/agent config. Run this AFTER you
  have loaded the extension (you need its Extension ID) and placed the host
  executable/launcher on disk.

  Run in an ELEVATED PowerShell (Run as administrator) for machine scope.

  -AgentId / -AgentKey are now OPTIONAL. If you omit them, this script reads
  them from the main SeceoKnight endpoint agent's own key file (which now
  persists its server-issued api_key  - see AgentConfig::SaveApiKeyFile in
  agent.cpp). That means at fleet scale you do NOT need to separately
  register a browser-extension identity per machine with a curl command: as
  long as the main agent is already installed and has registered at least
  once, this script just reuses its identity, and browser-extension events
  show up under the SAME agent record as the endpoint agent for that machine.
  Pass -AgentId/-AgentKey explicitly only if you want a distinct identity, or
  if this machine runs the browser extension without the main endpoint agent.

  Example (typical  - reuse the already-installed endpoint agent's identity):
    .\install.ps1 `
        -ExtensionId  ppkk...your-extension-id... `
        -ServerUrl    https://dlp.example.com/api/v1 `
        -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"

  Example (explicit / standalone identity):
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
  [string]$AgentId,
  [string]$AgentKey,
  # Where the main endpoint agent persists its own identity (written by
  # AgentConfig::SaveApiKeyFile() in agent.cpp, in C:\ProgramData\SeceoKnight
  # rather than Program Files  - the agent's scheduled task runs as a
  # standard, non-elevated user that can't write to Program Files). Used to
  # auto-discover -AgentId/-AgentKey when they aren't passed explicitly.
  [string]$AgentConfigPath = (Join-Path $env:ProgramData 'SeceoKnight\agent_key.json'),
  # Full path to the host executable: a PyInstaller skdlp_host.exe (recommended)
  # or a .bat launcher that runs the Python script.
  [Parameter(Mandatory = $true)][string]$HostCommand,
  [ValidateSet('chrome', 'edge', 'both')][string]$Browser = 'both',
  [ValidateSet('user', 'machine')][string]$Scope = 'machine'
)
$ErrorActionPreference = 'Stop'

# Auto-discover the identity to use from the main endpoint agent's own config
# when the caller didn't pass -AgentId/-AgentKey explicitly. This is what
# removes the need for a separate manual registration per machine at scale.
if (-not $AgentId -or -not $AgentKey) {
  if (Test-Path $AgentConfigPath) {
    try {
      $agentCfg = Get-Content -Raw -Path $AgentConfigPath | ConvertFrom-Json
      if (-not $AgentId -and $agentCfg.agent_id) { $AgentId = $agentCfg.agent_id }
      if (-not $AgentKey -and $agentCfg.api_key) { $AgentKey = $agentCfg.api_key }
      if ($AgentId -and $AgentKey) {
        Write-Host "[+] Reusing endpoint agent identity from: $AgentConfigPath (agent_id=$AgentId)"
      }
    } catch {
      Write-Warning "Could not parse $AgentConfigPath : $($_.Exception.Message)"
    }
  }
}

if (-not $AgentId -or -not $AgentKey) {
  throw ("Could not determine -AgentId/-AgentKey. Either: (1) make sure the main " +
         "SeceoKnight agent is installed and has registered at least once (its " +
         "config at '$AgentConfigPath' should then contain agent_id + api_key  - " +
         "an older agent build that predates api_key persistence won't have one, " +
         "in which case reinstall/update the agent first), or (2) pass -AgentId " +
         "and -AgentKey explicitly for a standalone browser-extension identity.")
}

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
