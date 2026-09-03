# SeceoKnight DLP Agent  - Windows installation script
# Requires Administrator privileges.
#
# Usage (one-liner):
#   powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
#
# What this script does:
#   1. Validates server connectivity (IP or DNS hostname).
#   2. Cleans previous installs (scheduled task, service, running process).
#   3. Installs Chocolatey + Tesseract + Poppler for OCR (screenshots,
#      image files, USB-transferred images, clipboard paste, and PDFs  -
#      only if missing).
#   4. Downloads seceoknight_agent.exe from the repo, verifies its
#      SHA-256 against the sidecar manifest in the repo, and refuses to
#      install if the hash doesn't match. Also downloads skdlp_host.exe
#      (the browser extension's native-messaging host, pre-built in CI --
#      see Step 5b) the same way -- no Python/PyInstaller needed on this
#      PC. The extension itself, and skdlp_host's registration as a
#      Chrome/Edge native-messaging host, are then applied automatically
#      by the agent's own "Browser Extension Guard" scheduled task
#      (Step 9) every 2 minutes -- nothing else to run for this.
#   5. Optional Authenticode signature check (warn-only until an EV
#      signing cert is provisioned).
#   6. Writes agent_config.json. No VBScript launcher for either the main
#      agent or its watchdog -- both scheduled tasks call the exe directly
#      (--bg / --watchdog-check) so there's no script host for Windows
#      Application Control / Smart App Control to block.
#   7. Registers a Windows Scheduled Task that runs at logon + startup.
#   8. Starts the agent.
#
# Tested on: Windows 10 22H2, Windows 11 23H2/24H2, Windows Server 2019/2022.

#Requires -RunAsAdministrator

# Configuration
$GITHUB_REPO = "Seceo-Knight/Seceoknight-DLP"
$INSTALL_DIR = "C:\Program Files\SeceoKnight"
$DATA_DIR = "C:\ProgramData\SeceoKnight"
$EXE_NAME = "seceoknight_agent.exe"
$CONFIG_NAME = "agent_config.json"
$TASK_NAME = "SeceoKnight DLP Agent"
$RAW_BASE = "https://raw.githubusercontent.com/$GITHUB_REPO/main"

# Colors for output
function Write-ColorOutput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    switch ($Type) {
        "Info"    { Write-Host $Message -ForegroundColor Cyan }
        "Success" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error"   { Write-Host $Message -ForegroundColor Red }
    }
}

function Test-ServerHost {
    # Accept either an IPv4 literal, "localhost", or an RFC1123 hostname
    # / FQDN. Operators in real environments use names like
    # `dlp.corp.local`, not just IPs.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -eq "localhost") { return $true }
    if ($Value -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
        return $true
    }
    # RFC1123 hostname / FQDN: labels of 1-63 alnum/hyphen, dot-separated,
    # total length <= 253. Each label can't start or end with a hyphen.
    if ($Value.Length -le 253 -and `
        $Value -match '^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') {
        return $true
    }
    return $false
}

function Test-PositiveInteger {
    param([string]$Value)
    $num = 0
    if ([int]::TryParse($Value, [ref]$num)) { return $num -gt 0 }
    return $false
}

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SeceoKnight DLP Agent - Windows Installation Script   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Configuration
Write-ColorOutput "Step 1: Configuration Setup" -Type "Info"
Write-Host ""

do {
    $serverIP = Read-Host "Enter server IP or hostname (default: localhost)"
    if ([string]::IsNullOrWhiteSpace($serverIP)) { $serverIP = "localhost" }
    if (-not (Test-ServerHost $serverIP)) {
        Write-ColorOutput "Invalid host. Use an IPv4 literal, 'localhost', or an RFC1123 hostname/FQDN." -Type "Error"
    }
} while (-not (Test-ServerHost $serverIP))

$serverURL = "http://${serverIP}:80/api/v1"
Write-ColorOutput "Server URL: $serverURL" -Type "Success"
Write-Host ""

# Trust self-signed certs for health check
try {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
} catch {}

# Test server connectivity
Write-ColorOutput "Testing server connectivity..." -Type "Info"
try {
    $healthUrl = "http://${serverIP}/api/v1/health"
    $resp = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 10
    if ($resp.status -eq "healthy") {
        Write-ColorOutput "Server is healthy" -Type "Success"
    }
} catch {
    Write-ColorOutput "Could not reach server at $healthUrl - continuing anyway" -Type "Warning"
}
Write-Host ""

$defaultAgentName = $env:COMPUTERNAME
$agentName = Read-Host "Enter Agent Name (default: $defaultAgentName)"
if ([string]::IsNullOrWhiteSpace($agentName)) { $agentName = $defaultAgentName }
Write-ColorOutput "Agent Name: $agentName" -Type "Success"
Write-Host ""

do {
    $heartbeatInput = Read-Host "Enter heartbeat interval in seconds (default: 30)"
    if ([string]::IsNullOrWhiteSpace($heartbeatInput)) { $heartbeatInterval = 30; break }
    if (-not (Test-PositiveInteger $heartbeatInput)) {
        Write-ColorOutput "Please enter a valid positive number." -Type "Error"
    } else { $heartbeatInterval = [int]$heartbeatInput; break }
} while ($true)
Write-ColorOutput "Heartbeat Interval: $heartbeatInterval seconds" -Type "Success"
Write-Host ""

do {
    $policySyncInput = Read-Host "Enter policy sync interval in seconds (default: 60)"
    if ([string]::IsNullOrWhiteSpace($policySyncInput)) { $policySyncInterval = 60; break }
    if (-not (Test-PositiveInteger $policySyncInput)) {
        Write-ColorOutput "Please enter a valid positive number." -Type "Error"
    } else { $policySyncInterval = [int]$policySyncInput; break }
} while ($true)
Write-ColorOutput "Policy Sync Interval: $policySyncInterval seconds" -Type "Success"
Write-Host ""

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "Configuration Summary:" -ForegroundColor Yellow
Write-Host "  Server URL:          $serverURL"
Write-Host "  Agent Name:          $agentName"
Write-Host "  Heartbeat Interval:  $heartbeatInterval seconds"
Write-Host "  Policy Sync:         $policySyncInterval seconds"
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Proceed with installation? (Y/N)"
if ($confirm -ne "Y" -and $confirm -ne "y") {
    Write-ColorOutput "Installation cancelled by user." -Type "Warning"
    exit 0
}

Write-Host ""

# Step 2: Remove old installations
Write-ColorOutput "Step 2: Removing previous installations..." -Type "Info"

# Tell the server this machine's OLD agent identity is retired, before we
# kill the process and (later, on a real uninstall) wipe the file that
# identity lives in. Stop-Process -Force below is a hard kill — it never
# gives the running agent a chance to run its own graceful-shutdown /
# unregister code, so without this the server is left with a permanently
# stale "ghost" row every time this script re-runs on a machine that was
# previously installed and then had ProgramData cleared (or is simply
# being re-keyed). That ghost row never disappears from the Agents view
# on its own (it's a normal audit-retained record, not an active-heartbeat
# filter), so an admin ends up having to notice and delete it by hand —
# exactly the "duplicate agent" symptom this closes.
$existingKeyPath = Join-Path $DATA_DIR "agent_key.json"
$oldConfigPath   = Join-Path $INSTALL_DIR $CONFIG_NAME
if (Test-Path $existingKeyPath) {
    try {
        $existingKey = Get-Content -Raw -Path $existingKeyPath | ConvertFrom-Json
        $oldAgentId  = $existingKey.agent_id
        $oldApiKey   = $existingKey.api_key

        # Unregister against whatever server the PREVIOUS install actually
        # talked to (its own agent_config.json), not the server URL just
        # entered above — they're usually the same, but if this run is
        # re-pointing the machine at a different server, the old identity
        # only exists on the old one.
        $oldServerUrl = $serverURL
        if (Test-Path $oldConfigPath) {
            try {
                $oldCfg = Get-Content -Raw -Path $oldConfigPath | ConvertFrom-Json
                if ($oldCfg.server_url) { $oldServerUrl = $oldCfg.server_url }
            } catch {}
        }

        if ($oldAgentId) {
            try {
                $headers = @{}
                if ($oldApiKey) { $headers["X-Agent-Key"] = $oldApiKey }
                Invoke-RestMethod -Method Delete `
                    -Uri "$($oldServerUrl.TrimEnd('/'))/agents/$oldAgentId/unregister" `
                    -Headers $headers -TimeoutSec 10 -ErrorAction Stop | Out-Null
                Write-ColorOutput "  Unregistered previous agent identity ($oldAgentId) from $oldServerUrl" -Type "Success"
            } catch {
                # Best-effort only — server may be unreachable, already gone,
                # or this may be the very first install on a fresh server.
                # Never block the (re)install on this.
                Write-ColorOutput "  Could not unregister previous agent identity (non-fatal): $($_.Exception.Message)" -Type "Warning"
            }
        }
    } catch {
        Write-ColorOutput "  Could not read $existingKeyPath (non-fatal): $($_.Exception.Message)" -Type "Warning"
    }
}

Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName "SeceoKnightAgent" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SeceoKnightAgent" -Confirm:$false -ErrorAction SilentlyContinue
$svc = Get-Service -Name "SeceoKnightAgent" -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service "SeceoKnightAgent" -Force -ErrorAction SilentlyContinue
    sc.exe delete "SeceoKnightAgent" 2>$null
}
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Write-ColorOutput "Previous installations cleaned" -Type "Success"
Write-Host ""

# Step 3: Create directories
Write-ColorOutput "Step 3: Creating installation directories..." -Type "Info"

foreach ($d in @($INSTALL_DIR, "$DATA_DIR\logs", "$DATA_DIR\quarantine", "$DATA_DIR\cache")) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}
Write-ColorOutput "Directories created" -Type "Success"
Write-Host ""

# Step 4: Install OCR dependencies (Chocolatey + Tesseract + Poppler)
# Tesseract is used by the screen-capture classifier as its Stage 4 OCR
# fallback  - it lets the agent read text from a screenshot when window-
# text extraction doesn't find anything. It's also used to OCR image
# files being written/saved, copied to USB, or pasted from the
# clipboard. Poppler (pdftotext + pdftoppm) extends that coverage to
# PDFs: pdftotext reads a PDF's embedded text layer directly when one
# exists, and pdftoppm rasterizes scanned/photo-only PDF pages so
# Tesseract can OCR them.
Write-ColorOutput "Step 4: Installing OCR dependencies (Chocolatey + Tesseract + Poppler)..." -Type "Info"

function Test-CommandExists {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Install-Chocolatey {
    Write-ColorOutput "  Chocolatey not found  - installing..." -Type "Warning"
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        # TLS 1.2 is required by chocolatey.org
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        # Refresh PATH for this session so `choco` is callable immediately.
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path    = "$machinePath;$userPath"
        if (Test-Path "$env:ProgramData\chocolatey\bin") {
            $env:Path = "$env:ProgramData\chocolatey\bin;$env:Path"
        }

        if (Test-CommandExists "choco") {
            Write-ColorOutput "  Chocolatey installed successfully" -Type "Success"
            return $true
        } else {
            Write-ColorOutput "  Chocolatey install ran but 'choco' is not on PATH yet" -Type "Warning"
            Write-ColorOutput "  You may need to open a new PowerShell window after install completes" -Type "Warning"
            return $false
        }
    } catch {
        Write-ColorOutput "  Failed to install Chocolatey: $($_.Exception.Message)" -Type "Error"
        return $false
    }
}

function Install-Tesseract {
    Write-ColorOutput "  Tesseract not found  - installing via choco..." -Type "Warning"
    try {
        # -y auto-confirms; --no-progress keeps logs clean
        $proc = Start-Process -FilePath "choco" `
                              -ArgumentList "install","tesseract","-y","--no-progress" `
                              -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-ColorOutput "  choco install tesseract exited with code $($proc.ExitCode)" -Type "Warning"
        }

        # Refresh PATH so `tesseract` is callable in this session.
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path    = "$machinePath;$userPath"

        # The chocolatey package drops tesseract into Program Files\Tesseract-OCR
        $tessDir = "C:\Program Files\Tesseract-OCR"
        if ((Test-Path "$tessDir\tesseract.exe") -and ($env:Path -notlike "*$tessDir*")) {
            $env:Path = "$tessDir;$env:Path"
        }

        if (Test-CommandExists "tesseract") {
            $ver = & tesseract --version 2>&1 | Select-Object -First 1
            Write-ColorOutput "  Tesseract installed: $ver" -Type "Success"
            return $true
        } else {
            Write-ColorOutput "  Tesseract install ran but 'tesseract' is not on PATH yet" -Type "Warning"
            Write-ColorOutput "  A reboot or new PowerShell session may be required" -Type "Warning"
            return $false
        }
    } catch {
        Write-ColorOutput "  Failed to install Tesseract: $($_.Exception.Message)" -Type "Error"
        return $false
    }
}

function Install-Poppler {
    Write-ColorOutput "  Poppler not found  - installing via choco..." -Type "Warning"
    try {
        # -y auto-confirms; --no-progress keeps logs clean
        $proc = Start-Process -FilePath "choco" `
                              -ArgumentList "install","poppler","-y","--no-progress" `
                              -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-ColorOutput "  choco install poppler exited with code $($proc.ExitCode)" -Type "Warning"
        }

        # Refresh PATH so `pdftotext`/`pdftoppm` are callable in this session.
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path    = "$machinePath;$userPath"

        if (Test-CommandExists "pdftotext") {
            Write-ColorOutput "  Poppler installed (pdftotext, pdftoppm available)" -Type "Success"
            return $true
        } else {
            Write-ColorOutput "  Poppler install ran but 'pdftotext' is not on PATH yet" -Type "Warning"
            Write-ColorOutput "  A reboot or new PowerShell session may be required" -Type "Warning"
            return $false
        }
    } catch {
        Write-ColorOutput "  Failed to install Poppler: $($_.Exception.Message)" -Type "Error"
        return $false
    }
}

# 4a. Chocolatey
if (Test-CommandExists "choco") {
    $chocoVer = (& choco --version 2>&1 | Select-Object -First 1)
    Write-ColorOutput "  Chocolatey already installed (v$chocoVer)" -Type "Success"
    $chocoOk = $true
} else {
    $chocoOk = Install-Chocolatey
}

# 4b. Tesseract (only if choco is now available)
if ($chocoOk) {
    if (Test-CommandExists "tesseract") {
        $tessVer = (& tesseract --version 2>&1 | Select-Object -First 1)
        Write-ColorOutput "  Tesseract already installed: $tessVer" -Type "Success"
    } else {
        $tessOk = Install-Tesseract
        if (-not $tessOk) {
            Write-ColorOutput "  Tesseract install incomplete  - screenshot OCR fallback will be disabled" -Type "Warning"
            Write-ColorOutput "  After this script finishes, run: choco install tesseract -y" -Type "Warning"
        }
    }
} else {
    Write-ColorOutput "  Skipping Tesseract  - Chocolatey is not available" -Type "Warning"
    Write-ColorOutput "  Install manually from https://github.com/UB-Mannheim/tesseract/wiki, then re-run this script" -Type "Warning"
}

# 4c. Poppler (pdftotext + pdftoppm  - PDF text extraction and OCR fallback for scanned PDFs)
if ($chocoOk) {
    if (Test-CommandExists "pdftotext") {
        Write-ColorOutput "  Poppler already installed" -Type "Success"
    } else {
        $popplerOk = Install-Poppler
        if (-not $popplerOk) {
            Write-ColorOutput "  Poppler install incomplete  - PDF text/OCR extraction will be disabled" -Type "Warning"
            Write-ColorOutput "  After this script finishes, run: choco install poppler -y" -Type "Warning"
        }
    }
} else {
    Write-ColorOutput "  Skipping Poppler  - Chocolatey is not available" -Type "Warning"
    Write-ColorOutput "  Install manually from https://github.com/oschwartz10612/poppler-windows/releases, then re-run this script" -Type "Warning"
}

Write-Host ""

# Step 5: Download agent binary (with SHA-256 integrity check)
Write-ColorOutput "Step 5: Downloading agent from GitHub..." -Type "Info"

$exePath      = Join-Path $INSTALL_DIR $EXE_NAME
$downloadUrl  = "$RAW_BASE/agents/endpoint/windows/$EXE_NAME"
$sumUrl       = "$RAW_BASE/agents/endpoint/windows/$EXE_NAME.sha256"

try {
    Write-ColorOutput "Downloading binary: $downloadUrl" -Type "Info"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing
    $fileSize = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-ColorOutput "Binary downloaded ($fileSize MB)" -Type "Success"
} catch {
    Write-ColorOutput "Error downloading agent: $($_.Exception.Message)" -Type "Error"
    Write-ColorOutput "Please check internet connection and GitHub repository access" -Type "Warning"
    exit 1
}

# SECURITY: verify the binary's SHA-256 against the sidecar file checked
# into the repo. If the sidecar is not yet published (first-time rollout),
# emit a clear warning but continue  - the operator can gate deployment on
# signed releases once the sidecar is in place.
$expectedHash = $null
try {
    Write-ColorOutput "Fetching integrity manifest: $sumUrl" -Type "Info"
    $expectedHash = (Invoke-WebRequest -Uri $sumUrl -UseBasicParsing -ErrorAction Stop).Content.Trim().Split()[0].ToUpper()
} catch {
    Write-ColorOutput "WARNING: no SHA-256 sidecar at $sumUrl  - skipping integrity check." -Type "Warning"
    Write-ColorOutput "  Create one at repo root/.../seceoknight_agent.exe.sha256 to gate installs." -Type "Warning"
}

if ($expectedHash) {
    $actualHash = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash.ToUpper()
    if ($actualHash -ne $expectedHash) {
        Write-ColorOutput "CRITICAL: SHA-256 mismatch  - refusing to install a tampered binary." -Type "Error"
        Write-ColorOutput "  expected: $expectedHash" -Type "Error"
        Write-ColorOutput "  actual  : $actualHash"   -Type "Error"
        Remove-Item $exePath -Force -ErrorAction SilentlyContinue
        exit 2
    }
    Write-ColorOutput "SHA-256 verified: $actualHash" -Type "Success"
}

# Optional: Authenticode signature check. Only warn if unsigned so
# unsigned dev builds still install; flip to `exit 3` once a signing
# cert is provisioned.
try {
    $sig = Get-AuthenticodeSignature -FilePath $exePath
    if ($sig.Status -eq 'Valid') {
        Write-ColorOutput "Authenticode signature OK (signer: $($sig.SignerCertificate.Subject))" -Type "Success"
    } else {
        Write-ColorOutput "WARNING: Authenticode status = $($sig.Status). Binary is not code-signed." -Type "Warning"
    }
} catch {
    Write-ColorOutput "Authenticode check skipped: $($_.Exception.Message)" -Type "Warning"
}
Write-Host ""

# Step 5b: Download the browser-extension native-messaging host (skdlp_host.exe)
# This used to be a separate manual build (pip install pyinstaller + `pyinstaller
# --onefile skdlp_host.py`, per the README's old Step 5.4) that every endpoint
# needed Python for. It's now built once in CI (see
# .github/workflows/build-windows-agent.yml) and published in the repo next to
# seceoknight_agent.exe, so it downloads the same way -- no Python needed on
# this PC at all. The elevated "Browser Extension Guard" scheduled task
# (registered in Step 9 below) auto-registers it as the Chrome/Edge native
# messaging host once it sees this file on disk, using whatever extension is
# currently published on the server -- see WriteNativeMessagingHostRegistration()
# in agent.cpp. Non-fatal if this fails (e.g. an older repo state without a
# published skdlp_host.exe yet): the endpoint agent itself still installs fine,
# just without cloud-upload/web-activity browser protection until a later
# Update-Agent run picks it up.
Write-ColorOutput "Step 5b: Downloading browser-extension native host..." -Type "Info"

$hostExeName    = "skdlp_host.exe"
$hostExePath    = Join-Path $INSTALL_DIR $hostExeName
$hostDownloadUrl = "$RAW_BASE/agents/browser-extension/native-host/$hostExeName"
$hostSumUrl      = "$RAW_BASE/agents/browser-extension/native-host/$hostExeName.sha256"

try {
    Invoke-WebRequest -Uri $hostDownloadUrl -OutFile $hostExePath -UseBasicParsing -ErrorAction Stop
    $hostExpectedHash = $null
    try {
        $hostExpectedHash = (Invoke-WebRequest -Uri $hostSumUrl -UseBasicParsing -ErrorAction Stop).Content.Trim().Split()[0].ToUpper()
    } catch {
        Write-ColorOutput "  No SHA-256 sidecar for $hostExeName yet -- skipping integrity check." -Type "Warning"
    }
    if ($hostExpectedHash) {
        $hostActualHash = (Get-FileHash -Algorithm SHA256 -Path $hostExePath).Hash.ToUpper()
        if ($hostActualHash -ne $hostExpectedHash) {
            Write-ColorOutput "CRITICAL: $hostExeName SHA-256 mismatch -- removing, browser protection will be disabled." -Type "Error"
            Remove-Item $hostExePath -Force -ErrorAction SilentlyContinue
        } else {
            $hostFileSize = [math]::Round((Get-Item $hostExePath).Length / 1MB, 1)
            Write-ColorOutput "  Native host downloaded and verified ($hostFileSize MB)" -Type "Success"
        }
    } elseif (Test-Path $hostExePath) {
        Write-ColorOutput "  Native host downloaded (unverified)" -Type "Success"
    }
} catch {
    Write-ColorOutput "  Could not download $hostExeName -- browser-extension protection will be disabled until a later Update-Agent run: $($_.Exception.Message)" -Type "Warning"
}
Write-Host ""

# Step 6: Set environment variable
Write-ColorOutput "Step 6: Setting environment variables..." -Type "Info"
[Environment]::SetEnvironmentVariable("SECEOKNIGHT_SERVER_URL", $serverURL, "Machine")
$env:SECEOKNIGHT_SERVER_URL = $serverURL
Write-ColorOutput "Environment variable set" -Type "Success"
Write-Host ""

# Step 7: Create configuration file
Write-ColorOutput "Step 7: Creating configuration file..." -Type "Info"

$configPath = Join-Path $INSTALL_DIR $CONFIG_NAME
$config = @{
    server_url = $serverURL
    agent_name = $agentName
    heartbeat_interval = $heartbeatInterval
    policy_sync_interval = $policySyncInterval
    monitoring = @{
        file_system = $true
        clipboard = $true
        usb_devices = $true
        screen_capture = $true
        print_jobs = $true
        monitored_paths = @(
            "C:\Users\$env:USERNAME\Documents",
            "C:\Users\$env:USERNAME\Desktop",
            "C:\Users\$env:USERNAME\Downloads"
        )
        file_extensions = @(".pdf", ".docx", ".xlsx", ".csv", ".txt", ".json", ".xml", ".sql", ".pem", ".key", ".env", ".conf")
    }
    quarantine_path = "$DATA_DIR\quarantine"
    log_path = "$DATA_DIR\logs"
    cache_path = "$DATA_DIR\cache"
}

$config | ConvertTo-Json -Depth 4 | Out-File -FilePath $configPath -Encoding UTF8 -Force
Write-ColorOutput "Configuration created: $configPath" -Type "Success"
Write-Host ""

# Step 8: (Skipped  - no VBScript launcher needed; exe has built-in --bg mode)
Write-ColorOutput "Step 8: Skipping VBScript launcher (exe has built-in background mode)..." -Type "Info"
Write-Host ""

# Step 9: Configure scheduled task
Write-ColorOutput "Step 9: Configuring auto-start scheduled task..." -Type "Info"

try {
    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
    }

    # Action: run the exe directly with --bg flag (hides console window).
    # Running directly (not via VBScript) means the scheduled task stays in
    # state "Running" for as long as the exe is alive.  When the exe exits
    # (crash / network failure / OS update), Task Scheduler sees the task
    # complete and the RestartCount setting automatically relaunches it.
    # The old VBScript pattern launched the exe asynchronously, exited
    # immediately, put the task in "Ready" state, and left nothing to
    # restart the exe if it crashed.
    $action = New-ScheduledTaskAction -Execute $exePath -Argument "--bg" -WorkingDirectory $INSTALL_DIR

    # Triggers: at logon, at startup (30-second boot delay)
    $triggerLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $triggerStartup = New-ScheduledTaskTrigger -AtStartup
    $triggerStartup.Delay = "PT30S"

    # Watchdog trigger: re-fires every 10 minutes, indefinitely. This is
    # what makes the agent self-heal from a CLEAN exit -- Task Scheduler's
    # RestartCount/RestartInterval below only apply when the task *fails*
    # (non-zero exit code). A graceful stop -- Ctrl+C during manual testing,
    # someone running Stop-ScheduledTask, a shutdown handshake that returns
    # 0 -- is not a "failure" to Task Scheduler, so it leaves the task
    # sitting in "Ready" state forever with nothing to bring it back except
    # a logon or reboot. That's exactly the "shows offline, had to manually
    # Start-ScheduledTask" symptom on a real endpoint. MultipleInstances
    # IgnoreNew (in $settings below) makes each tick a safe no-op while the
    # agent is already running; it only actually does anything when the
    # task has stopped for whatever reason.
    #
    # NOTE: [TimeSpan]::MaxValue (~29,247 years) is NOT valid here -- Task
    # Scheduler's XML schema rejects it ("Duration:P99999999DT23H59M59S ...
    # incorrectly formatted or out of range"), and Register-ScheduledTask
    # raises that as a NON-terminating error, so the script sailed past it,
    # printed "Scheduled task created successfully!", and left NO task
    # registered at all -- worse than the bug this was meant to fix. 10
    # years is comfortably "indefinite" for any real deployment and is
    # well within the schema's accepted range.
    $triggerWatchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 10) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    # Principal: run at normal user privilege (Interactive, RunLevel Limited).
    # This is essential  - clipboard hooks and keyboard/mouse event monitoring
    # require the process to run in the same security context as the desktop.
    # Running elevated (RunLevel Highest) isolates the process from non-elevated
    # apps and silently breaks all hook-based monitoring.  USB block via registry
    # is the only feature that needs elevation; it is handled by a separate
    # one-shot elevated task below.
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

    # Settings: no execution time limit, restart automatically on crash
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -DontStopOnIdleEnd `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([System.TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew

    # -ErrorAction Stop is deliberate: Register-ScheduledTask raises a
    # NON-terminating error by default (e.g. the invalid-Duration bug this
    # comment sits next to), which a bare try/catch does NOT catch — the
    # script would print "success" below regardless of whether the task
    # was actually created. Forcing it terminating makes the catch block
    # below actually mean something.
    Register-ScheduledTask `
        -TaskName $TASK_NAME `
        -Action $action `
        -Trigger @($triggerLogon, $triggerStartup, $triggerWatchdog) `
        -Principal $principal `
        -Settings $settings `
        -Description "SeceoKnight DLP Agent - Data Loss Prevention monitoring (clipboard, USB, files, screen capture)" `
        -Force -ErrorAction Stop | Out-Null

    Write-ColorOutput "Scheduled task created successfully!" -Type "Success"
    Write-ColorOutput "Task Name: $TASK_NAME" -Type "Info"
    Write-ColorOutput "Agent will start automatically at logon and restart if it ever stops." -Type "Success"
} catch {
    Write-ColorOutput "Error configuring scheduled task: $($_.Exception.Message)" -Type "Error"
    exit 1
}
Write-Host ""

# Step 9b: Health-check watchdog -- catches a HUNG (not exited) agent process.
#
# Real incident (2026-07-31): an endpoint's agent process deadlocked (still
# alive, still "Responding" per Get-Process, but stopped logging and stopped
# heartbeating) and sat that way for 2+ hours. The main task's 10-minute
# watchdog trigger above WAS firing on schedule the whole time, but
# Get-ScheduledTaskInfo showed LastTaskResult 0x800710E0 ("the operator or
# administrator has refused the request") on every single attempt --
# MultipleInstances=IgnoreNew treats "process still alive" as "healthy" and
# refuses to start a replacement, so a genuinely hung process defeats that
# watchdog completely. RestartCount/RestartInterval don't help either --
# those only fire on a non-zero exit code, and a hung process never exits.
#
# Switching the main task to MultipleInstances=StopExisting was considered
# and rejected: that trigger fires unconditionally every 10 minutes, so it
# would force-kill and restart a perfectly HEALTHY agent as routine churn
# every 10 minutes forever, which is worse than the bug it'd fix.
#
# This is a genuinely different check: a separate task on its own 5-minute
# cadence that looks at a real liveness signal (has the log file been
# written to recently -- the agent logs at least once per heartbeat, every
# 30s when healthy) before ever touching the process. Only force-kills when
# the log has actually gone stale, so a healthy agent is never touched.
#
# Four rounds of console-flash fixes on THIS task (Interactive -> S4U logon,
# then wrapping powershell.exe in a VBScript host with SW_HIDE, then moving
# the whole staleness check into VBScript/COM so no interpreter was ever
# spawned on the healthy path, then LogonType ServiceAccount as SYSTEM once
# S4U turned out to fail entirely for Azure AD-joined accounts) ended with
# the task calling `wscript.exe watchdog_launcher.vbs`. That held up in the
# lab, but failed silently in the field: Windows 11's Application Control
# and Smart App Control block script hosts (wscript.exe/cscript.exe) by
# default, so on any endpoint under that policy the task never ran at all --
# "An Application Control policy has blocked this file" -- meaning this
# entire hang-detector was silently disabled with no symptom short of
# noticing a hung agent stayed hung. Identical root cause and identical fix
# to CyberSentinel-DLP's own launch_agent.vbs problem on their main task
# (ported here Aug 18, 2026 evening -- see CHANGELOG.md).
#
# Fix: no script host at all. The staleness-check logic now lives natively
# in agent.cpp (HandleWatchdogCheck(), invoked as `seceoknight_agent.exe
# --watchdog-check`) instead of a VBScript. This preserves the "zero
# console, ever" property the .vbs chain was built four times over to get
# -- the agent binary is already GUI-subsystem (see agent.cpp's
# AttachForegroundConsole) -- while removing the one thing Application
# Control was actually blocking. It's also the one binary Application
# Control already has to allow on this endpoint, since it's the main agent
# itself, so there's nothing left for a script policy to catch.
Write-ColorOutput "Step 9b: Configuring agent health-check watchdog..." -Type "Info"
try {
    $watchdogTaskName = "SeceoKnight DLP Watchdog"

    # Dead weight from any older install -- Windows keeps complaining about
    # (or, under Application Control, silently refusing to run) both of
    # these. Take them with us; agent.cpp's HandleWatchdogCheck() is the
    # only thing the watchdog task calls now.
    $legacyWatchdogVbs = Join-Path $INSTALL_DIR "watchdog_launcher.vbs"
    $legacyWatchdogPs1 = Join-Path $INSTALL_DIR "watchdog.ps1"
    foreach ($legacy in @($legacyWatchdogVbs, $legacyWatchdogPs1)) {
        if (Test-Path $legacy) {
            Remove-Item $legacy -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "Removed legacy watchdog launcher: $legacy" -Type "Info"
        }
    }

    $existingWatchdog = Get-ScheduledTask -TaskName $watchdogTaskName -ErrorAction SilentlyContinue
    if ($existingWatchdog) {
        Unregister-ScheduledTask -TaskName $watchdogTaskName -Confirm:$false
    }

    $watchdogAction = New-ScheduledTaskAction -Execute $exePath -Argument "--watchdog-check" `
        -WorkingDirectory $INSTALL_DIR

    $watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    # LogonType ServiceAccount running as SYSTEM (not per-user S4U -- see
    # the block comment above on why S4U reliably fails for Azure AD/Entra
    # ID-joined accounts). Same pattern the USB-block task below already
    # uses successfully. SYSTEM sidesteps user credential logon entirely,
    # works whether or not anyone is logged into the desktop, and has more
    # than enough rights for everything --watchdog-check does (read a
    # ProgramData log file, query/kill the agent process by PID, re-trigger
    # the main agent task via schtasks -- none of that requires being the
    # specific logged-on user).
    $watchdogPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $watchdogSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $watchdogTaskName `
        -Action $watchdogAction `
        -Trigger $watchdogTrigger `
        -Principal $watchdogPrincipal `
        -Settings $watchdogSettings `
        -Description "Detects a hung (alive-but-unresponsive) SeceoKnight DLP Agent process via log staleness and force-restarts it. Complements the main task's own restart triggers, which only fire on a clean exit or crash -- neither covers a deadlocked process that never exits." `
        -Force -ErrorAction Stop | Out-Null

    Write-ColorOutput "Watchdog task created: $watchdogTaskName (checks every 5 minutes)" -Type "Success"
} catch {
    Write-ColorOutput "Warning: Could not create watchdog task: $($_.Exception.Message)" -Type "Warning"
    Write-ColorOutput "The agent will still work, but won't self-recover from a hang (only from a clean exit or crash)." -Type "Warning"
}
Write-Host ""

try {
    # -- USB block: one-shot elevated task at startup -------------------------
    # The main agent runs at normal privilege (required for clipboard/hooks).
    # USB drive blocking via the USBSTOR registry key needs elevation.
    # Register a separate task that runs once at startup as SYSTEM to set it.
    $usbTaskName = "SeceoKnight DLP USB Block"
    try {
        $usbAction = New-ScheduledTaskAction `
            -Execute "reg.exe" `
            -Argument 'add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f'

        $usbTrigger = New-ScheduledTaskTrigger -AtStartup
        $usbTrigger.Delay = "PT10S"

        $usbPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        $usbSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        $existingUsb = Get-ScheduledTask -TaskName $usbTaskName -ErrorAction SilentlyContinue
        if ($existingUsb) { Unregister-ScheduledTask -TaskName $usbTaskName -Confirm:$false }

        Register-ScheduledTask `
            -TaskName $usbTaskName `
            -Action $usbAction `
            -Trigger $usbTrigger `
            -Principal $usbPrincipal `
            -Settings $usbSettings `
            -Description "SeceoKnight DLP - Disable USB storage at boot (requires SYSTEM elevation)" `
            -Force | Out-Null

        Write-ColorOutput "USB block task created: $usbTaskName" -Type "Success"
    } catch {
        Write-ColorOutput "Could not create USB block task (non-fatal): $($_.Exception.Message)" -Type "Warning"
    }

    # -- CLI Guard: one-shot elevated task at startup (task #142/#145) -------
    # Same problem as USB block above: the main agent task runs unelevated
    # (required for clipboard/hooks), but the CLI Guard zero-race feature's
    # Image File Execution Options "Debugger" redirects need HKLM write
    # access a standard user's token does not have (confirmed live:
    # RegCreateKeyExA returns ACCESS_DENIED from the main task every time).
    # Register a separate task that runs once at startup as SYSTEM to write
    # them via `seceoknight_agent.exe --apply-ifeo-guards`.
    $cliGuardTaskName = "SeceoKnight DLP CLI Guard"
    try {
        $cliGuardAction = New-ScheduledTaskAction `
            -Execute $exePath `
            -Argument "--apply-ifeo-guards" `
            -WorkingDirectory $INSTALL_DIR

        $cliGuardTrigger = New-ScheduledTaskTrigger -AtStartup
        $cliGuardTrigger.Delay = "PT15S"

        $cliGuardPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        $cliGuardSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        $existingCliGuard = Get-ScheduledTask -TaskName $cliGuardTaskName -ErrorAction SilentlyContinue
        if ($existingCliGuard) { Unregister-ScheduledTask -TaskName $cliGuardTaskName -Confirm:$false }

        Register-ScheduledTask `
            -TaskName $cliGuardTaskName `
            -Action $cliGuardAction `
            -Trigger $cliGuardTrigger `
            -Principal $cliGuardPrincipal `
            -Settings $cliGuardSettings `
            -Description "SeceoKnight DLP - Register CLI Guard zero-race pre-launch IFEO redirects (requires SYSTEM elevation)" `
            -Force | Out-Null

        Write-ColorOutput "CLI Guard task created: $cliGuardTaskName" -Type "Success"

        # Also run it immediately (best-effort) rather than making the user
        # wait for the next reboot to see CLI Guard actually take effect.
        try { Start-ScheduledTask -TaskName $cliGuardTaskName } catch {}
    } catch {
        Write-ColorOutput "Could not create CLI Guard task (non-fatal): $($_.Exception.Message)" -Type "Warning"
    }

    # -- Wireless Guard: repeating elevated task (task #147) -----------------
    # Same unelevated-process problem as CLI Guard above, but wireless
    # control is POLICY-DRIVEN (can change any time the server config
    # changes), so a one-shot-at-startup task isn't enough -- this one
    # repeats every 2 minutes, reading the state the main agent task caches
    # to C:\ProgramData\SeceoKnight\logs\wireless_state.cache and applying
    # it via `seceoknight_agent.exe --apply-wireless-guard`.
    $wirelessGuardTaskName = "SeceoKnight DLP Wireless Guard"
    try {
        $wirelessGuardAction = New-ScheduledTaskAction `
            -Execute $exePath `
            -Argument "--apply-wireless-guard" `
            -WorkingDirectory $INSTALL_DIR

        $wirelessGuardTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes 2) `
            -RepetitionDuration (New-TimeSpan -Days 3650)

        $wirelessGuardPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        $wirelessGuardSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        $existingWirelessGuard = Get-ScheduledTask -TaskName $wirelessGuardTaskName -ErrorAction SilentlyContinue
        if ($existingWirelessGuard) { Unregister-ScheduledTask -TaskName $wirelessGuardTaskName -Confirm:$false }

        Register-ScheduledTask `
            -TaskName $wirelessGuardTaskName `
            -Action $wirelessGuardAction `
            -Trigger $wirelessGuardTrigger `
            -Principal $wirelessGuardPrincipal `
            -Settings $wirelessGuardSettings `
            -Description "SeceoKnight DLP - Reconcile Bluetooth/Nearby Sharing IFEO and policy state every 2 minutes (requires SYSTEM elevation)" `
            -Force | Out-Null

        Write-ColorOutput "Wireless Guard task created: $wirelessGuardTaskName" -Type "Success"

        # Best-effort immediate run -- will likely no-op on a fresh install
        # (no cached state yet until the main task's first successful sync),
        # but harmless, and picks up an existing cache instantly on upgrade.
        try { Start-ScheduledTask -TaskName $wirelessGuardTaskName } catch {}
    } catch {
        Write-ColorOutput "Could not create Wireless Guard task (non-fatal): $($_.Exception.Message)" -Type "Warning"
    }

    # -- Remove File Access Guard + audit setting if left over from an older
    # install -- the File Access Control feature (and its scheduled task)
    # was removed entirely after field testing found it unreliable (see
    # CHANGELOG.md). A machine that previously had it installed would
    # otherwise keep running a task with no server-side policy behind it.
    $legacyFileAccessGuardTaskName = "SeceoKnight DLP File Access Guard"
    $legacyFileAccessGuard = Get-ScheduledTask -TaskName $legacyFileAccessGuardTaskName -ErrorAction SilentlyContinue
    if ($legacyFileAccessGuard) {
        try {
            Unregister-ScheduledTask -TaskName $legacyFileAccessGuardTaskName -Confirm:$false
            Write-ColorOutput "Removed leftover File Access Guard task (feature removed)" -Type "Success"
        } catch {
            Write-ColorOutput "Could not remove leftover File Access Guard task (non-fatal): $($_.Exception.Message)" -Type "Warning"
        }
    }

    # -- Browser Extension Guard: repeating elevated task ---------------------
    # Gap-scan of CyberSentinel-DLP (August 18, 2026): the DLP browser
    # extension was previously only a manual "Load unpacked" dev-mode install,
    # something an end user could switch off in two clicks -- an unacceptable
    # property for a DLP control. Same unelevated-process problem as Wireless
    # Guard above, and force-install is likewise POLICY-DRIVEN (the published
    # extension id or target server can change any time), so this repeats
    # every 2 minutes, reading the state the main agent task caches to
    # C:\ProgramData\SeceoKnight\logs\browser_extension_state.cache and
    # applying it via `seceoknight_agent.exe --apply-browser-extension-guard`.
    #
    # A no-op (does nothing, exits cleanly) on a server that hasn't published
    # an extension yet (run scripts/pack-extension.py on the DLP server to do
    # that) -- registering this task is safe even before you've packed one.
    $extGuardTaskName = "SeceoKnight DLP Browser Extension Guard"
    try {
        $extGuardAction = New-ScheduledTaskAction `
            -Execute $exePath `
            -Argument "--apply-browser-extension-guard" `
            -WorkingDirectory $INSTALL_DIR

        $extGuardTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes 2) `
            -RepetitionDuration (New-TimeSpan -Days 3650)

        $extGuardPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        $extGuardSettings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        $existingExtGuard = Get-ScheduledTask -TaskName $extGuardTaskName -ErrorAction SilentlyContinue
        if ($existingExtGuard) { Unregister-ScheduledTask -TaskName $extGuardTaskName -Confirm:$false }

        Register-ScheduledTask `
            -TaskName $extGuardTaskName `
            -Action $extGuardAction `
            -Trigger $extGuardTrigger `
            -Principal $extGuardPrincipal `
            -Settings $extGuardSettings `
            -Description "SeceoKnight DLP - Force-install the DLP browser extension (ExtensionInstallForcelist) and reconcile its managed config every 2 minutes (requires SYSTEM elevation)" `
            -Force | Out-Null

        Write-ColorOutput "Browser Extension Guard task created: $extGuardTaskName" -Type "Success"

        # Best-effort immediate run -- no-ops on a fresh install (no cached
        # state yet until the main task's first successful sync), but
        # harmless, and picks up an existing cache instantly on upgrade.
        try { Start-ScheduledTask -TaskName $extGuardTaskName } catch {}
    } catch {
        Write-ColorOutput "Could not create Browser Extension Guard task (non-fatal): $($_.Exception.Message)" -Type "Warning"
    }

} catch {
    Write-ColorOutput "Error creating scheduled task: $($_.Exception.Message)" -Type "Error"
    Write-ColorOutput "You can manually start it: Start-ScheduledTask -TaskName '$TASK_NAME'" -Type "Info"
}

Write-Host ""

# Step 9c: Grant print spool read access -- CONFIRMED LIVE root cause of
# print content inspection silently never detecting sensitive content: the
# main agent process deliberately runs at normal (non-elevated) user
# privilege (see Step 9's principal above -- required for clipboard/keyboard
# hooks, which silently break if the process is elevated). But reading the
# actual spooled print job data under
# %SystemRoot%\System32\spool\PRINTERS\ requires elevated/SYSTEM access by
# default -- regular users can't read raw .SPL files there even for their
# own print jobs, since they're created by the SYSTEM-level Print Spooler
# service with restrictive inherited ACLs. The agent's own diagnostic log
# confirmed this exactly: every print job, from every app, resolved to "no
# spool file resolved" and silently fell back to the (uninformative)
# document name instead of the real content -- not a parsing problem, an
# access problem.
#
# Elevating the whole agent process is not an option (breaks the hooks --
# same reasoning as the USB block task above). Instead, since this
# installer itself already runs elevated (#Requires -RunAsAdministrator at
# the top), grant the logged-in user explicit read+list access to the spool
# directory here, once, at install time -- with (OI)(CI) inheritance so
# every NEW spool file created after this point picks up the grant
# automatically, without needing to re-run this for each future print job.
Write-ColorOutput "Step 9c: Granting print spool read access..." -Type "Info"
try {
    $spoolDir = "$env:SystemRoot\System32\spool\PRINTERS"
    $icaclsResult = icacls $spoolDir /grant "${env:USERNAME}:(OI)(CI)RX" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "Granted $env:USERNAME read access to $spoolDir" -Type "Success"
    } else {
        Write-ColorOutput "icacls exited with code $LASTEXITCODE -- print content inspection may not be able to read job data. Output: $icaclsResult" -Type "Warning"
    }
} catch {
    Write-ColorOutput "Could not grant print spool read access (non-fatal): $($_.Exception.Message)" -Type "Warning"
    Write-ColorOutput "Print content inspection may silently fail to read job data as a result -- job detection and printer-control (device) blocking are unaffected." -Type "Warning"
}
Write-Host ""

# Step 10: Start the agent
Write-ColorOutput "Step 10: Starting the agent..." -Type "Info"

try {
    Start-ScheduledTask -TaskName $TASK_NAME
    Start-Sleep -Seconds 5

    $process = Get-Process -Name "seceoknight_agent" -ErrorAction SilentlyContinue
    if ($process) {
        Write-ColorOutput "Agent is running! (PID: $($process.Id))" -Type "Success"
        Write-ColorOutput "Running in background mode (no visible window)" -Type "Success"
    } else {
        Write-ColorOutput "Agent started, waiting for process to initialize..." -Type "Warning"
        Start-Sleep -Seconds 5
        $process = Get-Process -Name "seceoknight_agent" -ErrorAction SilentlyContinue
        if ($process) {
            Write-ColorOutput "Agent is running! (PID: $($process.Id))" -Type "Success"
        } else {
            Write-ColorOutput "Process not detected yet. Check logs for details." -Type "Warning"
        }
    }
} catch {
    Write-ColorOutput "Error starting agent: $($_.Exception.Message)" -Type "Error"
    Write-ColorOutput "You can manually start it: Start-ScheduledTask -TaskName '$TASK_NAME'" -Type "Info"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "           Installation Completed Successfully!            " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installation Details:" -ForegroundColor Yellow
Write-Host "  Location:        $INSTALL_DIR"
Write-Host "  Executable:      $EXE_NAME"
Write-Host "  Configuration:   $CONFIG_NAME"
Write-Host "  Scheduled Task:  $TASK_NAME"
Write-Host "  Runs As:         $env:USERNAME (normal user - required for clipboard/screen monitoring)"
Write-Host "  Server:          $serverURL"
Write-Host ""
Write-Host "Management Commands:" -ForegroundColor Yellow
Write-Host "  Start Agent:     Start-ScheduledTask -TaskName '$TASK_NAME'"
Write-Host "  Stop Agent:      Stop-Process -Name 'seceoknight_agent' -Force"
Write-Host "  Check Status:    Get-Process -Name 'seceoknight_agent'"
Write-Host "  View Logs:       Get-Content '$DATA_DIR\logs\seceoknight_agent.log' -Tail 30"
Write-Host "  OCR Diagnostics: Get-Content '$DATA_DIR\logs\ocr_diagnostics.log' -Tail 30"
Write-Host "  Disable Auto:    Disable-ScheduledTask -TaskName '$TASK_NAME'"
Write-Host "  Enable Auto:     Enable-ScheduledTask -TaskName '$TASK_NAME'"
Write-Host ""
Write-Host "Uninstall:" -ForegroundColor Yellow
Write-Host "  # Retire this machine's agent identity server-side FIRST -- once"
Write-Host "  # `$DATA_DIR\agent_key.json is deleted below, nothing can tell the"
Write-Host "  # server this device is gone, and it lingers in the Agents view."
Write-Host "  `$k = Get-Content -Raw '$DATA_DIR\agent_key.json' | ConvertFrom-Json"
Write-Host "  Invoke-RestMethod -Method Delete -Uri '$serverURL/agents/`$(`$k.agent_id)/unregister' -Headers @{'X-Agent-Key'=`$k.api_key}"
Write-Host "  Unregister-ScheduledTask -TaskName '$TASK_NAME' -Confirm:`$false"
Write-Host "  Unregister-ScheduledTask -TaskName 'SeceoKnight DLP USB Block' -Confirm:`$false"
Write-Host "  Stop-Process -Name 'seceoknight_agent' -Force"
Write-Host "  Remove-Item '$INSTALL_DIR' -Recurse -Force"
Write-Host "  Remove-Item '$DATA_DIR' -Recurse -Force"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"
