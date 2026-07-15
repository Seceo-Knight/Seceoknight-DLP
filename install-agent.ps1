# SeceoKnight DLP Agent — Windows installation script
# Requires Administrator privileges.
#
# Usage (one-liner):
#   powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
#
# What this script does:
#   1. Validates server connectivity (IP or DNS hostname).
#   2. Cleans previous installs (scheduled task, service, running process).
#   3. Installs Chocolatey + Tesseract + Poppler for OCR (screenshots,
#      image files, USB-transferred images, clipboard paste, and PDFs —
#      only if missing).
#   4. Downloads seceoknight_agent.exe from the repo, verifies its
#      SHA-256 against the sidecar manifest in the repo, and refuses to
#      install if the hash doesn't match.
#   5. Optional Authenticode signature check (warn-only until an EV
#      signing cert is provisioned).
#   6. Writes agent_config.json + a hidden VBScript launcher.
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
# fallback — it lets the agent read text from a screenshot when window-
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
    Write-ColorOutput "  Chocolatey not found — installing..." -Type "Warning"
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
    Write-ColorOutput "  Tesseract not found — installing via choco..." -Type "Warning"
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
    Write-ColorOutput "  Poppler not found — installing via choco..." -Type "Warning"
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
            Write-ColorOutput "  Tesseract install incomplete — screenshot OCR fallback will be disabled" -Type "Warning"
            Write-ColorOutput "  After this script finishes, run: choco install tesseract -y" -Type "Warning"
        }
    }
} else {
    Write-ColorOutput "  Skipping Tesseract — Chocolatey is not available" -Type "Warning"
    Write-ColorOutput "  Install manually from https://github.com/UB-Mannheim/tesseract/wiki, then re-run this script" -Type "Warning"
}

# 4c. Poppler (pdftotext + pdftoppm — PDF text extraction and OCR fallback for scanned PDFs)
if ($chocoOk) {
    if (Test-CommandExists "pdftotext") {
        Write-ColorOutput "  Poppler already installed" -Type "Success"
    } else {
        $popplerOk = Install-Poppler
        if (-not $popplerOk) {
            Write-ColorOutput "  Poppler install incomplete — PDF text/OCR extraction will be disabled" -Type "Warning"
            Write-ColorOutput "  After this script finishes, run: choco install poppler -y" -Type "Warning"
        }
    }
} else {
    Write-ColorOutput "  Skipping Poppler — Chocolatey is not available" -Type "Warning"
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
# emit a clear warning but continue — the operator can gate deployment on
# signed releases once the sidecar is in place.
$expectedHash = $null
try {
    Write-ColorOutput "Fetching integrity manifest: $sumUrl" -Type "Info"
    $expectedHash = (Invoke-WebRequest -Uri $sumUrl -UseBasicParsing -ErrorAction Stop).Content.Trim().Split()[0].ToUpper()
} catch {
    Write-ColorOutput "WARNING: no SHA-256 sidecar at $sumUrl — skipping integrity check." -Type "Warning"
    Write-ColorOutput "  Create one at repo root/.../seceoknight_agent.exe.sha256 to gate installs." -Type "Warning"
}

if ($expectedHash) {
    $actualHash = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash.ToUpper()
    if ($actualHash -ne $expectedHash) {
        Write-ColorOutput "CRITICAL: SHA-256 mismatch — refusing to install a tampered binary." -Type "Error"
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

# Step 8: (Skipped — no VBScript launcher needed; exe has built-in --bg mode)
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

    # Principal: run at normal user privilege (Interactive, RunLevel Limited).
    # This is essential — clipboard hooks and keyboard/mouse event monitoring
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

    Register-ScheduledTask `
        -TaskName $TASK_NAME `
        -Action $action `
        -Trigger @($triggerLogon, $triggerStartup) `
        -Principal $principal `
        -Settings $settings `
        -Description "SeceoKnight DLP Agent - Data Loss Prevention monitoring (clipboard, USB, files, screen capture)" `
        -Force | Out-Null

    Write-ColorOutput "Scheduled task created successfully!" -Type "Success"
    Write-ColorOutput "Task Name: $TASK_NAME" -Type "Info"
    Write-ColorOutput "Agent will start automatically at logon and restart if it ever stops." -Type "Success"

    # ── USB block: one-shot elevated task at startup ─────────────────────────
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

} catch {
    Write-ColorOutput "Error creating scheduled task: $($_.Exception.Message)" -Type "Error"
    Write-ColorOutput "You can manually start it: Start-ScheduledTask -TaskName '$TASK_NAME'" -Type "Info"
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
Write-Host "  Unregister-ScheduledTask -TaskName '$TASK_NAME' -Confirm:`$false"
Write-Host "  Unregister-ScheduledTask -TaskName 'SeceoKnight DLP USB Block' -Confirm:`$false"
Write-Host "  Stop-Process -Name 'seceoknight_agent' -Force"
Write-Host "  Remove-Item '$INSTALL_DIR' -Recurse -Force"
Write-Host "  Remove-Item '$DATA_DIR' -Recurse -Force"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"
