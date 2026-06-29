# ============================================================================
# SeceoKnight DLP — Kernel Minifilter Driver Install / Uninstall Script
#
# Run as Administrator in PowerShell.
# Usage:
#   .\install_driver.ps1 -Action install    # install + start
#   .\install_driver.ps1 -Action uninstall  # stop + remove
#   .\install_driver.ps1 -Action status     # show driver status
#   .\install_driver.ps1 -Action testsign   # enable test signing (reboot required)
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("install","uninstall","status","testsign","testnosign")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

$DriverName   = "SeceoKnightFilter"
$DriverSys    = "csfilter.sys"
$InfFile      = "csfilter.inf"
$DestDir      = "$env:SystemRoot\System32\drivers"
$DriverDest   = "$DestDir\$DriverSys"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Require-Admin {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator. Right-click PowerShell → Run as administrator."
        exit 1
    }
}

function Get-ScriptDir {
    Split-Path -Parent $MyInvocation.PSCommandPath
}

# ── Actions ──────────────────────────────────────────────────────────────────

function Enable-TestSigning {
    Write-Host ""
    Write-Host "=== Enabling Test Signing Mode ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Test signing allows unsigned/self-signed drivers to load."
    Write-Host "Required for development. Do NOT use on production machines."
    Write-Host ""

    bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        Write-Error "bcdedit failed. Make sure you are running as Administrator."
    }

    Write-Host ""
    Write-Host "✅ Test signing enabled." -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  You MUST REBOOT for this to take effect." -ForegroundColor Yellow
    Write-Host "   After reboot, a watermark 'Test Mode' will appear on the desktop."
    Write-Host "   Run this script again with -Action install after reboot."
    Write-Host ""
}

function Disable-TestSigning {
    Write-Host "Disabling test signing mode..." -ForegroundColor Cyan
    bcdedit /set testsigning off
    Write-Host "✅ Test signing disabled. Reboot required." -ForegroundColor Green
}

function Install-Driver {
    Require-Admin

    $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
    $sysSrc = Join-Path $scriptDir "x64\Release\$DriverSys"

    # Try Debug build if Release not found
    if (-not (Test-Path $sysSrc)) {
        $sysSrc = Join-Path $scriptDir "x64\Debug\$DriverSys"
    }
    # Try same directory as script
    if (-not (Test-Path $sysSrc)) {
        $sysSrc = Join-Path $scriptDir $DriverSys
    }

    if (-not (Test-Path $sysSrc)) {
        Write-Error @"
csfilter.sys not found. Expected at:
  $scriptDir\x64\Release\csfilter.sys   (after Release build)
  $scriptDir\x64\Debug\csfilter.sys     (after Debug build)

Build the driver first in Visual Studio (see KERNEL_DRIVER_BUILD.md).
"@
    }

    Write-Host ""
    Write-Host "=== Installing SeceoKnight Kernel Minifilter ===" -ForegroundColor Cyan
    Write-Host "Source : $sysSrc"
    Write-Host "Dest   : $DriverDest"
    Write-Host ""

    # Check test signing
    $bcdOutput = bcdedit /enum | Select-String "testsigning"
    if ($bcdOutput -notmatch "Yes") {
        Write-Host "⚠️  Test signing is NOT enabled." -ForegroundColor Yellow
        Write-Host "   Run: .\install_driver.ps1 -Action testsign   then reboot." -ForegroundColor Yellow
        Write-Host "   Continuing anyway — driver may fail to load without test signing."
        Write-Host ""
    }

    # Stop existing service if running
    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Host "Stopping existing driver service..."
            Stop-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        Write-Host "Removing existing driver service..."
        sc.exe delete $DriverName | Out-Null
        Start-Sleep -Seconds 1
    }

    # Copy driver binary
    Write-Host "Copying csfilter.sys to System32\drivers..."
    Copy-Item $sysSrc $DriverDest -Force

    # Create service
    Write-Host "Creating driver service..."
    sc.exe create $DriverName `
        type= filesys `
        start= demand `
        error= normal `
        binPath= $DriverDest `
        displayname= "SeceoKnight DLP File System Minifilter" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create driver service."
    }

    # Set altitude and instance registry keys
    Write-Host "Configuring driver registry (altitude 370100)..."
    $regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"

    New-Item -Path "$regBase\Instances" -Force | Out-Null
    Set-ItemProperty -Path "$regBase\Instances" -Name "DefaultInstance" -Value "SeceoKnight Default Instance" -Type String

    $instPath = "$regBase\Instances\SeceoKnight Default Instance"
    New-Item -Path $instPath -Force | Out-Null
    Set-ItemProperty -Path $instPath -Name "Altitude" -Value "370100" -Type String
    Set-ItemProperty -Path $instPath -Name "Flags"    -Value 0        -Type DWord

    # Start the driver
    Write-Host "Starting driver..."
    sc.exe start $DriverName

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "❌ Driver failed to start." -ForegroundColor Red
        Write-Host ""
        Write-Host "Common causes:" -ForegroundColor Yellow
        Write-Host "  1. Test signing not enabled  → run: .\install_driver.ps1 -Action testsign  then reboot"
        Write-Host "  2. Driver not signed         → right-click csfilter.sys → Properties → Digital Signatures"
        Write-Host "  3. Wrong altitude            → another filter has altitude 370100 (check Event Viewer)"
        Write-Host "  4. Missing FltMgr            → 'sc start FltMgr' to ensure filter manager is running"
        Write-Host ""
        Write-Host "Check Event Viewer → Windows Logs → System for detailed error."
        exit 1
    }

    Write-Host ""
    Write-Host "✅ SeceoKnight kernel minifilter INSTALLED and RUNNING!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The DLP agent will now connect to it automatically on next start."
    Write-Host "Restart the agent: Stop-ScheduledTask / Start-ScheduledTask -TaskName 'SeceoKnight DLP Agent'"
    Write-Host ""
}

function Uninstall-Driver {
    Require-Admin

    Write-Host "=== Uninstalling SeceoKnight Kernel Minifilter ===" -ForegroundColor Cyan

    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Host "Stopping driver..."
            sc.exe stop $DriverName | Out-Null
            Start-Sleep -Seconds 2
        }
        Write-Host "Deleting service..."
        sc.exe delete $DriverName | Out-Null
    } else {
        Write-Host "Driver service not found (already removed)."
    }

    if (Test-Path $DriverDest) {
        Write-Host "Removing $DriverDest..."
        Remove-Item $DriverDest -Force
    }

    Write-Host ""
    Write-Host "✅ Driver uninstalled." -ForegroundColor Green
    Write-Host "   (Test signing mode unchanged — run bcdedit /set testsigning off + reboot to revert)"
    Write-Host ""
}

function Show-Status {
    Write-Host ""
    Write-Host "=== SeceoKnight Driver Status ===" -ForegroundColor Cyan
    Write-Host ""

    # Test signing
    $bcd = bcdedit /enum | Select-String "testsigning"
    $tsEnabled = $bcd -match "Yes"
    Write-Host ("Test Signing : " + $(if ($tsEnabled) {"✅ Enabled"} else {"❌ Disabled"}))

    # Service status
    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        $color = if ($svc.Status -eq "Running") {"Green"} else {"Yellow"}
        Write-Host ("Driver Service: " + $svc.Status) -ForegroundColor $color
    } else {
        Write-Host "Driver Service : ❌ Not installed" -ForegroundColor Red
    }

    # Binary on disk
    if (Test-Path $DriverDest) {
        $info = Get-Item $DriverDest
        Write-Host "Driver Binary  : ✅ $DriverDest ($([math]::Round($info.Length/1KB, 1)) KB)"
    } else {
        Write-Host "Driver Binary  : ❌ Not found at $DriverDest" -ForegroundColor Red
    }

    # Communication port (check via fltMC)
    Write-Host ""
    Write-Host "=== Loaded Minifilters ===" -ForegroundColor Cyan
    fltmc filters

    Write-Host ""
    Write-Host "=== Filter Communication Ports ===" -ForegroundColor Cyan
    fltmc instances

    Write-Host ""
}

# ── Main ─────────────────────────────────────────────────────────────────────

switch ($Action) {
    "testsign"   { Enable-TestSigning }
    "testnosign" { Disable-TestSigning }
    "install"    { Install-Driver }
    "uninstall"  { Uninstall-Driver }
    "status"     { Show-Status }
}
