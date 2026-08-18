# SeceoKnight DLP Agent - Windows consolidated management script.
#
# One entry point for Install / Update / Uninstall / Status on a Windows
# endpoint, instead of the operator having to remember three separate
# commands (or hand-run the manual uninstall steps printed at the bottom of
# install-agent.ps1). Self-elevates, detects whatever is actually on the
# machine (installed/running/stopped/broken/not installed), shows recent
# log errors and whether a newer build is published, then offers:
#
#     [1] Install    [2] Update    [3] Uninstall    [4] Exit
#
# Run either form (both self-elevate to Administrator):
#   powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/manage-agent.ps1 | iex"
#   powershell -ExecutionPolicy Bypass -File .\manage-agent.ps1
#
# Design notes (why this isn't a straight port of a similar script from the
# CyberSentinel-DLP reference project):
#   - Install here deliberately DELEGATES to install-agent.ps1 (downloads
#     and runs it) rather than re-implementing OCR dependency setup,
#     SHA-256/Authenticode verification, and scheduled-task creation a
#     second time in this file. That installer is the real, maintained
#     implementation; duplicating its ~850 lines here would just give the
#     two copies room to drift apart.
#   - Uninstall calls the server's /agents/{id}/unregister endpoint with the
#     locally-stored agent_key.json BEFORE deleting anything. This is not
#     cosmetic: earlier work on this project (see CHANGELOG, "duplicate
#     agent entries" fix) found that skipping this step leaves a permanent
#     "ghost" row in the dashboard's Agents view for every machine that's
#     wiped without unregistering first. A naive port of the reference
#     project's uninstall function would reintroduce that exact bug, since
#     it never calls any unregister endpoint at all.
#   - Status detection removes three scheduled tasks, not one -- the main
#     agent task, the health-check watchdog, and the one-shot USB-block
#     task -- because install-agent.ps1 registers all three. A single-task
#     model would under-report "installed" and leave two orphaned tasks
#     behind on uninstall.

& {
  $ErrorActionPreference = 'Continue'

  # ---- Shared constants (MUST match install-agent.ps1) ----
  $GITHUB_REPO   = 'Seceo-Knight/Seceoknight-DLP'
  $RAW_BASE      = "https://raw.githubusercontent.com/$GITHUB_REPO/main"
  $INSTALL_URL   = "$RAW_BASE/install-agent.ps1"
  $SUM_URL       = "$RAW_BASE/agents/endpoint/windows/seceoknight_agent.exe.sha256"
  $DOWNLOAD_URL  = "$RAW_BASE/agents/endpoint/windows/seceoknight_agent.exe"

  $INSTALL_DIR   = 'C:\Program Files\SeceoKnight'
  $DATA_DIR      = 'C:\ProgramData\SeceoKnight'
  $EXE_NAME      = 'seceoknight_agent.exe'
  $CONFIG_NAME   = 'agent_config.json'
  $KEY_NAME      = 'agent_key.json'
  $LOG_NAME      = 'seceoknight_agent.log'
  $PROC_NAME     = 'seceoknight_agent'

  $TASK_NAME     = 'SeceoKnight DLP Agent'
  $WATCHDOG_TASK = 'SeceoKnight DLP Watchdog'
  $USB_TASK      = 'SeceoKnight DLP USB Block'
  $CLIGUARD_TASK = 'SeceoKnight DLP CLI Guard'   # task #142/#145
  $WIRELESSGUARD_TASK = 'SeceoKnight DLP Wireless Guard'   # task #147
  $EXTGUARD_TASK = 'SeceoKnight DLP Browser Extension Guard'   # gap-scan Aug 18 2026
  $EXT_STATE_CACHE = "$DATA_DIR\logs\browser_extension_state.cache"

  # ── Browsers ──────────────────────────────────────────────────────────
  # One table, one place, ported from the same idea in CyberSentinel-DLP's
  # manage-windows-agent.ps1. THE VALUE NAMES ARE NOT INTERCHANGEABLE:
  # Chrome reads IncognitoModeAvailability, Edge reads
  # InPrivateModeAvailability. Writing Chrome's name into Edge's key does
  # nothing whatsoever, and reads back looking exactly like success.
  $BROWSERS = @(
    [PSCustomObject]@{
      Name = 'Chrome'; Root = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
      PrivateValue = 'IncognitoModeAvailability'; PrivateLabel = 'Incognito'
    },
    [PSCustomObject]@{
      Name = 'Edge'; Root = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      PrivateValue = 'InPrivateModeAvailability'; PrivateLabel = 'InPrivate'
    }
  )

  function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
  function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
  function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
  function Err($m)  { Write-Host "[x] $m" -ForegroundColor Red }

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  function Show-Banner {
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host '   SeceoKnight DLP Agent - Windows Management Console   ' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''
  }

  # ================= Elevation =================

  $isAdmin = ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Warn 'Administrator rights required - relaunching in an elevated window...'
    try {
      if ($PSCommandPath) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
      } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', "irm $RAW_BASE/manage-agent.ps1 | iex")
      }
    } catch {
      Err "Could not self-elevate: $($_.Exception.Message)"
      Warn "Re-open PowerShell with 'Run as administrator' and run this again."
    }
    return
  }

  # ================= Detection =================

  function Get-AgentStatus {
    $exePath = Join-Path $INSTALL_DIR $EXE_NAME
    $cfgPath = Join-Path $INSTALL_DIR $CONFIG_NAME
    $keyPath = Join-Path $DATA_DIR $KEY_NAME
    $logPath = Join-Path $DATA_DIR "logs\$LOG_NAME"

    $exeExists = Test-Path $exePath
    $dirExists = Test-Path $INSTALL_DIR
    $proc      = Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue | Select-Object -First 1
    $task      = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    $watchdog  = Get-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
    $usbTask   = Get-ScheduledTask -TaskName $USB_TASK -ErrorAction SilentlyContinue

    $agentId = $null; $serverUrl = $null; $agentName = $null
    if (Test-Path $cfgPath) {
      try {
        $c = Get-Content $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $serverUrl = $c.server_url; $agentName = $c.agent_name
      } catch {}
    }
    if (Test-Path $keyPath) {
      try {
        $k = Get-Content $keyPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $agentId = $k.agent_id
      } catch {}
    }

    $exeHash = $null; $exeSize = $null
    if ($exeExists) {
      try { $exeHash = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash.ToUpper() } catch {}
      try { $exeSize = [math]::Round((Get-Item $exePath).Length / 1MB, 1) } catch {}
    }

    $installed = $dirExists -or $exeExists -or [bool]$proc -or [bool]$task

    $health = 'NOT INSTALLED'; $healthColor = 'Yellow'
    if ($installed) {
      if ($exeExists) {
        if ($proc)     { $health = 'RUNNING';                                  $healthColor = 'Green' }
        elseif ($task) { $health = 'STOPPED (installed, autostart configured)'; $healthColor = 'Yellow' }
        else            { $health = 'BROKEN - installed but no autostart task'; $healthColor = 'Red' }
      } else {
        if ($proc) { $health = 'RUNNING but binary missing on disk!';          $healthColor = 'Red' }
        else       { $health = 'BROKEN - install dir present, binary missing'; $healthColor = 'Red' }
      }
    }

    $logErrCount = 0; $lastErr = $null
    if (Test-Path $logPath) {
      try {
        $tail = Get-Content $logPath -Tail 80 -ErrorAction SilentlyContinue
        $errLines = $tail | Where-Object { $_ -match '(?i)\b(error|critical|fatal|exception|traceback)\b' }
        $logErrCount = @($errLines).Count
        if ($logErrCount -gt 0) { $lastErr = ($errLines | Select-Object -Last 1) }
      } catch {}
    }

    [PSCustomObject]@{
      Installed = $installed; Health = $health; HealthColor = $healthColor
      InstallDir = $INSTALL_DIR; ExeExists = $exeExists; ExeHash = $exeHash; ExeSize = $exeSize; ExePath = $exePath
      AgentId = $agentId; ServerUrl = $serverUrl; AgentName = $agentName
      TaskExists = [bool]$task; TaskState = $(if ($task) { $task.State } else { $null })
      WatchdogExists = [bool]$watchdog; UsbTaskExists = [bool]$usbTask
      ProcRunning = [bool]$proc; ProcId = $(if ($proc) { $proc.Id } else { $null })
      KeyPath = $keyPath; LogPath = $logPath; LogErrCount = $logErrCount; LastErr = $lastErr
    }
  }

  function Show-Status($s, $remoteHash) {
    Write-Host '  +----------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host -NoNewline '   Status  : '
    Write-Host $s.Health -ForegroundColor $s.HealthColor

    if ($s.Installed) {
      if ($s.ProcRunning) { Write-Host "   PID     : $($s.ProcId)" }
      Write-Host "   Path    : $($s.InstallDir)"
      if ($s.AgentName) { Write-Host "   Agent   : $($s.AgentName)" }
      if ($s.AgentId)   { Write-Host "   ID      : $($s.AgentId)" }
      if ($s.ServerUrl) { Write-Host "   Server  : $($s.ServerUrl)" }
      if ($s.ExeExists -and $s.ExeHash) {
        Write-Host "   Binary  : $($s.ExeSize) MB  sha $($s.ExeHash.Substring(0,12))..."
      }
      $taskLine = if ($s.TaskExists) { "$TASK_NAME [$($s.TaskState)]" } else { '(none - agent will NOT auto-start)' }
      if ($s.TaskExists) { Write-Host "   Task    : $taskLine" } else { Write-Host "   Task    : $taskLine" -ForegroundColor Red }
      Write-Host "   Watchdog: $(if ($s.WatchdogExists) { 'configured' } else { 'MISSING (no hang recovery)' })" `
        -ForegroundColor $(if ($s.WatchdogExists) { 'DarkGray' } else { 'Yellow' })
      Write-Host "   USB task: $(if ($s.UsbTaskExists) { 'configured' } else { 'MISSING' })" `
        -ForegroundColor $(if ($s.UsbTaskExists) { 'DarkGray' } else { 'Yellow' })

      if ($s.ExeExists -and $s.ExeHash) {
        if ($remoteHash) {
          if ($remoteHash -eq $s.ExeHash) {
            Write-Host '   Update  : up to date' -ForegroundColor Green
          } else {
            Write-Host "   Update  : AVAILABLE (latest sha $($remoteHash.Substring(0,12))...) - use [2] Update" -ForegroundColor Yellow
          }
        } else {
          Write-Host '   Update  : could not check (offline / GitHub unreachable)' -ForegroundColor DarkGray
        }
      }

      if ($s.LogErrCount -gt 0) {
        Write-Host "   Log     : $($s.LogErrCount) recent error line(s) in $($s.LogPath)" -ForegroundColor Yellow
        if ($s.LastErr) {
          $le = $s.LastErr.Trim()
          if ($le.Length -gt 100) { $le = $le.Substring(0, 100) + '...' }
          Write-Host "             last: $le" -ForegroundColor DarkYellow
        }
      }
    }
    Write-Host '  +----------------------------------------------------------------+' -ForegroundColor DarkCyan
  }

  # ================= Browser controls (extension force-install + Incognito) =================
  #
  # Gap-scan of CyberSentinel-DLP (August 18, 2026) found two related holes:
  # the DLP browser extension was only ever a manual "Load unpacked" dev-mode
  # install (user-removable in two clicks), and there was no way to close the
  # separate InPrivate/Incognito gap -- Chrome and Edge require the user to
  # tick "Allow in InPrivate" per extension, by design, so even a
  # force-installed extension simply does not run in a private window. The
  # only control that actually closes THAT hole is disabling private
  # browsing outright, which is a browser-wide change, not a DLP-only one --
  # so it's offered here, asked rather than assumed, exactly like
  # CyberSentinel's own equivalent menu item.

  # Read back what's actually true, per browser -- never collapsed to a
  # single yes/no. Reporting "disabled" because ONE browser is covered is
  # how the other one could stay wide open while the screen said otherwise.
  function Get-PrivateBrowsingState {
    foreach ($b in $BROWSERS) {
      $priv = $null
      if (Test-Path $b.Root) {
        $priv = (Get-ItemProperty -Path $b.Root -Name $b.PrivateValue -ErrorAction SilentlyContinue).$($b.PrivateValue)
      }
      [PSCustomObject]@{ Name = $b.Name; Label = $b.PrivateLabel; Disabled = ($priv -eq 1); Raw = $priv }
    }
  }

  # Set private browsing and VERIFY it, per browser. Returns what is
  # actually true afterwards, not what was intended -- "I called
  # Set-ItemProperty" is not evidence.
  function Set-PrivateBrowsing {
    param([bool]$Disable)
    $results = @()
    foreach ($b in $BROWSERS) {
      $err = $null
      try {
        if (-not (Test-Path $b.Root)) { New-Item -Path $b.Root -Force | Out-Null }
        if ($Disable) {
          # 1 = disabled, 0 = available (the default), 2 = forced.
          Set-ItemProperty -Path $b.Root -Name $b.PrivateValue -Value 1 -Type DWord -ErrorAction Stop
        } else {
          Remove-ItemProperty -Path $b.Root -Name $b.PrivateValue -ErrorAction SilentlyContinue
        }
      } catch { $err = $_.Exception.Message }

      $now = $null
      if (Test-Path $b.Root) {
        $now = (Get-ItemProperty -Path $b.Root -Name $b.PrivateValue -ErrorAction SilentlyContinue).$($b.PrivateValue)
      }
      $want = if ($Disable) { 1 } else { $null }
      $results += [PSCustomObject]@{ Name = $b.Name; Label = $b.PrivateLabel; Applied = ($now -eq $want); Value = $now; Error = $err }
    }
    $results
  }

  # Reads the extension id the main agent task last cached (see agent.cpp's
  # FetchBrowserExtensionPolicy -- 4 lines: id / update URL / agent id /
  # server URL) and reports whether ExtensionInstallForcelist actually
  # carries an entry for it, per browser. This is what's ACTUALLY true on
  # this machine, not what any script assumed it wrote.
  function Get-ExtensionForceInstallStatus {
    $extId = $null
    if (Test-Path $EXT_STATE_CACHE) {
      $lines = Get-Content -Path $EXT_STATE_CACHE -ErrorAction SilentlyContinue
      if ($lines -and $lines.Count -ge 1) { $extId = $lines[0].Trim() }
    }
    $forced = @()
    if ($extId) {
      foreach ($b in $BROWSERS) {
        $fl = Join-Path $b.Root 'ExtensionInstallForcelist'
        if (Test-Path $fl) {
          $props = Get-ItemProperty -Path $fl -ErrorAction SilentlyContinue
          foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($p.Value -like "$extId;*") { $forced += $b.Name }
          }
        }
      }
    }
    [PSCustomObject]@{ ExtensionId = $extId; Forced = $forced }
  }

  function Show-BrowserControls {
    Write-Host ''
    Info 'Browser controls'
    Write-Host ''

    $extGuardTask = Get-ScheduledTask -TaskName $EXTGUARD_TASK -ErrorAction SilentlyContinue
    $extStatus = Get-ExtensionForceInstallStatus
    Write-Host '   Extension force-install:'
    if (-not $extGuardTask) {
      Warn '     Browser Extension Guard task is not installed - run [1] Install/[2] Update first.'
    } elseif (-not $extStatus.ExtensionId) {
      Warn '     No extension published yet on the configured server, or the agent has not synced.'
      Warn '     Run scripts/pack-extension.py on the DLP server, then wait up to 2 minutes.'
    } else {
      Write-Host "     Extension id: $($extStatus.ExtensionId)"
      foreach ($b in $BROWSERS) {
        if ($extStatus.Forced -contains $b.Name) {
          Ok "     $($b.Name): force-installed"
        } else {
          Warn "     $($b.Name): NOT force-installed yet (installed browser, or guard task hasn't run)"
        }
      }
    }

    Write-Host ''
    Write-Host '   Private browsing (Incognito / InPrivate):'
    foreach ($s in (Get-PrivateBrowsingState)) {
      if ($s.Disabled) { Ok "     $($s.Name) ($($s.Label)): disabled" }
      else { Warn "     $($s.Name) ($($s.Label)): AVAILABLE - anything done in a private window is uninspected" }
    }

    Write-Host ''
    Write-Host '   [1] Disable private browsing ' -ForegroundColor Yellow -NoNewline; Write-Host '- closes the "open an Incognito window" DLP bypass'
    Write-Host '   [2] Re-allow private browsing' -ForegroundColor Gray   -NoNewline; Write-Host '- restores the browser default'
    Write-Host '   [3] Back                     ' -ForegroundColor Gray   -NoNewline; Write-Host '- return to the main menu'
    Write-Host ''
    $bc = Read-Host '   Choose an option (1-3)'
    switch ($bc.Trim()) {
      '1' {
        Write-Host ''
        Warn 'This disables Incognito/InPrivate browsing machine-wide for Chrome and Edge.'
        Warn 'It is a browser-wide change, not a DLP-only one, and is fully reversible ([2]).'
        $confirm = Read-Host "   Type 'y' to confirm (anything else cancels)"
        if ($confirm -eq 'y' -or $confirm -eq 'Y') {
          foreach ($r in (Set-PrivateBrowsing -Disable $true)) {
            if ($r.Applied) { Ok "   $($r.Name) ($($r.Label)): disabled" }
            else { Err "   $($r.Name) ($($r.Label)): FAILED to apply$(if ($r.Error) { " - $($r.Error)" })" }
          }
        } else {
          Warn 'Cancelled - no changes made.'
        }
      }
      '2' {
        Write-Host ''
        foreach ($r in (Set-PrivateBrowsing -Disable $false)) {
          if ($r.Applied) { Ok "   $($r.Name) ($($r.Label)): restored to default" }
          else { Err "   $($r.Name) ($($r.Label)): FAILED to restore$(if ($r.Error) { " - $($r.Error)" })" }
        }
      }
      default {}
    }
    Write-Host ''
    Read-Host '   Press Enter to return to the menu' | Out-Null
  }

  # ================= Update (binary-only swap) =================

  function Update-Agent($s) {
    $tmpPath = Join-Path $env:TEMP "$EXE_NAME.new"
    try {
      Info "Downloading latest binary: $DOWNLOAD_URL"
      Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $tmpPath -UseBasicParsing -ErrorAction Stop
    } catch {
      Err "Download failed: $($_.Exception.Message)"
      return
    }

    $expectedHash = $null
    try {
      $expectedHash = (Invoke-WebRequest -Uri $SUM_URL -UseBasicParsing -ErrorAction Stop).Content.Trim().Split()[0].ToUpper()
    } catch {
      Warn "No SHA-256 sidecar reachable at $SUM_URL - skipping integrity check."
    }
    if ($expectedHash) {
      $actualHash = (Get-FileHash -Algorithm SHA256 -Path $tmpPath).Hash.ToUpper()
      if ($actualHash -ne $expectedHash) {
        Err 'SHA-256 mismatch - refusing to install a tampered/corrupt binary.'
        Err "  expected: $expectedHash"
        Err "  actual  : $actualHash"
        Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue
        return
      }
      Ok "SHA-256 verified: $actualHash"
    }

    Info 'Stopping the agent so the binary can be replaced...'
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    try {
      Move-Item -Path $tmpPath -Destination $s.ExePath -Force -ErrorAction Stop
      Ok 'Binary replaced.'
    } catch {
      Err "Could not replace binary (file locked?): $($_.Exception.Message)"
      Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue
      return
    }

    try {
      Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction Stop
      Start-Sleep -Seconds 3
      $p = Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue
      if ($p) { Ok "Agent restarted (PID $($p.Id))." }
      else    { Warn 'Task started but process not detected yet - check logs.' }
    } catch {
      Err "Could not restart the scheduled task: $($_.Exception.Message)"
      Warn "Start it manually: Start-ScheduledTask -TaskName '$TASK_NAME'"
    }
  }

  # ================= Uninstall =================

  function Uninstall-Agent($s) {
    # 1) Unregister this machine's agent identity server-side FIRST. Once the
    #    key file is deleted below, nothing can ever tell the server this
    #    device is gone, and it lingers in the Agents view as a permanent
    #    ghost row (this is the exact bug install-agent.ps1's Step 2 exists
    #    to prevent on a reinstall; uninstall needs the same protection).
    if ((Test-Path $s.KeyPath) -and $s.AgentId) {
      try {
        $k = Get-Content -Raw $s.KeyPath | ConvertFrom-Json
        $headers = @{}
        if ($k.api_key) { $headers['X-Agent-Key'] = $k.api_key }
        $base = if ($s.ServerUrl) { $s.ServerUrl.TrimEnd('/') } else { $null }
        if ($base) {
          Invoke-RestMethod -Method Delete -Uri "$base/agents/$($s.AgentId)/unregister" `
            -Headers $headers -TimeoutSec 10 -ErrorAction Stop | Out-Null
          Ok "Unregistered agent identity ($($s.AgentId)) from $base"
        } else {
          Warn 'No server URL on record - skipping server-side unregister (non-fatal).'
        }
      } catch {
        Warn "Could not unregister from server (non-fatal): $($_.Exception.Message)"
      }
    }

    # 2) Stop the process.
    Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue | ForEach-Object {
      Info "Stopping $($_.Name) (PID $($_.Id))"
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 150

    # 2b) Clear every Image File Execution Options "Debugger" redirect this
    #     agent may have installed -- the Bluetooth fsquirt.exe block (task
    #     #113) and the CLI Guard zero-race pre-launch redirects (task
    #     #142/#143: curl.exe, wget.exe, rclone.exe, s3cmd.exe, azcopy.exe,
    #     aws.exe, scp.exe, pscp.exe, winscp.com). Leaving any of these behind
    #     after the agent.exe binary is deleted below would leave the
    #     redirected tool COMPLETELY UNABLE TO LAUNCH (Windows tries to run a
    #     debugger that no longer exists) until someone manually clears the
    #     registry -- this must run before directory deletion, not after.
    $ifeoGuardedExes = @(
      'fsquirt.exe', 'curl.exe', 'wget.exe', 'rclone.exe', 's3cmd.exe',
      'azcopy.exe', 'aws.exe', 'scp.exe', 'pscp.exe', 'winscp.com'
    )
    foreach ($exe in $ifeoGuardedExes) {
      $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
      if (Test-Path $ifeoPath) {
        $dbg = (Get-ItemProperty -Path $ifeoPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg -and $dbg -match 'seceoknight_agent') {
          Remove-ItemProperty -Path $ifeoPath -Name Debugger -ErrorAction SilentlyContinue
          Info "Cleared IFEO redirect for $exe"
        }
      }
    }

    # 2c) Drop the extension force-install entry so an uninstalled agent
    #     doesn't leave a browser permanently force-installing an extension
    #     pointed at a manager this machine no longer reports to. Read the
    #     extension id from the cache BEFORE it's deleted in step 4 below.
    $extIdAtUninstall = $null
    if (Test-Path $EXT_STATE_CACHE) {
      $lines = Get-Content -Path $EXT_STATE_CACHE -ErrorAction SilentlyContinue
      if ($lines -and $lines.Count -ge 1) { $extIdAtUninstall = $lines[0].Trim() }
    }
    if ($extIdAtUninstall) {
      foreach ($b in $BROWSERS) {
        $fl = Join-Path $b.Root 'ExtensionInstallForcelist'
        if (Test-Path $fl) {
          $props = Get-ItemProperty -Path $fl -ErrorAction SilentlyContinue
          foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($p.Value -like "$extIdAtUninstall;*") {
              Remove-ItemProperty -Path $fl -Name $p.Name -ErrorAction SilentlyContinue
              Info "Cleared $($b.Name) force-install entry for extension $extIdAtUninstall"
            }
          }
        }
        $mp = Join-Path $b.Root "3rdparty\extensions\$extIdAtUninstall"
        if (Test-Path $mp) { Remove-Item -Path $mp -Recurse -Force -ErrorAction SilentlyContinue }
      }
    }

    # 3) Remove all scheduled tasks this project registers.
    foreach ($n in @($TASK_NAME, $WATCHDOG_TASK, $USB_TASK, $CLIGUARD_TASK, $WIRELESSGUARD_TASK, $EXTGUARD_TASK)) {
      if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
        Info "Removing scheduled task: $n"
        Stop-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue
      }
    }

    # 4) Delete install + data directories.
    foreach ($d in @($INSTALL_DIR, $DATA_DIR)) {
      if (Test-Path $d) {
        Info "Deleting $d"
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $d) { Warn "Could not fully delete $d (a file may be locked - reboot and re-run)" }
      }
    }

    # 5) Clear the machine-wide server URL env var the installer set.
    try { [Environment]::SetEnvironmentVariable('SECEOKNIGHT_SERVER_URL', $null, 'Machine') } catch {}

    Write-Host ''
    Ok 'SeceoKnight DLP agent removed from this endpoint.'
  }

  # ================= Main menu loop =================

  while ($true) {
    Clear-Host
    Show-Banner

    $s = Get-AgentStatus

    $remoteHash = $null
    if ($s.ExeExists -and $s.ExeHash) {
      Info 'Checking for the latest published build...'
      try {
        $remoteHash = ((Invoke-WebRequest -Uri $SUM_URL -UseBasicParsing -ErrorAction Stop).Content).Trim().Split()[0].ToUpper()
      } catch {}
    }

    Show-Status $s $remoteHash

    Write-Host ''
    Write-Host '   [1] Install    ' -ForegroundColor Green  -NoNewline; Write-Host '- set up the agent on this device (fresh install)'
    Write-Host '   [2] Update     ' -ForegroundColor Cyan   -NoNewline; Write-Host '- replace the agent binary with the latest build'
    Write-Host '   [3] Uninstall  ' -ForegroundColor Red    -NoNewline; Write-Host '- stop and completely remove the agent + files'
    Write-Host '   [4] Browser    ' -ForegroundColor Magenta -NoNewline; Write-Host '- extension force-install status, disable Incognito/InPrivate'
    Write-Host '   [5] Exit       ' -ForegroundColor Gray   -NoNewline; Write-Host '- do nothing and quit'
    Write-Host ''
    $choice = Read-Host '   Choose an option (1-5)'

    switch ($choice.Trim()) {
      '1' {
        Write-Host ''
        if ($s.Installed) {
          Warn "Agent is already installed (status: $($s.Health))."
          Warn 'Use [2] Update to refresh the binary, or [3] Uninstall first for a clean reinstall.'
        } else {
          Info 'Launching the full installer (it will ask for the server address, etc.)...'
          Write-Host ''
          try {
            $installer = Invoke-RestMethod -Uri $INSTALL_URL -UseBasicParsing -ErrorAction Stop
            if ($installer) { Invoke-Expression $installer }
            else { Err 'Could not download the installer (offline / GitHub unreachable).' }
          } catch { Err "Installer failed: $($_.Exception.Message)" }
        }
        Write-Host ''
        Read-Host '   Press Enter to return to the menu' | Out-Null
      }

      '2' {
        Write-Host ''
        if (-not $s.Installed) {
          Warn 'No agent is installed - there is nothing to update.'
          Warn 'Choose [1] Install to set it up first.'
        } else {
          Update-Agent $s
        }
        Write-Host ''
        Read-Host '   Press Enter to return to the menu' | Out-Null
      }

      '3' {
        Write-Host ''
        if (-not $s.Installed) {
          Warn 'No SeceoKnight DLP agent found - nothing to uninstall.'
        } else {
          Warn 'This STOPS and COMPLETELY REMOVES the SeceoKnight DLP agent:'
          Warn '  - unregisters this machine''s agent identity from the server (best-effort)'
          Warn '  - kills the running process'
          Warn '  - removes all three scheduled tasks (agent, watchdog, USB block)'
          Warn '  - deletes the install and data directories'
          Write-Host ''
          $confirm = Read-Host "   Type 'y' to confirm uninstall (anything else cancels)"
          if ($confirm -eq 'y' -or $confirm -eq 'Y') {
            Write-Host ''
            Uninstall-Agent $s
          } else {
            Warn 'Uninstall cancelled - no changes made.'
          }
        }
        Write-Host ''
        Read-Host '   Press Enter to return to the menu' | Out-Null
      }

      '4' {
        Show-BrowserControls
      }

      '5' {
        Write-Host ''
        Info 'Exiting - no changes made.'
        return
      }

      default {
        Write-Host ''
        Warn 'Invalid choice - please enter 1, 2, 3, 4, or 5.'
        Start-Sleep -Milliseconds 900
      }
    }
  }
}
