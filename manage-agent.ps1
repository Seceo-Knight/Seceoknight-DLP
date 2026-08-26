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

# On 64-bit Windows, a 32-bit PowerShell has every HKLM:\SOFTWARE\Policies\...
# access silently redirected into WOW6432Node, which no browser reads at all.
# This script (and specifically [4] Browser -> [3] Force extension reinstall,
# added August 26 2026) writes/removes ExtensionInstallForcelist there -- from
# a 32-bit process it would write and read back policy from a hidden copy of
# the hive, reporting success on every operation while Chrome/Edge never see
# any of it. Ported from CyberSentinel-DLP's own installer, which lost real
# time to exactly this before adding the same guard. Refusing to run here is
# better than a silent no-op that claims to have worked.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
  Write-Host ''
  Write-Host '  This is 32-bit PowerShell on 64-bit Windows.' -ForegroundColor Red
  Write-Host '  Browser policy written from here goes to WOW6432Node, which Chrome' -ForegroundColor Red
  Write-Host '  and Edge never read -- every extension operation in this script would' -ForegroundColor Red
  Write-Host '  silently do nothing while reporting success.' -ForegroundColor Red
  Write-Host ''
  Write-Host '  Re-run with the 64-bit PowerShell:' -ForegroundColor Yellow
  Write-Host '    %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -File "' -NoNewline -ForegroundColor Yellow
  Write-Host "$PSCommandPath`"" -ForegroundColor Yellow
  Write-Host ''
  exit 1
}

& {
  $ErrorActionPreference = 'Continue'

  # ---- Shared constants (MUST match install-agent.ps1) ----
  $GITHUB_REPO   = 'Seceo-Knight/Seceoknight-DLP'
  $RAW_BASE      = "https://raw.githubusercontent.com/$GITHUB_REPO/main"
  $INSTALL_URL   = "$RAW_BASE/install-agent.ps1"
  $SUM_URL       = "$RAW_BASE/agents/endpoint/windows/seceoknight_agent.exe.sha256"
  $DOWNLOAD_URL  = "$RAW_BASE/agents/endpoint/windows/seceoknight_agent.exe"
  # Browser-extension native-messaging host -- built in CI alongside the main
  # binary (see .github/workflows/build-windows-agent.yml's build-native-host
  # job) and downloaded the same way. Kept current here so a machine that was
  # set up before this existed (or missed a build) picks it up on the next
  # Update, without a separate manual PyInstaller step.
  $HOST_SUM_URL      = "$RAW_BASE/agents/browser-extension/native-host/skdlp_host.exe.sha256"
  $HOST_DOWNLOAD_URL = "$RAW_BASE/agents/browser-extension/native-host/skdlp_host.exe"
  $HOST_EXE_NAME     = 'skdlp_host.exe'

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

  # Every Chrome/Edge profile on this machine, across every Windows user
  # account -- not just whoever is running this script, since the browser
  # that matters may belong to a different logged-in user.
  function Get-BrowserProfileDirs {
    $roots = @(
      @{ Browser = 'Chrome'; Base = 'AppData\Local\Google\Chrome\User Data' },
      @{ Browser = 'Edge';   Base = 'AppData\Local\Microsoft\Edge\User Data' }
    )
    $out = @()
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
      foreach ($r in $roots) {
        $userDataDir = Join-Path $u.FullName $r.Base
        if (-not (Test-Path $userDataDir)) { continue }
        foreach ($prof in (Get-ChildItem $userDataDir -Directory -ErrorAction SilentlyContinue)) {
          if ($prof.Name -eq 'Default' -or $prof.Name -like 'Profile *') {
            $out += [PSCustomObject]@{ Browser = $r.Browser; User = $u.Name; Name = $prof.Name; Path = $prof.FullName }
          }
        }
      }
    }
    $out
  }

  # Where did the browser actually get this extension from? Ported from
  # CyberSentinel-DLP (commit 8c207b5), hit live on this exact deployment:
  # manifest.json pins the signing key, so a "Load unpacked" copy (loaded
  # via the OLD documented manual-install flow, before force-install
  # existed) has the SAME extension id as the published, force-installed
  # build -- that's deliberate (you debug what you deploy), but it means a
  # leftover unpacked folder occupies the id slot the policy is trying to
  # fill, and the managed build never visibly takes over. Every symptom
  # then points somewhere else: Remove is still clickable, and nothing
  # about the registry policy or the server looks wrong, because neither
  # of them ARE wrong.
  #
  # Chrome records the origin in each profile's Preferences JSON as a
  # numeric `location` under extensions.settings.<id>:
  #   1  = installed from a packaged .crx
  #   4  = LOADED UNPACKED  <- the one that shadows everything
  #   5  = component
  #   10 = installed by enterprise policy (what force-install produces)
  function Get-ExtensionInstallSources {
    param([string]$ExtId)
    $out = @()
    foreach ($p in (Get-BrowserProfileDirs)) {
      foreach ($file in @('Secure Preferences', 'Preferences')) {
        $path = Join-Path $p.Path $file
        if (-not (Test-Path $path)) { continue }
        try {
          $json = Get-Content $path -Raw -ErrorAction Stop | ConvertFrom-Json
          $entry = $json.extensions.settings.$ExtId
          if (-not $entry) { continue }
          $loc = $entry.location
          $label = switch ($loc) {
            1  { 'packaged .crx' }
            4  { 'LOADED UNPACKED' }
            5  { 'component' }
            10 { 'enterprise policy' }
            default { "location $loc" }
          }
          $out += [PSCustomObject]@{
            Browser = $p.Browser; User = $p.User; Profile = $p.Name
            Location = $loc; Label = $label
            Path = $entry.path; Version = $entry.manifest.version
          }
          break   # one record per profile is enough
        } catch { }
      }
    }
    $out
  }

  # Forces a clean re-issue of the ExtensionInstallForcelist entry, then
  # immediately kicks the guard task so it rewrites it -- instead of waiting
  # up to 2 minutes for the task's own schedule.
  #
  # Added from this engagement's own live debugging (August 26 2026), not a
  # line-for-line CyberSentinel-DLP port -- their equivalent problem (an
  # extension stuck on an old version, self-update and every UI Update
  # button failing to move it) was fixed in their installer script's
  # Deploy/Repair flow, but SeceoKnight has no imperative "repair the
  # extension" action at all: force-install is entirely reconcile-driven by
  # the Browser Extension Guard task, with nothing that lets an operator
  # force a fresh cycle on demand. On a real endpoint this session, Chrome
  # DevTools access was itself blocked for this (force-installed) extension,
  # so there was no way to inspect *why* it was stuck -- the only thing that
  # actually worked was removing the ExtensionInstallForcelist entry
  # (Chrome/Edge auto-uninstall on the next policy read), letting the guard
  # task re-add it (a genuinely fresh install, not an in-place patch), then
  # closing and reopening the browser. This function is exactly that
  # procedure, so nobody has to type out raw registry commands by hand a
  # second time.
  #
  # Deliberately does NOT force-kill the browser (CyberSentinel hit real
  # data loss doing that with too short a grace window -- see their commit
  # 90a2608). Removing the registry value is enough; Chrome/Edge only need
  # to be closed and reopened once afterwards, on the user's own schedule.
  function Reset-ExtensionForceInstall {
    $extStatus = Get-ExtensionForceInstallStatus
    if (-not $extStatus.ExtensionId) {
      Err '   No extension id cached yet -- nothing to reset. Run [1] Install/[2] Update first.'
      return
    }
    if (@($extStatus.Forced).Count -eq 0) {
      Warn '   No browser currently shows a force-install entry for this extension -- nothing to remove.'
      Warn '   If the extension still looks stuck, just restart the Browser Extension Guard task below.'
    } else {
      Write-Host ''
      Warn "   This removes the ExtensionInstallForcelist entry for $($extStatus.ExtensionId) from:"
      foreach ($name in $extStatus.Forced) { Warn "     - $name" }
      Warn '   Chrome/Edge will auto-uninstall the extension on their next policy read, then the'
      Warn '   guard task (triggered immediately below) re-adds the entry for a genuinely fresh install.'
      Warn '   You will need to fully close and reopen each affected browser afterwards.'
      $confirm = Read-Host "   Type 'y' to confirm (anything else cancels)"
      if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Warn '   Cancelled -- no changes made.'
        return
      }
      foreach ($b in $BROWSERS) {
        if ($extStatus.Forced -notcontains $b.Name) { continue }
        $fl = Join-Path $b.Root 'ExtensionInstallForcelist'
        if (-not (Test-Path $fl)) { continue }
        $props = Get-ItemProperty -Path $fl -ErrorAction SilentlyContinue
        $removed = $false
        foreach ($p in $props.PSObject.Properties) {
          if ($p.Name -like 'PS*') { continue }
          if ($p.Value -like "$($extStatus.ExtensionId);*") {
            Remove-ItemProperty -Path $fl -Name $p.Name -ErrorAction SilentlyContinue
            $removed = $true
          }
        }
        if ($removed) { Ok "   $($b.Name): force-install entry removed." }
        else { Warn "   $($b.Name): entry not found when removing (already gone?)." }
      }
    }
    Write-Host ''
    $task = Get-ScheduledTask -TaskName $EXTGUARD_TASK -ErrorAction SilentlyContinue
    if ($task) {
      try {
        Start-ScheduledTask -TaskName $EXTGUARD_TASK -ErrorAction Stop
        Ok '   Browser Extension Guard task triggered -- it will re-add the entry within a few seconds.'
      } catch {
        Err "   Could not trigger the guard task: $($_.Exception.Message)"
        Warn "   It will still run on its own schedule (up to 2 minutes)."
      }
    } else {
      Warn '   Browser Extension Guard task is not installed -- run [1] Install/[2] Update first.'
    }
    Write-Host ''
    Warn '   Now fully close and reopen each affected browser (not just a tab/window) to complete'
    Warn '   the reinstall. Verify afterwards with chrome://extensions or edge://extensions.'
  }

  # Reads a registry value from an EXPLICIT view (64-bit or 32-bit),
  # regardless of which bitness this PowerShell process happens to be. The
  # startup guard at the top of this script already refuses to run under
  # 32-bit PowerShell at all, so in normal use this and Get-ItemProperty
  # agree -- this exists for [5] Diagnose, which deliberately checks BOTH
  # views side by side to prove there's no WOW6432Node shadow copy sitting
  # underneath the real one (see Show-ExtensionDiagnostics below). Ported
  # from CyberSentinel-DLP commit 9e01900.
  function Get-PolicyValueInView {
    param(
      [Parameter(Mandatory)][string]$SubKey,   # e.g. 'SOFTWARE\Policies\Google\Chrome'
      [Parameter(Mandatory)][string]$ValueName,
      [ValidateSet('Registry64', 'Registry32')][string]$View = 'Registry64'
    )
    try {
      $viewEnum = [Microsoft.Win32.RegistryView]::$View
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $viewEnum)
      $key = $base.OpenSubKey($SubKey)
      if (-not $key) { return $null }
      $val = $key.GetValue($ValueName)
      $key.Close(); $base.Close()
      return $val
    } catch { return $null }
  }

  # [5] Diagnose -- reports what the BROWSER actually sees, not what this
  # script last wrote. Ported from CyberSentinel-DLP commit 9e01900
  # ("report what the BROWSER sees, and refuse to run where it cannot"),
  # adapted to SeceoKnight's own $BROWSERS table, $EXT_STATE_CACHE-cached
  # extension id, and $s.ServerUrl for the update-feed reachability check.
  #
  # Exists for the same reason the startup bitness guard exists: every
  # write this script (and the reconcile-driven Browser Extension Guard
  # task) makes to ExtensionInstallForcelist goes through
  # HKLM:\SOFTWARE\Policies\..., and on 64-bit Windows a 32-bit process
  # reading or writing that path is silently redirected into
  # WOW6432Node\Policies\... instead -- a hidden copy no browser ever
  # reads. The guard task itself runs as SYSTEM via Task Scheduler, which
  # is always the native 64-bit host, so it isn't at risk -- but this
  # gives an operator a direct way to PROVE that, per browser, instead of
  # trusting it.
  function Show-ExtensionDiagnostics($s) {
    Write-Host ''
    Info 'Extension diagnostics -- what the browser sees'
    Write-Host ''

    # 1) This process's own bitness view (informational -- the startup
    #    guard already refused to run at all if this were 32-bit process
    #    on a 64-bit OS).
    $procBits = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
    $osBits   = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
    Write-Host "   1. Process/OS bitness"
    Ok "     This PowerShell process: $procBits  (OS: $osBits)"

    # 2) Per-browser, per-view policy read -- the registry view that
    #    actually matters is Registry64 (browsers are always 64-bit
    #    processes on a 64-bit OS today), read explicitly rather than
    #    relying on this process's own default view.
    $extId = $null
    if (Test-Path $EXT_STATE_CACHE) {
      $lines = Get-Content -Path $EXT_STATE_CACHE -ErrorAction SilentlyContinue
      if ($lines -and $lines.Count -ge 1) { $extId = $lines[0].Trim() }
    }
    Write-Host ''
    Write-Host "   2. Per-browser policy (Registry64 view -- what the browser itself reads)"
    if (-not $extId) {
      Warn '     No extension id cached yet -- run [1] Install/[2] Update first.'
    } else {
      foreach ($b in $BROWSERS) {
        $subKey = $b.Root -replace '^HKLM:\\', ''
        $flVal  = Get-PolicyValueInView -SubKey "$subKey\ExtensionInstallForcelist" -ValueName '1' -View Registry64
        # Forcelist entries aren't guaranteed to be under name "1" -- walk
        # all of them via the standard API for an authoritative read, this
        # 64-bit-view probe is just to prove the view itself isn't empty
        # while Get-ItemProperty (native view) shows something.
        $present = $false
        try {
          $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
          $key = $base.OpenSubKey("$subKey\ExtensionInstallForcelist")
          if ($key) {
            foreach ($name in $key.GetValueNames()) {
              $v = $key.GetValue($name)
              if ($v -like "$extId;*") { $present = $true; break }
            }
            $key.Close()
          }
          $base.Close()
        } catch {}
        if ($present) { Ok "     $($b.Name): force-install entry visible in the 64-bit registry view" }
        else { Warn "     $($b.Name): NOT visible in the 64-bit view (the one the browser reads)" }

        # ExtensionSettings JSON validity, if the admin has also set that
        # (a separate, richer policy some deployments layer on top).
        $esRaw = Get-PolicyValueInView -SubKey $subKey -ValueName 'ExtensionSettings' -View Registry64
        if ($esRaw) {
          try { $null = $esRaw | ConvertFrom-Json; Ok "     $($b.Name): ExtensionSettings present and is valid JSON" }
          catch { Err "     $($b.Name): ExtensionSettings present but is NOT valid JSON -- the browser will ignore it" }
        }

        # wantVersion -- the managed minimum-version pin agent.cpp/self-update
        # publishes (see task #23/#26's history: this key is powerful enough
        # to block Chrome/Edge startup entirely if malformed, handle with care).
        $wantVer = Get-PolicyValueInView -SubKey $subKey -ValueName 'wantVersion' -View Registry64
        if ($wantVer) { Write-Host "     $($b.Name): wantVersion policy = $wantVer" -ForegroundColor DarkGray }
      }

      # 3) WOW6432Node shadow-copy detection -- if ANYTHING for this
      #    extension id exists under the 32-bit view, some process (this
      #    script running 32-bit in the past, a scheduled task misconfigured
      #    to launch 32-bit PowerShell, etc.) wrote there by mistake. Its
      #    mere presence is the bug, regardless of what the 64-bit view says.
      Write-Host ''
      Write-Host '   3. WOW6432Node shadow-copy check (32-bit view -- should be EMPTY)'
      $shadowFound = $false
      foreach ($b in $BROWSERS) {
        $subKey = $b.Root -replace '^HKLM:\\', ''
        try {
          $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
          $key = $base.OpenSubKey("$subKey\ExtensionInstallForcelist")
          if ($key) {
            foreach ($name in $key.GetValueNames()) {
              $v = $key.GetValue($name)
              if ($v -like "$extId;*") {
                $shadowFound = $true
                Err "     $($b.Name): entry found under WOW6432Node -- this is a shadow copy no browser reads"
              }
            }
            $key.Close()
          }
          $base.Close()
        } catch {}
      }
      if (-not $shadowFound) { Ok '     No WOW6432Node shadow copy found in either browser -- clean.' }

      # 4) Installed-vs-published version, per profile that actually has
      #    the extension -- reuses the same profile-scan Get-ExtensionInstallSources
      #    already does for the unpacked-copy check above.
      Write-Host ''
      Write-Host '   4. Installed version (per browser profile)'
      $sources = Get-ExtensionInstallSources $extId
      if (@($sources).Count -eq 0) {
        Warn '     Extension not found installed in any browser profile on this machine yet.'
      } else {
        foreach ($src in $sources) {
          Write-Host "     $($src.Browser) / $($src.User) / $($src.Profile): v$($src.Version)  ($($src.Label))"
        }
      }
    }

    # 5) Update-feed reachability -- the same URL the browser itself polls
    #    for updates, built from this agent's own configured server.
    Write-Host ''
    Write-Host '   5. Update-feed reachability'
    if (-not $s.ServerUrl) {
      Warn '     Agent is not configured with a server URL yet -- cannot build the feed URL.'
    } else {
      $feedUrl = "$($s.ServerUrl.TrimEnd('/'))/api/v1/extension/update.xml"
      try {
        $resp = Invoke-WebRequest -Uri $feedUrl -UseBasicParsing -Method Head -TimeoutSec 8 -ErrorAction Stop
        Ok "     $feedUrl -- reachable (HTTP $($resp.StatusCode))"
      } catch {
        Err "     $feedUrl -- NOT reachable: $($_.Exception.Message)"
      }
    }
  }

  function Show-BrowserControls($s) {
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
          Ok "     $($b.Name): policy set (force-install entry present)"
        } else {
          Warn "     $($b.Name): NOT force-installed yet (installed browser, or guard task hasn't run)"
        }
      }
      # Honest caveat (gap-scan of CyberSentinel-DLP found this the hard way,
      # across several of their own iterations today): this reads the
      # REGISTRY POLICY, not whether the browser has actually picked it up.
      # Chrome/Edge apply ExtensionInstallForcelist live, but only check for
      # it when the browser starts (or on its own periodic policy refresh) --
      # a "policy set" line above does not mean the extension is loaded and
      # running in an already-open browser window yet.
      Write-Host '     (checks the registry policy, not chrome://extensions itself -- close and' -ForegroundColor DarkGray
      Write-Host '      reopen the browser once, or wait for its normal policy refresh, to confirm)' -ForegroundColor DarkGray

      $sources = Get-ExtensionInstallSources $extStatus.ExtensionId
      $unpacked = @($sources | Where-Object { $_.Location -eq 4 })
      if (@($unpacked).Count -gt 0) {
        Write-Host ''
        Err '     AN UNPACKED COPY IS LOADED, AND IT IS WHAT CHROME/EDGE IS SHOWING YOU.'
        foreach ($u in $unpacked) {
          Warn "       $($u.Browser) / $($u.User) / $($u.Profile)  v$($u.Version)"
          if ($u.Path) { Warn "         from: $($u.Path)" }
        }
        Warn '       It has the same extension id as the published build (the signing key'
        Warn '       is pinned so you debug what you deploy), so it occupies the slot the'
        Warn '       policy is trying to fill -- the popup, icon and behavior you see all'
        Warn '       come from that folder, and a Remove button stays visible, until it is'
        Warn '       gone. This is expected if you set the extension up manually (Load'
        Warn '       unpacked) before force-install existed.'
        Warn '       FIX: chrome://extensions -> SeceoKnight DLP -> Remove. Close and'
        Warn '            reopen the browser -- it reinstalls from the policy instead.'
      } elseif (@($sources | Where-Object { $_.Location -eq 10 }).Count -gt 0) {
        Ok '     Confirmed installed via enterprise policy in at least one browser profile.'
      }
    }

    Write-Host ''
    Write-Host '   Native messaging host (skdlp_host.exe -- what makes the extension actually'
    Write-Host '   evaluate uploads / web activity instead of doing nothing):'
    $hostExePath = Join-Path $INSTALL_DIR $HOST_EXE_NAME
    if (-not (Test-Path $hostExePath)) {
      Warn "     $hostExePath is missing -- run [2] Update to download it."
    } else {
      Ok "     Binary present: $hostExePath"
      $manifestPath = Join-Path $DATA_DIR 'com.seceoknightdlp.dlp.json'
      if (Test-Path $manifestPath) {
        Ok "     Manifest present: $manifestPath"
      } else {
        Warn '     Manifest not written yet -- wait up to 2 minutes (Browser Extension Guard task), or confirm the extension is published on the server.'
      }
      foreach ($root in @(@{ Name='Chrome'; Key='SOFTWARE\Google\Chrome\NativeMessagingHosts' }, @{ Name='Edge'; Key='SOFTWARE\Microsoft\Edge\NativeMessagingHosts' })) {
        $nmhKey = "HKLM:\$($root.Key)\com.seceoknightdlp.dlp"
        if (Test-Path $nmhKey) {
          Ok "     $($root.Name): native-messaging host registered"
        } else {
          Warn "     $($root.Name): NOT registered yet"
        }
      }
      Write-Host '     (confirm end-to-end: chrome://extensions -> the extension -> "service worker"' -ForegroundColor DarkGray
      Write-Host '      console -> look for "native host reachable (pong)")' -ForegroundColor DarkGray
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
    Write-Host '   [3] Force extension reinstall' -ForegroundColor Yellow -NoNewline; Write-Host '- extension stuck / wrong version and self-update is not fixing it'
    Write-Host '   [4] Diagnose                 ' -ForegroundColor Cyan   -NoNewline; Write-Host '- report exactly what the browser sees (both registry views, versions, update-feed)'
    Write-Host '   [5] Back                     ' -ForegroundColor Gray   -NoNewline; Write-Host '- return to the main menu'
    Write-Host ''
    $bc = Read-Host '   Choose an option (1-5)'
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
      '3' {
        Write-Host ''
        Reset-ExtensionForceInstall
      }
      '4' {
        Show-ExtensionDiagnostics $s
      }
      default {}
    }
    Write-Host ''
    Read-Host '   Press Enter to return to the menu' | Out-Null
  }

  # ================= Update (binary-only swap) =================

  # Rewrites the watchdog task if it's still calling the old
  # wscript.exe/watchdog_launcher.vbs launcher instead of the exe directly
  # (agent.cpp's HandleWatchdogCheck(), --watchdog-check).
  #
  # Update-Agent only ever replaced the BINARY historically -- a machine
  # installed before this fix would keep the stale wscript.exe task action
  # forever, since nothing else ever looked at it. That task action is the
  # exact one Windows 11 Application Control/Smart App Control blocks by
  # default ("An Application Control policy has blocked this file"),
  # silently disabling hang-recovery with no visible symptom. Same
  # reconcile-on-Update pattern already used for the browser extension
  # guard and the unpacked-extension check -- an Update should converge a
  # machine on the CURRENT correct install, not just swap the exe.
  function Test-WatchdogTaskCurrent {
    $task = Get-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
    if (-not $task) { return $false }
    foreach ($a in @($task.Actions)) {
      $exe = "$($a.Execute)"
      $arg = "$($a.Arguments)"
      if ($exe -match '(?i)wscript|cscript|powershell|cmd\.exe') { return $false }
      if ($arg -match '(?i)\.vbs') { return $false }
      if ($exe -notmatch [regex]::Escape($EXE_NAME)) { return $false }
    }
    return $true
  }

  function Repair-WatchdogTask($s) {
    if (Test-WatchdogTaskCurrent) { return }
    Warn 'Watchdog task launches via a legacy script host - rewriting it to call the agent directly...'

    foreach ($legacy in @((Join-Path $INSTALL_DIR 'watchdog_launcher.vbs'), (Join-Path $INSTALL_DIR 'watchdog.ps1'))) {
      if (Test-Path $legacy) {
        Remove-Item $legacy -Force -ErrorAction SilentlyContinue
        Info "Removed legacy watchdog launcher: $legacy"
      }
    }

    try {
      $existing = Get-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
      if ($existing) { Unregister-ScheduledTask -TaskName $WATCHDOG_TASK -Confirm:$false }

      $action = New-ScheduledTaskAction -Execute $s.ExePath -Argument '--watchdog-check' -WorkingDirectory $INSTALL_DIR
      $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
      $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew

      Register-ScheduledTask -TaskName $WATCHDOG_TASK -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description 'Detects a hung (alive-but-unresponsive) SeceoKnight DLP Agent process via log staleness and force-restarts it.' `
        -Force -ErrorAction Stop | Out-Null
      Ok 'Watchdog task rewritten to call the agent directly.'
    } catch {
      Err "Could not rewrite watchdog task: $($_.Exception.Message)"
    }
  }

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
      # Start-ScheduledTask returns as soon as the task is QUEUED, not once
      # the process actually exists -- a single check shortly after it was
      # a false-alarm "not detected" on a routine update that was starting
      # normally and heartbeating seconds later (gap-scan of
      # CyberSentinel-DLP hitting and fixing this exact race today, August
      # 19, 2026: their Update path made the identical single-check-after-
      # 3-seconds mistake). Retry like Install already effectively does,
      # instead of crying wolf on a routine update.
      $p = $null
      for ($i = 0; $i -lt 6 -and -not $p; $i++) {
        Start-Sleep -Seconds 2
        $p = Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue
      }
      if ($p) { Ok "Agent restarted (PID $($p.Id))." }
      else    { Warn 'Task started but process not detected yet - check logs.' }
    } catch {
      Err "Could not restart the scheduled task: $($_.Exception.Message)"
      Warn "Start it manually: Start-ScheduledTask -TaskName '$TASK_NAME'"
    }

    # A fresh $s.ExePath now points at the just-replaced binary, which is
    # what the new watchdog task action (if it needs rewriting) must call.
    Repair-WatchdogTask $s

    Update-NativeHost
  }

  # Refreshes skdlp_host.exe (browser-extension native-messaging host)
  # alongside the main agent binary. Best-effort/non-fatal on every failure
  # path -- an Update run must never fail just because the browser-extension
  # piece (optional, only relevant if the extension is actually published on
  # the server) couldn't refresh.
  function Update-NativeHost {
    $hostPath = Join-Path $INSTALL_DIR $HOST_EXE_NAME
    $tmpHostPath = Join-Path $env:TEMP "$HOST_EXE_NAME.new"
    try {
      Invoke-WebRequest -Uri $HOST_DOWNLOAD_URL -OutFile $tmpHostPath -UseBasicParsing -ErrorAction Stop
    } catch {
      Warn "Native-host download failed (non-fatal): $($_.Exception.Message)"
      return
    }

    $expectedHash = $null
    try {
      $expectedHash = (Invoke-WebRequest -Uri $HOST_SUM_URL -UseBasicParsing -ErrorAction Stop).Content.Trim().Split()[0].ToUpper()
    } catch {
      Warn "No SHA-256 sidecar reachable for $HOST_EXE_NAME - skipping integrity check."
    }
    if ($expectedHash) {
      $actualHash = (Get-FileHash -Algorithm SHA256 -Path $tmpHostPath).Hash.ToUpper()
      if ($actualHash -ne $expectedHash) {
        Err "$HOST_EXE_NAME SHA-256 mismatch - refusing to install a tampered/corrupt binary."
        Remove-Item $tmpHostPath -Force -ErrorAction SilentlyContinue
        return
      }
    }

    # skdlp_host.exe is launched fresh by the browser for each native-messaging
    # connection (chrome.runtime.connectNative), so an existing copy can be
    # locked by a still-open Chrome/Edge window even though nothing here
    # started it directly -- Move-Item -Force does NOT override an OS file
    # lock (unlike the main agent binary above, replacing this one doesn't
    # go through a scheduled task we control, so there's no task to stop
    # first). Kill any live skdlp_host processes before attempting the
    # replace; harmless if none are running.
    Get-Process -Name ($HOST_EXE_NAME -replace '\.exe$', '') -ErrorAction SilentlyContinue |
      Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    try {
      Move-Item -Path $tmpHostPath -Destination $hostPath -Force -ErrorAction Stop
      Ok "Native host updated: $hostPath"
      Ok "It will be (re-)registered as the Chrome/Edge native-messaging host automatically within 2 minutes (Browser Extension Guard task)."
      return
    } catch {
      Warn "First replace attempt failed ($($_.Exception.Message)) - retrying once after closing any remaining handle..."
    }

    # One retry: explicitly delete the old file first (a plain Remove-Item
    # sometimes succeeds where Move-Item -Force's implicit overwrite doesn't,
    # e.g. a stale read-only flag from how the file was originally placed),
    # then a longer pause in case a browser process was still exiting.
    Start-Sleep -Seconds 2
    try {
      if (Test-Path $hostPath) {
        Set-ItemProperty -Path $hostPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Remove-Item -Path $hostPath -Force -ErrorAction Stop
      }
      Move-Item -Path $tmpHostPath -Destination $hostPath -Force -ErrorAction Stop
      Ok "Native host updated: $hostPath"
      Ok "It will be (re-)registered as the Chrome/Edge native-messaging host automatically within 2 minutes (Browser Extension Guard task)."
    } catch {
      Warn "Could not replace $HOST_EXE_NAME (non-fatal, still locked - close all Chrome/Edge windows and re-run Update): $($_.Exception.Message)"
      Remove-Item $tmpHostPath -Force -ErrorAction SilentlyContinue
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

    # 2d) Remove the native-messaging host registration (com.seceoknightdlp.dlp)
    #     -- the manifest file itself and skdlp_host.exe live under $INSTALL_DIR/
    #     $DATA_DIR and are deleted wholesale in step 4 below; only the HKLM
    #     registry pointers need clearing separately so they don't dangle at a
    #     path that no longer exists.
    foreach ($root in @('SOFTWARE\Google\Chrome\NativeMessagingHosts', 'SOFTWARE\Microsoft\Edge\NativeMessagingHosts')) {
      $nmhKey = "HKLM:\$root\com.seceoknightdlp.dlp"
      if (Test-Path $nmhKey) {
        Remove-Item -Path $nmhKey -Force -ErrorAction SilentlyContinue
        Info "Cleared native-messaging host registration: $nmhKey"
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
        Show-BrowserControls $s
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
