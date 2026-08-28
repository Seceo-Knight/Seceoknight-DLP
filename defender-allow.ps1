# SeceoKnight DLP Agent - Windows Defender exclusion helper.
#
# Split out of manage-agent.ps1 on August 28, 2026. The exclusion logic
# below (Add-MpPreference -ExclusionPath / -ExclusionProcess) is a
# legitimate, admin-invoked feature -- letting the DLP agent avoid being
# flagged by the same antivirus it complements -- but it is also the
# textbook malware-evasion pattern, and Microsoft Defender's AMSI content
# scanner flags any script containing it especially hard when that script
# arrives via the classic "download-and-instantly-execute" shape
# (`irm ... | iex`), which is exactly how manage-agent.ps1 is normally run.
# With this code inline, AMSI was blocking the ENTIRE manage-agent.ps1
# script before anything in it could run -- including [2] Update, which
# has nothing to do with Defender exclusions and is needed constantly.
#
# Moving this into its own file means only an administrator who
# specifically needs this one feature ever fetches content that trips the
# heuristic; the routine Update/Install/Uninstall/Browser/Status paths in
# manage-agent.ps1 are unaffected.
#
# Run either form (self-elevates to Administrator):
#   powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/defender-allow.ps1 | iex"
#   powershell -ExecutionPolicy Bypass -File .\defender-allow.ps1
#
# If THIS script also gets blocked by AMSI on a given machine, there is no
# further split available -- Add-MpPreference exclusion calls are
# irreducibly what triggers it. In that case, add the exclusion manually
# instead: Windows Security -> Virus & threat protection -> Manage
# settings -> Add or remove exclusions -> add the folder
# "C:\Program Files\SeceoKnight" and the process "seceoknight_agent.exe".

& {
  $ErrorActionPreference = 'Continue'

  $INSTALL_DIR = 'C:\Program Files\SeceoKnight'
  $EXE_NAME    = 'seceoknight_agent.exe'
  $PROC_NAME   = 'seceoknight_agent'
  $TASK_NAME   = 'SeceoKnight DLP Agent'

  function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
  function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
  function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
  function Err($m)  { Write-Host "[x] $m" -ForegroundColor Red }

  Write-Host '============================================================' -ForegroundColor Cyan
  Write-Host '   SeceoKnight DLP - Windows Defender Exclusion   ' -ForegroundColor Cyan
  Write-Host '============================================================' -ForegroundColor Cyan
  Write-Host ''

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
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
          'irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/defender-allow.ps1 | iex')
      }
    } catch {
      Err "Could not self-elevate: $($_.Exception.Message)"
      Warn "Re-open PowerShell with 'Run as administrator' and run this again."
    }
    return
  }

  if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    Warn 'Microsoft Defender cmdlets are not available on this device.'
    Info "A third-party antivirus is probably managing protection instead -- exclude"
    Info "$INSTALL_DIR and $PROC_NAME.exe there by hand."
    return
  }

  # Smart App Control ignores exclusions entirely -- check for it first so
  # this doesn't report false success on a machine where nothing here can
  # possibly help.
  $sac = try {
    $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
            -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop).VerifiedAndReputablePolicyState
    switch ($v) { 0 { 'off' } 1 { 'ON' } 2 { 'evaluation' } default { "unknown ($v)" } }
  } catch { 'not present' }
  if ($sac -eq 'ON') {
    Err 'Smart App Control is ON. It blocks unsigned binaries and IGNORES exclusions.'
    Info 'Nothing below will make the agent run while it is on. It can only be turned'
    Info 'off (Windows Security -> App & browser control -> Smart App Control), which'
    Info 'Windows makes permanent until the OS is reinstalled.'
    return
  }

  # Restore from quarantine first -- excluding a path Defender has already
  # emptied looks like it worked and still leaves you with no binary.
  $hits = @()
  foreach ($cmd in 'Get-MpThreat', 'Get-MpThreatDetection') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { continue }
    try {
      foreach ($t in @(& $cmd -ErrorAction Stop)) {
        $res = @($t.Resources) -join ' '
        if ($res -match [regex]::Escape($PROC_NAME) -or $res -match [regex]::Escape($INSTALL_DIR)) {
          $hits += $t.ThreatName
        }
      }
    } catch {}
  }
  if ($hits.Count -gt 0) {
    $mpcmd = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $mpcmd) {
      foreach ($name in ($hits | Select-Object -Unique)) {
        Info "Restoring from quarantine: $name"
        & $mpcmd -Restore -Name $name 2>&1 | Out-Null
      }
    } else { Warn 'MpCmdRun.exe not found - cannot restore from quarantine automatically.' }
  }

  try {
    Add-MpPreference -ExclusionPath $INSTALL_DIR -ErrorAction Stop
    Ok "Excluded path: $INSTALL_DIR"
  } catch { Err "Could not add the path exclusion: $($_.Exception.Message)" }
  try {
    Add-MpPreference -ExclusionProcess "$PROC_NAME.exe" -ErrorAction Stop
    Ok "Excluded process: $PROC_NAME.exe"
  } catch { Err "Could not add the process exclusion: $($_.Exception.Message)" }

  # Read it back. Add-MpPreference reports success even when tamper
  # protection or a management policy silently discards the change.
  $pref = $null; try { $pref = Get-MpPreference -ErrorAction Stop } catch {}
  $okPath = $pref -and (@($pref.ExclusionPath) | Where-Object { $_ -and $_.TrimEnd('\') -ieq $INSTALL_DIR.TrimEnd('\') }).Count -gt 0
  $okProc = $pref -and (@($pref.ExclusionProcess) | Where-Object { $_ -and $_ -imatch [regex]::Escape($PROC_NAME) }).Count -gt 0
  if (-not ($okPath -and $okProc)) {
    Err 'The exclusions did not stick.'
    Info 'Usually tamper protection, or Defender settings managed by group policy'
    Info 'or Intune. On a managed fleet the exclusion belongs in that policy, not here.'
    return
  }
  Ok 'Exclusions confirmed present.'

  $exe = Join-Path $INSTALL_DIR $EXE_NAME
  if (-not (Test-Path $exe)) {
    Write-Host ''
    Warn 'The binary is still missing - Defender removed it before this ran.'
    Info 'Run manage-agent.ps1 -> [2] Update to fetch a fresh copy; it will not be'
    Info 'quarantined again now that the exclusion is in place.'
    return
  }

  Write-Host ''
  Info 'Restarting the agent...'
  Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
  $proc = $null
  for ($i = 0; $i -lt 6 -and -not $proc; $i++) {
    Start-Sleep -Seconds 2
    $proc = Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue | Select-Object -First 1
  }
  if ($proc) {
    $v = $null; try { $v = (Get-Item $proc.Path).VersionInfo.ProductVersion } catch {}
    if ($v) { Ok "Agent v$($v.Trim()) running (PID $($proc.Id))." } else { Ok "Agent running (PID $($proc.Id))." }
  } else {
    Warn 'Agent still not running. Check the log file for what it says on startup.'
  }
}
