<#
  What the DLP agent's typed-message hook resolves the foreground app to.

  Ported from CyberSentinel-DLP (gap-scan of commit 07ea6ba, August 21
  2026). This is the exact diagnostic that found the WhatsApp-never-matches
  bug: the hook is deliberately silent when the foreground app is not in
  the policy's managed list -- it does no I/O -- so when typed-message
  inspection appears to do nothing, there was previously no way from the
  log alone to tell "the app was ignored" apart from "the app was
  inspected and found nothing". This prints exactly what the hook sees,
  independent of the agent/log entirely.

  Run it, then click into the app's message box and wait for the countdown.
#>

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class FgProbe {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out int p);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
}
"@

Write-Host ''
Write-Host '  Click into the chat app''s message box now.' -ForegroundColor Cyan
foreach ($n in 6..1) { Write-Host ("  capturing in {0}..." -f $n); Start-Sleep -Seconds 1 }
Write-Host ''

$fg = [FgProbe]::GetForegroundWindow()
if ($fg -eq [IntPtr]::Zero) { Write-Host '  no foreground window' -ForegroundColor Red; return }

# NOTE: not $pid — that is a read-only PowerShell automatic variable.
$ownerPid = 0
[void][FgProbe]::GetWindowThreadProcessId($fg, [ref]$ownerPid)
$cls = New-Object System.Text.StringBuilder 256; [void][FgProbe]::GetClassName($fg, $cls, 256)
$ttl = New-Object System.Text.StringBuilder 256; [void][FgProbe]::GetWindowText($fg, $ttl, 256)
$proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue

Write-Host '  FOREGROUND WINDOW  (this is what the hook resolves the app from)' -ForegroundColor Yellow
Write-Host ("    exe   : {0}.exe" -f $(if ($proc) { $proc.ProcessName } else { '<gone>' }))
Write-Host ("    pid   : {0}" -f $ownerPid)
Write-Host ("    class : {0}" -f $cls.ToString())
Write-Host ("    title : {0}" -f $ttl.ToString())

$script:ownerPid = $ownerPid
$script:kids = New-Object System.Collections.ArrayList
$cb = [FgProbe+EnumWindowsProc] {
  param($h, $l)
  $cp = 0
  [void][FgProbe]::GetWindowThreadProcessId($h, [ref]$cp)
  if ($cp -ne $script:ownerPid) {
    $c = New-Object System.Text.StringBuilder 256
    [void][FgProbe]::GetClassName($h, $c, 256)
    $p2 = Get-Process -Id $cp -ErrorAction SilentlyContinue
    [void]$script:kids.Add(("    exe={0}.exe  pid={1}  class={2}" -f `
      $(if ($p2) { $p2.ProcessName } else { '<gone>' }), $cp, $c.ToString()))
  }
  return $true
}
[void][FgProbe]::EnumChildWindows($fg, $cb, [IntPtr]::Zero)

if ($script:kids.Count -gt 0) {
  Write-Host ''
  Write-Host '  CHILD WINDOWS OWNED BY ANOTHER PROCESS  (packaged / webview hosting)' -ForegroundColor Yellow
  $script:kids | Select-Object -Unique | ForEach-Object { Write-Host $_ }
}

Write-Host ''
Write-Host '  The exe on the FOREGROUND line is the name the policy must list.' -ForegroundColor Green
Write-Host '  If it is applicationframehost.exe, the agent steps through to the child.' -ForegroundColor DarkGray
Write-Host ''
