# Windows Agent Installation Guide

## Prerequisites

- Windows 10/11 (64-bit)
- Administrator privileges
- Network access to the SeceoKnight server (port 55000)
- .NET Framework 4.5+ (pre-installed on Windows 10/11)

## Step 1: Get the server URL

Your SeceoKnight server should be running and accessible. Verify:

```powershell
curl http://<SERVER_IP>:55000/health
```

You should see `{"status":"healthy",...}`.

## Step 2: Download the agent

Option A -- Copy from this repository:

```
agents/endpoint/windows/seceoknight_agent.exe
```

Option B -- Download from the server (if hosted):

```powershell
Invoke-WebRequest -Uri "http://<SERVER_IP>:55000/downloads/agent" -OutFile "seceoknight_agent.exe"
```

## Step 3: Create installation directory

Open PowerShell as Administrator:

```powershell
New-Item -ItemType Directory -Path "C:\Program Files\SeceoKnight" -Force
Copy-Item seceoknight_agent.exe "C:\Program Files\SeceoKnight\"
```

## Step 4: Create agent configuration

```powershell
@"
{
  "server_url": "http://<SERVER_IP>:55000/api/v1",
  "agent_name": "$env:COMPUTERNAME",
  "heartbeat_interval": 30,
  "policy_sync_interval": 60,
  "monitoring": {
    "file_system": true,
    "clipboard": true,
    "usb_devices": true,
    "screen_capture": true,
    "print_jobs": true,
    "monitored_paths": [
      "C:\\Users\\$env:USERNAME\\Documents",
      "C:\\Users\\$env:USERNAME\\Desktop",
      "C:\\Users\\$env:USERNAME\\Downloads"
    ],
    "file_extensions": [".pdf", ".docx", ".xlsx", ".csv", ".txt", ".json", ".xml", ".sql", ".pem", ".key"]
  },
  "quarantine_path": "C:\\ProgramData\\SeceoKnight\\quarantine",
  "log_path": "C:\\ProgramData\\SeceoKnight\\logs",
  "cache_path": "C:\\ProgramData\\SeceoKnight\\cache"
}
"@ | Set-Content "C:\Program Files\SeceoKnight\agent_config.json"
```

Replace `<SERVER_IP>` with your actual server address.

## Step 5: Create data directories

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\SeceoKnight\quarantine" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\SeceoKnight\logs" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\SeceoKnight\cache" -Force
```

## Step 6: Register as a Scheduled Task (canonical method)

> **Recommended:** use the one-liner installer which performs all of steps 3–7
> automatically, including SHA-256 verification of the downloaded binary:
>
> ```powershell
> powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
> ```

If you are registering manually, create a scheduled task named
`SeceoKnight DLP Agent`. The task runs the agent at user logon and at
system startup with elevated privileges, and auto-restarts on crash.

```powershell
$agentExe  = "C:\Program Files\SeceoKnight\seceoknight_agent.exe"
$launchVbs = "C:\Program Files\SeceoKnight\launch_agent.vbs"

# VBScript launcher hides the console window
@'
Set objShell = CreateObject("WScript.Shell")
objShell.Run """C:\Program Files\SeceoKnight\seceoknight_agent.exe""", 0, False
'@ | Out-File -FilePath $launchVbs -Encoding ASCII

$action    = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$launchVbs`""
$trigger1  = New-ScheduledTaskTrigger -AtLogOn
$trigger2  = New-ScheduledTaskTrigger -AtStartup
$trigger2.Delay = "PT30S"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "SeceoKnight DLP Agent" `
    -Action $action -Trigger @($trigger1, $trigger2) `
    -Principal $principal -Settings $settings
```

## Step 7: Start the scheduled task

```powershell
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

Verify the process is running:

```powershell
Get-Process -Name "seceoknight_agent"
```

You should see **exactly one** `seceoknight_agent` process.

## Step 8: Verify registration

The agent automatically registers with the server on first start. Check the server dashboard or API:

```powershell
curl http://<SERVER_IP>:55000/api/v1/agents/
```

Your agent should appear with status `active`.

## Step 9: Verify monitoring

1. Copy a test file to a USB drive -- the agent should detect and report it
2. Copy sensitive text (e.g., a fake SSN `123-45-6789`) to clipboard -- should be detected
3. Press PrintScreen -- screen capture should be logged
4. Check the dashboard at `http://<SERVER_IP>:3023` for events

## Kernel Driver (Optional)

The kernel minifilter driver provides deeper file operation interception. It requires:

- Windows Driver Kit (WDK) for building
- Test signing enabled or a valid code signing certificate
- Driver loaded via `fltmc load SeceoKnightFilter`

The user-mode agent works without the kernel driver using Windows API hooks.

To install the kernel driver:

```powershell
# Enable test signing (development only, reboot required)
bcdedit /set testsigning on

# Copy driver files
Copy-Item kernel\csfilter.sys C:\Windows\System32\drivers\
Copy-Item kernel\csfilter.inf C:\Windows\INF\

# Install the driver
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 C:\Windows\INF\csfilter.inf

# Load the minifilter
fltmc load SeceoKnightFilter
```

## Agent Management

> The task is configured with `RestartCount 999`. Always
> `Stop-ScheduledTask` **before** killing the process — otherwise the
> Task Scheduler will restart it within 1 minute.

```powershell
# Stop the agent (must stop task first, then process)
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue

# Start the agent
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"

# Restart (stop + start)
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"

# View status (should show exactly one process)
Get-Process -Name "seceoknight_agent"

# View task state
Get-ScheduledTask -TaskName "SeceoKnight DLP Agent" | Get-ScheduledTaskInfo

# Tail logs
Get-Content "C:\Program Files\SeceoKnight\seceoknight_agent.log" -Tail 50 -Wait
```

## Uninstall

```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent" -ErrorAction SilentlyContinue
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SeceoKnight DLP Agent" -Confirm:$false
Remove-Item "C:\Program Files\SeceoKnight" -Recurse -Force
# Optionally remove data:
Remove-Item "C:\ProgramData\SeceoKnight" -Recurse -Force
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Agent not registering | Check firewall allows outbound to port 55000 |
| Agent crashes on start | Check `agent_config.json` is valid JSON, verify server URL |
| Two `seceoknight_agent` processes running | Zombie from previous run — `Stop-ScheduledTask` first, then `Stop-Process -Force`, verify empty, then `Start-ScheduledTask` |
| USB events not detected | Ensure `usb_devices: true` in config, agent must run as SYSTEM |
| No events in dashboard | Check agent logs in `C:\ProgramData\SeceoKnight\logs\` |
| Policy sync failing | Verify server is reachable, check API key in agent logs |
| High CPU usage | Reduce monitored paths, increase `policy_sync_interval` |
