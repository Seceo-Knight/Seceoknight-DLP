# SeceoKnight Kernel Minifilter — Complete Build & Install Guide

This guide takes you from zero to a running kernel-mode file system filter driver.

---

## What You Need (one-time install)

| Tool | Download | Notes |
|------|----------|-------|
| Visual Studio 2022 | https://visualstudio.microsoft.com/downloads/ | Community (free) is fine |
| Windows Driver Kit (WDK) | https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk | Must match VS 2022 |

---

## Phase 1 — Install Visual Studio 2022

1. Download and run **vs_community.exe**
2. On the "Workloads" screen, check:
   - ✅ **Desktop development with C++**
3. Click **Install** and wait (~5–10 min)

---

## Phase 2 — Install WDK (Windows Driver Kit)

> The WDK adds kernel-mode compiler targets and driver libraries to Visual Studio.

1. Go to: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Download **WDK for Windows 11, version 24H2** (matches VS 2022)
3. Run the installer — it will auto-detect your Visual Studio installation
4. When prompted: ✅ **Install Windows Driver Kit Visual Studio extension**
5. Click Install

**Verify the install worked:**
- Open Visual Studio 2022
- File → New → Project
- Search "minifilter" — you should see **"Kernel Mode Driver, Empty (KMDF)"** and **"Filter Driver: IFS MiniFilter"** templates
- If you see them, WDK is installed correctly ✅

---

## Phase 3 — Build the Driver

1. **Pull the latest code** on your Windows machine:
   ```
   cd C:\path\to\NewDLP\extracted\cybersentineldlp-prod-main
   git pull origin main
   ```

2. **Open the solution** in Visual Studio:
   ```
   File → Open → Project/Solution
   → agents\endpoint\windows\kernel\SeceoKnightFilter.sln
   ```

3. **Set configuration** to `Release | x64` (top toolbar dropdown)

4. **Build:**
   ```
   Build → Build Solution   (or press F7)
   ```

5. **Find the output:**
   ```
   agents\endpoint\windows\kernel\x64\Release\csfilter.sys
   ```

If Build fails, see the **Troubleshooting** section at the bottom.

---

## Phase 4 — Enable Test Signing (Development)

> Windows blocks unsigned drivers by default. For development we use test signing.
> **This shows a "Test Mode" watermark on the desktop — normal for dev machines.**

Open PowerShell **as Administrator** and run:

```powershell
cd C:\path\to\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\kernel

.\install_driver.ps1 -Action testsign
```

**Then REBOOT your Windows machine.**

After reboot you will see "Test Mode" in the bottom-right corner of the desktop. That means it worked.

---

## Phase 5 — Install & Start the Driver

After reboot, open PowerShell **as Administrator** again:

```powershell
cd C:\path\to\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\kernel

.\install_driver.ps1 -Action install
```

Expected output:
```
=== Installing SeceoKnight Kernel Minifilter ===
Copying csfilter.sys to System32\drivers...
Creating driver service...
Configuring driver registry (altitude 370100)...
Starting driver...
✅ SeceoKnight kernel minifilter INSTALLED and RUNNING!
```

---

## Phase 6 — Verify Everything is Working

Run the status check:
```powershell
.\install_driver.ps1 -Action status
```

You should see `SeceoKnightFilter` in the `fltmc filters` list with altitude `370100`.

Also check the DLP agent log (`C:\Program Files\SeceoKnight\agent.log`):
```
Kernel minifilter CONNECTED — kernel-level file system enforcement is ACTIVE.
Driver: SeceoKnightFilter (\SeceoKnightPort)
```

If the agent is already running, restart it:
```powershell
Stop-ScheduledTask  -TaskName "SeceoKnight DLP Agent"
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

---

## Phase 7 — Rebuild the Agent .exe (with -lfltlib)

The user-mode agent now links against `fltlib.lib` for the kernel communication.
Rebuild it in MSYS2 with the new flag:

```bash
cd /c/path/to/agents/endpoint/windows

g++ -std=c++17 -O2 \
  agent.cpp network_exfil_monitor.cpp print_monitor.cpp screen_capture_monitor.cpp \
  -o seceoknight_agent.exe \
  -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lws2_32 \
  -lgdi32 -lcomdlg32 -lwinspool -lsetupapi -lcfgmgr32 \
  -lfltlib -static
```

Then deploy:
```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
Get-Process | Where-Object {$_.Path -like "*SeceoKnight*"} | Stop-Process -Force
Copy-Item "seceoknight_agent.exe" "C:\Program Files\SeceoKnight\seceoknight_agent.exe" -Force
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

---

## How the Kernel Driver Works (summary)

```
File Write/Create/Rename happens on disk
         ↓
Windows Filter Manager intercepts it
         ↓
csfilter.sys receives IRP (I/O Request Packet)
         ↓
Driver sends event via \SeceoKnightPort to user-mode agent
         ↓
Agent classifies content (policy_engine.h — <10ms)
         ↓
Agent replies: ALLOW or BLOCK
         ↓
csfilter.sys completes or cancels the IRP
         ↓
File write succeeds or is blocked at kernel level
```

This is the most powerful enforcement level — even admin users cannot bypass it because the block happens inside the OS kernel, before the data reaches the disk.

---

## Uninstall

```powershell
.\install_driver.ps1 -Action uninstall
```

---

## For Production (EV Certificate signing)

Test signing is fine for development. For production machines:

1. Purchase an **EV Code Signing Certificate** from DigiCert, Sectigo, or GlobalSign (~$200-500/year)
2. Use **Microsoft Attestation Signing** (free, via Partner Center) — Microsoft signs your driver after reviewing it
3. Or submit for **WHQL certification** (full Hardware Lab Kit testing)

For production, change in `SeceoKnightFilter.vcxproj`:
```xml
<SignMode>ProductionSign</SignMode>
<ProductionCertificate>YourEVCert.pfx</ProductionCertificate>
```

---

## Troubleshooting

### Build error: "Cannot open include file: fltKernel.h"
WDK is not installed or not linked to Visual Studio.
→ Re-run the WDK installer and make sure "Install WDK VS extension" is checked.

### Build error: "unresolved external symbol FltRegisterFilter"
The project is not linking FltMgr.lib.
→ In VS: Project → Properties → Linker → Input → Additional Dependencies → add `FltMgr.lib`

### Driver fails to start: error 577 (Cannot verify digital signature)
Test signing is not enabled.
→ Run: `.\install_driver.ps1 -Action testsign` then reboot.

### Driver starts but agent shows "Kernel minifilter NOT loaded"
The agent cannot connect to `\SeceoKnightPort`.
→ Check `fltmc filters` — is SeceoKnightFilter listed?
→ If not listed, the driver loaded but crashed. Check Event Viewer → System log.

### "Test Mode" watermark won't go away
Run: `.\install_driver.ps1 -Action testnosign` then reboot.
