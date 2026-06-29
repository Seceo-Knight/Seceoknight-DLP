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

## Phase 7 — Install MSYS2 and Rebuild the Agent .exe

The user-mode agent needs to be rebuilt with an extra flag (`-lfltlib`) for kernel communication.
MSYS2 is the compiler environment we use to build the Windows C++ agent.

### Step 7a — Install MSYS2 (if not already installed)

1. Go to **https://www.msys2.org/**
2. Download `msys2-x86_64-XXXXXXXX.exe` and run it
3. Install to the default path: `C:\msys64`
4. When installation finishes, **uncheck** "Run MSYS2 now" and click Finish

### Step 7b — Open MSYS2 MinGW64 terminal

> ⚠️ You must use the **MinGW64** terminal, NOT the MSYS2 or UCRT64 terminal.
> Only MinGW64 produces native Windows .exe files.

1. Press the **Windows key**
2. Search for **"MSYS2 MinGW x64"**
3. Click it to open the terminal — it looks like a black command prompt window

### Step 7c — Install g++ compiler (first time only)

Inside the MSYS2 MinGW64 terminal, run these two commands one at a time:

```bash
pacman -Syu
```
> If it says "close the terminal and reopen", do that, then open MSYS2 MinGW64 again and run:

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gcc-libs
```
Press `Y` and Enter when asked to confirm.

### Step 7d — Navigate to the project folder

Still inside the MSYS2 MinGW64 terminal:

```bash
cd /c/Users/YourWindowsUsername/Downloads/NewDLP/extracted/cybersentineldlp-prod-main/agents/endpoint/windows
```

> Replace `YourWindowsUsername` with your actual Windows username (e.g. `vaibhav`).
> In MSYS2, `C:\` is written as `/c/`

Pull the latest code first:
```bash
cd /c/Users/YourWindowsUsername/Downloads/NewDLP/extracted/cybersentineldlp-prod-main
git pull origin main
cd agents/endpoint/windows
```

### Step 7e — Build the agent

Run this single command inside the MSYS2 MinGW64 terminal:

```bash
g++ -std=c++17 -O2 \
  agent.cpp network_exfil_monitor.cpp print_monitor.cpp screen_capture_monitor.cpp \
  -o seceoknight_agent.exe \
  -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lws2_32 \
  -lgdi32 -lcomdlg32 -lwinspool -lsetupapi -lcfgmgr32 \
  -lfltlib -static
```

> The key new flag is **`-lfltlib`** — this links the Windows Filter Manager library
> so the agent can talk to the kernel driver via `FilterConnectCommunicationPort`.

Wait ~1-2 minutes. When it finishes with no errors, you will see `seceoknight_agent.exe`
in the current folder.

### Step 7f — Deploy the new .exe

Now switch to **PowerShell as Administrator** and run:

```powershell
# Stop the running agent
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
Get-Process | Where-Object {$_.Path -like "*SeceoKnight*"} | Stop-Process -Force

# Copy new binary (adjust path to match your Windows username)
Copy-Item "C:\Users\YourWindowsUsername\Downloads\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\seceoknight_agent.exe" `
          "C:\Program Files\SeceoKnight\seceoknight_agent.exe" -Force

# Start the agent again
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

### Step 7g — Push the new .exe to git (from MSYS2 terminal)

```bash
cd /c/Users/YourWindowsUsername/Downloads/NewDLP/extracted/cybersentineldlp-prod-main
git add agents/endpoint/windows/seceoknight_agent.exe
git commit -m "build: Windows agent with kernel minifilter support (-lfltlib)"
git push origin main
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
