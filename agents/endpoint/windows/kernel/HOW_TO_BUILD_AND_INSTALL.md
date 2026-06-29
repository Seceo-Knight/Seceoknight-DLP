# How to Build and Install the SeceoKnight Kernel Driver
### Simple Step-by-Step Guide (No technical experience needed)

---

## PART A — Do this on your Mac first

Open the **Terminal** app on your Mac and run these commands one by one:

```
cd /Users/vaibhavhandekar/Downloads/NewDLP/extracted/cybersentineldlp-prod-main
git push origin main
```

That's all for the Mac. Everything else is on your Windows computer.

---

## PART B — Do these steps on your Windows computer

---

### STEP 1 — Download and Install Visual Studio 2022

Visual Studio is a program that lets us build/compile code into software.

1. Open your browser and go to:
   **https://visualstudio.microsoft.com/downloads/**

2. Click the **"Free download"** button under **Community 2022**

3. A file called `vs_community.exe` will download. Open it.

4. A window will open. Wait for it to load (may take 1-2 minutes).

5. You will see a screen with tiles/checkboxes. Look for the tile that says:
   **"Desktop development with C++"**
   Click the checkbox to select it (it should show a blue checkmark).

6. Click the **"Install"** button at the bottom right.

7. Wait for it to finish. This can take **10–20 minutes** depending on your internet speed.
   You will see a progress bar. Just let it run.

8. When it says "Installation succeeded", click **Close**.

---

### STEP 2 — Download and Install the WDK

WDK (Windows Driver Kit) is an add-on that lets Visual Studio build kernel drivers.

1. Open your browser and go to:
   **https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk**

2. Scroll down until you see a heading that says **"Download WDK"** or **"WDK for Windows 11"**

3. Click the download link. A file called `wdksetup.exe` will download.

4. Open `wdksetup.exe`.

5. Click **Next** on all screens until you reach a screen that says:
   **"Install Windows Driver Kit Visual Studio extension"**
   Make sure that checkbox is **ticked**.

6. Click **Install**.

7. Wait for it to finish (5–10 minutes).

8. Click **Close** when done.

---

### STEP 3 — Pull the latest code to your Windows computer

1. Open **File Explorer** (the folder icon in your taskbar)

2. Navigate to the folder where you have the project.
   For example: `C:\Users\YourName\Downloads\NewDLP\extracted\cybersentineldlp-prod-main`

3. In that folder, **right-click on an empty area** and look for one of these options:
   - "Open in Terminal"
   - "Open PowerShell window here"
   - "Git Bash Here"

   Click whichever one appears.

4. In the window that opens, type this and press Enter:
   ```
   git pull origin main
   ```

5. Wait for it to finish. It will show files being downloaded.

---

### STEP 4 — Open the project in Visual Studio and Build the Driver

1. Open **Visual Studio 2022** (search for it in the Windows Start menu)

2. When Visual Studio opens, click **"Open a project or solution"**

3. Navigate to:
   ```
   [your project folder]\agents\endpoint\windows\kernel\
   ```
   And open the file called **`SeceoKnightFilter.sln`**

4. Visual Studio will open with the project loaded.

5. At the top of the screen you will see two dropdown menus.
   Change them to:
   - First dropdown: **Release**
   - Second dropdown: **x64**

6. Now click the menu at the top: **Build → Build Solution**
   (Or press the **F7** key on your keyboard)

7. Wait 1–3 minutes. At the bottom of the screen you will see messages scrolling.

8. When it finishes, look for this message at the bottom:
   ```
   ========== Build: 1 succeeded, 0 failed ==========
   ```
   That means success! ✅

9. The driver file has been created at:
   ```
   [project folder]\agents\endpoint\windows\kernel\x64\Release\csfilter.sys
   ```

> **If you see errors:** Most common cause is WDK not installed correctly.
> Close Visual Studio, re-run `wdksetup.exe`, and make sure the VS extension checkbox is ticked.

---

### STEP 5 — Enable "Test Signing" on Windows

Windows normally blocks drivers that aren't officially signed by Microsoft.
For development, we turn on "Test Signing" mode which allows our driver to run.

> ⚠️ After doing this, you will see a small watermark on your desktop saying
> **"Test Mode"**. This is normal and expected for a development machine.

1. Click the **Windows Start button** (bottom left)

2. Search for **"PowerShell"**

3. Right-click on **"Windows PowerShell"** and choose **"Run as administrator"**

4. A blue/black window will open. Type this and press Enter:
   ```
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
   If it asks you to confirm, type `Y` and press Enter.

5. Now navigate to the kernel folder. Type this (replace the path with your actual path) and press Enter:
   ```
   cd "C:\Users\YourName\Downloads\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\kernel"
   ```

6. Run this command and press Enter:
   ```
   .\install_driver.ps1 -Action testsign
   ```

7. You will see:
   ```
   ✅ Test signing enabled.
   ⚠️  You MUST REBOOT for this to take effect.
   ```

8. **Restart your Windows computer now.**

9. After reboot, you will see **"Test Mode"** text in the bottom-right corner of your desktop.
   This is correct — it means test signing is working.

---

### STEP 6 — Install the Kernel Driver

After the computer restarts:

1. Open **PowerShell as Administrator** again (same as Step 5, steps 1–4)

2. Navigate to the kernel folder again:
   ```
   cd "C:\Users\YourName\Downloads\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\kernel"
   ```

3. Run this command:
   ```
   .\install_driver.ps1 -Action install
   ```

4. You should see:
   ```
   ✅ SeceoKnight kernel minifilter INSTALLED and RUNNING!
   ```

5. Verify it is working by running:
   ```
   .\install_driver.ps1 -Action status
   ```
   You should see **SeceoKnightFilter** listed with status **Running**.

---

### STEP 7 — Install MSYS2 (the compiler tool)

MSYS2 is a free tool that lets us compile the Windows agent program on Windows.

1. Open your browser and go to:
   **https://www.msys2.org/**

2. Click the big download button. A file called `msys2-x86_64-XXXXXXXX.exe` will download.

3. Open that file. A setup wizard will appear.

4. Click **Next** on every screen. Leave the install path as the default (`C:\msys64`).

5. When it finishes, **uncheck** the box that says "Run MSYS2 now" and click **Finish**.

---

### STEP 8 — Open the MSYS2 MinGW64 Terminal

> ⚠️ There are multiple MSYS2 shortcuts installed. You MUST use the right one.
> The wrong terminal will not work.

1. Click the **Windows Start button**

2. In the search box, type exactly: **MSYS2 MinGW x64**

3. You should see an app called **"MSYS2 MinGW x64"** — click it

4. A black terminal window will open. This is where we type all remaining commands.

---

### STEP 9 — Install the C++ Compiler inside MSYS2

This only needs to be done once.

1. Inside the MSYS2 MinGW x64 terminal, type this and press Enter:
   ```
   pacman -Syu
   ```

2. It will download updates. If it says:
   ```
   :: To complete this update all MSYS2 processes including this terminal will be closed...
   ```
   Just press Enter to confirm, then the terminal will close.

3. Open **MSYS2 MinGW x64** again from the Start menu.

4. Now type this and press Enter:
   ```
   pacman -S mingw-w64-x86_64-gcc
   ```

5. It will ask:
   ```
   :: Proceed with installation? [Y/n]
   ```
   Type `Y` and press Enter.

6. Wait for it to download and install. When done, you'll see the `$` prompt again.

---

### STEP 10 — Navigate to the project folder in MSYS2

In the MSYS2 MinGW x64 terminal:

> In MSYS2, Windows drives are written differently:
> - `C:\` becomes `/c/`
> - `C:\Users\vaibhav` becomes `/c/Users/vaibhav`

Type this command (replace `YourName` with your actual Windows username) and press Enter:
```
cd /c/Users/YourName/Downloads/NewDLP/extracted/cybersentineldlp-prod-main/agents/endpoint/windows
```

To confirm you are in the right place, type:
```
ls
```
You should see files like `agent.cpp`, `network_exfil_monitor.cpp`, etc.

---

### STEP 11 — Build the Agent Program

Still in the MSYS2 MinGW x64 terminal, copy and paste this entire command and press Enter:

```
g++ -std=c++17 -O2 agent.cpp network_exfil_monitor.cpp print_monitor.cpp screen_capture_monitor.cpp -o seceoknight_agent.exe -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lws2_32 -lgdi32 -lcomdlg32 -lwinspool -lsetupapi -lcfgmgr32 -lfltlib -static
```

Wait 1–2 minutes. The cursor will blink and then you will get the `$` prompt back.
No output at all = success (compilers are quiet when they work).

Type this to confirm the file was created:
```
ls seceoknight_agent.exe
```
If you see the file listed, it worked ✅

---

### STEP 12 — Deploy the New Agent

1. Open **PowerShell as Administrator** (Step 5, steps 1–3)

2. Run these commands one by one:

```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

```powershell
Get-Process | Where-Object {$_.Path -like "*SeceoKnight*"} | Stop-Process -Force
```

```powershell
Copy-Item "C:\Users\YourName\Downloads\NewDLP\extracted\cybersentineldlp-prod-main\agents\endpoint\windows\seceoknight_agent.exe" "C:\Program Files\SeceoKnight\seceoknight_agent.exe" -Force
```

```powershell
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

---

### STEP 13 — Verify Everything is Working

1. Open the agent log file to confirm the kernel driver connected:
   - Open **File Explorer**
   - Go to: `C:\Program Files\SeceoKnight\`
   - Open the file `agent.log` in Notepad

2. Look for this line near the top:
   ```
   Kernel minifilter CONNECTED — kernel-level file system enforcement is ACTIVE.
   ```
   If you see it, the kernel driver is fully working ✅

3. If you instead see:
   ```
   Kernel minifilter NOT loaded — running in user-mode-only mode
   ```
   Go back to Step 6 and make sure the driver installed and started correctly.

---

### STEP 14 — Push the new agent file to GitHub

Go back to the **MSYS2 MinGW x64** terminal and run:

```
cd /c/Users/YourName/Downloads/NewDLP/extracted/cybersentineldlp-prod-main
git add agents/endpoint/windows/seceoknight_agent.exe
git commit -m "build: Windows agent with kernel minifilter support"
git push origin main
```

---

## You are done! 🎉

Your DLP system now has:
- ✅ Clipboard monitoring and blocking
- ✅ USB file transfer monitoring and blocking
- ✅ File system monitoring (user-mode)
- ✅ **Kernel-level file system enforcement** (new — cannot be bypassed)
- ✅ Server-side classification with block decisions
- ✅ Linux agent with server block support
