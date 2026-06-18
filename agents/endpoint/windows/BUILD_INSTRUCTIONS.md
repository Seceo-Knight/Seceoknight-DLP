# Windows Agent Build Instructions

## Changes Made

The Windows agent has been updated with real-time classification-based blocking functionality. The following changes were made to `agent.cpp`:

### 1. New PolicyEvaluationResult Struct
Added at line ~5147 to hold classification results from the server:
- `shouldBlock`: Whether to block the file transfer
- `action`: "allow" or "block"
- `reason`: Human-readable reason
- `classificationLevel`: "Public", "Internal", "Confidential", or "Restricted"
- `confidenceScore`: 0.0-1.0 confidence score
- `matchedRules`: List of sensitive data types detected (e.g., "Aadhaar Number", "US Phone Number")
- `totalMatches`: Total number of pattern matches
- `evaluationSucceeded`: Whether the API call succeeded

### 2. New EvaluatePolicyRealtime() Function
Added at line ~5158 to call the server's real-time classification API:
- Reads file content from disk (up to 10MB limit)
- Escapes content for JSON transmission
- Calls `POST /api/v1/agents/{agent_id}/policy/evaluate`
- Parses classification response
- Returns evaluation result with full classification details

### 3. Modified CheckUSBDriveForMonitoredFiles() Function
Updated at line ~5411 to use real-time classification:
- **Before**: Immediately blocked ALL files from monitored paths
- **After**: Calls `EvaluatePolicyRealtime()` to classify content FIRST
- Only blocks if server detects sensitive data
- Logs detailed classification information
- Falls back to traditional blocking on API errors (fail-safe)

### Key Features:
- ✅ Content-aware blocking (only blocks files with sensitive data)
- ✅ Detailed logging showing classification level, confidence, and matched rules
- ✅ Fail-safe design (allows transfer on API errors)
- ✅ Allows normal files, blocks only sensitive files

## Building the Agent

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- MSYS2 with MinGW-w64 (64-bit)
- G++ compiler with C++17 support

### Step 1: Install MSYS2
1. Download from https://www.msys2.org/
2. Install to `C:\msys64`
3. Open "MSYS2 MinGW 64-bit" terminal

### Step 2: Install Required Packages
```bash
pacman -S mingw-w64-x86_64-gcc
```

### Step 3: Navigate to Agent Directory
```bash
cd /c/path/to/Data-Loss-Prevention/agents/endpoint/windows
```

### Step 4: Compile
```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 agent.cpp -o seceoknight_agent.exe \
    -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 \
    -lws2_32 -lsetupapi -ladvapi32 -lcfgmgr32 -lshell32 -static
```

**Or using the simpler g++ command in MSYS2:**
```bash
g++ -std=c++17 -O2 agent.cpp -o seceoknight_agent.exe \
    -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 \
    -lws2_32 -lsetupapi -ladvapi32 -lcfgmgr32 -lshell32 -static
```

### Step 5: Verify Compilation
```bash
ls -lh seceoknight_agent.exe
```

The executable should be around 3-4 MB.

## Deploying the Agent

### Option 1: Update Existing Installation

> The agent runs as a **Scheduled Task** named `SeceoKnight DLP Agent`
> (not a Windows service). The task is configured with `RestartCount 999`,
> so you must stop the task *before* killing the process, otherwise the
> Task Scheduler will restart it within 1 minute.

1. Stop the scheduled task (prevents auto-restart):
   ```powershell
   Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
   ```

2. Kill any remaining agent process:
   ```powershell
   Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
   ```

3. Verify no agent process is still running:
   ```powershell
   Get-Process -Name "seceoknight_agent" -ErrorAction SilentlyContinue
   # (output should be empty)
   ```

4. Backup old executable:
   ```powershell
   Copy-Item "C:\Program Files\SeceoKnight\seceoknight_agent.exe" `
             "C:\Program Files\SeceoKnight\seceoknight_agent.exe.backup" -Force
   ```

5. Replace with new executable:
   ```powershell
   Copy-Item "path\to\seceoknight_agent.exe" `
             "C:\Program Files\SeceoKnight\seceoknight_agent.exe" -Force
   ```

6. Start the scheduled task:
   ```powershell
   Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
   ```

7. Verify exactly one agent process is running:
   ```powershell
   Get-Process -Name "seceoknight_agent"
   ```

### Option 2: re-run the canonical one-liner installer

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
```

This is the recommended path. The installer cleans the previous
install in Step 2 and verifies the downloaded binary against its
SHA-256 sidecar. See [`DEPLOYMENT.md`](../../../DEPLOYMENT.md) for the
full walkthrough.

## Testing the New Functionality

### Test 1: Block Sensitive File
1. Create a test file with sensitive data:
   ```
   Employee Name: John Doe
   Aadhaar: 1234 5678 9012
   Phone: +91 98765 43210
   Email: john.doe@company.com
   Account: 1234567890123456
   ```

2. Save as `employee_data.xlsx` in Downloads folder

3. Insert USB drive

4. Copy `employee_data.xlsx` to USB

5. **Expected Result**:
   - File transfer should be BLOCKED
   - Log should show:
     ```
     🔍 Calling real-time classification API for: employee_data.xlsx
     📊 Classification Result:
        File: employee_data.xlsx
        Level: Restricted
        Confidence: 95%
        Decision: block
        Detected sensitive data types:
           - Aadhaar Number
           - Indian Mobile Number
           - Email Address
     🚫 CONTENT-AWARE BLOCKING TRIGGERED!
     ```

### Test 2: Allow Normal File
1. Create a normal text file:
   ```
   This is a normal document with no sensitive information.
   Just some regular text content.
   ```

2. Save as `normal_file.txt` in Downloads folder

3. Copy to USB

4. **Expected Result**:
   - File transfer should be ALLOWED
   - Log should show:
     ```
     🔍 Calling real-time classification API for: normal_file.txt
     📊 Classification Result:
        File: normal_file.txt
        Level: Public
        Confidence: 5%
        Decision: allow
     ✅ File ALLOWED - Classification: Public (5% confidence)
        No sensitive data detected, allowing transfer
     ```

## Troubleshooting

### Compilation Errors
- **Error: mutex not found**: Ensure you're using MinGW-w64 64-bit, not 32-bit
- **Error: cannot find -lwinhttp**: Install Windows SDK headers: `pacman -S mingw-w64-x86_64-headers-git`
- **Error: C++17 not supported**: Update GCC: `pacman -Syu mingw-w64-x86_64-gcc`

### Runtime Errors
- **API call fails**: Check that DLP server is running and accessible
- **Agent crashes**: Check Windows Event Viewer → Application logs
- **No classification logs**: Ensure `SECEOKNIGHT_LOG_DIR` environment variable is set or check current directory for `seceoknight_agent.log`

## Verification

After deployment, verify the new functionality is working:

1. Check agent log for real-time classification calls:
   ```powershell
   Get-Content "C:\Program Files\SeceoKnight\seceoknight_agent.log" -Tail 50 | Select-String "Classification"
   ```

2. Check server logs for evaluation API calls:
   ```bash
   docker logs dlp-manager 2>&1 | grep "policy/evaluate"
   ```

3. Test both scenarios (sensitive and normal files) to ensure content-aware blocking is working correctly.

## Notes

- The agent now makes an API call for EVERY file transfer to USB, which adds ~100-500ms latency
- Large files (>10MB) are allowed by default for performance reasons
- On API errors, the agent fails-open (allows transfer) to avoid breaking workflows
- Classification results are cached on server-side for performance

## Rollback

If you need to rollback to the previous version:

```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Copy-Item "C:\Program Files\SeceoKnight\seceoknight_agent.exe.backup" `
          "C:\Program Files\SeceoKnight\seceoknight_agent.exe" -Force
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```
