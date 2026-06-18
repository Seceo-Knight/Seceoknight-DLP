#!/bin/bash
# Build script for SeceoKnight Windows Agent
# Run this in MSYS2 MinGW 64-bit terminal

echo "=========================================="
echo "SeceoKnight Agent Build Script"
echo "=========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "agent.cpp" ]; then
    echo "ERROR: agent.cpp not found!"
    echo "Please run this script from the agents/endpoint/windows directory"
    exit 1
fi

# Backup old executable if it exists
if [ -f "seceoknight_agent.exe" ]; then
    echo "Backing up existing executable..."
    cp seceoknight_agent.exe seceoknight_agent.exe.backup.$(date +%Y%m%d_%H%M%S)
    echo "✓ Backup created"
    echo ""
fi

echo "Compiling agent..."
echo "This may take 30-60 seconds..."
echo ""

# Compile the agent
g++ -std=c++17 -O2 \
    agent.cpp screen_capture_monitor.cpp print_monitor.cpp network_exfil_monitor.cpp \
    -o seceoknight_agent.exe \
    -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lgdi32 \
    -lws2_32 -lsetupapi -ladvapi32 -lcfgmgr32 -lshell32 -lwinspool \
    -luiautomationcore -lpsapi -static

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "✓ Compilation successful!"
    echo "=========================================="
    echo ""

    # Show file size (pure shell - no bc dependency)
    SIZE=$(stat -c%s seceoknight_agent.exe 2>/dev/null || stat -f%z seceoknight_agent.exe 2>/dev/null)
    if [ -n "$SIZE" ]; then
        SIZE_MB=$(( SIZE / 1024 / 1024 ))
        SIZE_KB_REM=$(( (SIZE / 1024) % 1024 ))
        printf "Executable: seceoknight_agent.exe\n"
        printf "Size: %d.%02d MB (%d bytes)\n" "$SIZE_MB" "$(( SIZE_KB_REM * 100 / 1024 ))" "$SIZE"
    else
        echo "Executable: seceoknight_agent.exe"
    fi
    echo ""

    echo "Features in this build:"
    echo "  • Clipboard / USB / Screenshot / Print monitoring (existing)"
    echo "  • Real-time content classification before blocking"
    echo "  • Network Exfiltration Monitor (NEW):"
    echo "      - curl / wget / PowerShell / bitsadmin / certutil: BLOCKING"
    echo "      - Python script-based transfers: BEST-EFFORT detection"
    echo "      - Browser (chrome/msedge/firefox) file-dialog: ALERT ONLY"
    echo ""

    echo "=========================================="
    echo "Deployment (PowerShell as Administrator)"
    echo "=========================================="
    echo ""
    echo "NOTE: The agent runs as a Scheduled Task named"
    echo "      \"SeceoKnight DLP Agent\" (not a Windows service)."
    echo ""
    echo "  1. Stop the scheduled task (prevents auto-restart):"
    echo "     Stop-ScheduledTask -TaskName \"SeceoKnight DLP Agent\""
    echo ""
    echo "  2. Kill any remaining agent process:"
    echo "     Stop-Process -Name \"seceoknight_agent\" -Force -ErrorAction SilentlyContinue"
    echo ""
    echo "  3. Verify no agent process is running:"
    echo "     Get-Process -Name \"seceoknight_agent\" -ErrorAction SilentlyContinue"
    echo "     (output should be empty)"
    echo ""
    echo "  4. Backup the current binary:"
    echo "     Copy-Item \"C:\\Program Files\\SeceoKnight\\seceoknight_agent.exe\" \`"
    echo "               \"C:\\Program Files\\SeceoKnight\\seceoknight_agent.exe.backup\" -Force"
    echo ""
    echo "  5. Copy the newly built binary into place:"
    echo "     Copy-Item \"$(pwd)/seceoknight_agent.exe\" \`"
    echo "               \"C:\\Program Files\\SeceoKnight\\seceoknight_agent.exe\" -Force"
    echo ""
    echo "  6. (Optional) Ensure heartbeat_interval is set to 3 in the config:"
    echo "     notepad \"C:\\Program Files\\SeceoKnight\\agent_config.json\""
    echo ""
    echo "  7. Start the scheduled task:"
    echo "     Start-ScheduledTask -TaskName \"SeceoKnight DLP Agent\""
    echo ""
    echo "  8. Verify exactly ONE process is running:"
    echo "     Get-Process -Name \"seceoknight_agent\""
    echo ""
else
    echo ""
    echo "=========================================="
    echo "✗ Compilation failed!"
    echo "=========================================="
    echo ""
    echo "Please check the error messages above."
    echo ""
    echo "Common issues:"
    echo "  • Make sure you're running this in MSYS2 MinGW 64-bit terminal"
    echo "  • Ensure g++ is installed: pacman -S mingw-w64-x86_64-gcc"
    echo "  • Check for syntax errors in agent.cpp"
    echo ""
    exit 1
fi
