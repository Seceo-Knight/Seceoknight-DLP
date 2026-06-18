#!/usr/bin/env python3
"""
SeceoKnight DLP - Linux Agent Installer

Downloads the agent from GitHub, creates a virtualenv, installs dependencies,
generates configuration, and sets up a systemd service — all in one command.

Usage:
    sudo python3 install_linux_agent.py --server-url http://<SERVER-IP>:55000/api/v1
    sudo python3 install_linux_agent.py --server-url http://192.168.1.100:55000/api/v1
    sudo python3 install_linux_agent.py --server-url http://10.0.0.5:55000/api/v1 --no-start

One-liner (download and run):
    curl -sLO https://raw.githubusercontent.com/seceoknight-06/Data-Loss-Prevention/main/install_linux_agent.py && sudo python3 install_linux_agent.py --server-url http://<SERVER-IP>:55000/api/v1
"""

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
import uuid

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

REPO_OWNER = "seceoknight-06"
REPO_NAME = "Data-Loss-Prevention"
DEFAULT_BRANCH = "main"
DEFAULT_INSTALL_DIR = "/opt/seceoknight/agent"
DEFAULT_CONFIG_DIR = "/etc/seceoknight"
SERVICE_NAME = "seceoknight_dlp-agent"

RAW_BASE = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}"

# Files to download: (remote_path, local_filename)
AGENT_FILES = [
    ("agents/endpoint/linux/agent.py", "agent.py"),
    ("agents/endpoint/linux/requirements.txt", "requirements.txt"),
]


# ──────────────────────────────────────────────
# Terminal colours
# ──────────────────────────────────────────────

class Color:
    if sys.stdout.isatty():
        BOLD = "\033[1m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        CYAN = "\033[96m"
        RESET = "\033[0m"
    else:
        BOLD = GREEN = YELLOW = RED = CYAN = RESET = ""


def info(msg):
    print(f"  {Color.CYAN}[INFO]{Color.RESET}  {msg}")


def ok(msg):
    print(f"  {Color.GREEN}[ OK ]{Color.RESET}  {msg}")


def warn(msg):
    print(f"  {Color.YELLOW}[WARN]{Color.RESET}  {msg}")


def err(msg):
    print(f"  {Color.RED}[FAIL]{Color.RESET}  {msg}")


def banner():
    print(
        textwrap.dedent(f"""\
    {Color.CYAN}{Color.BOLD}
    ╔══════════════════════════════════════════════════╗
    ║     SeceoKnight DLP  -  Linux Agent Installer  ║
    ╚══════════════════════════════════════════════════╝{Color.RESET}
    """)
    )


# ──────────────────────────────────────────────
# Prerequisite checks
# ──────────────────────────────────────────────

def check_prerequisites():
    """Verify root, Python version, and systemd."""
    print(f"\n{Color.BOLD}[1/5] Checking prerequisites{Color.RESET}\n")
    all_ok = True

    # Root check
    if os.geteuid() != 0:
        err("This installer must be run as root (use sudo)")
        sys.exit(1)
    ok("Running as root")

    # Python version (3.8+)
    if sys.version_info >= (3, 8):
        ok(f"Python {platform.python_version()}")
    else:
        err(f"Python >= 3.8 required (found {platform.python_version()})")
        all_ok = False

    # Check python3 venv basics — ensurepip is optional, we can bootstrap pip later
    ok("Python venv module available")

    # systemd
    if shutil.which("systemctl"):
        ok("systemd available")
    else:
        err("systemctl not found — systemd is required")
        all_ok = False

    if not all_ok:
        print()
        err("Please fix the issues above and re-run the installer.")
        sys.exit(1)


# ──────────────────────────────────────────────
# Download files
# ──────────────────────────────────────────────

def download_file(url, dest):
    """Download a single file from url to dest."""
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except urllib.error.HTTPError as exc:
        err(f"HTTP {exc.code} downloading {url}")
        return False
    except urllib.error.URLError as exc:
        err(f"Network error: {exc.reason}")
        return False


def download_agent_files(install_dir, branch):
    """Download all agent files into install_dir."""
    print(f"\n{Color.BOLD}[2/5] Downloading agent files{Color.RESET}\n")
    os.makedirs(install_dir, exist_ok=True)

    for remote_path, local_name in AGENT_FILES:
        url = f"{RAW_BASE}/{branch}/{remote_path}"
        dest = os.path.join(install_dir, local_name)
        if download_file(url, dest):
            ok(f"  {local_name}")
        else:
            err(f"  Failed to download {remote_path}")
            sys.exit(1)

    ok(f"Agent files saved to {install_dir}/")


# ──────────────────────────────────────────────
# Python virtualenv and dependencies
# ──────────────────────────────────────────────

def _install_venv_package():
    """Try to install python3-venv via the system package manager."""
    pkg = f"python3.{sys.version_info.minor}-venv"
    pkg_fallback = "python3-venv"
    if shutil.which("apt-get"):
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
        for p in [pkg, pkg_fallback]:
            r = subprocess.run(
                ["apt-get", "install", "-y", "-qq", p],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                return True
    elif shutil.which("dnf"):
        r = subprocess.run(
            ["dnf", "install", "-y", "-q", "python3-libs"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            return True
    elif shutil.which("yum"):
        r = subprocess.run(
            ["yum", "install", "-y", "-q", "python3-libs"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            return True
    return False

def setup_virtualenv(install_dir, force):
    """Create virtualenv and install dependencies."""
    print(f"\n{Color.BOLD}[3/5] Setting up Python environment{Color.RESET}\n")

    venv_dir = os.path.join(install_dir, ".venv")
    venv_python = os.path.join(venv_dir, "bin", "python")
    requirements = os.path.join(install_dir, "requirements.txt")

    # Always remove existing venv if pip is missing (broken from previous run)
    if os.path.exists(venv_dir) and not force:
        check = subprocess.run(
            [venv_python, "-m", "pip", "--version"],
            capture_output=True, text=True
        )
        if check.returncode != 0:
            warn("Existing virtualenv is broken (no pip) — removing...")
            shutil.rmtree(venv_dir)

    if force and os.path.exists(venv_dir):
        warn("Force mode: removing existing virtualenv")
        shutil.rmtree(venv_dir)

    need_create = not os.path.exists(venv_dir)

    if need_create:
        info("Creating virtual environment...")

        # First try: normal venv (includes pip via ensurepip)
        result = subprocess.run(
            [sys.executable, "-m", "venv", venv_dir],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            # Try installing python3-venv package and retry
            warn("venv creation failed — installing python3-venv...")
            _install_venv_package()
            if os.path.exists(venv_dir):
                shutil.rmtree(venv_dir)
            result = subprocess.run(
                [sys.executable, "-m", "venv", venv_dir],
                capture_output=True, text=True
            )

        if result.returncode != 0:
            # Last resort: create venv without pip, then bootstrap pip manually
            warn("Standard venv failed — creating without pip and bootstrapping...")
            if os.path.exists(venv_dir):
                shutil.rmtree(venv_dir)
            result = subprocess.run(
                [sys.executable, "-m", "venv", "--without-pip", venv_dir],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                err(f"Failed to create venv: {result.stderr}")
                sys.exit(1)

        ok("Virtual environment created")

    else:
        ok("Virtual environment already exists")

    # Ensure pip is available — bootstrap with get-pip.py if missing
    pip_check = subprocess.run(
        [venv_python, "-m", "pip", "--version"],
        capture_output=True, text=True
    )
    if pip_check.returncode != 0:
        info("pip not found in venv — bootstrapping with get-pip.py...")
        get_pip_path = os.path.join(install_dir, "get-pip.py")
        if not download_file("https://bootstrap.pypa.io/get-pip.py", get_pip_path):
            err("Failed to download get-pip.py")
            sys.exit(1)
        result = subprocess.run(
            [venv_python, get_pip_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            err(f"Failed to bootstrap pip: {result.stderr}")
            sys.exit(1)
        os.remove(get_pip_path)
        ok("pip bootstrapped successfully")
    else:
        # Upgrade pip
        info("Upgrading pip...")
        subprocess.run(
            [venv_python, "-m", "pip", "install", "--upgrade", "pip"],
            capture_output=True, text=True
        )

    # Install dependencies
    info("Installing dependencies...")
    result = subprocess.run(
        [venv_python, "-m", "pip", "install", "-r", requirements],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        err(f"Failed to install dependencies: {result.stderr}")
        sys.exit(1)
    ok("Dependencies installed (requests, watchdog, python-dateutil)")

    return venv_python


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

def detect_ip():
    """Best-effort detection of the machine's LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def generate_config(config_dir, server_url, install_dir, force):
    """Generate agent_config.json with server URL and agent identity."""
    print(f"\n{Color.BOLD}[4/5] Generating agent configuration{Color.RESET}\n")

    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "agent_config.json")
    quarantine_dir = os.path.join(os.path.dirname(install_dir), "quarantine")

    if os.path.exists(config_path) and not force:
        # Preserve existing config but update server_url
        info("Existing config found — updating server_url only")
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            config["server_url"] = server_url
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            ok(f"Config updated: {config_path}")
            ok(f"Agent ID: {config.get('agent_id', 'unknown')}")
            return
        except Exception as e:
            warn(f"Could not update existing config: {e}, creating new one")

    hostname = socket.gethostname()
    agent_id = str(uuid.uuid4())

    config = {
        "server_url": server_url,
        "agent_id": agent_id,
        "agent_name": hostname,
        "heartbeat_interval": 30,
        "policy_sync_interval": 60,
        "monitoring": {
            "file_system": True,
            "monitored_paths": [
                "/home",
                "/var/www",
                "/opt/data"
            ],
            "exclude_paths": [
                "/home/*/.cache",
                "/home/*/.local/share",
                "/home/*/snap",
                "/opt/seceoknight"
            ],
            "file_extensions": [
                ".pdf", ".docx", ".xlsx", ".txt", ".csv",
                ".json", ".xml", ".sql", ".conf"
            ]
        },
        "quarantine": {
            "enabled": True,
            "folder": quarantine_dir
        },
        "classification": {
            "enabled": True,
            "max_file_size_mb": 10
        }
    }

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    os.makedirs(quarantine_dir, exist_ok=True)

    ok(f"Config written: {config_path}")
    ok(f"Agent ID:       {agent_id}")
    ok(f"Agent name:     {hostname}")
    ok(f"Server URL:     {server_url}")
    ok(f"Quarantine:     {quarantine_dir}")


# ──────────────────────────────────────────────
# Systemd service
# ──────────────────────────────────────────────

def setup_systemd(install_dir, venv_python, server_url, no_start):
    """Create and enable the systemd service."""
    print(f"\n{Color.BOLD}[5/5] Setting up systemd service{Color.RESET}\n")

    unit_path = f"/etc/systemd/system/{SERVICE_NAME}.service"
    agent_script = os.path.join(install_dir, "agent.py")

    unit_content = f"""[Unit]
Description=SeceoKnight DLP Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={install_dir}
Environment=SECEOKNIGHT_SERVER_URL={server_url}
ExecStart={venv_python} {agent_script}
Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    with open(unit_path, "w") as f:
        f.write(unit_content)

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
    ok(f"Service '{SERVICE_NAME}' installed and enabled")

    if not no_start:
        info("Starting agent...")
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True)
        ok("Agent started")

        # Brief pause then check status
        import time
        time.sleep(2)
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "active":
            ok("Agent is running")
        else:
            warn("Agent may not have started correctly")
            info(f"Check logs: journalctl -u {SERVICE_NAME} -n 50")
    else:
        info("Service installed but not started (--no-start)")


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

def print_summary(install_dir, config_dir, server_url, started):
    agent_ip = detect_ip()
    config_path = os.path.join(config_dir, "agent_config.json")

    print(
        textwrap.dedent(f"""
    {Color.CYAN}{Color.BOLD}
    ╔══════════════════════════════════════════════════╗
    ║          Installation Complete                    ║
    ╚══════════════════════════════════════════════════╝{Color.RESET}

    {Color.BOLD}Agent IP:     {Color.RESET}  {agent_ip}
    {Color.BOLD}Server URL:   {Color.RESET}  {server_url}
    {Color.BOLD}Install path: {Color.RESET}  {install_dir}
    {Color.BOLD}Config:       {Color.RESET}  {config_path}
    {Color.BOLD}Service:      {Color.RESET}  {SERVICE_NAME}
    {Color.BOLD}Status:       {Color.RESET}  {"Running" if started else "Not started"}

    {Color.BOLD}Useful Commands:{Color.RESET}
      systemctl status {SERVICE_NAME}          # Check status
      journalctl -u {SERVICE_NAME} -f          # View live logs
      systemctl restart {SERVICE_NAME}         # Restart agent
      systemctl stop {SERVICE_NAME}            # Stop agent

    {Color.BOLD}Configuration:{Color.RESET}
      {config_path}

    {Color.BOLD}Uninstall:{Color.RESET}
      sudo systemctl stop {SERVICE_NAME}
      sudo systemctl disable {SERVICE_NAME}
      sudo rm /etc/systemd/system/{SERVICE_NAME}.service
      sudo rm -rf {install_dir}
      sudo rm -rf {config_dir}
      sudo systemctl daemon-reload
    """)
    )


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SeceoKnight DLP - Linux Agent Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 install_linux_agent.py --server-url http://192.168.1.100:55000/api/v1
              sudo python3 install_linux_agent.py --server-url http://10.0.0.5:55000/api/v1 --no-start
              sudo python3 install_linux_agent.py --server-url http://myserver:55000/api/v1 --force

            One-liner:
              curl -sLO https://raw.githubusercontent.com/seceoknight-06/Data-Loss-Prevention/main/install_linux_agent.py && sudo python3 install_linux_agent.py --server-url http://<SERVER-IP>:55000/api/v1
        """),
    )
    parser.add_argument(
        "--server-url", "-s",
        required=True,
        help="Manager API URL (e.g., http://192.168.1.100:55000/api/v1)",
    )
    parser.add_argument(
        "--install-dir",
        default=DEFAULT_INSTALL_DIR,
        help=f"Agent install directory (default: {DEFAULT_INSTALL_DIR})",
    )
    parser.add_argument(
        "--config-dir",
        default=DEFAULT_CONFIG_DIR,
        help=f"Config directory (default: {DEFAULT_CONFIG_DIR})",
    )
    parser.add_argument(
        "--branch", "-b",
        default=DEFAULT_BRANCH,
        help=f"Git branch to fetch from (default: {DEFAULT_BRANCH})",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Install and configure only — do not start the service",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config and virtualenv",
    )

    args = parser.parse_args()

    # Normalize server URL — strip trailing slash
    server_url = args.server_url.rstrip("/")

    banner()

    # Step 1 — Prerequisites
    check_prerequisites()

    # Step 2 — Download agent files
    download_agent_files(args.install_dir, args.branch)

    # Step 3 — Virtualenv and deps
    venv_python = setup_virtualenv(args.install_dir, args.force)

    # Step 4 — Generate config
    generate_config(args.config_dir, server_url, args.install_dir, args.force)

    # Step 5 — Systemd service
    started = not args.no_start
    setup_systemd(args.install_dir, venv_python, server_url, args.no_start)

    # Summary
    print_summary(args.install_dir, args.config_dir, server_url, started)


if __name__ == "__main__":
    main()
