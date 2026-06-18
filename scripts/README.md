# Agent installer scripts

This directory holds the **Linux agent installer**.

The Windows agent installer used to live here too (`install_windows_agent.ps1`),
along with several legacy duplicates. They have all been removed in
favour of the single canonical script at the repo root:

> **`install-agent.ps1`** (in the repo root)

For the full deployment walkthrough — server install, agent build, agent
install, day-2 ops — see **[`DEPLOYMENT.md`](../DEPLOYMENT.md)** at the
repo root.

---

## Linux agent installer (`install_linux_agent.sh`)

`install_linux_agent.sh` automates fetching the Linux agent from git,
creating a venv, installing dependencies, templating `agent_config.json`,
and registering a systemd service with boot autostart.

### Arguments

- `--manager-url` (default `https://YOUR_SERVER_IP/api/v1`)
- `--install-dir` (default `/opt/seceoknight/agent`)
- `--config-dir` (default `/etc/seceoknight`)
- `--venv-dir` (default `<install-dir>/.venv`)
- `--repo-url` (default `https://github.com/Seceo-Knight/Seceoknight-DLP.git`)
- `--branch` (default `main`)
- `--ref` (optional commit/tag)
- `--service-name` (default `seceoknight-agent`)
- `--log-path` (default `<install-dir>/seceoknight_agent.log`)
- `--no-start` (skip starting service)
- `--force` (re-clone and overwrite config/venv)
- If `SECEOKNIGHT_SERVER_URL` is set and you omit `--manager-url`,
  the installer uses that value.

### Usage examples

```bash
# Fresh install
sudo bash scripts/install_linux_agent.sh \
    --manager-url https://YOUR_SERVER_IP/api/v1

# Pin to a specific commit and skip starting the service
sudo bash scripts/install_linux_agent.sh \
    --manager-url https://YOUR_SERVER_IP/api/v1 \
    --ref abc123 --no-start

# Re-provision with overwrite
sudo bash scripts/install_linux_agent.sh \
    --manager-url https://YOUR_SERVER_IP/api/v1 --force

# Remote host via env var
sudo SECEOKNIGHT_SERVER_URL=https://YOUR_SERVER_IP/api/v1 \
    bash scripts/install_linux_agent.sh --force
```

### Notes

- Requires `root`/`sudo`, `git`, Python 3.10+, and `systemd`.
- The service autostarts on boot (`WantedBy=multi-user.target`),
  `Restart=on-failure`, and gets `SECEOKNIGHT_SERVER_URL` from
  `--manager-url`.
- Config is written to `<config-dir>/agent_config.json`. Existing
  config is preserved unless `--force` is used.
- Logs go to `<install-dir>/seceoknight_agent.log` and to journalctl.

### Useful commands

```bash
systemctl status seceoknight-agent
journalctl -u seceoknight-agent -n 50
sudo tail -n 50 /opt/seceoknight/agent/seceoknight_agent.log
sudo systemctl start|stop|restart seceoknight-agent
```
