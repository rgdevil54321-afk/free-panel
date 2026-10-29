# DeupGaming Free Panel

Self-hosted VPS panel (LXD containers, no KVM) with a one-command management suite.

## Quick start

On a fresh Debian 12 / Ubuntu 22.04+ VPS:

```bash
git clone https://github.com/venlixnodes-oss/free-panel-dxd.git
cd free-panel-dxd
bash install.sh
```

You get a menu:

```
1) Install panel        (full automatic setup)
2) Reinstall panel      (keeps database)
3) Update panel
4) Start    5) Stop    6) Restart    7) Status    8) Logs
9) Reset admin password
10) Change panel port
11) Backup now   12) Restore backup
13) Uninstall panel
14) Open shell in panel directory
```

Pick `1`, enter a username and password (or leave the password blank to
auto-generate one), and the installer will:

- install system packages (LXD, Python, iptables, …)
- enable IPv4 forwarding
- start and initialise LXD (`lxd init --auto`, never `--minimal-config`)
- create the storage pool — ZFS when available, automatic `dir` fallback when not
- import the `ubuntu/22.04` image
- create a Python **venv** (required on PEP 668 distros such as Debian 12)
- install `requirements.txt`
- create the admin account and per-VPS CPU/RAM/disk limits
- install and start the `deup-panel` systemd service
- open the port in ufw/firewalld when they are active
- verify the panel answers on HTTP and repair itself if it does not

At the end it prints the panel URL and the login, and saves it to
`/root/.deup-panel-credentials`.

After installation, `panel` opens the same menu from anywhere.

## Non-interactive install

```bash
PANEL_USER=admin PANEL_PASS='change-me' VPS_CPU=4 VPS_RAM=4 VPS_DISK=80 \
  bash install.sh --install
```

Other flags: `--reinstall`, `--update`, `--start`, `--stop`, `--restart`,
`--status`, `--logs`, `--backup`, `--restore [file]`, `--reset-admin`,
`--port N`, `--uninstall [--purge]`, `--help`.

## Requirements

- root (the script re-executes itself with `sudo` when needed)
- ~2 GB RAM, a few GB free disk
- outbound internet for packages, PyPI and the base image

## Troubleshooting

The suite repairs most problems by itself. If the panel is not answering:

```bash
panel            # menu -> 7) Status, 8) Logs
journalctl -u deup-panel -n 100 --no-pager
```

Common causes:

| Symptom | Fix |
| --- | --- |
| Port already used | `panel` → 10) Change panel port |
| `lxd` socket missing | `systemctl enable --now lxd` (the installer does this) |
| No storage pool | `lxc storage list`; installer creates `zfs-new` (dir fallback) |
| Panel unreachable from browser | open the panel port in the provider firewall/security group |
| Lost admin password | `panel` → 9) Reset admin password |

## Privacy

External IP intelligence is **off** by default. Set `IP_INTEL_ENABLED=1` only
if you explicitly want `ip-api.com` lookups; otherwise the panel never sends
visitor IPs to a third party. `ProxyFix` is only enabled when `TRUST_PROXY` is
set, so `X-Forwarded-For` cannot be spoofed by default.
