# DeupGaming Free Panel

Self-hosted VPS panel with a one-command management suite.

Two provisioning backends are supported by `vps.py`:

| Backend | Needs | Status |
| --- | --- | --- |
| **chroot + sshd** (default) | `CAP_SYS_CHROOT`, `CAP_MKNOD`, optionally `CAP_SYS_ADMIN` for `/proc` + PTY mounts | works on plain Docker/LXC hosts where cgroups cannot be delegated |
| LXD | `--privileged` container or a KVM VPS | legacy; not used by this fork |

The chroot backend exists because LXD cannot start containers on hosts where
the container runtime refuses cgroup controller delegation
(`Could not enable "+cpuset +cpu +io +memory ..." controllers`). It gives every
user a real Ubuntu root filesystem, root access and SSH, without needing
cgroups.

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
15) Connect Cloudflare Tunnel
```

Pick `1`, enter a username and password (or leave the password blank to
auto-generate one), and the installer will:

- install system packages (Python, debootstrap, openssh-client, …)
- create `/var/lib/deup-vps` (`base/`, `meta/`, `logs/`)
- test whether `mount` works inside the host container (needed for PTY logins)
- build the shared Ubuntu 22.04 base rootfs once (1–3 minutes)
- create a Python **venv** (required on PEP 668 distros such as Debian 12)
- install `requirements.txt`
- create the admin account and per-VPS CPU/RAM/disk display limits
- install and start the `deup-panel` systemd service
- open the port in ufw/firewalld when they are active
- verify the panel answers on HTTP and repair itself if it does not

At the end it prints the panel URL and the login, and saves it to
`/root/.deup-panel-credentials`.

After installation, `panel` opens the same menu from anywhere.

## How a VPS is built (chroot backend)

```
/var/lib/deup-vps/base/            shared Ubuntu 22.04 rootfs (ssh + curl + tools)
/var/lib/deup-vps/<container_id>/  full copy of the base, one per VPS
/var/lib/deup-vps/meta/<id>.json   cpu / ram / disk / password / ssh port
/var/lib/deup-vps/logs/<id>.log    sshd log for that VPS
```

- `create` copies the base rootfs, sets a random root password, regenerates
  SSH host keys, applies branding, and installs `sshx`.
- `nat.py` allocates a public port (`10000–10999`); the jailed `sshd` binds it
  directly on the host, so no iptables DNAT is used.
- Extra ports (`11000–19999`) are recorded for display; users can bind them
  directly from inside their VPS.
- `start` / `stop` / `suspend` start, kill or `SIGSTOP` every process whose
  `/proc/<pid>/root` is that VPS directory.
- `destroy` kills the processes, unmounts `/proc` and `/dev/pts`, then deletes
  the directory and metadata.
- Panel restarts keep VPSes alive (`KillMode=process` in the unit), and
  `reapply_all_rules()` restarts every jailed `sshd` on boot/panel start.

### Known trade-offs

- CPU/RAM/disk values are **recorded and shown** but not hard-enforced
  (no cgroups on this class of host). Disk quota is therefore advisory.
- Networking is shared with the host. A VPS root user can bind ports on the
  host network, so only give access to people you trust.
- Root inside a VPS is host root from the kernel's perspective. The chroot
  jail prevents accidental access, not a determined attacker.
- If `mount` is blocked by the provider, SSH still works but without a PTY
  (no interactive shell). The installer prints a warning in that case.

## Non-interactive install

```bash
PANEL_USER=admin PANEL_PASS='change-me' VPS_CPU=4 VPS_RAM=4 VPS_DISK=80 \
  bash install.sh --install
```

Other flags: `--reinstall`, `--update`, `--start`, `--stop`, `--restart`,
`--status`, `--logs`, `--backup`, `--restore [file]`, `--reset-admin`,
`--port N`, `--uninstall [--purge]`, `--help`.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `PANEL_PORT` / `PANEL_HOST` | `5000` / `0.0.0.0` | panel listener |
| `VPS_CHROOT_ROOT` | `/var/lib/deup-vps` | backend data directory |
| `VPS_BACKEND` | `chroot` | backend selector |
| `MIN_FREE_DISK_GB` | `5` | host disk reserve before refusing new VPS |
| `CLOUDFLARE_TOKEN` | unset | tunnel token for unattended `--cloudflare` setup |
| `IP_ABUSE_CHECK_ENABLED` | unset (off) | block multiple VPSes from one IP (breaks behind NAT/shared hosting) |
| `IP_INTEL_ENABLED` | unset | enables external IP lookups |

## Requirements

- root (the script re-executes itself with `sudo` when needed)
- ~2 GB RAM, a few GB free disk (each VPS copy is ~350 MB)
- outbound internet for packages, PyPI and the Ubuntu base rootfs

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
| `VPS rootfs is not ready` | `panel` → 3) Update panel (rebuilds the base rootfs) |
| Base rootfs build failed | check internet; `apt-get install -y debootstrap`; retry |
| SSH login has no PTY | provider blocks `mount`; ask for `CAP_SYS_ADMIN`/privileged |
| Panel unreachable from browser | open the panel port in the provider firewall/security group |
| Lost admin password | `panel` → 9) Reset admin password |

Per-VPS sshd logs:

```bash
ls /var/lib/deup-vps/logs/
tail -f /var/lib/deup-vps/logs/vps-*.log
```

## Privacy

External IP intelligence is **off** by default. Set `IP_INTEL_ENABLED=1` only
if you explicitly want `ip-api.com` lookups; otherwise the panel never sends
visitor IPs to a third party. `ProxyFix` is only enabled when `TRUST_PROXY` is
set, so `X-Forwarded-For` cannot be spoofed by default.
