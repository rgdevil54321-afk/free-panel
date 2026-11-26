"""
DeupGaming Free Panel — Premium Installer (Python)

A self-diagnosing, self-repairing, highly automated installation suite
for the DXD Free VPS Panel.

Usage:
    python3 installer.py [OPTIONS]

Options:
    --install        Full automatic install (default if no args)
    --reinstall      Reinstall (keeps database)
    --update         Pull + update dependencies
    --repair         Detect and repair broken components
    --start          Start panel service
    --stop           Stop panel service
    --restart        Restart panel service
    --status         Show system status
    --logs           Show panel logs
    --backup         Create backup
    --restore [f]    Restore backup
    --reset-admin    Reset admin password
    --port N         Change panel port
    --uninstall      Uninstall (add --purge to remove data)
    --cloudflare     Connect Cloudflare Tunnel
    --diagnose       Run full system diagnostics
    --help           Show this help

Environment (for unattended installs):
    PANEL_USER=admin  PANEL_PASS=secret  VPS_CPU=4  VPS_RAM=4  VPS_DISK=80
    CLOUDFLARE_TOKEN=eyJ...  IP_ABUSE_CHECK_ENABLED=0  IP_INTEL_ENABLED=0
"""

import os
import sys
import time
import shutil
import subprocess
import sqlite3
import json
import secrets
import socket
import platform
import urllib.request
import urllib.error
import logging
import argparse
import signal
import stat
import errno
from pathlib import Path
from datetime import datetime

# ── Constants ───────────────────────────────────────────────────────────────
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE = "deup-panel"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE}.service"
VENV_DIR = os.path.join(REPO_DIR, "venv")
PY = os.path.join(VENV_DIR, "bin", "python")
PIP = os.path.join(VENV_DIR, "bin", "pip")
PORT_FILE = os.path.join(REPO_DIR, ".panel-port")
CRED_FILE = "/root/.deup-panel-credentials"
BACKUP_DIR = "/root/deup-backups"
CLI_PATH = os.environ.get("PANEL_CLI_PATH", "/usr/local/bin/panel")
CHROOT_ROOT = os.environ.get("VPS_CHROOT_ROOT", "/var/lib/deup-vps")
DEFAULT_PORT = 5000
LOG_FILE = os.path.join(REPO_DIR, "install.log")
MAX_RETRIES = 3
PYTHON_MIN_VERSION = (3, 8)

# ── Color & UI ──────────────────────────────────────────────────────────────
class C:
    """Terminal color constants."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"

    # No-color fallback
    _enabled = True

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if not attr.startswith("_") and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# Auto-detect color support
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.disable()


class UI:
    """Premium terminal UI helpers."""

    @staticmethod
    def banner():
        print(f"""
{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════════════════════╗
  ║                                                                  ║
  ║   {C.GREEN}██████╗ ██╗  ██╗██╗   ██╗{C.CYAN}  {C.GREEN}███████╗██████╗ ███████╗███████╗{C.CYAN}   ║
  ║   {C.GREEN}██╔══██╗╚██╗██╔╝██║   ██║{C.CYAN}  {C.GREEN}██╔════╝██╔══██╗██╔════╝██╔════╝{C.CYAN}   ║
  ║   {C.GREEN}██║  ██║ ╚███╔╝ ██║   ██║{C.CYAN}  {C.GREEN}█████╗  ██████╔╝█████╗  ███████╗{C.CYAN}   ║
  ║   {C.GREEN}██║  ██║ ██╔██╗ ██║   ██║{C.CYAN}  {C.GREEN}██╔══╝  ██╔══██╗██╔══╝  ╚════██║{C.CYAN}   ║
  ║   {C.GREEN}██████╔╝██╔╝ ██╗╚██████╔╝{C.CYAN}  {C.GREEN}██║     ██║  ██║███████╗███████║{C.CYAN}   ║
  ║   {C.GREEN}╚═════╝ ╚═╝  ╚═╝ ╚═════╝{C.CYAN}   {C.GREEN}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝{C.CYAN}   ║
  ║                                                                  ║
  ║   {C.DIM}Free VPS Panel — Premium Installation Suite{C.CYAN}                      ║
  ║   {C.DIM}Version: 3.0 — Self-Diagnosing · Self-Repairing{C.CYAN}                   ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")

    @staticmethod
    def stage(num: str, title: str, status: str = "running"):
        """Print a stage header. status: running, done, fail, skip, warn."""
        icons = {
            "running": f"{C.CYAN}▶{C.RESET}",
            "done": f"{C.GREEN}✓{C.RESET}",
            "fail": f"{C.RED}✗{C.RESET}",
            "skip": f"{C.GRAY}–{C.RESET}",
            "warn": f"{C.YELLOW}⚠{C.RESET}",
        }
        icon = icons.get(status, f"{C.CYAN}▶{C.RESET}")
        print(f"  {C.DIM}[{num}]{C.RESET} {icon}  {title}")

    @staticmethod
    def progress(label: str, percent: int, width: int = 40):
        """Print a progress bar."""
        filled = int(width * percent / 100)
        empty = width - filled
        bar = f"{C.GREEN}{'█' * filled}{C.DIM}{'░' * empty}{C.RESET}"
        print(f"\r  {label}: [{bar}] {percent:3d}%", end="", flush=True)

    @staticmethod
    def info(msg: str):
        print(f"  {C.BLUE}[*]{C.RESET} {msg}")

    @staticmethod
    def ok(msg: str):
        print(f"  {C.GREEN}[✓]{C.RESET} {msg}")

    @staticmethod
    def warn(msg: str):
        print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

    @staticmethod
    def err(msg: str):
        print(f"  {C.RED}[✗]{C.RESET} {msg}")

    @staticmethod
    def die(msg: str):
        UI.err(msg)
        sys.exit(1)

    @staticmethod
    def section(title: str):
        print(f"\n  {C.BOLD}{C.CYAN}{'─' * 60}{C.RESET}")
        print(f"  {C.BOLD}{title}{C.RESET}")
        print(f"  {C.CYAN}{'─' * 60}{C.RESET}")

    @staticmethod
    def spinner(msg: str, duration: float = 1.0):
        """Simple spinner for short operations."""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            print(f"\r  {C.CYAN}{frames[i % len(frames)]}{C.RESET} {msg}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        print(f"\r  {C.GREEN}✓{C.RESET} {msg}")

    @staticmethod
    def ask(prompt: str, default: str = "", secret: bool = False) -> str:
        """Prompt user for input. Returns default if user presses Enter."""
        if default:
            full = f"  {prompt} [{default}]: "
        else:
            full = f"  {prompt}: "
        if secret:
            import getpass
            try:
                val = getpass.getpass(full)
            except Exception:
                val = input(full)
        else:
            try:
                val = input(full)
            except EOFError:
                val = ""
        return val.strip() or default

    @staticmethod
    def confirm(prompt: str, default: bool = True) -> bool:
        """Ask yes/no confirmation."""
        hint = "[Y/n]" if default else "[y/N]"
        try:
            ans = input(f"  {prompt} {hint}: ").strip().lower()
        except EOFError:
            return default
        if ans == "":
            return default
        return ans in ("y", "yes", "true", "1")

    @staticmethod
    def table(headers: list, rows: list, widths: list = None):
        """Print a formatted table."""
        if not widths:
            widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0)) + 2
                      for i, h in enumerate(headers)]
        # Header
        line = "  "
        for i, h in enumerate(headers):
            line += str(h).ljust(widths[i])
        print(line)
        print("  " + "─" * sum(widths))
        for row in rows:
            line = "  "
            for i, val in enumerate(row):
                line += str(val).ljust(widths[i])
            print(line)

    @staticmethod
    def success_box(title: str, lines: list):
        """Print a success summary box."""
        width = max(len(title) + 4, max((len(l) + 4 for l in lines), default=0))
        width = min(width, 68)
        print(f"\n  {C.GREEN}╔{'═' * (width - 2)}╗{C.RESET}")
        print(f"  {C.GREEN}║{C.RESET} {C.BOLD}{title.center(width - 4)}{C.RESET} {C.GREEN}║{C.RESET}")
        print(f"  {C.GREEN}╠{'═' * (width - 2)}╣{C.RESET}")
        for line in lines:
            print(f"  {C.GREEN}║{C.RESET} {line.ljust(width - 4)} {C.GREEN}║{C.RESET}")
        print(f"  {C.GREEN}╚{'═' * (width - 2)}╝{C.RESET}\n")

    @staticmethod
    def error_box(title: str, lines: list):
        """Print an error summary box."""
        width = max(len(title) + 4, max((len(l) + 4 for l in lines), default=0))
        width = min(width, 68)
        print(f"\n  {C.RED}╔{'═' * (width - 2)}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}{title.center(width - 4)}{C.RESET} {C.RED}║{C.RESET}")
        print(f"  {C.RED}╠{'═' * (width - 2)}╣{C.RESET}")
        for line in lines:
            print(f"  {C.RED}║{C.RESET} {line.ljust(width - 4)} {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═' * (width - 2)}╝{C.RESET}\n")


# ── Logger ──────────────────────────────────────────────────────────────────
class Logger:
    """Installation logger with file output."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self._file = None
        self._start_time = time.time()
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        try:
            self._file = open(log_file, "a", encoding="utf-8")
            self._file.write(f"\n{'=' * 70}\n")
            self._file.write(f"Installation started: {datetime.now().isoformat()}\n")
            self._file.write(f"{'=' * 70}\n")
            self._file.flush()
        except Exception:
            self._file = None

    def _write(self, level: str, msg: str, exc: Exception = None):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        if exc:
            line += f"\n  Exception: {type(exc).__name__}: {exc}"
        if self._file:
            try:
                self._file.write(line + "\n")
                self._file.flush()
            except Exception:
                pass

    def info(self, msg: str):
        self._write("INFO", msg)

    def warn(self, msg: str):
        self._write("WARN", msg)

    def error(self, msg: str, exc: Exception = None):
        self._write("ERROR", msg, exc)

    def success(self, msg: str):
        self._write("OK", msg)

    def close(self):
        if self._file:
            elapsed = time.time() - self._start_time
            try:
                self._file.write(f"\nInstallation ended: {datetime.now().isoformat()} "
                                 f"(elapsed {elapsed:.1f}s)\n")
                self._file.close()
            except Exception:
                pass
            self._file = None


# ── Environment Detection ───────────────────────────────────────────────────
class EnvDetect:
    """Detect the current system environment."""

    def __init__(self, log: Logger):
        self.log = log
        self.info = {}

    def detect_all(self) -> dict:
        UI.stage("01", "Environment Detection", "running")
        self.log.info("Starting environment detection")

        self._detect_os()
        self._detect_arch()
        self._detect_cpu()
        self._detect_ram()
        self._detect_disk()
        self._detect_init()
        self._detect_network()
        self._detect_existing()

        UI.stage("01", "Environment Detection", "done")
        self.log.info(f"Detection complete: {self.info}")
        return self.info

    def _detect_os(self):
        try:
            with open("/etc/os-release") as f:
                lines = f.read().splitlines()
            os_info = {}
            for line in lines:
                if "=" in line:
                    key, val = line.split("=", 1)
                    os_info[key] = val.strip().strip('"')
            self.info["distro"] = os_info.get("ID", "unknown")
            self.info["distro_name"] = os_info.get("NAME", "unknown")
            self.info["version"] = os_info.get("VERSION_ID", "unknown")
            self.info["codename"] = os_info.get("VERSION_CODENAME", "")
            self.info["os_pretty"] = os_info.get("PRETTY_NAME", "unknown")
        except Exception as e:
            self.info["distro"] = "unknown"
            self.info["distro_name"] = "unknown"
            self.info["version"] = "unknown"
            self.info["codename"] = ""
            self.info["os_pretty"] = "unknown"
            self.log.warn(f"OS detection failed: {e}")

        # Validate supported distros
        distro = self.info["distro"]
        version = self.info["version"]
        supported = {
            "ubuntu": ["20.04", "22.04", "24.04"],
            "debian": ["11", "12", "13"],
        }
        if distro in supported:
            if version in supported[distro]:
                self.info["os_supported"] = True
                UI.ok(f"OS: {self.info['os_pretty']} (supported)")
            else:
                self.info["os_supported"] = False
                UI.warn(f"OS: {self.info['os_pretty']} (untested version, may work)")
        else:
            self.info["os_supported"] = False
            UI.warn(f"OS: {self.info['os_pretty']} (not officially supported)")

    def _detect_arch(self):
        self.info["arch"] = platform.machine()
        supported_arches = ["x86_64", "amd64", "aarch64", "arm64", "armv7l", "armhf"]
        if self.info["arch"] in supported_arches:
            self.info["arch_supported"] = True
            UI.ok(f"Architecture: {self.info['arch']} (supported)")
        else:
            self.info["arch_supported"] = False
            UI.warn(f"Architecture: {self.info['arch']} (may not be supported)")

    def _detect_cpu(self):
        try:
            self.info["cpu_cores"] = os.cpu_count() or 1
        except Exception:
            self.info["cpu_cores"] = 1
        UI.ok(f"CPU cores: {self.info['cpu_cores']}")

    def _detect_ram(self):
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        self.info["ram_mb"] = int(line.split()[1]) // 1024
                        break
        except Exception:
            self.info["ram_mb"] = 0
        UI.ok(f"RAM: {self.info['ram_mb']} MB")

        if self.info["ram_mb"] < 512:
            UI.warn("Low RAM detected (<512MB). Panel may run poorly.")
            self.log.warn("Low RAM: <512MB")

    def _detect_disk(self):
        try:
            usage = shutil.disk_usage("/")
            self.info["disk_total_gb"] = usage.total // (1024 ** 3)
            self.info["disk_free_gb"] = usage.free // (1024 ** 3)
        except Exception:
            self.info["disk_total_gb"] = 0
            self.info["disk_free_gb"] = 0
        UI.ok(f"Disk: {self.info['disk_free_gb']}GB free / {self.info['disk_total_gb']}GB total")

        if self.info["disk_free_gb"] < 3:
            UI.warn("Low disk space (<3GB). Base rootfs build needs ~2GB.")
            self.log.warn("Low disk space: <3GB")

    def _detect_init(self):
        # Check if systemd is available
        self.info["systemd"] = False
        if os.path.exists("/run/systemd/system"):
            self.info["systemd"] = True
            self.info["init_system"] = "systemd"
            UI.ok("Init system: systemd")
        else:
            # Check for sysvinit
            if os.path.exists("/etc/init.d"):
                self.info["init_system"] = "sysvinit"
                UI.warn("Init system: sysvinit (systemd not available — service management limited)")
            else:
                self.info["init_system"] = "unknown"
                UI.warn("Init system: unknown (service management may not work)")
        self.log.info(f"Init system: {self.info.get('init_system', 'unknown')}")

    def _detect_network(self):
        # Check root
        try:
            self.info["is_root"] = (os.geteuid() == 0)
        except AttributeError:
            # Windows / non-Unix: check via whoami or assume non-root
            try:
                self.info["is_root"] = (os.getlogin() == "root")
            except Exception:
                self.info["is_root"] = False
        if self.info["is_root"]:
            UI.ok("Root privileges: yes")
        else:
            UI.warn("Root privileges: no (installer will attempt sudo elevation)")

        # Check network connectivity
        self.info["network_ok"] = False
        try:
            req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "deup-panel/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    self.info["network_ok"] = True
                    self.info["public_ip"] = ip
                    UI.ok(f"Network: OK (public IP: {ip})")
        except Exception as e:
            self.info["network_ok"] = False
            self.info["public_ip"] = ""
            UI.warn(f"Network: limited ({e})")
            self.log.warn(f"Network connectivity issue: {e}")

        # Check DNS resolution
        self.info["dns_ok"] = False
        try:
            socket.getaddrinfo("archive.ubuntu.com", 80, socket.AF_INET)
            self.info["dns_ok"] = True
            UI.ok("DNS resolution: OK")
        except Exception as e:
            self.info["dns_ok"] = False
            UI.warn(f"DNS resolution: failed ({e})")
            self.log.warn(f"DNS resolution failed: {e}")

    def _detect_existing(self):
        self.info["existing_install"] = os.path.exists(os.path.join(REPO_DIR, "panel.db"))
        self.info["existing_service"] = False
        self.info["existing_base_rootfs"] = os.path.isdir(CHROOT_ROOT + "/base")
        self.info["existing_venv"] = os.path.exists(os.path.join(REPO_DIR, "venv", "bin", "python"))

        if self.info["existing_install"]:
            UI.info("Existing installation detected (panel.db found)")
        if self.info["existing_base_rootfs"]:
            UI.info(f"Base rootfs already built ({CHROOT_ROOT}/base)")
        if self.info["existing_venv"]:
            UI.info("Python venv already exists")

        # Check for port conflicts
        port = self._get_panel_port()
        self.info["panel_port"] = port
        self.info["port_conflict"] = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                self.info["port_conflict"] = True
                UI.warn(f"Port {port} is already in use")
            s.close()
        except Exception:
            pass

    def _get_panel_port(self) -> int:
        port_file = os.path.join(REPO_DIR, ".panel-port")
        if os.path.exists(port_file):
            try:
                return int(open(port_file).read().strip())
            except Exception:
                pass
        return DEFAULT_PORT


# ── Dependency Manager ──────────────────────────────────────────────────────
class DepManager:
    """Manages system and Python dependencies with recovery."""

    # Required system packages
    SYSTEM_PACKAGES = [
        "ca-certificates", "curl", "wget", "git", "openssl",
        "python3", "python3-venv", "python3-pip", "python3-full",
        "iptables", "iproute2", "net-tools", "debootstrap",
        "openssh-client", "openssh-server", "tar", "procps",
        "util-linux", "coreutils",
    ]

    # Required Python packages
    PYTHON_PACKAGES = [
        "flask>=3.0", "flask-login>=0.6", "werkzeug>=3.0",
        "requests>=2.31",
    ]

    def __init__(self, log: Logger, env: dict):
        self.log = log
        self.env = env
        self.installed = {}
        self.failed = []

    def detect_installed(self):
        """Detect which system packages are already installed."""
        UI.stage("02", "System Compatibility Check", "running")
        self.log.info("Checking installed packages")
        for pkg in self.SYSTEM_PACKAGES:
            try:
                result = subprocess.run(
                    ["dpkg", "-s", pkg], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    self.installed[pkg] = True
                else:
                    self.installed[pkg] = False
            except Exception:
                self.installed[pkg] = False
        missing = [p for p in self.SYSTEM_PACKAGES if not self.installed[p]]
        if missing:
            UI.info(f"Missing: {', '.join(missing)}")
            self.log.info(f"Missing packages: {missing}")
        else:
            UI.ok("All required system packages present")
        UI.stage("02", "System Compatibility Check", "done")
        return missing

    def install_system_deps(self) -> bool:
        """Install missing system packages with recovery."""
        UI.stage("03", "Dependency Installation", "running")
        missing = self.detect_installed()
        if not missing:
            UI.stage("03", "Dependency Installation", "done")
            return True

        self.log.info(f"Installing {len(missing)} missing packages")

        # Fix broken packages first
        self._fix_broken_packages()

        # Update package index
        UI.info("Updating package index...")
        if not self._apt_update():
            UI.warn("Package index update failed — trying with existing lists")
            self.log.warn("apt-get update failed")

        # Install packages (each separately for resilience)
        failed = []
        for pkg in missing:
            UI.info(f"Installing {pkg}...")
            if not self._install_package(pkg):
                failed.append(pkg)
                UI.warn(f"Failed to install {pkg}")
                self.log.warn(f"Failed to install: {pkg}")
            else:
                UI.ok(f"{pkg} installed")
                self.installed[pkg] = True
                self.log.success(f"Installed: {pkg}")

        if failed:
            UI.warn(f"Failed packages: {', '.join(failed)}")
            self.log.warn(f"Failed packages: {failed}")
            # Try recovery
            recovered = self._recover_failed_packages(failed)
            if recovered:
                UI.ok("Recovery successful for some packages")
            else:
                UI.err("Some packages could not be installed")
                self.log.error(f"Unrecoverable: {failed}")
                UI.stage("03", "Dependency Installation", "warn")
                return len(failed) < len(missing)  # partial success OK

        UI.stage("03", "Dependency Installation", "done")
        return True

    def _apt_update(self) -> bool:
        """Update apt package index with retry."""
        for attempt in range(MAX_RETRIES):
            try:
                result = subprocess.run(
                    ["apt-get", "-o", "DPkg::Lock::Timeout=180",
                     "-o", "Acquire::Retries=3", "update"],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0:
                    return True
                self.log.warn(f"apt update attempt {attempt+1} failed: {result.stderr[:200]}")
            except Exception as e:
                self.log.warn(f"apt update attempt {attempt+1} error: {e}")
            time.sleep(2 * (attempt + 1))
        return False

    def _install_package(self, pkg: str) -> bool:
        """Install a single package with retry."""
        for attempt in range(MAX_RETRIES):
            try:
                result = subprocess.run(
                    ["apt-get", "-o", "DPkg::Lock::Timeout=180",
                     "-o", "Acquire::Retries=3", "-y", "install", pkg],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0:
                    return True
                # Try fixing broken packages
                subprocess.run(["apt-get", "-f", "-y", "install"],
                               capture_output=True, timeout=120)
            except Exception as e:
                self.log.warn(f"Install {pkg} attempt {attempt+1} error: {e}")
            time.sleep(2 * (attempt + 1))
        return False

    def _fix_broken_packages(self):
        """Attempt to fix broken package installations."""
        try:
            subprocess.run(["dpkg", "--configure", "-a"],
                           capture_output=True, timeout=120)
            subprocess.run(["apt-get", "-f", "-y", "install"],
                           capture_output=True, timeout=120)
            self.log.info("Fixed broken packages")
        except Exception as e:
            self.log.warn(f"Could not fix broken packages: {e}")

    def _recover_failed_packages(self, failed: list) -> bool:
        """Attempt recovery for failed packages."""
        self.log.info(f"Attempting recovery for: {failed}")
        # Try fixing dpkg state
        self._fix_broken_packages()
        # Retry failed packages
        recovered = False
        for pkg in list(failed):
            if self._install_package(pkg):
                failed.remove(pkg)
                recovered = True
                UI.ok(f"{pkg} recovered")
                self.log.success(f"Recovered: {pkg}")
        return recovered

    def install_python_deps(self) -> bool:
        """Install Python dependencies into venv."""
        UI.stage("04", "Runtime Configuration", "running")
        self.log.info("Setting up Python environment")

        # Create venv if needed
        if not os.path.exists(os.path.join(VENV_DIR, "bin", "python")):
            UI.info("Creating Python virtual environment...")
            try:
                subprocess.run([sys.executable, "-m", "venv", VENV_DIR],
                               check=True, capture_output=True, timeout=120)
            except Exception:
                # Maybe python3-venv is missing
                try:
                    subprocess.run(["apt-get", "-y", "install", "python3-venv", "python3-full"],
                                   capture_output=True, timeout=120)
                    subprocess.run([sys.executable, "-m", "venv", VENV_DIR],
                                   check=True, capture_output=True, timeout=120)
                except Exception as e:
                    UI.err(f"Could not create venv: {e}")
                    self.log.error("venv creation failed", e)
                    UI.stage("04", "Runtime Configuration", "fail")
                    return False

        # Upgrade pip
        try:
            subprocess.run([PIP, "install", "--upgrade", "pip", "setuptools", "wheel"],
                           capture_output=True, timeout=120)
        except Exception:
            pass

        # Install requirements
        req_file = os.path.join(REPO_DIR, "requirements.txt")
        if os.path.exists(req_file):
            UI.info("Installing Python requirements...")
            result = subprocess.run(
                [PIP, "install", "-q", "--disable-pip-version-check", "-r", req_file],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                UI.warn("requirements.txt install failed — trying core packages")
                self.log.warn(f"pip install failed: {result.stderr[:300]}")
                # Fallback: install core packages individually
                for pkg in self.PYTHON_PACKAGES:
                    subprocess.run(
                        [PIP, "install", "-q", "--disable-pip-version-check", pkg],
                        capture_output=True, timeout=120,
                    )
        else:
            # No requirements.txt — install core packages
            for pkg in self.PYTHON_PACKAGES:
                subprocess.run(
                    [PIP, "install", "-q", "--disable-pip-version-check", pkg],
                    capture_output=True, timeout=120,
                )

        # Verify
        try:
            subprocess.run([PY, "-c", "import flask, flask_login, werkzeug, requests"],
                           check=True, capture_output=True, timeout=30)
            UI.ok("Python environment ready")
            self.log.success("Python deps installed")
        except Exception as e:
            UI.err(f"Python dependencies broken: {e}")
            self.log.error("Python deps broken", e)
            UI.stage("04", "Runtime Configuration", "fail")
            return False

        UI.stage("04", "Runtime Configuration", "done")
        return True

    # install_system_deps is the main entry point (defined above)


# ── Configuration Manager ───────────────────────────────────────────────────
class ConfigManager:
    """Manages application configuration."""

    def __init__(self, log: Logger, env: dict):
        self.log = log
        self.env = env

    def read_config(self) -> dict:
        """Read the existing .env without changing it.

        Used by write_config so upgrades/repairs never discard settings an
        operator added by hand (custom tokens, feature flags, proxy trust).
        """
        values: dict = {}
        path = os.path.join(REPO_DIR, ".env")
        try:
            with open(path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip().strip('"').strip("'")
        except OSError:
            pass
        return values

    def write_config(self, port: int) -> bool:
        """Write .env, preserving every existing operator setting.

        Only missing keys are added.  SSHX security defaults are inserted when
        absent so an upgraded installation inherits the hardened baseline.
        """
        try:
            chroot_root = self.env.get("VPS_CHROOT_ROOT", CHROOT_ROOT) or CHROOT_ROOT
            # Security baseline for fresh installs.  An existing operator value
            # is always preserved by the merge below.
            # SSHX_GATEWAY_USER=sshx-gw
            defaults = {
                "VPS_BACKEND": "chroot",
                "VPS_CHROOT_ROOT": chroot_root,
                "PANEL_PORT": str(port),
                "PANEL_HOST": "0.0.0.0",
                # IP abuse check: 0=off (allow shared IPs/NAT/Cloudflare), 1=on
                "IP_ABUSE_CHECK_ENABLED": "0",
                # External IP intel: 0=off (privacy), 1=on
                "IP_INTEL_ENABLED": "0",
                # Only trust X-Forwarded-* when an operator explicitly opts in.
                "TRUST_PROXY": "0",
                # SSHX isolation: short-lived sessions bound to one authenticated
                # user and one owned VPS.  Never run sshx as root or in a chroot.
                "SSHX_GATEWAY_USER": "sshx-gw",
                "SSHX_SESSION_TTL": "900",
                "SSHX_MAX_PER_USER": "2",
                "SSHX_MAX_PER_VPS": "1",
            }
            existing = self.read_config()
            merged = {**defaults, **existing}  # existing values always win

            lines = [
                "# Managed by DXD Free Panel installer.",
                "# Existing operator settings are preserved on upgrade/repair.",
                "# SSHX stays contained until an admin validates isolation in",
                "# /admin/sshx — no session can be created before that.",
            ]
            lines += [f"{key}={merged[key]}" for key in sorted(merged)]
            env_path = os.path.join(REPO_DIR, ".env")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            os.chmod(env_path, 0o600)
            self.log.info("Config file written (existing settings preserved)")
            return True
        except Exception as e:
            self.log.error("Failed to write config", e)
            return False

    def install_cli(self) -> bool:
        """Install the restored Management Suite as /usr/local/bin/panel.

        The original bash menu was removed in commit 9785c5f.  The menu now
        lives in management_suite.py and delegates to this installer's modes.
        """
        try:
            target = CLI_PATH
            source = os.path.join(REPO_DIR, "management_suite.py")
            if not os.path.isfile(source):
                self.log.error("Management Suite entrypoint missing")
                return False
            py = PY if os.path.exists(PY) else sys.executable
            wrapper = (
                "#!/bin/sh\n"
                "# Restored Management Suite — delegates to installer.py modes.\n"
                f'exec "{py}" "{source}" "$@"\n'
            )
            with open(target, "w", encoding="utf-8") as f:
                f.write(wrapper)
            os.chmod(target, 0o755)
            self.log.info("Management Suite CLI installed at " + target)
            return True
        except Exception as e:
            self.log.error("Failed to install Management Suite CLI", e)
            return False

    def write_service(self, port: int, chroot_root: str) -> bool:
        """Create systemd service unit."""
        try:
            py = PY
            repo_dir = REPO_DIR
            service_content = f"""[Unit]
Description=DeupGaming Free Panel
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
KillMode=process
TasksMax=infinity
WorkingDirectory={repo_dir}
Environment=PYTHONUNBUFFERED=1
Environment=PANEL_HOST=0.0.0.0
Environment=PANEL_PORT={port}
Environment=VPS_BACKEND=chroot
Environment=VPS_CHROOT_ROOT={chroot_root}
Environment=MIN_FREE_DISK_GB=5
ExecStart={py} -u app.py
Restart=always
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
"""
            with open(SERVICE_FILE, "w") as f:
                f.write(service_content)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
            subprocess.run(["systemctl", "enable", SERVICE], capture_output=True, timeout=30)
            self.log.info("Service unit created")
            return True
        except Exception as e:
            self.log.error("Failed to create service", e)
            return False

    def setup_admin(self, opts: dict) -> bool:
        """Create admin account and set limits."""
        try:
            env = os.environ.copy()
            env["PANEL_USER"] = opts.get("username", "admin")
            env["PANEL_PASS"] = opts.get("password", "")
            env["VPS_CPU"] = str(opts.get("cpu", 4))
            env["VPS_RAM"] = str(opts.get("ram", 4))
            env["VPS_DISK"] = str(opts.get("disk", 80))

            result = subprocess.run(
                [PY, os.path.join(REPO_DIR, "setup.py"), "--auto"],
                capture_output=True, text=True, timeout=60,
                env=env, cwd=REPO_DIR,
            )
            if result.returncode != 0:
                self.log.error(f"Admin setup failed: {result.stderr}")
                return False
            self.log.success("Admin account created")
            return True
        except Exception as e:
            self.log.error("Admin setup failed", e)
            return False


# ── Service Manager ──────────────────────────────────────────────────────────
class ServiceManager:
    """Manages systemd services and verification."""

    def __init__(self, log: Logger):
        self.log = log

    def has_systemd(self) -> bool:
        return os.path.exists("/run/systemd/system")

    def is_active(self) -> bool:
        """True only when the panel service is actually running."""
        try:
            return subprocess.run(
                ["systemctl", "is-active", "--quiet", SERVICE],
                capture_output=True, timeout=10,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def start_panel(self, port: int) -> bool:
        """Start the panel service and verify it's responding."""
        try:
            subprocess.run(["systemctl", "restart", SERVICE],
                           capture_output=True, timeout=30)
            # Wait for HTTP response
            for i in range(45):
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{port}/")
                    with urllib.request.urlopen(req, timeout=3) as r:
                        if r.status in (200, 302, 301):
                            self.log.success(f"Panel responding on port {port}")
                            return True
                except Exception:
                    pass
                time.sleep(1)
            self.log.error("Panel did not respond to health check")
            return False
        except Exception as e:
            self.log.error("Failed to start panel", e)
            return False

    def start_cloudflare(self, token: str, port: int) -> bool:
        """Set up and start Cloudflare Tunnel."""
        if not token:
            return False
        # Install cloudflared if missing
        if not shutil.which("cloudflared"):
            self._install_cloudflared()
        # Store token
        os.makedirs("/etc/cloudflared", exist_ok=True)
        with open("/etc/cloudflared/token", "w") as f:
            f.write(token)
        os.chmod("/etc/cloudflared/token", 0o600)
        # Clean stale units
        for u in ["cloudflared", "cloudflared-update"]:
            subprocess.run(["systemctl", "stop", u], capture_output=True, timeout=10)
            subprocess.run(["systemctl", "disable", u], capture_output=True, timeout=10)
        for p in ["/etc/systemd/system/cloudflared.service",
                   "/lib/systemd/system/cloudflared.service"]:
            if os.path.exists(p):
                os.remove(p)
        # Create unit
        cfd_bin = shutil.which("cloudflared") or "/usr/local/bin/cloudflared"
        unit = f"""[Unit]
Description=Cloudflare Tunnel (DeupGaming Free Panel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={cfd_bin} --no-autoupdate tunnel --protocol http2 run --token-file /etc/cloudflared/token
Restart=always
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/cloudflared.service", "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "enable", "cloudflared"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "restart", "cloudflared"], capture_output=True, timeout=30)
        # Verify
        for _ in range(20):
            result = subprocess.run(["systemctl", "is-active", "cloudflared"],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.log.success("Cloudflare tunnel running (http2)")
                return True
            time.sleep(1)
        self.log.warn("Cloudflared did not start")
        return False

    def _install_cloudflared(self):
        """Install cloudflared binary."""
        arch = platform.machine()
        arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
                    "arm64": "arm64", "armv7l": "arm", "armhf": "arm"}
        arch = arch_map.get(arch, "amd64")
        url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}"
        tmpbin = "/tmp/cloudflared.install"
        try:
            urllib.request.urlretrieve(url, tmpbin)
            os.chmod(tmpbin, 0o755)
            shutil.move(tmpbin, "/usr/local/bin/cloudflared")
            self.log.success("cloudflared installed")
        except Exception as e:
            self.log.error("cloudflared install failed", e)
            raise


# ── VPS Backend Builder ──────────────────────────────────────────────────────
class VPSBackendBuilder:
    """Builds the chroot VPS backend."""

    def __init__(self, log: Logger, env: dict):
        self.log = log
        self.env = env
        self.chroot_root = env.get("VPS_CHROOT_ROOT", CHROOT_ROOT)

    def setup(self) -> bool:
        """Set up the chroot backend and build base rootfs."""
        UI.stage("05", "VPS Backend Setup", "running")
        self.log.info("Setting up chroot VPS backend")

        try:
            os.makedirs(os.path.join(self.chroot_root, "meta"), exist_ok=True)
            os.makedirs(os.path.join(self.chroot_root, "logs"), exist_ok=True)
            os.chmod(self.chroot_root, 0o711)
        except Exception as e:
            self.log.warn(f"Could not create chroot dirs: {e}")

        # Mount capability probe
        mtest = os.path.join(self.chroot_root, ".mounttest")
        os.makedirs(mtest, exist_ok=True)
        try:
            result = subprocess.run(
                ["mount", "--bind", "/dev/pts", mtest],
                capture_output=True, timeout=15
            )
            if result.returncode == 0:
                subprocess.run(["umount", "-l", mtest], capture_output=True, timeout=15)
                UI.ok("Mount support: yes (PTY + /proc enabled)")
                self.log.info("Mount support: yes")
            else:
                UI.warn("Mount support: NO (SSH without PTY)")
                self.log.warn("Mount support: no")
        except Exception:
            UI.warn("Mount support: unknown")
        try:
            os.rmdir(mtest)
        except Exception:
            pass

        # Build base rootfs
        UI.info("Building base Ubuntu rootfs (1-3 minutes)...")
        try:
            sys.path.insert(0, REPO_DIR)
            import vps
            os.environ["VPS_CHROOT_ROOT"] = self.chroot_root
            if vps.ensure_base_rootfs(verbose=False):
                UI.ok(f"Base rootfs ready ({self.chroot_root}/base)")
                self.log.success("Base rootfs built")
                UI.stage("05", "VPS Backend Setup", "done")
                return True
            else:
                UI.warn("Base rootfs not ready — will retry on first VPS creation")
                self.log.warn("Base rootfs build failed")
                UI.stage("05", "VPS Backend Setup", "warn")
                return False
        except Exception as e:
            UI.err(f"Base rootfs build error: {e}")
            self.log.error("Base rootfs build error", e)
            UI.stage("05", "VPS Backend Setup", "fail")
            return False


# ── SSHX isolation hardening ─────────────────────────────────────────────────
class SSHXHardening:
    """Installs the isolated SSHX gateway and removes insecure legacy config."""

    USER = "sshx-gw"
    HOME = "/var/lib/sshx-gw"
    OPT = "/opt/sshx"
    BIN = "/opt/sshx/bin"
    SESSION_ROOT = os.path.join(CHROOT_ROOT, "sshx")

    def __init__(self, log: Logger, chroot_root: str = CHROOT_ROOT):
        self.log = log
        self.chroot_root = chroot_root
        self.SESSION_ROOT = os.path.join(chroot_root, "sshx")

    def _run(self, cmd, **kwargs):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kwargs)

    def apply(self) -> bool:
        UI.section("SSHX isolation hardening")
        ok = True

        # Dedicated, unprivileged service account.  Never root, no login shell.
        if not self._user_exists():
            r = self._run([
                "useradd", "--system", "--no-create-home", "--home-dir", self.HOME,
                "--shell", "/usr/sbin/nologin", self.USER,
            ])
            ok &= (r.returncode == 0)
            UI.ok("Created unprivileged sshx-gw service account" if r.returncode == 0
                  else "Could not create sshx-gw account")
        else:
            UI.info("sshx-gw service account already present")

        for d in (self.OPT, self.BIN, self.HOME, self.SESSION_ROOT,
                  os.path.join(self.SESSION_ROOT, "sessions")):
            try:
                os.makedirs(d, mode=0o755 if d != self.SESSION_ROOT else 0o700, exist_ok=True)
            except Exception as e:
                self.log.warn(f"mkdir {d}: {e}")
        try:
            import pwd
            u = pwd.getpwnam(self.USER)
            for d in (self.HOME, os.path.join(self.SESSION_ROOT, "sessions")):
                os.chown(d, u.pw_uid, u.pw_gid)
                os.chmod(d, 0o700)
        except Exception as e:
            self.log.warn(f"chown sshx dirs: {e}")

        # Install root-owned gateway code: the service user must not be able to
        # modify the code it executes.
        for src_name, dst_name in (("sshx_gateway.py", "sshx_gateway.py"),
                                   ("sshx-target-shell", "sshx-target-shell")):
            src = os.path.join(REPO_DIR, "gateway", src_name)
            dst = os.path.join(self.BIN, dst_name)
            if not os.path.isfile(src):
                UI.warn(f"Missing gateway source {src}")
                ok = False
                continue
            shutil.copy2(src, dst)
            os.chown(dst, 0, 0)
            os.chmod(dst, 0o755 if dst_name.endswith(".py") else 0o755)
        UI.ok("Installed isolated SSHX gateway (root-owned, non-writable)")

        # sshx client: downloaded once to a root-owned location on the host.
        if not self._install_sshx_binary():
            UI.warn("SSHX binary not installed — sessions will fail until it is available")
            ok = False
        else:
            UI.ok("SSHX client installed at /opt/sshx/sshx")

        # openssh-client is required for the forced SSH hop into the VPS.
        try:
            r = self._run(["sh", "-c", "command -v ssh || "
                           "(apt-get update -qq && apt-get install -y -qq openssh-client)"])
            if r.returncode != 0:
                UI.warn("openssh-client could not be verified")
        except Exception as e:
            self.log.warn(f"openssh-client check: {e}")

        self._remove_legacy()
        self._migrate_db()
        UI.ok("Legacy in-chroot sshx binaries and permanent links removed")
        return ok

    def _user_exists(self) -> bool:
        try:
            import pwd
            pwd.getpwnam(self.USER)
            return True
        except KeyError:
            return False

    def _install_sshx_binary(self) -> bool:
        target = os.path.join(self.OPT, "sshx")
        if os.path.isfile(target) and os.path.getsize(target) > 100000:
            return True
        import platform
        import tarfile
        import tempfile
        m = platform.machine().lower()
        arch = ("aarch64" if m in ("aarch64", "arm64") else
                "armv7" if m == "armv7l" else "arm" if m == "armv6l" else "x86_64")
        url = f"https://s3.amazonaws.com/sshx/sshx-{arch}-unknown-linux-musl.tar.gz"
        try:
            tmp = os.path.join(tempfile.gettempdir(), f"sshx-{arch}-panel.tar.gz")
            urllib.request.urlretrieve(url, tmp)
            with tarfile.open(tmp, "r:gz") as tf:
                member = next((x for x in tf.getmembers()
                               if os.path.basename(x.name) == "sshx" and x.isfile()), None)
                if member is None:
                    return False
                f = tf.extractfile(member)
                data = f.read() if f else b""
            if len(data) < 100000:
                return False
            with open(target, "wb") as out:
                out.write(data)
            os.chown(target, 0, 0)
            os.chmod(target, 0o755)
            return True
        except Exception as e:
            self.log.warn(f"sshx binary download failed: {e}")
            return False

    def _remove_legacy(self):
        """Kill and delete every legacy root-run sshx process/binary in VPSes."""
        try:
            sys.path.insert(0, REPO_DIR)
            import vps
            # Also scrub the shared base rootfs: new VPSes are copied from it,
            # so a leftover binary there would be reintroduced forever.
            for base_rel in ("usr/local/bin/sshx", "usr/bin/sshx",
                             "root/.local/bin/sshx"):
                p = os.path.join(vps.BASE_ROOT, base_rel)
                if os.path.lexists(p):
                    os.remove(p)
            for name in vps.list_vps_names():
                try:
                    for pid in vps._pids_in(name):
                        try:
                            cmdline = open(f"/proc/{pid}/cmdline", "rb").read()
                        except OSError:
                            cmdline = b""
                        if b"sshx" in cmdline:
                            os.kill(pid, signal.SIGKILL)
                    root = vps._path(name)
                    for rel in ("usr/local/bin/sshx", "usr/bin/sshx",
                                "root/.local/bin/sshx", "tmp/sshx.log"):
                        p = os.path.join(root, rel)
                        if os.path.lexists(p):
                            os.remove(p)
                except Exception as e:
                    self.log.warn(f"legacy sshx cleanup {name}: {e}")
        except Exception as e:
            self.log.warn(f"legacy sshx cleanup: {e}")

    def _migrate_db(self):
        try:
            sys.path.insert(0, REPO_DIR)
            import sshx_manager
            db = sqlite3.connect(os.path.join(REPO_DIR, "panel.db"))
            sshx_manager.init_sshx_tables(db)
            db.close()
        except Exception as e:
            self.log.warn(f"sshx db migration: {e}")

    def verify(self) -> tuple[bool, list[str]]:
        """Post-install isolation checks.  Returns (ok, failures)."""
        failures = []
        checks = {
            "service account": self._user_exists(),
            "gateway installed": os.path.isfile(os.path.join(self.BIN, "sshx_gateway.py")),
            "forced shell installed": os.path.isfile(os.path.join(self.BIN, "sshx-target-shell")),
            "sshx binary installed": os.path.isfile(os.path.join(self.OPT, "sshx")),
        }
        for name, result in checks.items():
            UI.ok(f"SSHX check: {name}") if result else UI.warn(f"SSHX check failed: {name}")
            if not result:
                failures.append(name)
        for f, uid in ((os.path.join(self.BIN, "sshx_gateway.py"), 0),
                       (os.path.join(self.BIN, "sshx-target-shell"), 0),
                       (os.path.join(self.OPT, "sshx"), 0)):
            if os.path.exists(f) and os.stat(f).st_uid != uid:
                failures.append(f"{os.path.basename(f)} not root-owned")
        return not failures, failures


# ── Installer ───────────────────────────────────────────────────────────────
class Installer:
    """Main installation orchestrator."""

    def __init__(self, mode: str = "install", opts: dict = None):
        self.mode = mode
        self.opts = opts or {}
        self.log = Logger(LOG_FILE)
        self.env = {
            "VPS_CHROOT_ROOT": CHROOT_ROOT,
            "VPS_BACKEND": "chroot",
        }
        self.env_detect = EnvDetect(self.log)
        self.dep_manager = DepManager(self.log, self.env)
        self.config_mgr = ConfigManager(self.log, self.env)
        self.service_mgr = ServiceManager(self.log)
        self.vps_builder = VPSBackendBuilder(self.log, self.env)
        self.sshx_hardening = SSHXHardening(self.log)
        self.env_info = {}

    def run(self):
        """Execute the installation based on mode."""
        try:
            UI.banner()

            if self.mode == "install":
                self._do_install()
            elif self.mode == "reinstall":
                self._do_reinstall()
            elif self.mode == "update":
                self._do_update()
            elif self.mode == "repair":
                self._do_repair()
            elif self.mode == "uninstall":
                self._do_uninstall()
            elif self.mode == "diagnose":
                self._do_diagnose()
            elif self.mode == "cloudflare":
                self._do_cloudflare()
            elif self.mode in ("start", "stop", "restart", "status", "logs"):
                self._do_service(self.mode)
            elif self.mode == "backup":
                self._do_backup()
            elif self.mode == "restore":
                self._do_restore(self.opts.get("restore_file"))
            elif self.mode == "reset-admin":
                self._do_reset_admin()
            elif self.mode == "port":
                self._do_change_port(self.opts.get("port"))
            else:
                UI.err(f"Unknown mode: {self.mode}")
                self.log.error(f"Unknown mode: {self.mode}")
                return 1

            return 0
        except KeyboardInterrupt:
            print("\n")
            UI.warn("Installation cancelled by user.")
            self.log.warn("Cancelled by user")
            return 130
        except Exception as e:
            UI.err(f"Unexpected error: {e}")
            self.log.error("Unexpected error", e)
            import traceback
            traceback.print_exc()
            return 1
        finally:
            self.log.close()

    def _do_install(self):
        """Full installation."""
        UI.section("Phase 1: Environment Detection")
        self.env_info = self.env_detect.detect_all()

        if not self.env_info.get("is_root"):
            UI.err("Root privileges required. Run with sudo.")
            self.log.error("Not running as root")
            return

        UI.section("Phase 2: System Compatibility")
        missing = self.dep_manager.detect_installed()

        UI.section("Phase 3: Dependency Installation")
        if not self.dep_manager.install_system_deps():
            UI.warn("Some system packages failed — continuing")
            self.log.warn("Partial system dep install")

        if not self.dep_manager.install_python_deps():
            UI.die("Python dependencies could not be installed")
            return

        UI.section("Phase 4: Runtime Configuration")
        # Port selection
        port = self._select_port()
        self.env["PORT"] = str(port)

        # Write config
        if not self.config_mgr.write_config(port):
            UI.warn("Config file write failed — using defaults")

        # Restore the Management Suite CLI (the `panel` menu).
        if self.config_mgr.install_cli():
            UI.ok("Management Suite CLI installed (/usr/local/bin/panel)")
        else:
            UI.warn("Management Suite CLI installation failed")

        # Create admin account
        UI.info("Creating administrator account...")
        admin_opts = self._ask_admin()
        if not self.config_mgr.setup_admin(admin_opts):
            UI.warn("Admin setup had issues — check logs")

        # VPS backend
        UI.section("Phase 5: VPS Backend Setup")
        self.vps_builder.setup()

        # SSHX isolation: dedicated account, gateway, legacy cleanup
        self.sshx_hardening.apply()

        # Service creation
        UI.section("Phase 6: Service Creation")
        if not self.config_mgr.write_service(port, CHROOT_ROOT):
            UI.err("Service creation failed")
            self.log.error("Service creation failed")

        # Firewall
        UI.section("Phase 7: Network Configuration")
        self._open_firewall(port)
        UI.ok("Firewall configured")

        # Start panel
        UI.section("Phase 8: Starting Panel")
        if not self.service_mgr.start_panel(port):
            UI.warn("Panel did not respond — attempting repair")
            self._repair_panel(port)
        else:
            UI.ok(f"Panel is running on port {port}")

        # Optional Cloudflare
        UI.section("Phase 9: Cloudflare Tunnel (Optional)")
        token = self.env.get("CLOUDFLARE_TOKEN") or os.environ.get("CLOUDFLARE_TOKEN", "")
        if not token and sys.stdin.isatty():
            ans = UI.ask("Connect Cloudflare Tunnel now? (y/N)", "N")
            if ans.lower() in ("y", "yes"):
                token = UI.ask("Tunnel token (paste, or Enter to skip)", "")
        if token:
            self.service_mgr.start_cloudflare(token, port)
        else:
            UI.info("Skipping Cloudflare Tunnel (run 'panel' -> 15 later)")

        # Verification
        UI.section("Phase 10: Installation Verification")
        if self._verify_installation(port):
            UI.section("Phase 11: Finalization")
            self._show_summary(port, admin_opts)
            self._write_credentials(admin_opts, port)
        else:
            UI.err("Installation verification failed")
            self.log.error("Verification failed")
            self._do_diagnose()

    def _do_reinstall(self):
        """Reinstall (keeps database)."""
        UI.section("Reinstalling Panel")
        self.log.info("Reinstall started")

        # Stop service
        subprocess.run(["systemctl", "stop", SERVICE], capture_output=True, timeout=30)
        # Backup DB
        db_path = os.path.join(REPO_DIR, "panel.db")
        if os.path.exists(db_path):
            backup = db_path + ".pre-reinstall"
            shutil.copy2(db_path, backup)
            UI.ok("Database backed up")

        # System deps
        self.dep_manager.install_system_deps()
        self.dep_manager.install_python_deps()

        # Config
        port = self._select_port()
        self.config_mgr.write_config(port)
        self.config_mgr.install_cli()
        self.config_mgr.setup_admin(self._ask_admin())
        self.vps_builder.setup()
        self.sshx_hardening.apply()

        # Service
        self.config_mgr.write_service(port, CHROOT_ROOT)
        self._open_firewall(port)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)

        if self.service_mgr.start_panel(port):
            UI.ok("Reinstall complete")
            self._show_summary(port, {})
        else:
            UI.err("Reinstall failed — attempting repair")
            self._repair_panel(port)

    def _do_update(self):
        """Update panel (git pull + deps)."""
        UI.section("Updating Panel")
        if os.path.isdir(os.path.join(REPO_DIR, ".git")):
            UI.info("Pulling latest changes...")
            try:
                subprocess.run(["git", "-C", REPO_DIR, "pull", "--ff-only"],
                               capture_output=True, timeout=120, check=True)
                UI.ok("Source updated")
            except Exception as e:
                UI.warn(f"git pull failed: {e}")
                self.log.warn(f"git pull failed: {e}")
        self.dep_manager.install_python_deps()
        self.sshx_hardening.apply()
        self.config_mgr.write_config(self._select_port())
        self.config_mgr.install_cli()
        self.config_mgr.write_service(self._select_port(), CHROOT_ROOT)
        subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)
        port = self._select_port()
        if self.service_mgr.start_panel(port):
            UI.ok("Panel updated and running")
        else:
            UI.err("Update failed — check logs")

    def _do_repair(self):
        """Detect and repair broken components."""
        UI.section("Repairing Installation")
        self.log.info("Repair started")

        # Check Python
        if not os.path.exists(PY):
            UI.warn("Python venv missing — recreating")
            self.dep_manager.install_python_deps()

        # Check config
        if not os.path.exists(os.path.join(REPO_DIR, ".env")):
            UI.warn("Config missing — recreating")
            self.config_mgr.write_config(self._select_port())

        # Restored Management Suite CLI — reinstall if missing or broken.
        if not os.path.exists(CLI_PATH):
            UI.warn("Management Suite CLI missing — reinstalling")
        self.config_mgr.install_cli()

        # Check service
        if not os.path.exists(SERVICE_FILE):
            UI.warn("Service unit missing — recreating")
            self.config_mgr.write_service(self._select_port(), CHROOT_ROOT)

        # Check base rootfs
        sys.path.insert(0, REPO_DIR)
        os.environ["VPS_CHROOT_ROOT"] = CHROOT_ROOT
        import vps
        if not vps.base_rootfs_ready():
            UI.warn("Base rootfs missing — rebuilding")
            vps.ensure_base_rootfs(verbose=True)
        self.sshx_hardening.apply()
        ok, failures = self.sshx_hardening.verify()
        if not ok:
            UI.warn(f"SSHX isolation verification failed: {', '.join(failures)}")

        # Restart
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)

        port = self._select_port()
        if self.service_mgr.start_panel(port):
            UI.ok("Repair successful")
        else:
            UI.err("Repair failed — check logs")
            self._do_diagnose()

    def _do_uninstall(self):
        """Uninstall panel."""
        UI.section("Uninstalling Panel")
        purge = self.opts.get("purge", False) or (not self.opts.get("yes", False) and UI.confirm("Also delete database, venv and VPS data?", False))

        subprocess.run(["systemctl", "stop", SERVICE], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "disable", SERVICE], capture_output=True, timeout=30)
        if os.path.exists(SERVICE_FILE):
            os.remove(SERVICE_FILE)
        cli_path = CLI_PATH
        if os.path.exists(cli_path):
            os.remove(cli_path)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        UI.ok("Service removed")

        if purge:
            UI.warn("Deleting all panel data...")
            # Stop and delete VPS jails
            if os.path.isdir(CHROOT_ROOT):
                for d in os.listdir(CHROOT_ROOT):
                    if d.startswith("vps-") and os.path.isdir(os.path.join(CHROOT_ROOT, d)):
                        jail = os.path.join(CHROOT_ROOT, d)
                        # Kill processes in jail
                        self._kill_jail_processes(jail)
                        # Unmount
                        for sub in ["proc", "dev/pts", "dev", "sys", "dev/shm"]:
                            subprocess.run(["umount", "-l", os.path.join(jail, sub)],
                                           capture_output=True, timeout=15)
                        shutil.rmtree(jail, ignore_errors=True)
                shutil.rmtree(CHROOT_ROOT, ignore_errors=True)
            # Remove panel files
            for f in ["panel.db", "secret.key", ".env", ".panel-port", ".storage-pool",
                      "__pycache__", "panel.db.pre-reinstall"]:
                path = os.path.join(REPO_DIR, f)
                if os.path.exists(path):
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        os.remove(path)
            # Remove venv
            if os.path.exists(VENV_DIR):
                shutil.rmtree(VENV_DIR, ignore_errors=True)
            UI.ok("Panel data deleted")
        else:
            UI.info("Panel data kept (database at panel.db)")

        UI.info(f"Source files remain in: {REPO_DIR}")

    def _do_diagnose(self):
        """Run full system diagnostics."""
        UI.section("System Diagnostics")
        self.env_info = self.env_detect.detect_all()
        print()
        UI.table(
            ["Check", "Status"],
            [
                ["Python", f"{sys.version.split()[0]}"],
                ["Venv", "OK" if os.path.exists(PY) else "MISSING"],
                ["Panel DB", "OK" if os.path.exists(os.path.join(REPO_DIR, "panel.db")) else "MISSING"],
                ["Base rootfs", "OK" if os.path.isdir(CHROOT_ROOT + "/base") else "MISSING"],
                ["Service", "active" if self.service_mgr.is_active()
                 else ("no systemd" if not self.service_mgr.has_systemd() else "inactive")],
                ["Management CLI", "OK" if os.path.isfile(CLI_PATH) else "MISSING"],
                ["Port", str(self._select_port())],
            ]
        )
        # Check panel health
        port = self._select_port()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/")
            with urllib.request.urlopen(req, timeout=5) as r:
                UI.ok(f"Panel responding: HTTP {r.status}")
        except Exception as e:
            UI.err(f"Panel not responding: {e}")

    def _do_cloudflare(self):
        """Connect Cloudflare Tunnel."""
        token = os.environ.get("CLOUDFLARE_TOKEN", "")
        if not token and sys.stdin.isatty():
            token = UI.ask("Tunnel token (paste, or Enter to skip)", "")
        # Strip prefix
        token = token.replace("sudo cloudflared service install ", "").replace("cloudflared service install ", "")
        token = token.strip()
        if not token:
            UI.warn("No token provided - skipping")
            return
        if not token.startswith("eyJ"):
            UI.warn("Token doesn't look valid (should start with eyJ...)")
            return
        port = self._select_port()
        if self.service_mgr.start_cloudflare(token, port):
            UI.ok("Cloudflare tunnel connected")
        else:
            UI.err("Cloudflare setup failed — check logs")

    def _do_service(self, action: str):
        """Handle service actions."""
        if action == "start":
            port = self._select_port()
            if self.service_mgr.start_panel(port):
                UI.ok(f"Panel started on port {port}")
            else:
                UI.err("Failed to start panel")
        elif action == "stop":
            subprocess.run(["systemctl", "stop", SERVICE], capture_output=True, timeout=30)
            UI.ok("Panel stopped")
        elif action == "restart":
            subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)
            time.sleep(3)
            port = self._select_port()
            if self.service_mgr.start_panel(port):
                UI.ok(f"Panel restarted on port {port}")
            else:
                UI.err("Failed to restart panel")
        elif action == "status":
            self._do_diagnose()
        elif action == "logs":
            subprocess.run(["journalctl", "-u", SERVICE, "-n", "50", "--no-pager"])

    def _do_backup(self):
        """Create backup."""
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        f = os.path.join(BACKUP_DIR, f"panel-{ts}.tar.gz")
        items = []
        for item in ["panel.db", "secret.key", ".panel-port", ".env"]:
            path = os.path.join(REPO_DIR, item)
            if os.path.exists(path):
                items.append(item)
        if not items:
            UI.warn("Nothing to back up yet")
            return
        result = subprocess.run(
            ["tar", "-czf", f, "-C", REPO_DIR] + items,
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            UI.ok(f"Backup: {f}")
        else:
            UI.err(f"Backup failed: {result.stderr}")

    def _do_restore(self, backup_file: str = None):
        """Restore from backup."""
        if not backup_file:
            backups = sorted(
                [f for f in os.listdir(BACKUP_DIR) if f.startswith("panel-") and f.endswith(".tar.gz")],
                reverse=True
            )
            if not backups:
                UI.err("No backups found")
                return
            print("  Available backups:")
            for i, b in enumerate(backups[:10], 1):
                print(f"    {i}) {b}")
            choice = UI.ask("Backup number or path", "1")
            if choice.isdigit() and 1 <= int(choice) <= len(backups):
                backup_file = os.path.join(BACKUP_DIR, backups[int(choice) - 1])
            else:
                backup_file = choice
        if not os.path.exists(backup_file):
            UI.err(f"Backup not found: {backup_file}")
            return
        subprocess.run(["systemctl", "stop", SERVICE], capture_output=True, timeout=30)
        # Safety backup
        self._do_backup()
        result = subprocess.run(
            ["tar", "-xzf", backup_file, "-C", REPO_DIR],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            subprocess.run(["systemctl", "start", SERVICE], capture_output=True, timeout=30)
            UI.ok(f"Restored from {backup_file}")
        else:
            UI.err(f"Restore failed: {result.stderr}")

    def _do_reset_admin(self):
        """Reset admin password."""
        user = os.environ.get("RESET_USER", "")
        password = os.environ.get("RESET_PASS", "")
        if not user and sys.stdin.isatty():
            user = UI.ask("Username", "admin")
        if not user:
            user = "admin"
        if not password and sys.stdin.isatty():
            password = UI.ask("New password (blank = auto)", "", secret=True)
        if not password:
            password = secrets.token_urlsafe(12)
            UI.info(f"Generated password: {password}")
        try:
            result = subprocess.run(
                [PY, os.path.join(REPO_DIR, "setup.py"), "--reset-pass", user, password],
                capture_output=True, text=True, timeout=60, cwd=REPO_DIR,
            )
            if result.returncode == 0:
                UI.ok(f"Password updated for '{user}': {password}")
            else:
                UI.err(f"Reset failed: {result.stderr}")
        except Exception as e:
            UI.err(f"Reset failed: {e}")

    def _do_change_port(self, new_port: str = None):
        """Change panel port."""
        port = int(new_port) if new_port and new_port.isdigit() else None
        if port is None and sys.stdin.isatty():
            port = int(UI.ask("New panel port", str(self._select_port())))
        if port is None:
            port = self._select_port()
        port_file = os.path.join(REPO_DIR, ".panel-port")
        with open(port_file, "w") as f:
            f.write(str(port))
        self.config_mgr.write_config(port)
        self.config_mgr.write_service(port, CHROOT_ROOT)
        self._open_firewall(port)
        subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)
        time.sleep(3)
        if self.service_mgr.start_panel(port):
            UI.ok(f"Panel now on port {port}")
        else:
            UI.warn(f"Panel not responding on port {port} — check logs")

    def _select_port(self) -> int:
        """Select a free port, honouring existing operator configuration."""
        port_file = os.path.join(REPO_DIR, ".panel-port")
        if os.path.exists(port_file):
            try:
                return int(open(port_file).read().strip())
            except Exception:
                pass
        # .panel-port may be missing on an older install; reuse the port the
        # operator already set in .env instead of silently changing it.
        saved = self.config_mgr.read_config().get("PANEL_PORT", "")
        if saved.isdigit() and 1 <= int(saved) <= 65535:
            return int(saved)
        # Find free port
        for p in range(DEFAULT_PORT, DEFAULT_PORT + 101):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex(("127.0.0.1", p)) != 0:
                    s.close()
                    return p
                s.close()
            except Exception:
                pass
        return DEFAULT_PORT

    def _ask_admin(self) -> dict:
        """Ask for admin credentials."""
        if not sys.stdin.isatty():
            return {
                "username": os.environ.get("PANEL_USER", "admin"),
                "password": os.environ.get("PANEL_PASS", ""),
                "cpu": int(os.environ.get("VPS_CPU", "4")),
                "ram": int(os.environ.get("VPS_RAM", "4")),
                "disk": int(os.environ.get("VPS_DISK", "80")),
            }
        UI.info("Panel administrator")
        username = os.environ.get("PANEL_USER", "").strip()
        if not username:
            username = UI.ask("Username", "admin")
        password = os.environ.get("PANEL_PASS", "")
        if not password:
            password = UI.ask("Password (blank = auto-generate)", "", secret=True)
            if not password:
                password = secrets.token_urlsafe(12)
                UI.info(f"Generated password: {password}")
        cpu_raw = UI.ask("CPU cores per VPS", "4")
        ram_raw = UI.ask("RAM GB per VPS", "4")
        disk_raw = UI.ask("Disk GB per VPS", "80")
        cpu = int(cpu_raw) if cpu_raw.strip() else 4
        ram = int(ram_raw) if ram_raw.strip() else 4
        disk = int(disk_raw) if disk_raw.strip() else 80
        return {
            "username": username or "admin",
            "password": password,
            "cpu": cpu,
            "ram": ram,
            "disk": disk,
        }

    def _open_firewall(self, port: int):
        """Open firewall ports."""
        # ufw
        if shutil.which("ufw"):
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in result.stdout.lower():
                subprocess.run(["ufw", "allow", "22/tcp"], capture_output=True)
                subprocess.run(["ufw", "allow", f"{port}/tcp"], capture_output=True)
                UI.ok(f"ufw: allowed port {port}")
        # firewalld
        if shutil.which("firewall-cmd"):
            result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
            if result.returncode == 0:
                subprocess.run(["firewall-cmd", "--permanent", f"--add-port={port}/tcp"],
                               capture_output=True)
                subprocess.run(["firewall-cmd", "--reload"], capture_output=True)
                UI.ok(f"firewalld: allowed port {port}")

    def _write_credentials(self, admin_opts: dict, port: int):
        """Write credentials file."""
        try:
            with open(CRED_FILE, "w") as f:
                f.write(f"Panel URL      : http://{self.env_detect.info.get('public_ip', 'YOUR_IP')}:{port}\n")
                f.write(f"Admin username : {admin_opts.get('username', 'admin')}\n")
                f.write(f"Admin password : {admin_opts.get('password', '')}\n")
                f.write(f"Generated      : {datetime.now().isoformat()}\n")
            os.chmod(CRED_FILE, 0o600)
        except Exception as e:
            self.log.warn(f"Could not write credentials file: {e}")

    def _show_summary(self, port: int, admin_opts: dict):
        """Show installation summary."""
        ip = self.env_detect.info.get("public_ip", "YOUR_IP")
        username = admin_opts.get("username", "admin")
        password = admin_opts.get("password", "")
        UI.success_box("INSTALLATION COMPLETE", [
            f"Panel URL  : http://{ip}:{port}",
            f"Username   : {username}",
            f"Password   : {password}",
            f"",
            f"Credentials saved to {CRED_FILE}",
            f"",
            f"If the browser cannot reach it, open TCP {port}",
            f"in your hosting provider firewall.",
            f"",
            f"Manage it later with:  python3 installer.py",
        ])

    def _verify_installation(self, port: int) -> bool:
        """Verify the installation is working."""
        UI.info("Verifying installation...")
        checks = []

        # Check 1: Application files exist
        checks.append(("App files exist", os.path.exists(os.path.join(REPO_DIR, "app.py"))))

        # Check 2: Python venv exists
        checks.append(("Python venv", os.path.exists(PY)))

        # Check 3: Database exists
        checks.append(("Database", os.path.exists(os.path.join(REPO_DIR, "panel.db"))))

        # Check 4: Base rootfs exists
        checks.append(("Base rootfs", os.path.exists(os.path.join(CHROOT_ROOT, "base", "bin", "bash"))))

        # Check 5: Service is actually running (not merely systemd present)
        checks.append((
            "Service active",
            self.service_mgr.is_active() if self.service_mgr.has_systemd() else True,
        ))

        # Check 6: Restored Management Suite CLI
        checks.append(("Management Suite CLI", os.path.isfile(CLI_PATH)))

        # Check 7: SSHX isolation hardening
        sshx_ok, sshx_failures = self.sshx_hardening.verify()
        checks.append(("SSHX isolation", sshx_ok))
        if not sshx_ok:
            self.log.error(f"SSHX isolation failures: {sshx_failures}")

        # Check 8: HTTP response
        http_ok = False
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/")
            with urllib.request.urlopen(req, timeout=5) as r:
                http_ok = r.status in (200, 302, 301)
        except Exception:
            http_ok = False
        checks.append(("HTTP health check", http_ok))

        # Print results
        for name, ok in checks:
            if ok:
                UI.ok(f"{name}: OK")
            else:
                UI.err(f"{name}: FAIL")
                self.log.error(f"Verification failed: {name}")

        return all(ok for _, ok in checks)

    def _repair_panel(self, port: int):
        """Attempt to repair a broken panel installation."""
        UI.info("Attempting repair...")
        self.dep_manager.install_python_deps()
        self.config_mgr.write_config(port)
        self.config_mgr.install_cli()
        self.config_mgr.write_service(port, CHROOT_ROOT)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "reset-failed", SERVICE], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, timeout=30)
        time.sleep(3)
        if self.service_mgr.start_panel(port):
            UI.ok("Repair successful")
        else:
            UI.err("Repair failed — check logs")
            self._do_diagnose()

    def _kill_jail_processes(self, jail: str):
        """Kill all processes whose root is the given jail."""
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    root = os.readlink(f"/proc/{entry}/root")
                    if os.path.realpath(root) == os.path.realpath(jail):
                        os.kill(int(entry), 9)
                except Exception:
                    pass
        except Exception:
            pass


# ── Entry Point ─────────────────────────────────────────────────────────────
def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="DeupGaming Free Panel — Premium Installation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --install        Full automatic install (default)
  --reinstall      Reinstall (keeps database)
  --update         Pull + update dependencies
  --repair         Detect and repair broken components
  --start          Start panel service
  --stop           Stop panel service
  --restart        Restart panel service
  --status         Show system status
  --logs           Show panel logs
  --backup         Create backup
  --restore [f]    Restore backup
  --reset-admin    Reset admin password
  --port N         Change panel port
  --uninstall      Uninstall (--purge to remove data)
  --cloudflare     Connect Cloudflare Tunnel
  --diagnose       Run full system diagnostics
  --help           Show this help

Environment (for unattended installs):
  PANEL_USER=admin  PANEL_PASS=secret  VPS_CPU=4  VPS_RAM=4  VPS_DISK=80
  CLOUDFLARE_TOKEN=eyJ...  IP_ABUSE_CHECK_ENABLED=0  IP_INTEL_ENABLED=0
""",
    )
    parser.add_argument("--install", "--all", action="store_true", help="Full automatic install")
    parser.add_argument("--reinstall", action="store_true", help="Reinstall (keeps database)")
    parser.add_argument("--update", action="store_true", help="Pull + update dependencies")
    parser.add_argument("--repair", action="store_true", help="Detect and repair broken components")
    parser.add_argument("--start", action="store_true", help="Start panel service")
    parser.add_argument("--stop", action="store_true", help="Stop panel service")
    parser.add_argument("--restart", action="store_true", help="Restart panel service")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--logs", action="store_true", help="Show panel logs")
    parser.add_argument("--backup", action="store_true", help="Create backup")
    parser.add_argument("--restore", nargs="?", const="", default=None, help="Restore backup")
    parser.add_argument("--reset-admin", action="store_true", help="Reset admin password")
    parser.add_argument("--port", type=int, default=None, help="Change panel port")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall panel")
    parser.add_argument("--purge", action="store_true", help="Purge all data (with --uninstall)")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm (with --uninstall)")
    parser.add_argument("--cloudflare", action="store_true", help="Connect Cloudflare Tunnel")
    parser.add_argument("--diagnose", action="store_true", help="Run full system diagnostics")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    # Determine mode
    mode = "install"
    opts = {}
    if args.reinstall:
        mode = "reinstall"
    elif args.update:
        mode = "update"
    elif args.repair:
        mode = "repair"
    elif args.start:
        mode = "start"
    elif args.stop:
        mode = "stop"
    elif args.restart:
        mode = "restart"
    elif args.status:
        mode = "status"
    elif args.logs:
        mode = "logs"
    elif args.backup:
        mode = "backup"
    elif args.restore is not None:
        mode = "restore"
        opts["restore_file"] = args.restore if args.restore else None
    elif args.reset_admin:
        mode = "reset-admin"
    elif args.port is not None:
        mode = "port"
        opts["port"] = str(args.port)
    elif args.uninstall:
        mode = "uninstall"
        opts["purge"] = args.purge
        opts["yes"] = args.yes
    elif args.cloudflare:
        mode = "cloudflare"
    elif args.diagnose:
        mode = "diagnose"

    installer = Installer(mode=mode, opts=opts)
    sys.exit(installer.run())


if __name__ == "__main__":
    main()