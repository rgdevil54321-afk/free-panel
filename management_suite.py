#!/usr/bin/env python3
"""DeupGaming Free Panel — Management Suite (interactive CLI).

This restores the menu that was removed in commit 9785c5f when the monolithic
``install.sh`` was replaced by ``installer.py``.  The original bash menu had 15
actions; every backend action is delegated to ``installer.py::Installer`` so
there is exactly one implementation of install/repair/backup/etc.

Usage:
    panel                       open the management menu
    panel --status              run one action non-interactively
    panel --help                show all supported flags

The menu is installed as ``/usr/local/bin/panel`` by the installer.
"""

from __future__ import annotations

import os
import shutil
import sys

from installer import C, Installer, PORT_FILE, REPO_DIR, SERVICE, UI


# The original menu's 15 actions, mapped to the surviving Installer modes.
# Action 14 (open shell) is handled locally; it is not an Installer mode.
ACTION_MODES = {
    "1": ("install", "Install panel (full automatic setup)"),
    "2": ("reinstall", "Reinstall panel (keeps database)"),
    "3": ("update", "Update panel (git pull + deps)"),
    "4": ("start", "Start panel"),
    "5": ("stop", "Stop panel"),
    "6": ("restart", "Restart panel"),
    "7": ("status", "Status"),
    "8": ("logs", "Logs"),
    "9": ("reset-admin", "Reset admin password"),
    "10": ("port", "Change panel port"),
    "11": ("backup", "Backup now"),
    "12": ("restore", "Restore backup"),
    "13": ("uninstall", "Uninstall panel"),
    "14": ("shell", "Open shell in panel directory"),
    "15": ("cloudflare", "Connect Cloudflare Tunnel"),
}


def banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}  ____                  ____       _                {C.RESET}
{C.CYAN}{C.BOLD} |  _ \\  ___ _   _ _ __ / ___| __ _ _ __ ___   ___ _ __ {C.RESET}
{C.CYAN}{C.BOLD} | | | |/ _ \\ | | | '_ \\ |  _ / _` | '_ ` _ \\ / _ \\ '__|{C.RESET}
{C.CYAN}{C.BOLD} | |_| |  __/ |_| | |_) | |_| | (_| | | | | | |  __/ |   {C.RESET}
{C.CYAN}{C.BOLD} |____/ \\___|\\__,_| .__/ \\____|\\__,_|_| |_| |_|\\___|_|   {C.RESET}
{C.CYAN}{C.BOLD}                 |_|   Free Panel — Management Suite{C.RESET}
{C.DIM} ------------------------------------------------------------{C.RESET}
""")


def panel_port() -> str:
    try:
        with open(PORT_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip() or "5000"
    except OSError:
        return "5000"


def service_active() -> bool:
    import subprocess
    try:
        return subprocess.run(
            ["systemctl", "is-active", "--quiet", SERVICE],
            capture_output=True, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_action(mode: str, opts: dict | None = None) -> int:
    """Execute one management action using the shared installer engine."""
    return Installer(mode=mode, opts=opts or {}).run()


def open_shell() -> int:
    shell = os.environ.get("SHELL") or "/bin/bash"
    UI.info(f"Opening shell in {REPO_DIR} (type 'exit' to return)")
    try:
        os.chdir(REPO_DIR)
        os.execv(shell, [shell])
    except OSError as exc:
        UI.err(f"Could not start shell: {exc}")
        return 1


def show_menu() -> None:
    while True:
        banner()
        if service_active():
            print(f"  Panel: {C.GREEN}running{C.RESET} on port {C.BOLD}{panel_port()}{C.RESET}  ({REPO_DIR})")
        else:
            print(f"  Panel: {C.YELLOW}not running{C.RESET}  ({REPO_DIR})")
        print()
        for key, (_, label) in ACTION_MODES.items():
            print(f"  {C.BOLD}{key:>2}){C.RESET} {label}")
        print(f"  {C.BOLD} 0){C.RESET} Exit")
        print()
        try:
            choice = input("  Choose [0-15]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        print()
        if choice == "0":
            print("  Bye.")
            return
        if choice not in ACTION_MODES:
            UI.err("Invalid choice")
        else:
            mode, _ = ACTION_MODES[choice]
            opts: dict = {}
            if mode == "restore":
                target = UI.ask("Backup file (Enter for latest)", "")
                if target:
                    opts["restore_file"] = target
            if mode == "port":
                opts["port"] = UI.ask("New panel port", panel_port())
            if mode == "uninstall":
                opts["purge"] = UI.confirm("Also delete database, venv and VPS data?", False)
                opts["yes"] = True  # menu already asked; don't prompt twice
            run_action(mode, opts)
        try:
            input("\n  Press Enter to return to the menu...")
        except (EOFError, KeyboardInterrupt):
            print()
            return


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("--menu", "-m"):
        if os.geteuid() != 0:
            if shutil.which("sudo"):
                os.execvp("sudo", ["sudo", sys.argv[0]] + args)
            UI.err("The management suite needs root. Run: sudo panel")
            return 1
        show_menu()
        return 0
    # Non-interactive flags are handled by the single existing parser.
    import installer
    saved = sys.argv
    try:
        sys.argv = [saved[0]] + args
        return installer.main()
    finally:
        sys.argv = saved


if __name__ == "__main__":
    sys.exit(main())
