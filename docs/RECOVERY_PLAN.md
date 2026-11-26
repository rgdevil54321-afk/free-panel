# SSHX containment + Management Suite recovery plan

Baseline inspected: `a1c6d6343f04f251e39fed69388d5254ae0cd904` (2026-11-24).
Backups of all files changed by this work are in `/tmp/opencode/free-panel-backups`
(outside the repository, so no customer data is touched).

## 1. What Git history proves

| Question | Evidence | Answer |
| --- | --- | --- |
| Which commit removed the Management Suite? | `9785c5f` ("Add premium Python-based installer suite") replaces 1,183 lines of `install.sh` with a 90-line bootstrap. `git show 9785c5f^:install.sh` still contains the "DeupGaming Free Panel — Management Suite" banner, 15-item interactive menu, `install_cli()` (writes `/usr/local/bin/panel`), and `usage()`. | The interactive management CLI was removed in `9785c5f`. |
| Are any tracked management files deleted anywhere in history? | `git log --all --diff-filter=D --name-status` is empty; only `main` exists; no unreachable objects. | No tracked files were deleted — the functionality was deleted *inside* `install.sh`. |
| Do all backend modes survive? | `installer.py::Installer.run()` still dispatches install/reinstall/update/repair/start/stop/restart/status/logs/backup/restore/reset-admin/port/uninstall/cloudflare/diagnose. `setup.py` still owns schema/admin creation. | Yes. Only the menu + CLI installation and config preservation were lost. |
| Did SSHX originally connect to a customer VPS or the host? | `bc26729:vps.py::_start_sshx_session()` ran `sshx` via `chroot <vps-root>` as the panel's root service user and stored a permanent `https://sshx.io/s/...` link in `vps.ssh_command`. | It was a permanent root shell in a chroot on the **host kernel** — not an isolated connection to a customer VM. That is the critical isolation failure. |
| Were VPS/user tables ever dropped? | No `DROP TABLE`/destructive migration exists in any commit. | No. Safe, additive migrations only. |

## 2. Containment (do first)

1. Add a fail-closed `sshx_contained` policy (default `1`). Authorization denies every
   session while it is set, regardless of the legacy `global_enabled` flag. This
   closes existing installations that already have `global_enabled=1` stored.
2. The admin SSHX page shows a maintenance/containment banner and requires an
   explicit, audited "validate and lift containment" action. Re-enable is impossible
   until an administrator has done this after verifying the gateway.
3. Strip any remaining legacy `|||https://sshx.io/...` links during migration, even
   when SSHX is disabled.

## 3. SSHX rebuild — gaps to close in the existing `a1c6d63` broker

- Re-check ownership/status/suspension/policy of **live** sessions in the sweeper and
  revoke them immediately when authorization is lost (not just at creation).
- Add a partial unique index for active sessions per VPS plus in-process locking.
- Add idle cleanup via a server-side `last_seen` heartbeat, status transitions
  (`starting` → `active`), and a `touch` endpoint called by authorized status polling.
- Add gateway-side validation of all spec fields (IDs, paths, binary ownership,
  expiry) and heartbeat writing; no browser-supplied destination is ever accepted.
- Stop trusting `X-Forwarded-For` unless `TRUST_PROXY` is explicitly configured.
- Wire revocation into user suspension, VPS suspension, VPS deletion, user deletion,
  ownership changes, and global disable.
- Keep the existing unprivileged `sshx-gw` + forced `ssh` wrapper architecture; it is
  the only compatible design for this chroot backend. Document honestly that a
  chroot is not a VM: a kernel-level escape from a customer VPS is outside the
  guarantee. No host shell is created by SSHX itself.

## 4. Management Suite restoration

Restore the **original 15 menu actions** from `9785c5f^:install.sh` as
`management_suite.py`, implemented by reusing `installer.py::Installer` modes
(no duplicated shell logic). Install `/usr/local/bin/panel` again from
`ConfigManager.install_cli()`, including in install/reinstall/update/repair paths.
Preserve existing `.env` keys on rewrite (never overwrite administrator settings).

## 5. Integration, DB, installer, tests

- Admin SSHX page: containment banner, validation action, revoke-all-by-user/VPS,
  denied attempts, audit events.
- Add safe, additive SQLite migrations only; never drop `users`, `vps`, `nat_rules`.
- Make install/repair/update fail verification when service is not running.
- Extend isolated tests (temp DB/VPS roots, mocked process launcher) for containment,
  live authorization revocation, duplicates, idle timeout, CLI menu mapping, and
  admin permissions. Never use real customer VPSes in tests.

## 6. Verification / delivery

Run `python -m unittest discover -s tests -v`, compile all Python, check routes,
check migration on a copy of a legacy DB, review diff, commit. Push requires
credentials; if unavailable, report that limitation instead of claiming it was pushed.

## 7. Implementation status

All items in sections 2–5 are implemented. Verification: 32 isolated unit/HTTP
tests pass (`/tmp/opencode/free-panel-venv/bin/python -m unittest discover -s
tests -v`), all modified Python files compile, and inline dashboard JavaScript
passes `node --check`. SSHX remains contained by default; no real host/VPS
end-to-end test was possible in this environment, so isolation is proven only
at the unit/HTTP/static level. See `docs/SSHX_SECURITY.md` for the final design.
