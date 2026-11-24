# SSHX isolation: root cause, fix and verification

## Critical finding (exact root cause)

The panel did **not** implement SSHX as a per-user, authorized session. It
implemented it as a permanent, shareable root shell:

1. `vps.py::create_vps_container()` ran `_install_sshx(inst)` and
   `_start_sshx_session(inst)` at provision time.
2. `_install_sshx()` downloaded the statically linked `sshx` binary **into the
   customer's chroot** (`<rootfs>/usr/local/bin/sshx`) and copied the host CA
   bundle in.
3. `_start_sshx_session()` executed, through `_ChrootVPS.execute()`:
   `setsid sh -c '... nohup sshx > /tmp/sshx.log ... &'`.
   `_ChrootVPS.execute()` ultimately runs `chroot <vps-root> /bin/bash -c ...`
   as the panel's systemd user — **root** (`installer.py` writes
   `User=root` for `deup-panel.service`).
4. `sshx` printed a URL into `/tmp/sshx.log` inside the jail. The panel parsed
   it with `SSHX_LINK_RE` and stored it forever in
   `vps.ssh_command` as `ssh ... |||https://sshx.io/s/...#...`.
5. `app.py::parse_ssh_command()` handed that URL straight to the dashboard,
   which rendered it as a clickable link and a `navigator.clipboard` copy
   button. Anyone who saw, copied, or guessed the link got a root terminal.

Why that reached the **main VPS/host**, not just the customer's VPS:

* The "VPS" implementation is a **chroot on the host**, not a VM or a
  container with its own kernel boundary. Root inside a chroot is root from
  the kernel's point of view; escaping a chroot is trivial with
  `CAP_SYS_CHROOT`/`CAP_SYS_ADMIN`, `/proc/self/root`, `open_by_handle_at`,
  or device/node tricks.
* `_prepare_runtime()` **bind-mounted the host's `/dev/pts` and `/dev/shm`**
  into every jail, so host PTYs and shared memory were reachable from the
  session.
* Networking was the **host network namespace** (`nat.py` in chroot mode does
  not create netns). The shell could connect to host-only services on
  `127.0.0.1`, and every VPS could see every other VPS's ports.
* No authentication, ownership check, expiry, revocation, rate limit,
  concurrency cap, or audit event existed for the link. The link was a bearer
  credential with no binding to the logged-in panel user.

`regen_ssh()` simply repeated steps 3–5, so "regenerating" never revoked
anything and produced yet another permanent root link.

## New architecture

```
browser (authenticated, CSRF)
   |  POST /api/sshx/session {vps_id}
   v
app.py  ──> sshx_manager.authorize_session()
              * global toggle, user suspension, per-user disable
              * vps exists AND vps.user_id == current_user.id
              * vps status == running, meta state not suspended
              * per-vps disable, valid container id, NAT port, VPS host key
              * rate limit + per-user/per-VPS concurrent caps
   |
   |  creates ephemeral ED25519 key, pins the VPS host key, injects a
   |  restricted authorized_keys entry (from="127.0.0.1", no forwarding)
   |  into the CUSTOMER'S OWN VPS only
   v
sshx_manager._spawn_gateway()   (subprocess list args; no shell; no_new_privs;
                                 rlimits; drops to uid/gid of `sshx-gw`)
   v
/opt/sshx/bin/sshx_gateway.py   (runs as `sshx-gw`, NEVER root; minimal env;
                                 parses link, redacts it from logs)
   v
/opt/sshx/sshx --shell /opt/sshx/bin/sshx-target-shell
   v
sshx-target-shell  ──execv──> /usr/bin/ssh -i <ephemeral key>
                              -o StrictHostKeyChecking=yes
                              -p <DB-assigned port> root@127.0.0.1
   v
SHELL INSIDE THE CUSTOMER'S OWN VPS (never a host shell)
```

Key properties:

* **No browser-controlled connection data.** The API accepts only `vps_id`.
  Host, port, SSH user, key path, forwarding and command are read from the DB
  or fixed constants. Extra JSON fields are ignored (tested).
* **No root SSHX.** The gateway and target wrapper both refuse to run as
  uid 0. The panel (which must manage chroots) never executes `sshx`.
* **No host shell.** sshx's shell is a fixed wrapper whose only action is an
  `execv` of `ssh` into the customer's VPS. No generic command endpoint was
  added.
* **Short-lived, revocable.** 15-minute default TTL, expiry sweeper,
  explicit revoke (user/admin), global/user/VPS disable, and mandatory
  teardown at panel restart. Revocation kills the process group, removes the
  ephemeral authorized_keys marker, and deletes all session files.
* **No credentials in browser storage/URLs/logs.** The URL is returned once
  in a JSON response body, held in JS memory, and written only to a 0600
  file under the session directory. Gateway logs redact the link. Admin
  screens never show links or keys.
* **Hardened chroot runtime.** Host `/dev/pts` and `/dev/shm` bind mounts were
  replaced with a private `devpts newinstance` and a size-limited tmpfs.

## Files changed

| File | Change |
|---|---|
| `sshx_manager.py` (new) | Authorization gate, session DB schema, ephemeral keys, host-key pinning, process launch as `sshx-gw`, expiry/revocation sweeper, audit + admin policy API. |
| `gateway/sshx_gateway.py` (new) | Unprivileged gateway; refuses root; minimal env; explicit argv; link redaction; signal cleanup. |
| `gateway/sshx-target-shell` (new) | Forced command; refuses root; `execv` SSH to customer's VPS only. |
| `vps.py` | Removed all legacy SSHX install/session/regen code and regexes; provisioning no longer starts SSHX; added public metadata/host-key/authorized-key helpers and VPS-name listing; private devpts/tmpfs instead of host bind mounts. |
| `app.py` | New session create/status/revoke routes, admin SSHX page, boot cleanup + sweeper, legacy filter no longer renders stored links, `regen_ssh` is now inert. |
| `templates/dashboard.html` | Removed stored-link display/regen form; added AJAX-driven secure session UI with expiry polling and revoke. |
| `templates/admin_sshx.html` (new) | Session list, stats, security events, global/user/VPS controls; no credentials. |
| `templates/base.html` | Admin SSHX navigation entry. |
| `installer.py` | `SSHXHardening`: creates `sshx-gw`, installs root-owned gateway code, installs sshx client + openssh-client, kills/removes legacy in-chroot binaries, strips legacy DB links, verifies ownership, wired into install/reinstall/update/repair/verify, new `.env` knobs. |
| `tests/test_sshx_isolation.py` (new) | Tests A–J. |
| `tests/test_sshx_routes.py` (new) | HTTP-level ownership, parameter-ignoring, isolation and admin-no-credential tests. |

## Verification performed

```
$ python3 -m unittest discover -s tests -v
Ran 14 tests ... OK
```

* A — normal access: link issued, correct DB port/VPS, never persisted/logged.
* B — cross-user VPS id denied at manager and HTTP layers, no process spawned.
* C — host-style identifiers/rows rejected; no host connection possible.
* D — suspended VPS and suspended user denied.
* E — another user cannot read or revoke a session; owner can.
* F — expired sessions are marked expired, process killed, key/link removed.
* G — revocation kills process group and scrubs credentials.
* H — invalid ids, global/user/VPS disable enforced; extra browser
  `host/port/key/password/forwarding` fields ignored.
* I — static checks: gateway/wrapper refuse root, no `shell=True`, no
  `chroot` invocation in the SSHX manager, legacy functions gone.
* J — two users get distinct keys/ports and cannot cross-read sessions.

No destructive test was run against a real customer VPS: all tests use temp
directories, a temp SQLite DB, and patched process launchers.

## Remaining limitations

* **Chroot is not a VM.** The pre-existing panel terminal
  (`/vps/<id>/terminal` via `exec_command`) still runs commands as root inside
  the same chroot. Strong host isolation against kernel-level chroot escapes
  requires migrating the VPS backend to unprivileged LXC or KVM. The SSHX
  feature no longer depends on that boundary being perfect: it never gives a
  host shell, but a determined kernel-exploit escape from a customer VPS is
  outside what this patch can guarantee.
* The panel service itself still runs as root because it manages chroots,
  iptables and privileged ports. The SSHX gateway does not inherit that
  privilege.
* If the host's `sshd` inside a VPS is stopped, an SSHX session cannot be
  established (fails closed with a clear error).
* `sshx.io` is an external relay. The session link is end-to-end encrypted by
  sshx, but the relay learns session existence/timing. A self-hosted sshx
  server can be substituted via `SSHX_SERVER` without changing the model.
* Host-key pinning uses the VPS's ed25519 host key captured at session start;
  if a VPS host key is regenerated while a session is live, that session will
  fail closed.
