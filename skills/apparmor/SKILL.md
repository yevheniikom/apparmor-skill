---
name: apparmor
description: Create, edit, audit, and troubleshoot AppArmor profiles on Linux (path-based mandatory access control). Trigger on AppArmor, confining an app or service, profile rules (file, network, capability, signal, dbus, mount), abstractions, tunables, denial-log analysis, the aa-* tools, or apparmor_parser. ALSO trigger for Docker/Kubernetes AppArmor (docker-default, --security-opt apparmor, container escapes) and for Electron/Chromium apps failing to launch on Ubuntu 24.04+ (sandbox/userns errors, kernel.apparmor_restrict_unprivileged_userns) -- prefer triggering over not.
---

# AppArmor Skill

AppArmor is a Linux security module that confines programs with path-based profiles loaded into the kernel. A profile lists the files, capabilities, network families, IPC (signal, dbus, unix), mounts, and exec transitions a program may use; anything not allowed is denied. Profiles run in **enforce** mode (block) or **complain** mode (log, allow).

Two facts drive most debugging, so keep them in mind from the start:

- **Rules match the resolved path.** Symlinks, including the `#!` interpreter of a script, are resolved before matching. A rule written on the symlink path never fires.
- **Profiles attach at `exec()`.** A process started before its profile was loaded stays unconfined until it is restarted. Always test with a freshly exec'd process.

## When to Read Reference Files

- **references/rules.md** -- Everyday rule syntax: profile structure and flags, file permissions, globs (AARE), network, capability, signal, DBus, mount; `priority=` (4.1+); what `flags=(unconfined)` really does; `attach_disconnected`. Read when writing or editing any rule.
- **references/rules-advanced.md** -- Rarely needed primitives: `userns,`, `io_uring`, standalone `unix` rules, `xattrs()` attachment, `mqueue`. Read only when the app uses one, or to `deny` one explicitly.
- **references/hardening.md** -- Deny precedence, audit mode, the numbered pitfalls (BAD/GOOD examples, incl. symlinks = pitfall 11 and parser cache = pitfall 12), and §4 cross-checking a "Permission denied" (strace, `ausearch`, reproduction). Read when hardening, or when a denial or a silent failure makes no sense.
- **references/abstractions.md** -- All abstractions, tunables and variables, and runtime domain changes made by the program itself (`change_hat`, `change_profile`). Read when choosing includes or defining variables.
- **references/workflow.md** -- Lifecycle (complain to enforce), the `aa-*` tool reference, management commands, `local/` overrides, profile naming, a full profile template, verifying enforcement (`attr/current`, `aa-exec` caveats, exit-0-is-not-proof), validating a source profile before install, `aa-notify`, `aa-remove-unknown`, systemd `AppArmorProfile=`. Read for any operational task.
- **references/child-processes.md** -- Exec transitions (`ix`, `Px`, `Cx`, `Ux`, named), child profiles, stacking, and patterns for browsers, sandbox runtimes (bwrap/firejail), CI runners, setuid helpers, service workers. Read whenever the program spawns other programs.
- **references/electron-chromium.md** -- Electron/Chromium apps: the Ubuntu 24.04+ userns restriction, the minimal `flags=(unconfined)` + `userns,` profile, chrome-sandbox, AppImages, full confinement. Read for any Electron/Chromium app or sandbox launch error.
- **references/docker.md** -- `docker-default` and what it enforces, `--security-opt apparmor=`, Kubernetes `appArmorProfile`, why MAC overrides granted capabilities, and path-based container-escape classes. Read for any container workload.
- **references/parser-bugs/** -- One file per version-specific `apparmor_parser` bug. Currently `4.0.0-4.0.1-unconfined-mediation.md` (body rules demote a `flags=(unconfined)` stub to enforce). Read when an unconfined stub runs enforced.

## Core Workflows

### 1. Write a new profile

1. Recon: `readlink -f $(which myapp)` (profile the **resolved** path), check for an existing profile (`aa-status`, `grep -rl <path> /etc/apparmor.d/`), list what it touches (`ldd`, config/data/log dirs).
2. Generate or write:
   - `aa-genprof /usr/bin/myapp` while exercising the app -- good for services you don't know well.
   - Write by hand from the template in `references/workflow.md` §3 and the syntax in `references/rules.md` -- better when you understand the app.
3. Validate without loading: `apparmor_parser -QTK <file>` (for an uninstalled profile with `#include <local/...>`, see `references/workflow.md` §4).
4. Load in complain mode, exercise the app, run `aa-logprof`, then `aa-enforce`.
5. Verify a fresh process is confined (`references/workflow.md` §4), and `strace` one real run for swallowed `EACCES` -- exit 0 is not proof.

### 2. Audit and harden an existing profile

Check the profile against this list; each item points at the detail:

- `#include <tunables/global>` and `abstractions/base` present; paths use `@{HOME}`, `@{multiarch}` (`references/abstractions.md`).
- No `/** rw`-style globs where a narrower tree works (`references/hardening.md` pitfall 1).
- Sensitive dirs denied with `/{,**}`, not bare `/**` (pitfall 2b), plus `/**/.ssh/{,**}`-style mirrors if home may sit behind a symlink (pitfall 11).
- Exec transitions use `Px`/`Cx`/`Ux` (scrubbed), not lowercase or `ux` (`references/child-processes.md`); every `Cx`/`Px` child re-includes the deny rules, because children inherit nothing.
- Minimal capabilities; `network inet tcp,` rather than `network,` where possible.
- `audit deny` on sensitive paths; `#include <local/...>` at the end.

### 3. Diagnose a denial

Diagnose in this order before writing or widening any allow:

1. **Does a rule already cover the path with the right mask?** If yes, it is matching a different string than the kernel checked -- go to 2.
2. **Is the path (or a parent, or a script's interpreter) a symlink?** `readlink -f <path>`; `ls -ld <path> $(dirname <path>)`; `head -1 <script>`. Write the rule on the resolved target (`references/hardening.md` pitfall 11).
3. **Is it AppArmor at all?** Read the record with `sudo ausearch -m AVC,USER_AVC -ts recent`, not `dmesg`: DBus denials (`USER_AVC`) never reach the kernel ring buffer, and a plain `deny` (no `audit`) blocks without logging. Cross-check with strace and a reproduction outside the profile (`references/hardening.md` §4).
4. Only then treat it as a missing allow: read `operation`, `name`, `requested_mask` from the record and add the narrowest rule (`references/rules.md`), or use `aa-logprof`.

Reload after editing with `sudo apparmor_parser -rK <file>` (`-K` skips the compiled cache, which can serve stale policy -- `references/hardening.md` pitfall 12).

### 4. Profile by workload type

- **Network service:** `base`, `nameservice`, `ssl_certs`; `capability net_bind_service,` for ports < 1024; `network inet tcp,` / `network inet6 tcp,`; read the docroot, append to logs. Per-vhost confinement uses hats (`references/abstractions.md` §3).
- **Database:** `base`, `nameservice`; the specific capabilities it drops privileges with (`chown`, `setuid`, `setgid`, ...); data dir, WAL, temp files; `signal (receive) set=(term hup) peer=unconfined,` for shutdown.
- **systemd service:** profile the `ExecStart=` binary; check `systemd-analyze security <unit>` for overlap; `AppArmorProfile=` pins a non-default profile (`references/workflow.md` §5).
- **Desktop app:** `base`, `nameservice`, the toolkit abstraction (`gnome`/`kde`), `X`/`wayland`, `audio`; `owner @{HOME}/.config/<app>/** rw,`; explicit `dbus` rules (`references/abstractions.md`). Never blanket-`deny network,` -- it can cut the display socket (`references/rules.md` §4).
- **Electron/Chromium:** on Ubuntu 24.04+ it won't start without a profile granting `userns,` -- `references/electron-chromium.md`.
- **Programs that spawn programs:** one exec-transition rule per `execve` boundary; capabilities and `userns,` are per profile -- `references/child-processes.md`.
- **Containers:** `docker-default` applies unless overridden; MAC beats `--cap-add` -- `references/docker.md`.

## Common Troubleshooting

| Symptom | Likely cause | Where to look |
|---------|--------------|---------------|
| "Permission denied" although a matching rule exists | Path is a symlink; the kernel matched the resolved path | Core Workflow 3; `hardening.md` pitfall 11 |
| "Permission denied", nothing in `dmesg` | DBus `USER_AVC`, or a non-`audit` `deny` | `hardening.md` §4, pitfall 8 |
| A deny rule doesn't block | Glob/mask doesn't match the denial record; bare `/**`; symlink; or a higher `priority=` allow (4.1+) | `hardening.md` §1, pitfalls 2b, 11 |
| `audit deny` doesn't block in complain mode | Long-standing quirk: complain downgrades `audit deny` to log-and-allow (plain `deny` still blocks) | `hardening.md` pitfall 5 |
| Edits don't take effect after `apparmor_parser -r` | Stale compiled cache | `hardening.md` pitfall 12 |
| App crashes at start / segfaults loading a library | Missing `abstractions/base`, or `r` without `m` on `.so` files | `hardening.md` pitfalls 3, 6 |
| DNS fails | Missing `abstractions/nameservice` | `hardening.md` pitfall 3 |
| Can't bind port < 1024 | Missing `capability net_bind_service,` | `rules.md` §5 |
| `attr/current` says `unconfined` after loading the profile | Process started before the profile loaded | `workflow.md` §4 |
| Profile loaded but app runs unconfined | Attachment path doesn't match the resolved binary path, or another profile with the same name/attachment won | `workflow.md` §2 |
| Child process denied / child exec fails | Missing or wrong transition; `Px` target profile doesn't exist; `Cx` without a matching child profile | `child-processes.md` |
| Workers become zombies | Parent lacks `signal (send) ... peer=<child>` | `child-processes.md` pitfalls |
| Electron app won't launch on Ubuntu 24.04+; or tabs crash | Missing `userns,` (in the parent, or in the renderer child profile) | `electron-chromium.md` |
| `bwrap: setting up uid map: Permission denied` | `bwrap` needs a profile granting `userns,`; which release ships one varies | `child-processes.md` Pattern 2a |
| An unconfined stub runs *enforced* after adding a `local/` deny | Parser 4.0.0/4.0.1 bug; the deny would be inert on a fixed parser anyway | `parser-bugs/4.0.0-4.0.1-unconfined-mediation.md` |
| AppImage profile stopped matching | `/tmp/.mount_*` path changes per run | `electron-chromium.md` AppImages |
| Container with `--cap-add SYS_ADMIN` still can't mount | `docker-default` denies the operation regardless of the cap | `docker.md` §3 |
| Profile won't compile | Syntax error or missing `tunables/global` | `apparmor_parser -QTK`; `hardening.md` pitfall 9 |

## Important Notes

- AppArmor is path-based, not inode-based: renaming or bind-mounting a file changes which rules apply.
- `ux` / `Ux` removes all confinement from the child; use it only when nothing else works.

## References

Upstream and distro documentation, for corner cases and version-specific behaviour:

- [`apparmor.d(5)`](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html) -- full profile syntax
- [`apparmor_parser(8)`](https://manpages.ubuntu.com/manpages/noble/man8/apparmor_parser.8.html) -- compile/load flags (`-r`, `-QTK`, `--skip-cache`, `-I`)
- [AppArmor project site](https://apparmor.net/) -- release notes (which version carries a fix), wiki
- [Ubuntu Server AppArmor guide](https://documentation.ubuntu.com/server/how-to/security/apparmor/) -- distro tooling and the 24.04+ `unprivileged_userns` restriction
- [roddhjav/apparmor.d](https://github.com/roddhjav/apparmor.d) -- the most complete third-party profile set; reference for namespace-creating tools (bwrap, podman, runc) and `attach_disconnected`/`@{att}`
