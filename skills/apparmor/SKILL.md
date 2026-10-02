---
name: apparmor
description: Create, edit, audit, and troubleshoot AppArmor profiles on Linux -- the mandatory access control (MAC) system that confines programs via path-based policies. Trigger on AppArmor, mandatory access control, confining or hardening an app/service, profile rules (file, network, capability, signal, dbus, mount), abstractions, tunables, denial-log analysis, the aa-* tools (aa-genprof, aa-logprof, aa-complain, aa-enforce, aa-status), or apparmor_parser. ALSO trigger for confining or auditing Docker/container/Kubernetes workloads, the docker-default profile, --security-opt apparmor, or container escapes. ALSO trigger for Electron/Chromium apps that fail to launch on Ubuntu 24.04+ with chrome-sandbox, SUID sandbox, userns, or namespace-sandbox errors, or any mention of kernel.apparmor_restrict_unprivileged_userns -- prefer triggering over not.
---

# AppArmor Skill

AppArmor (Application Armor) is a Linux kernel security module that confines programs to a limited set of resources using path-based mandatory access control profiles. Each profile declares exactly what files, capabilities, network access, IPC, and other resources a program may use -- anything not explicitly allowed is denied.

## How AppArmor Works

AppArmor enforces security through profiles loaded into the kernel:

1. **Path-based rules** -- file access permissions (read, write, execute, mmap, lock, link) on specific paths with glob patterns
2. **Capabilities** -- POSIX.1e/Linux capabilities the program is allowed to use
3. **Network rules** -- socket families, types, and protocols the program may access
4. **IPC rules** -- signal, dbus, and unix socket mediation between processes
5. **Mount rules** -- control over mount, umount, remount, and pivot_root operations
6. **Profile transitions** -- how child processes inherit or switch confinement (ix, px, cx, ux)

Profiles operate in two modes: **enforce** (block and log violations) and **complain** (log violations but allow them). The standard development workflow starts in complain mode, analyzes logs, refines rules, then switches to enforce.

## When to Read Reference Files

The references/ directory contains detailed documentation split by domain. Read the appropriate file based on the task:

- **references/rules.md** -- Syntax for the everyday rule types: profile structure, file permissions, glob patterns (AARE), network, capability, signal, DBus, and mount rules. Read when creating a new profile, editing access rules, or looking up the syntax for any of these. (Advanced/4.0+ primitives are split into rules-advanced.md.)

- **references/rules-advanced.md** -- Advanced/AppArmor 4.0+ (and 3.x) rule primitives most profiles never need: user namespaces (`userns,` — the Ubuntu 23.10+ Electron/`unshare` restriction), `io_uring`, fine-grained AF_UNIX sockets (standalone `unix` rule), profile attachment by xattr (`xattrs()`), and message queues (`mqueue`). Read only when the app actually uses one of these, or when hardening wants an explicit `deny` on one (`deny userns,`/`deny io_uring,`/`deny mqueue,`).

- **references/hardening.md** -- Deny rules, audit mode, and the twelve most common pitfalls (numbered 1-12, with 2b) each with BAD/GOOD examples. Read when hardening a profile, troubleshooting unexpected denials, setting up monitoring, or debugging silent failures.

- **references/abstractions.md** -- All available abstractions (base, nameservice, desktop, application, audio/video), tunables and variables, and **API-driven** runtime domain transitions (`change_hat`, `change_profile`, hat subprofiles). Read when deciding which includes to use, defining custom variables, or when the program itself calls libapparmor to switch domains (e.g. Apache `mod_apparmor` per-vhost hats, privilege-drop-after-setup patterns).

- **references/workflow.md** -- Development lifecycle (complain-to-enforce), tool reference (aa-genprof, aa-logprof, etc.), management commands, local overrides, profile naming conventions, and a complete production-ready profile template. Read when managing profiles, looking up tool usage, or needing a quick-start template.

- **references/electron-chromium.md** -- Electron, Chromium, Chrome, and any Chromium-based app (Signal, Bitwarden, Obsidian, VSCode, Slack, Discord, Jitsi, Element, etc.), including the Ubuntu 24.04+ `unprivileged_userns` problem, the `userns,` rule, the chrome-sandbox SUID helper, AppImage path wildcards, and full-confinement vs. minimal `flags=(unconfined)` profiles. Read whenever the user mentions an Electron/Chromium app failing to launch, sandbox errors, `chrome-sandbox`, or `kernel.apparmor_restrict_unprivileged_userns`.

- **references/parser-bugs/** -- Version-specific `apparmor_parser` bugs and their version gates, one file per bug. Currently: `4.0.0-4.0.1-unconfined-mediation.md` (a `flags=(unconfined)` profile with body rules is silently demoted to enforce on parser 4.0.0/4.0.1). Read when shipping a `local/` deny include for an unconfined stub profile, or when an Electron/Firefox stub inexplicably runs enforced.

- **references/child-processes.md** -- Multi-process apps in general: **exec-time** transitions (`ix`, `Px`/`px`, `Cx`/`cx`, `Ux`/`ux`, named transitions), child profiles declared inside a parent, profile stacking (AppArmor 4.0), and patterns for browser-style sandboxes, sandbox runtimes (bwrap/firejail/nsjail), CI runners, setuid helpers, and systemd workers. Read whenever you need to confine a program that spawns other programs via `execve`, or whenever exec-transition rules are involved. (For `change_hat`/`change_profile` runtime API calls, see abstractions.md.)

- **references/docker.md** -- AppArmor for Docker/containers: the built-in `docker-default` profile and exactly what it enforces (`deny mount,`, `/proc`/`/sys` write denies, same-profile ptrace), `docker run --security-opt apparmor=<profile>` / `=unconfined`, `docker inspect ... AppArmorProfile`, the Kubernetes `securityContext.appArmorProfile` field, and **why MAC overrides granted capabilities** (a `--cap-add SYS_ADMIN` container still can't mount). Also hardening against the path-based bypass classes container escapes use (bind-mount alternate paths, shebang/interpreter confusion, disable/weaken-and-reload). Read whenever the user mentions Docker, containers, Kubernetes/k8s, `docker-default`, `--security-opt`, container escapes, or confining/auditing a containerized workload.

## Core Workflows

### 1. Generate a New Profile for a Binary

First, identify the binary and understand what it does:

```bash
# Find the binary's full path
which myapp
readlink -f $(which myapp)

# Check if a profile already exists
sudo aa-status 2>/dev/null | grep myapp
ls /etc/apparmor.d/ | grep myapp

# See what the binary accesses (quick recon)
ldd /usr/bin/myapp          # shared libraries
ls -la /etc/myapp* 2>/dev/null   # config files
ls -la /var/lib/myapp* 2>/dev/null  # data dirs
ls -la /var/log/myapp* 2>/dev/null  # log dirs
```

Then generate the initial profile using one of two approaches:

**Approach A: Interactive generation with aa-genprof (recommended for services)**

```bash
sudo aa-genprof /usr/bin/myapp
# In another terminal: exercise the application normally
# Return to aa-genprof: press S to scan, accept/reject rules, press F to finish
```

**Approach B: Write from scratch (recommended when you understand the app well)**

Read **references/rules.md** for the full syntax and **references/workflow.md** for the quick reference template. The minimal structure:

```
abi <abi/4.0>,
#include <tunables/global>

profile myapp /usr/bin/myapp flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>    # if app does DNS/user lookups

  # Binary itself
  /usr/bin/myapp                    mr,

  # Libraries
  /usr/lib/@{multiarch}/lib*.so*    rm,

  # Config
  /etc/myapp/{,**}                  r,

  # Data
  /var/lib/myapp/{,**}              rw,

  # Logs
  /var/log/myapp/*.log              a,

  # Local overrides
  #include <local/usr.bin.myapp>
}
```

After writing, validate and load:

```bash
# Syntax check (dry run)
sudo apparmor_parser -QTK /etc/apparmor.d/usr.bin.myapp

# Load in complain mode first
sudo aa-complain /usr/bin/myapp

# Exercise the application, then review logs
sudo aa-logprof

# When satisfied, enforce
sudo aa-enforce /usr/bin/myapp
```

### 2. Audit and Harden an Existing Profile

Read the profile, then check it against **references/hardening.md** (deny rules, pitfalls) and **references/abstractions.md** (includes, tunables):

```bash
# Read the current profile
cat /etc/apparmor.d/usr.bin.myapp

# Check what mode it's in
sudo aa-status 2>/dev/null | grep myapp
```

Hardening checklist:

- **Includes**: Does it have `#include <abstractions/base>`? Does it include `nameservice` if it does DNS?
- **Overly broad globs**: Look for `/** rw` or `/* rw` that should be scoped narrower
- **Missing deny rules**: Should sensitive paths like `@{HOME}/.ssh/{,**}`, `@{HOME}/.gnupg/{,**}` be explicitly denied? Use `/{,**}` not bare `/**` so the rule also blocks directory enumeration -- see `references/hardening.md` pitfall 2b. If sensitive dirs may be reached via symlinks that resolve outside `@{HOME}`, also add wildcard-name denies (`deny /**/.ssh/{,**} rwmlk,`) -- see hardening.md pitfall 11
- **Execute transitions**: Are child processes using `Px` (safe, scrubbed) rather than `ux` (unconfined) or `px` (unscrubbed)?
- **Capabilities**: Are only the minimum needed capabilities granted? Is `sys_admin` being used when a narrower cap would work?
- **Network scope**: Is `network,` (all networking) used when `network inet tcp,` would suffice?
- **Audit on sensitive rules**: Are `audit deny` rules in place for known-bad accesses?
- **Local overrides**: Does it include `#include <local/profile-name>` at the end?
- **Tunables**: Is `#include <tunables/global>` present? Are paths using `@{HOME}` and `@{multiarch}` instead of hardcoded values?

### 3. Analyze Denial Logs and Fix Profiles

**Before writing or widening any rule, diagnose in this order — it saves the most time:**

1. **Is this path even allowed by an existing rule?** Read the profile and check whether a rule already covers the denied path with the right permission mask. If the intended rule is there but not firing, do NOT assume you need a *new* allow — the rule is probably matching a different string than the kernel checked (go to step 2).
2. **Is the path a symlink on THIS system?** AppArmor matches the **resolved** path, not the one you wrote. Symlinks are resolved *before* rule matching, so a rule on the symlink path never fires. This is the single most common time-sink in profile debugging, and it is invisible until you look — the error text names the path you wrote, not the one the kernel matched. Always run:

   ```bash
   readlink -f <denied-path>        # the path AppArmor actually matches
   ls -ld <denied-path> $(dirname <denied-path>)   # is any parent a symlink?
   head -1 <script>                 # if it's a script, its #! interpreter is ALSO resolved
   ```

   Common traps: `~/.ssh`/`~/.config/X` when `$HOME` is on a mounted volume; `~/.var/app` (Flatpak) or `~/snap` on another disk; `/bin/sh` → `/usr/bin/dash` (merged-usr); `*latex` → `xetex`/`pdftex`; `/proc/self/fd/N`. Write the rule on the **resolved** target (and, for dotdirs that may live behind a home-on-a-mount symlink, add a wildcard mirror like `/**/.ssh/{,**}` keeping the meaningful component). See `references/hardening.md` pitfall 11.

Only once both are ruled out should you treat the denial as a genuinely missing allow. Then parse the denial to see exactly what's being blocked:

```bash
# Recent AppArmor denials
sudo dmesg | grep -i "apparmor.*DENIED" | tail -20

# Or from the audit log
sudo grep "apparmor.*DENIED" /var/log/audit/audit.log 2>/dev/null | tail -20
# Or from syslog
sudo grep "apparmor.*DENIED" /var/log/syslog 2>/dev/null | tail -20

# Readable summary of recent denials (last 1 day): -s NUM = summary for last NUM days, -v = show the messages
sudo aa-notify -s 1 -v

# Structured parsing of a denial line
# Example: apparmor="DENIED" operation="open" profile="myapp" name="/etc/foo" requested_mask="r" denied_mask="r"
# Fields: profile (which profile), name (path), operation (syscall), requested_mask (what was asked), denied_mask (what was blocked)
```

For bulk analysis, use `aa-logprof` which reads the logs and proposes rule additions interactively:

```bash
sudo aa-logprof
```

When fixing manually, read **references/rules.md** (File Permissions section) to understand the correct permission mode, then add the rule. After editing, reload:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.myapp
```

**Troubleshooting silent denials**: If the app misbehaves but no denial appears in logs, the profile may have `deny` rules without `audit`. Temporarily add `flags=(complain,audit)` to the profile header to log everything, or convert specific `deny` rules to `audit deny`.

### 4. Manage Profile Lifecycle

```bash
# View all loaded profiles and their modes
sudo aa-status

# Switch modes
sudo aa-complain /usr/bin/myapp      # Log only (for testing)
sudo aa-enforce /usr/bin/myapp       # Block violations (for production)

# Disable a profile (unload + prevent loading at boot)
sudo aa-disable /usr/bin/myapp

# Or manually:
sudo ln -s /etc/apparmor.d/usr.bin.myapp /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.myapp

# Re-enable a disabled profile
sudo rm /etc/apparmor.d/disable/usr.bin.myapp
sudo apparmor_parser -a /etc/apparmor.d/usr.bin.myapp

# Reload all profiles
sudo systemctl reload apparmor.service

# Reload a single profile after editing
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.myapp

# Find unconfined processes (candidates for profiles)
sudo aa-unconfined
```

### 5. Use Abstractions and Tunables

Abstractions are pre-built rule bundles that cover common subsystems. Using them is both safer (maintained by distro packagers) and more concise than writing rules by hand. Read **references/abstractions.md** for the full list.

Key abstractions to know:

| Abstraction | When to include |
|-------------|----------------|
| `base` | Always -- every profile needs it |
| `nameservice` | App does DNS lookups, user/group resolution, or LDAP |
| `authentication` | App authenticates users (PAM, shadow) |
| `ssl_certs` | App makes TLS connections |
| `user-tmp` | App uses /tmp or /var/tmp |
| `private-files-strict` | Untrusted apps -- denies access to SSH keys, GPG, wallets |
| `gnome` / `kde` | Desktop apps using those toolkits |
| `X` / `wayland` | Apps needing display server access |
| `audio` | Apps that play or record audio |

Tunables provide variables like `@{HOME}`, `@{PROC}`, `@{multiarch}`. Always include `#include <tunables/global>` in the preamble. Define custom variables for app-specific paths:

```
@{app_data} = /var/lib/myapp /srv/myapp
@{app_log}  = /var/log/myapp

profile myapp /usr/bin/myapp {
  @{app_data}/{,**} rw,
  @{app_log}/*.log  a,
}
```

### 6. Write Profiles for Common Service Types

**Web server / API service:**
- `abstractions/base`, `abstractions/nameservice`, `abstractions/ssl_certs`
- `capability net_bind_service` for port < 1024
- `network inet tcp,` and `network inet6 tcp,`
- Read access to document root, write to log directory, append to access logs
- Consider hat subprofiles for virtual hosts (see **references/abstractions.md** §3 "Runtime Domain Transitions")

**Database service:**
- `abstractions/base`, `abstractions/nameservice`
- `capability chown dac_override fowner setuid setgid` (varies by DB)
- File access to data directory, WAL, temp files
- `network inet tcp,` for client connections
- `signal (receive) set=(term hup) peer=unconfined` for graceful shutdown

**Desktop application:**
- `abstractions/base`, `abstractions/nameservice`, `abstractions/gnome` or `abstractions/kde`
- `abstractions/X` or `abstractions/wayland`, `abstractions/audio`
- `abstractions/private-files-strict` to protect sensitive user data
- `owner @{HOME}/.config/appname/** rw,` for app config
- `dbus` rules for desktop integration

**Systemd service:**
- Check `systemd-analyze security myservice.service` for existing restrictions
- Profile the binary path from `ExecStart=`
- Include signal rules for systemd lifecycle: `signal (receive) set=(term hup) peer=unconfined`

**Electron / Chromium-based desktop app (Signal, Obsidian, VSCode, Slack, Discord, Jitsi, etc.):**
- On Ubuntu 24.04+ (the restriction was introduced in 23.10 and is default-on from 24.04) these apps will not launch without an AppArmor profile that grants `userns,` -- this is the #1 modern reason desktop users touch AppArmor
- Minimal "make it launch" profile uses `abi <abi/4.0>,` and `flags=(unconfined)` plus the `userns,` rule -- see **references/electron-chromium.md** for the template and explanation
- For full confinement, the renderer/GPU/utility children must transition into a child profile that *also* has `userns,` -- see **references/child-processes.md** for exec-transition mechanics (`Cx -> child`)
- AppImages: profile the `/tmp/.mount_*/AppRun` wildcard path or extract the AppImage to `/opt/<app>/` for a stable path
- Chromium needs `/dev/shm/** rwm,` for inter-process shared memory and PROT_EXEC mappings for V8 JIT -- omitting either causes blank windows or crashes

**Multi-process app spawning helpers (browsers, CI runners, sandbox runtimes, daemons forking workers):**
- Each `execve` boundary needs an exec-transition rule (`ix`, `Px`, `Cx`, named transitions) -- see **references/child-processes.md**
- Default to uppercase modes (`Px`, `Cx`, `Ux`) so the environment is scrubbed -- lowercase variants exist for legacy compatibility and let an attacker who controls the parent's environment influence the child
- Capabilities and `userns,` are profile-scoped, NOT inherited across exec -- each child profile that needs them must declare them
- Parent killing children requires `signal (send) set=(term kill) peer=child-profile-name,`

**Container / Docker workload:**
- On an AppArmor-capable host, Docker applies the auto-generated `docker-default` profile to every container unless overridden -- confirm with `docker inspect <id> | grep AppArmorProfile` or `cat /proc/self/attr/current` inside the container
- Apply a custom profile with `docker run --security-opt apparmor=<profile>` (the separator is `=`, not `:`); load it first with `sudo apparmor_parser -r -W <file>`. `apparmor=unconfined` (and `--privileged`) drop confinement entirely
- **MAC overrides granted capabilities**: `--cap-add SYS_ADMIN` does not let a default container mount or write sensitive `/proc`/`/sys` -- `docker-default` denies the operation regardless of the cap. Never judge a container's reach from `--cap-add` alone
- AppArmor is path-based, so bind-mounting host `/`, `/proc`, `/sys`, or the Docker socket into a container exposes content the profile's path rules don't cover -- see **references/docker.md** for the bypass classes and hardening

## Profile Naming Convention

Profile files in `/etc/apparmor.d/` are named by replacing `/` with `.` in the binary path:

| Binary | Profile file |
|--------|-------------|
| `/usr/bin/myapp` | `usr.bin.myapp` |
| `/usr/sbin/nginx` | `usr.sbin.nginx` |
| `/opt/app/bin/run` | `opt.app.bin.run` |

## Common Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "Permission denied" and a rule for the path already looks correct | The rule is matching a different string than the kernel checked -- almost always because the path is a **symlink**, which AppArmor resolves *before* matching | Diagnose in order (Workflow 3): (1) confirm a rule covers the path with the right mask; (2) `readlink -f <path>` and `ls -ld` its parents -- if any is a symlink, write the rule on the **resolved** target (add a `/**/<dir>/` mirror for home-on-a-mount dotdirs). Don't add a new allow until both are ruled out. See hardening.md pitfall 11 |
| App crashes immediately | Missing `abstractions/base` or library `m` permission | Add `#include <abstractions/base>` and `/usr/lib/@{multiarch}/** rm,` |
| DNS resolution fails | Missing nameservice abstraction | Add `#include <abstractions/nameservice>` |
| "Permission denied" but no log | `deny` rule without `audit` suppresses logging | Change `deny` to `audit deny` to see it, or add `flags=(audit)` |
| `audit deny` doesn't block in complain mode | On current AppArmor, `audit deny` is downgraded to log-and-allow under `flags=(complain)` -- a long-standing quirk, not the documented design | A plain `deny` (no `audit`) *is* enforced even in complain mode; switch to it, or run the profile in enforce, if you need the denial active while iterating. Use complain only to find missing *allow* rules -- see hardening.md §1/§3 pitfall 5 |
| Profile won't compile | Missing `#include <tunables/global>` or syntax error | Check preamble; run `apparmor_parser -QTK` for syntax validation |
| App works in complain but fails in enforce | Rules discovered in complain not yet added | Run `aa-logprof` to capture and add missing rules |
| Child process denied | Missing or wrong execute transition | Use `Px` for separate profile, `ix` for inherit, `Cx` for child profile |
| Shared library load fails (segfault) | Missing `m` (mmap PROT_EXEC) on .so files | Use `rm` not just `r` for shared libraries |
| App can't bind to port 80/443 | Missing capability | Add `capability net_bind_service,` |
| Deny rule not working | The deny rule's path or permissions don't actually match the operation being performed | At the same priority level, `deny` wins over `allow` regardless of include order. If a deny rule appears not to fire, it usually isn't matching -- check the path glob and the requested permission mask against the actual denial line in `dmesg`. Common causes: bare `/**` instead of `/{,**}` (misses the directory inode -- see hardening.md pitfall 2b), or a symlink that resolves outside `@{HOME}` (hardening.md pitfall 11). If the profile uses AppArmor 4.0 `priority=` qualifiers, a higher-priority allow can legitimately override a deny -- see rules.md §1 |
| Profile edits don't seem to take effect after `apparmor_parser -r` | Parser loaded stale compiled policy from `/var/cache/apparmor/` | Use `apparmor_parser -r --skip-cache <file>` (or `-rK`) during development, or `sudo systemctl reload apparmor`. See hardening.md pitfall 12 |
| `attr/current` says `unconfined` after installing a new profile | Profile attaches at `exec()`; the running process was started before the profile loaded | Verify with a freshly-exec'd process, not the current shell -- see workflow.md §4 |
| Profile loads but app runs unconfined | Profile name doesn't match binary path | Verify with `aa-status`; profile name must be the full absolute path |
| Electron app crashes on launch (Ubuntu 24.04+) with SIGSEGV or "setuid sandbox is not running" | Missing `userns,` rule -- Chromium can't create the namespace sandbox | Add `abi <abi/4.0>,` and a profile with `flags=(unconfined)` + `userns,` for the binary path -- see `references/electron-chromium.md` |
| `bwrap: setting up uid map: Permission denied` (Flatpak, sandbox-runtime) | Same root cause as Electron -- `bwrap` needs `userns,` | On Ubuntu 24.04+ the apparmor package ships `/etc/apparmor.d/bwrap-userns-restrict` (or similar) -- update the apparmor package and reload. On other distros the profile may live in `/usr/share/apparmor/extra-profiles/`; symlink it into `/etc/apparmor.d/`. Or write your own minimal profile with `userns,` for `/usr/bin/bwrap` |
| Electron app launches but tabs/windows crash | Renderer child profile missing `userns,` | The `userns,` rule is per-profile, not inherited -- add it to the child profile too |
| A `flags=(unconfined)` stub profile runs *enforced* after you added a `local/` deny include; app dies with `uid_map`/dconf/Wayland `EACCES` | Parser 4.0.0/4.0.1 bug: any body rule on an unconfined profile silently demotes it to enforce | Confirm the parser has the fix (`dpkg-query -W apparmor`; `--version` alone is insufficient) -- upstream ≥ 4.0.2 / Noble ≥ `4.0.1really4.0.1-0ubuntu0.24.04.3`. On an unpatched parser, don't ship the `local/` deny include. See `references/parser-bugs/4.0.0-4.0.1-unconfined-mediation.md` |
| `Cx` exec rule fails the child exec | Child profile name doesn't match binary basename, or no named target | Use `Cx -> name,` to explicitly name the target child profile; verify the `profile name { ... }` block exists inside the parent |
| `Px` exec rule fails the child exec | The named profile doesn't exist in `/etc/apparmor.d/` | Use `Pix` (with inherit fallback) during development, or write the missing profile |
| Worker processes turn into zombies, parent can't kill them | Missing `signal (send)` rule | Add `signal (send) set=(term kill) peer=child-profile-name,` to the parent |
| AppImage worked yesterday, fails today | AppImage extraction path changed (different `/tmp/.mount_*` hash) | Wildcard the path: `profile myapp /tmp/.mount_*/AppRun { ... }`, or extract once to `/opt/<app>/` |
| Container with `--cap-add SYS_ADMIN` still can't `mount` or write `/proc`/`/sys` | `docker-default` denies the operation regardless of the capability -- MAC overrides the granted cap | Expected and correct. To allow it, supply a custom profile via `--security-opt apparmor=<profile>` that permits the specific op -- not `apparmor=unconfined`. See `references/docker.md` |
| Container behaves differently after `--security-opt apparmor=unconfined` "fixed" it | Disabling the profile removed the MAC layer that was blocking a dangerous op -- a risky config became exploitable | Don't ship `apparmor=unconfined`; write a minimal custom profile that allows only the needed op. See `references/docker.md` §4 |

## Important Notes

- AppArmor is path-based, not inode-based -- renaming a file changes what rules apply to it
- The `owner` conditional restricts rules to files owned by the running UID -- useful for `@{HOME}`
- `ux` (unconfined execution) should be a last resort -- it removes all confinement from the child process
- Local overrides in `/etc/apparmor.d/local/` let you customize vendor profiles without edit conflicts on upgrades
- Test in complain mode first, run the app under real workloads, then use `aa-logprof` before switching to enforce

## References

Upstream and distro documentation — consult these when the reference files don't cover a corner case, or to confirm behavior on a specific version:

- [`apparmor.d(5)`](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html) -- full profile syntax: rule types, flags, globs, variables
- [`apparmor_parser(8)`](https://manpages.ubuntu.com/manpages/noble/man8/apparmor_parser.8.html) -- compile/load flags (`-r`, `-QTK`, `--skip-cache`, `-I`)
- [AppArmor project site](https://apparmor.net/) -- release notes (check which version carries a given fix), wiki, profile documentation
- [Ubuntu Server AppArmor guide](https://documentation.ubuntu.com/server/how-to/security/apparmor/) -- distro-specific tooling (`aa-genprof`, `aa-logprof`, `aa-status`) and the 24.04+ `unprivileged_userns` restriction
- [roddhjav/apparmor.d](https://github.com/roddhjav/apparmor.d) -- the most complete third-party profile set; authoritative for namespace-creating tools (bwrap, podman, runc) and the `attach_disconnected`/`@{att}` patterns (see rules.md §1)
