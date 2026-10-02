# AppArmor Rule Syntax Reference

Syntax reference for the everyday AppArmor rule types: profile structure, file permissions, glob patterns, network, capability, signal, DBus, and mount rules. Advanced/4.0+ primitives (userns, io_uring, fine-grained AF_UNIX, xattr attachment, message queues) live in `rules-advanced.md` — see the pointer at the end.

## Contents

1. [Profile Structure](#1-profile-structure) — preamble, header, flags, `priority=`, `flags=(unconfined)`, `attach_disconnected`/`@{att}`
2. [File Permissions](#2-file-permissions) — access modes, exec transitions (`ix`/`Px`/`Cx`/…), fallbacks, the `owner` conditional, the `link ->` rule for hard links
3. [Glob Patterns (AARE)](#3-glob-patterns-aare) — `*` vs `**`, the `/usr/lib/*/*` flat-helper trap, quoted-path brace limits
4. [Network Rules](#4-network-rules) — domains/types/protocols; the "never blanket-`deny network,` in a GUI profile" trap
5. [Capability Rules](#5-capability-rules) — capability list, modern `bpf`/`perfmon`/`checkpoint_restore` split-outs
6. [Signal Rules](#6-signal-rules) — `send`/`receive`, signal sets, peers
7. [DBus Rules](#7-dbus-rules) — bus/path/interface/member/peer conditionals
8. [Mount Rules](#8-mount-rules) — `mount`/`remount`/`umount`/`pivot_root`, fstype/options conditions
9. **[Advanced / 4.0+ primitives](#advanced--40-rule-primitives)** → pointer to `rules-advanced.md` (userns, io_uring, unix, xattr, mqueue)

---

## 1. Profile Structure

An AppArmor profile is a plain-text file stored in `/etc/apparmor.d/`. It has a **preamble** (includes, variables, ABI tag) and a **body** (rules enclosed in braces).

### Minimal skeleton

```
# abi 4.0 is required for newer rules (userns, profile stacking, io_uring).
# Use abi 3.0 only if you need to support kernels older than ~5.16.
abi <abi/4.0>,

#include <tunables/global>

profile myapp /usr/bin/myapp flags=(enforce) {
  #include <abstractions/base>

  # --- capabilities ---
  capability net_bind_service,

  # --- network ---
  network inet tcp,

  # --- file rules ---
  /etc/myapp.conf           r,
  /var/lib/myapp/{,**}      rw,
  /usr/lib/@{multiarch}/**  rm,

  # --- execute transitions ---
  /usr/bin/helper            Px,
}
```

### Preamble elements

| Element | Purpose | Example |
|---------|---------|---------|
| `abi` | Declares policy ABI version | `abi <abi/4.0>,` |
| `#include` | Pulls in shared rule sets | `#include <tunables/global>` |
| `@{VAR}` | Defines or appends variables | `@{LOG} = /var/log/myapp` |
| `alias` | Path rewriting | `alias /old/ -> /new/,` |

### Profile header

```
[profile] NAME [ATTACHMENT] [FLAGS] {
  RULES
}
```

- **NAME**: Either the binary path (`/usr/bin/myapp`) or a custom identifier when using the `profile` keyword.
- **ATTACHMENT**: Optional path or `xattrs()` conditional for binding the profile to executables.
- **FLAGS**: Comma-separated inside `flags=(...)`.

### Profile flags

| Flag | Effect |
|------|--------|
| `enforce` | Block and log violations (default) |
| `complain` | Log violations but allow them |
| `kill` | Kill the process on violation |
| `unconfined` | Label-only mode — the profile body is **not enforced** (see "What `flags=(unconfined)` actually does" below) |
| `audit` | Log all rule matches, not just denials |
| `mediate_deleted` | Mediate access to deleted files |
| `attach_disconnected` | Re-attach namespace-detached paths so the rule engine can address them (see "Confining namespace-creating tools" below) |
| `chroot_relative` | Resolve paths relative to chroot |

### Rule priority (AppArmor 4.0+)

AppArmor 4.0 adds a numeric `priority=N` qualifier on individual rules (range -1000 to 1000, default 0). Higher-priority rules completely override lower-priority rules where they overlap, **regardless** of the normal `deny > allow` precedence. This is the mechanism for building layered abstractions where a caller can opt out of a bundled deny.

```apparmor
priority=10 audit deny @{HOME}/.ssh/{,**} rwmlk,    # shared abstraction
priority=20 owner @{HOME}/.ssh/{,**} r,              # ssh-agent opts back in
```

The allow wins here because `20 > 10`. Without priorities, the deny would always win and no consumer could re-enable access. Requires `abi <abi/4.0>,` and AppArmor 4.0+ kernel/parser. Use sparingly — most conflicts are better resolved by restructuring rules (see hardening.md §3 pitfall 4).

### What `flags=(unconfined)` actually does — it is label-only

A profile with `flags=(unconfined)` does **not enforce the rules in its body**. The man page describes it as making "a task confined by the profile behave as though it is unconfined," via special kernel handling. In practice this means rules you write inside an unconfined profile are effectively documentation, not enforcement:

- A `Px` / `Pix` exec-transition rule in an unconfined body does **not** force the transition — exec'd children inherit the unconfined label.
- A `deny` rule in an unconfined body does **not** block — neither plain `deny` nor `audit deny` next to `flags=(unconfined)` stops e.g. SSH-key reads. (This is a different mechanism from the complain-mode `audit deny` quirk in hardening.md §1: there the profile *does* mediate and plain `deny` still fires; here the profile mediates nothing at all.)

The one rule that *does* take effect is `userns,` — which is exactly why every stock userns-creating profile (`/etc/apparmor.d/flatpak`, the Chromium/Firefox profiles, `unprivileged_userns`) is simply `flags=(unconfined)` + `userns,` and nothing else functional. (AppArmor 4.0 also exposes `flags=(default_allow)` for the same shim purpose; Ubuntu's docs use it interchangeably.)

**Architectural consequence:** you cannot build a "trampoline with denies" out of an unconfined profile — granting userns freedom via `unconfined` simultaneously discards all rule mediation. If a profile must allow `userns,` *and* enforce policy, the policy has to live in a different profile that the userspace tool transitions into, or rely on the tool's own sandbox primitives (bwrap `--ro-bind`, seccomp, landlock). Verify which label is actually in effect with `cat /proc/self/attr/current` under `aa-exec --profile=<name>` — if a known-denied path is readable, no confinement is happening (see workflow.md §4).

> **Version trap:** on `apparmor_parser` 4.0.0/4.0.1, adding *any* body rule to a `flags=(unconfined)` profile (including via `include if exists <local/...>`) silently demotes it to `enforce`. Before shipping a `local/` deny include for an unconfined stub profile, see `parser-bugs/4.0.0-4.0.1-unconfined-mediation.md`.

### Confining namespace-creating tools: `attach_disconnected` and `@{att}`

When a confined process creates a new mount namespace (bwrap, podman, runc, crun, unshare wrappers) and accesses files inside it, the kernel may resolve those paths in a context "disconnected" from the host filesystem root the profile rules were written against — so the normal rules don't match.

- **`flags=(attach_disconnected)`** tells the kernel to re-attach such detached paths so the rule engine can address them. By default (bare flag) they are re-attached at the **root of the namespace** (i.e. a `/` prefix). The man page warns this mode is a debugging/policy-development tool — it can mask aliasing — so use it deliberately, only for tools that genuinely create namespaces.
- **`attach_disconnected.path=/some/prefix`** (AppArmor 4.0+) sets a custom re-attachment prefix instead of `/`.
- **`@{att}`** is **not an upstream AppArmor tunable** — it is a convention from the [roddhjav/apparmor.d](https://github.com/roddhjav/apparmor.d) project, which auto-sets `attach_disconnected.path=@{att}` with `@{att}=/att/<profile_name>` for profiles carrying the flag (and `@{att}=""` otherwise). If you are not pulling in apparmor.d's tunables, you must define `@{att}` yourself (`@{att}=""` as a no-op placeholder so rules with the prefix parse) — the actual prefix is supplied by the kernel's runtime re-attachment, not the variable.

To confine such a tool you generally need the flag **plus** parallel `@{att}`-prefixed rules for namespace-internal paths. bwrap writes its own uid/gid maps from inside the freshly-cloned namespace, addressed by the **real numeric pid path** (not `/proc/self/`):

```
owner @{PROC}/@{pid}/uid_map           rw,    # host view
owner @{att}@{PROC}/@{pid}/uid_map     rw,    # namespace-internal view
owner @{att}@{PROC}/@{pid}/gid_map     rw,
owner @{att}@{PROC}/@{pid}/setgroups   rw,
```

The authoritative reference for the full rule shape (including mount/`pivot_root` coverage) is `apparmor.d/abstractions/bwrap` in roddhjav/apparmor.d — these primitives are not spelled out in the upstream man page, so a from-scratch profile that omits the `@{att}` half typically fails at namespace creation with no obvious clue. See child-processes.md for the multi-process exec-transition context this fits into.

---

## 2. File Permissions

File rules grant or deny specific access modes on path patterns.

```
[audit] [deny] [owner] PATH MODE,
```

### Access modes

| Mode | Meaning | Notes |
|------|---------|-------|
| `r` | Read | |
| `w` | Write | Conflicts with `a` |
| `a` | Append | Conflicts with `w`; write-only at EOF |
| `m` | Memory-map with `PROT_EXEC` | Required for shared libraries |
| `k` | File locking (`flock`, `fcntl`) | |
| `l` | Hard link creation | Requires both `l` on the link name and the target's permissions — **and** an explicit `link` rule (below) |

### Execute transition modes

| Mode | Behavior | Environment |
|------|----------|-------------|
| `ix` | Inherit parent profile | Not scrubbed (same privilege) |
| `px` | Transition to named profile | **Not** scrubbed -- caller may influence callee via `LD_PRELOAD` |
| `Px` | Transition to named profile | **Scrubbed** (safe) |
| `cx` | Transition to local/child subprofile | **Not** scrubbed |
| `Cx` | Transition to local/child subprofile | **Scrubbed** (safe) |
| `ux` | Run unconfined (no profile) | **Not** scrubbed -- dangerous |
| `Ux` | Run unconfined (no profile) | **Scrubbed** |

### Fallback execute modes

When the target profile does not exist, fall back to `ix` (inherit) or `ux` (unconfined) instead of denying.

| Mode | Primary | Fallback | Scrubbed |
|------|---------|----------|----------|
| `pix` | `px` | `ix` | No |
| `Pix` | `Px` | `ix` | Yes |
| `cix` | `cx` | `ix` | No |
| `Cix` | `Cx` | `ix` | Yes |
| `pux` | `px` | `ux` | No |
| `PUx` | `Px` | `Ux` | Yes |
| `cux` | `cx` | `ux` | No |
| `CUx` | `Cx` | `Ux` | Yes |

### Named profile transitions

Direct an exec to a specific profile name with `->`:

```
/usr/bin/helper Px -> sandbox_profile,
```

### Owner conditional

Restrict the rule to files whose owner matches the process **fsuid**:

```
owner /home/*/.ssh/** r,
```

**Don't reach for `owner` by default — it is a narrowing qualifier that costs more than it protects.**

- **It breaks legitimate cross-uid reads.** A user picks files in their file manager and hands them to a converter/viewer/archiver; those files may be owned by another uid (removable media formatted elsewhere, an NFS/SMB share, root-owned scans, a colleague's export on a shared mount). DAC already permitted the read; `owner` then denies it anyway, silently. So for **user-selected content and shared locations** (`@{HOME}/**` documents, `/mnt`, `/media`, `/run/media`, `/srv`), leave `owner` off.
- **`owner` + `deny` is a bug.** `deny owner @{HOME}/x` blocks only when the caller owns the file — a copy owned by someone else slips past. A security deny must be unconditional: `deny @{HOME}/x`.
- **It muddies diagnosis under `sudo aa-exec`.** That runs as euid 0, so every `owner @{HOME}` rule stops matching and the profile looks broken when it isn't (see workflow.md — validate `owner`-gated access from the real caller at the real uid, not root).

**Where `owner` does belong:** genuinely per-process / per-user private state where a cross-uid match would itself be the anomaly — `owner @{PROC}/@{pid}/**`, `owner /run/user/[0-9]*/**`, `owner @{HOME}/.config/**` / `.cache/**` / `.Xauthority`. Add it only when you can name the cross-uid access it stops, and never silently — leave a comment saying which read it blocks, or a later session will trip over it during `aa-exec` testing.

### Hard links need an explicit `link` rule — the `l` mode alone is not enough

Creating a hard link is mediated as its own operation, with a dedicated rule form:

```
[audit] [deny] link [subset] PATH -> TARGET,
```

Two things must both be present for `link(oldpath, newpath)` (or `linkat`) to succeed under a profile:

1. The `l` **mode** on the relevant file rules — on the **new** link name, and read/write as appropriate on the target. `l` in a plain file rule authorizes *link* as an access mode.
2. An explicit **`link` rule** naming source and target: `link /path/new -> /path/target,`. Without it, the create is denied even when both paths carry `l`.

The `subset` keyword restricts the new link so it cannot grant more access than the target already has (the safe default for most link rules).

This bites whenever a program creates a file by linking a temporary name onto the final path rather than writing it directly — atomic-save editors (`write tmp; link/rename onto target`), lockfile creators, and Unix-socket mux servers (`muxserver_listen()` does `link(tmpname, socketpath)`). The temp name usually has a random suffix, so it needs a glob, and it is mediated **separately** from the visible target:

```apparmor
owner @{HOME}/.ssh/sockets/**   rwkl,               # k: ssh flocks the socket; l: link mode
link  @{HOME}/.ssh/sockets/** -> @{HOME}/.ssh/sockets/**,
```

Symptom of the missing `link` rule: the operation fails even though `rw`/`k` on the path look correct, and (if the path is reached via a symlink onto a mount) the rule may also be matching the wrong resolved string — see §3 and hardening.md pitfall 11.

### Examples

```
/etc/app.conf                   r,
/var/lib/app/{,**}              rw,
/var/log/app/*.log              a,
/usr/lib/@{multiarch}/**        rm,
/tmp/app.lock                   k,
/usr/bin/helper                 Px,
/usr/bin/tool                   Cix -> tool_child,
owner @{HOME}/.config/app/**    rw,
```

---

## 3. Glob Patterns (AARE)

AppArmor uses AppArmor Regular Expressions (AARE), which are similar to shell globs but with important differences.

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `*` | Zero or more characters **except** `/` | Path separators |
| `**` | Zero or more characters **including** `/` | -- |
| `?` | Exactly one character **except** `/` | Path separators |
| `[abc]` | One of `a`, `b`, or `c` | |
| `[a-f]` | One character in range `a`-`f` | |
| `[^a-f]` | One character NOT in range | |
| `{foo,bar}` | Alternation -- expands to separate rules | |

### Critical distinctions

- `/dir/*` matches files directly in `/dir/`, not subdirectories.
- `/dir/**` matches everything under `/dir/` recursively (files and dirs).
- `/dir/` with a trailing slash matches the directory itself.
- `/dir/*/` matches only immediate subdirectories.

### Examples

```
/etc/app/*.conf          r,     # /etc/app/main.conf -- not /etc/app/sub/other.conf
/var/lib/app/**          rw,    # Everything under /var/lib/app recursively
/home/*/.bashrc          r,     # Any user's .bashrc (one level)
/usr/lib/app/plugin?.so  r,     # plugin1.so, pluginA.so
/opt/{foo,bar}/bin/*     rix,   # /opt/foo/bin/* OR /opt/bar/bin/*
/tmp/app.[0-9]*          rw,    # /tmp/app.0xxx, /tmp/app.9xxx
```

### Common mistakes

- Using `*` when `**` is needed (misses nested files).
- Forgetting the trailing `,` on rules.
- Using `**` too broadly (matches far more than intended).

### `*` does not cross `/` — Debian flat helper dirs are a common casualty

Because a single `*` matches anything *except* `/`, a glob like `/usr/lib/*/bin/*` requires a literal `bin` directory component: it matches `/usr/lib/<multiarch>/bin/<x>` (e.g. `/usr/lib/x86_64-linux-gnu/bin/...`) but **not** `/usr/lib/git-core/git-maintenance`. Debian/Ubuntu scatter executable helpers in *flat* per-package directories directly under `/usr/lib/<pkg>/` — `git-core` holds ~150 helper binaries (`git-maintenance`, `git-remote-https`, …), `openssh` holds `ssh-keysign`, `ssh-pkcs11-helper`, etc., none under a `bin/` subdir.

This produces a subtle exec denial. `git` itself runs fine (invoked as `/usr/bin/git`, covered by `/usr/bin/* ixr,`), but after a commit `git` re-execs itself as `/usr/lib/git-core/git-maintenance` for housekeeping. With only `/usr/lib/*/bin/* ixr,` that exec is denied (exit 126: "found but not executable") — and because git's own exit code is 0, the failure is easy to miss.

```
# Multiarch bin dirs only — misses flat helper dirs
/usr/lib/*/bin/*  ixr,

# Add a one-glob-level rule for Debian's flat <pkg>/<helper> layout
/usr/lib/*/*      ixr,    # catches git-core/*, openssh/*, etc.
```

`/usr/lib/*/*` is one glob level (`<pkg>/<helper>`), so it catches the flat helper dirs without matching deeply-nested `.so` trees. `ixr` on a path that turns out to be a non-executable `.so` is harmless — the `x` permission is only consulted at `execve()`, which never happens for a library. If you want tighter scope, name the dirs explicitly (`/usr/lib/git-core/* ixr,`). Audit the real layout with `find /usr/lib -maxdepth 2 -type f -executable` before trusting any `/usr/lib` exec glob. Remember exec rules don't inherit across `Cx`/`Px` children — the same rule must appear in every profile body that execs these helpers (see child-processes.md).

### Quoted paths cannot be concatenated with `{,**}` brace globs

When a path contains a space it must be quoted as a whole:

```
audit deny "@{HOME}/.config/Bitwarden CLI/" rwmlk,
```

You **cannot** append a brace expansion after the closing quote. The parser lexes the quoted string as one complete token, so the next `{` is read as a fresh open-brace where it expects the access mode — producing `syntax error, unexpected TOK_OPEN, expecting TOK_MODE`:

```
# BROKEN — brace expansion after a closing quote does not parse
audit deny "@{HOME}/.config/Bitwarden CLI/"{,**} rwmlk,
```

(In an *unquoted* path the braces are part of the path token and expand normally; closing the quote is what exposes the brace as a standalone token.) Workaround: emit the dir-inode rule and the contents-glob rule as two separate quoted rules:

```
audit deny "@{HOME}/.config/Bitwarden CLI/"   rwmlk,
audit deny "@{HOME}/.config/Bitwarden CLI/**" rwmlk,
```

Both are needed for the standard `/{,**}` defence-in-depth pattern (see hardening.md §3 pitfall 2b) — one blocks the directory inode so `ls`/`getdents` fail, the other blocks descendants.

---

## 4. Network Rules

Network rules control socket creation and communication.

```
[audit] [deny] network [DOMAIN] [TYPE] [PROTOCOL],
```

### Domain families

`inet`, `inet6`, `unix`, `netlink`, `packet`, `bluetooth`, `can`, `bridge`, `ax25`, `ipx`, `appletalk`, `vsock`, and others from `socket(2)`.

### Socket types

`stream`, `dgram`, `seqpacket`, `raw`, `rdm`, `packet`.

### Protocols

`tcp`, `udp`, `icmp`.

### Fine-grained access modes (AF_UNIX, newer kernels)

`create`, `bind`, `listen`, `accept`, `connect`, `shutdown`, `getattr`, `setattr`, `getopt`, `setopt`, `send`, `receive`.

### Examples

```
network,                          # All networking (very broad)
network inet tcp,                 # IPv4 TCP only
network inet6 tcp,                # IPv6 TCP only
network inet dgram,               # IPv4 UDP
network netlink raw,              # Netlink raw sockets
network unix stream,              # Unix stream sockets
deny network raw,                 # Block raw sockets
```

### Never blanket-`deny network,` in a GUI profile — it kills the display

GUI toolkits reach the display server and session bus over **AF_UNIX** (`/run/user/<uid>/wayland-0`, the X socket, the dbus socket). A blanket `deny network,` can sweep AF_UNIX in with it: on kernels without fine-grained af_unix mediation, `unix` rules downgrade to `network unix` and the deny catches them. Since `deny` beats `allow` at equal priority, it overrides the AF_UNIX access that `abstractions/base` + `wayland`/`X` + the dbus abstraction granted — the app then fails with `Failed to create wl_display (Permission denied)` / `could not connect to display` and, tellingly, **zero file denials** (a network-family implicit deny logs as `operation="create"`, not `"open"`).

Whether a bare `deny network,` actually clobbers AF_UNIX is kernel-dependent, but the guidance holds regardless: **allow AF_UNIX explicitly and deny only the real families.**

```
network unix,
deny network inet,
deny network inet6,
deny network raw,
deny network packet,
deny network netlink,
```

A non-GUI CLI worker has no display socket, so a plain `deny network,` is fine there — the trap is specifically GUI + blanket network-deny.

---

## 5. Capability Rules

Capability rules mediate POSIX.1e / Linux capabilities.

```
[audit] [deny] capability [CAP_NAME ...],
```

The `CAP_` prefix is **omitted** in the rule. Use the bare keyword `capability` with no name to grant all capabilities (dangerous).

### Commonly used capabilities

| Capability | Purpose |
|------------|---------|
| `chown` | Change file ownership |
| `dac_override` | Bypass file read/write/execute permission checks |
| `dac_read_search` | Bypass file read and directory search |
| `fowner` | Bypass permission checks on operations requiring file owner |
| `fsetid` | Don't clear setuid/setgid on modify |
| `kill` | Send signals to arbitrary processes |
| `net_bind_service` | Bind to privileged ports (< 1024) |
| `net_raw` | Use raw and packet sockets |
| `setuid` | Manipulate process UIDs |
| `setgid` | Manipulate process GIDs |
| `sys_admin` | Broad sysadmin operations (mount, sethostname, etc.) |
| `sys_chroot` | Use `chroot()` |
| `sys_ptrace` | Trace arbitrary processes |
| `sys_resource` | Override resource limits |
| `net_admin` | Network configuration |
| `bpf` | Load/manage BPF programs and maps (kernel 5.8+; split out from `sys_admin`) |
| `perfmon` | Perf events and hardware perf counters (kernel 5.8+; split out from `sys_admin`) |
| `checkpoint_restore` | CRIU-style checkpoint/restore and setting `/proc/self/exe` (kernel 5.9+) |

**Modern kernel note**: `bpf`, `perfmon`, and `checkpoint_restore` were carved out of the overloaded `sys_admin` in kernels 5.8–5.9. Grant these narrower caps instead of `sys_admin` where possible. Older `apparmor_parser` (before 3.0) built its capability list from kernel headers and would reject unknown names — modern parsers have a static list and accept all three.

### Examples

```
capability net_bind_service,
capability setuid setgid,                    # Multiple in one rule
capability chown dac_override fowner,
deny capability sys_admin,                   # Explicitly block
```

---

## 6. Signal Rules

Signal rules mediate `kill(2)`, `sigqueue(3)`, and related calls. Both the sender and receiver profiles must have matching permissions.

```
[audit] [deny] signal [ACCESS] [set=SIGNALS] [peer=PROFILE],
```

### Access modes

| Mode | Meaning |
|------|---------|
| `send` | Send a signal |
| `receive` | Receive a signal |
| `(send receive)` | Both directions |
| (omitted) | All signal permissions implied |

### Signal set

Use `set=(sig1 sig2 ...)` to restrict to specific signals. Named signals (without `SIG` prefix, lowercase): `hup`, `int`, `quit`, `ill`, `trap`, `abrt`, `bus`, `fpe`, `kill`, `usr1`, `segv`, `usr2`, `pipe`, `alrm`, `term`, `stkflt`, `chld`, `cont`, `stop`, `tstp`, `ttin`, `ttou`, `urg`, `xcpu`, `xfsz`, `vtalrm`, `prof`, `winch`, `io`, `pwr`, `sys`, `exists`.

Real-time signals: `rtmin+0` through `rtmin+31` (Linux provides 32 RT signals indexed 0..31).

### Examples

```
signal,                                       # All signals, all peers
signal (send) set=(term hup) peer=unconfined,
signal (receive) peer=/usr/bin/controller,
signal (send receive) set=(usr1 usr2),
deny signal (send) set=(kill stop),           # Block kill/stop
signal peer=@{profile_name},                  # Self-signaling
```

---

## 7. DBus Rules

DBus rules mediate communication over the D-Bus message bus.

```
[audit] [deny] dbus [ACCESS] [bus=BUS] [path=PATH] [interface=IFACE]
       [member=MEMBER] [peer=(name=NAME label=LABEL)],
```

### Access modes

| Mode | Applies to |
|------|------------|
| `send` | Sending messages |
| `receive` | Receiving messages |
| `bind` | Acquiring a bus name |
| `eavesdrop` | Monitoring messages on the bus |
| (omitted) | All DBus permissions implied |

### Conditionals

| Parameter | Values | Notes |
|-----------|--------|-------|
| `bus=` | `system`, `session`, `accessibility` | Which bus |
| `path=` | DBus object path | e.g. `/org/freedesktop/NetworkManager` |
| `interface=` | DBus interface name | e.g. `org.freedesktop.DBus.Properties` |
| `member=` | Method or signal name | e.g. `Get`, `Set`, `Notify` |
| `peer=(name= label=)` | Peer bus name and/or profile label | Can use AARE patterns |

### Examples

```
dbus,                                          # All DBus access (very broad)
dbus bus=system,                               # All on system bus
dbus (send) bus=system peer=(name=org.freedesktop.DBus),

dbus (send)
     bus=session
     path=/com/example/Object
     interface=com.example.Interface
     member=DoSomething
     peer=(name=com.example.Service label=example_service),

dbus (receive)
     bus=system
     interface=org.freedesktop.DBus.Properties
     member={Get,GetAll,Set}
     peer=(label=unconfined),

dbus bind
     bus=session
     name=com.myapp.Service,

deny dbus bus=session,                         # Block all session bus
```

---

## 8. Mount Rules

Mount rules control `mount(2)`, `umount(2)`, `remount`, and `pivot_root(2)`.

```
[audit] [deny] mount [CONDITIONS] [SOURCE] [-> MOUNTPOINT],
[audit] [deny] remount [CONDITIONS] MOUNTPOINT,
[audit] [deny] umount [CONDITIONS] MOUNTPOINT,
[audit] [deny] pivot_root [oldroot=OLDROOT] [NEWROOT] [-> PROFILE],
```

### Conditions

| Condition | Syntax | Meaning |
|-----------|--------|---------|
| `fstype=` | `fstype=ext4` | Match filesystem type exactly |
| `fstype in` | `fstype in (ext3, ext4, xfs)` | Match any of listed types |
| `options=` | `options=(ro, nosuid)` | Require exact option set |
| `options in` | `options in (ro, nosuid, nodev)` | Match any combination of listed options |

### Common mount flags

`ro`, `rw`, `nosuid`, `suid`, `nodev`, `dev`, `noexec`, `exec`, `sync`, `async`, `remount`, `bind`, `rbind`, `move`, `noatime`, `relatime`.

### Examples

```
mount,                                               # All mounts (dangerous)
mount /dev/sdb1,                                     # Mount specific device
mount options=(ro,nosuid) /dev/sdb1 -> /mnt/usb/,
mount fstype=ext4 options=(rw,nodev) /dev/sda2 -> /data/,
mount fstype=tmpfs -> /tmp/,
mount options in (bind,rbind) /data/ -> /container/,
remount options=(ro,nosuid) /mnt/,
umount /mnt/usb/,
pivot_root oldroot=/mnt/old/ /mnt/newroot/,
deny mount fstype=debugfs,                           # Block debugfs
deny mount options=(suid,dev),                       # Block suid/dev mounts
```

---

## Advanced / 4.0+ rule primitives

The rules above (§1–§8) cover everything an everyday profile needs. AppArmor also mediates a set of advanced primitives that most profiles never touch — **user namespaces** (`userns`), **io_uring**, **fine-grained AF_UNIX sockets** (the standalone `unix` rule), **profile attachment by xattr**, and **message queues** (`mqueue`). These live in a separate file so a routine profile-writing cycle doesn't have to load them:

➡ **See `rules-advanced.md`** when the app actually uses one of these, or when hardening wants an explicit `deny` on one (`deny userns,`, `deny io_uring,`, `deny mqueue,`). Note in particular the `userns,` rule — it is the Ubuntu 23.10+ mechanism behind every "Electron app won't launch on 24.04" bug (`electron-chromium.md`).
