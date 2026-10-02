# AppArmor Advanced Rule Primitives

Advanced / AppArmor 4.0+ (and 3.x) rule primitives that most everyday profiles never need: user namespaces, io_uring, fine-grained AF_UNIX sockets, xattr-based profile attachment, and message queues. Split out from `rules.md` so a routine profile-writing cycle (§1–§8 there: profile structure, file, glob, network, capability, signal, DBus, mount) does not have to load these. Reach for this file only when the app actually uses one of these mechanisms, or when hardening wants an explicit `deny` on one (e.g. `deny io_uring,`, `deny mqueue,`).

## Contents

1. [User Namespace Rules (4.0+)](#1-user-namespace-rules-apparmor-40) — `userns,`; the Ubuntu 23.10+ `unshare(CLONE_NEWUSER)` restriction
2. [io_uring Rules (4.0+)](#2-io_uring-rules-apparmor-40) — `sqpoll`, `override_creds`; cheap `deny io_uring,` hardening
3. [Fine-Grained Unix Socket Rules (3.x+)](#3-fine-grained-unix-socket-rules-apparmor-3x) — address/peer/operation-level AF_UNIX mediation
4. [Profile Attachment via Extended Attributes (3.x+)](#4-profile-attachment-via-extended-attributes-apparmor-3x) — `xattrs()` attach-by-inode
5. [Message Queue Rules (3.x+)](#5-message-queue-rules-apparmor-3x) — POSIX/SysV `mqueue`

---

## 1. User Namespace Rules (AppArmor 4.0+)

User namespace creation is mediated by the `userns` rule. This is the rule Ubuntu 23.10+ uses to enforce `kernel.apparmor_restrict_unprivileged_userns=1` — unconfined programs can't call `unshare(CLONE_NEWUSER)` unless their profile explicitly allows it.

```apparmor
[audit] [deny] userns [ACCESS],
```

The only access keyword is `create`. Standalone `userns,` grants all current (and any future) userns permissions.

### Examples

```apparmor
userns,                 # Allow creating user namespaces (all permissions)
userns create,          # Explicit "create" permission — equivalent today
deny userns,            # Block userns creation
```

`userns,` is **per-profile and not inherited** across exec transitions. A parent that can create namespaces will still have its child denied unless the child profile also has `userns,` — this is the #1 cause of "Electron tabs crash but the app launches" bugs. See `electron-chromium.md`.

---

## 2. io_uring Rules (AppArmor 4.0+)

`io_uring` rules mediate io_uring submission and credential overrides.

```apparmor
[audit] [deny] io_uring [ACCESS] [label=TARGET],
```

Access keywords:

| Keyword | Meaning |
|---------|---------|
| `sqpoll` | Allow creating io_uring instances with the SQPOLL (kernel poller thread) feature |
| `override_creds` | Allow io_uring operations to run under different credentials (`IORING_REGISTER_PERSONALITY` / `IOSQE_FIXED_FILE`) |

### Examples

```apparmor
io_uring,                                         # All io_uring permissions
io_uring sqpoll,                                  # Allow kernel poller thread
io_uring override_creds label="worker_profile",   # Restrict credential override target
deny io_uring,                                    # Block io_uring entirely
```

Rule of thumb: if the app doesn't use io_uring intentionally, a `deny io_uring,` is cheap defense-in-depth — io_uring has been the source of several 2023–2025 CVEs (escape from seccomp filters, memory corruption).

---

## 3. Fine-Grained Unix Socket Rules (AppArmor 3.x+)

The coarse `network unix,` rule allows *any* AF_UNIX access. For tighter control, use the standalone `unix` rule, which mediates by address, peer label, and operation.

```apparmor
[audit] [deny] unix [ACCESS] [RULE-CONDS] [LOCAL-EXPR] [PEER-EXPR],
```

Access keywords: `create`, `bind`, `listen`, `accept`, `connect`, `shutdown`, `getattr`, `setattr`, `getopt`, `setopt`, `send`, `receive` (aliases: `r`/`w` for receive/send).

Conditions:

| Condition | Example | Meaning |
|-----------|---------|---------|
| `type=` | `type=stream` | Socket type (`stream`, `dgram`, `seqpacket`) |
| `protocol=` | `protocol=0` | Socket protocol |
| `addr=` | `addr="@/my-app/*"` | Abstract or filesystem socket path (abstract sockets use `@` prefix; `addr=none` matches unnamed sockets) |
| `peer=(label=...)` | `peer=(label=unconfined)` | Profile of the peer process |
| `peer=(addr=...)` | `peer=(addr="@other")` | Address the peer is bound to |

### Examples

```apparmor
unix,                                                 # All unix socket access
unix (bind, listen) addr="@/my-app/ipc",              # Listen on abstract socket
unix (connect, send, receive) peer=(label=unconfined),# Talk to unconfined peers
unix (send receive) type=stream addr=none,            # Unnamed socketpair
unix (getattr, shutdown) addr=none,
deny unix bind addr="/var/run/malicious.sock",
```

When both a coarse `network unix,` rule and a fine-grained `unix` rule exist, both must permit the operation. Prefer the fine-grained form in modern profiles.

---

## 4. Profile Attachment via Extended Attributes (AppArmor 3.x+)

Normally a profile attaches by path — `/etc/apparmor.d/usr.bin.foo` confines `/usr/bin/foo`. But if two binaries share a path (e.g. inside containers) or a binary is relocated, path-based attachment breaks. The `xattrs()` condition attaches by inode xattr instead.

```apparmor
profile NAME PATH xattrs=(xattr_name="value" ...) { ... }
```

### Example

```apparmor
profile trusted_helper /usr/local/bin/* xattrs=(security.apparmor="trusted") {
  #include <abstractions/base>
  /usr/local/bin/* mr,
  # ...
}
```

The profile attaches only to binaries under `/usr/local/bin/` that have the xattr `security.apparmor="trusted"`. Set the xattr with:

```bash
sudo setfattr -n security.apparmor -v trusted /usr/local/bin/my-helper
```

Use cases: signing a binary for elevated confinement, distinguishing distro-shipped vs sideloaded copies of the same binary name, container orchestration where the same path has different trust levels. Requires a recent kernel + parser (AppArmor 3.0+). Not available on very old LTS kernels.

---

## 5. Message Queue Rules (AppArmor 3.x+)

POSIX and SysV message queues are mediated by the `mqueue` rule.

```apparmor
[audit] [deny] mqueue [ACCESS] [type=TYPE] [label=LABEL] [NAME],
```

Access keywords: `create`, `open`, `delete`, `read`, `write`, `getattr`, `setattr`.

Types: `posix` (POSIX `mq_open`), `sysv` (SysV `msgget`).

### Examples

```apparmor
mqueue,                                         # All message queue access
mqueue (open, read, write) type=posix /myqueue,
mqueue (create, delete) type=sysv,
deny mqueue,                                    # Block all MQ access
```

Most applications don't use message queues; `deny mqueue,` is a safe default for hardened profiles unless the app explicitly needs them.
