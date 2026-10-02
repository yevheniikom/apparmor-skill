# AppArmor Abstractions, Tunables, and Profile Transitions

Reusable rule bundles, variables, and how child processes inherit or switch confinement.

---

## 1. Abstractions

Abstractions are reusable rule bundles stored in `/etc/apparmor.d/abstractions/`. Include them with:

```
#include <abstractions/name>
```

### Essential abstractions

| Abstraction | Purpose |
|-------------|---------|
| `base` | Core system files that virtually all programs need: `/etc/ld.so.cache`, `/etc/locale/`, `/usr/share/locale/`, `/proc/sys/kernel/`, basic `/dev/` entries. Include this in every profile. |
| `nameservice` | DNS, LDAP, NIS, SMB lookups. Access to `/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/gai.conf`, `/run/nscd/`, NSS libraries. Required for any program that does name resolution. |
| `authentication` | PAM, shadow password files, login-related access. Access to `/etc/pam.d/`, `/etc/security/`, `/etc/login.defs`, `/etc/shadow` (r). Required for services that authenticate users. |
| `user-tmp` | Read/write access to user temp directories: `/tmp/`, `/var/tmp/`, `@{HOME}/tmp/`. |
| `private-files` | Denies **owner** access to shell-history/dotfiles/autostart paths. Use in profiles for apps that run as the user and legitimately need broad `@{HOME}` access (file managers, text editors) but shouldn't read history or modify autostart. Uses `/{,**}` brace form throughout. |
| `private-files-strict` | Like `private-files` but denies access **regardless of owner** (both the confined user's own files AND other users' files). Use for untrusted apps that should never see private data. |

### Desktop/GUI abstractions

| Abstraction | Purpose |
|-------------|---------|
| `gnome` | GNOME desktop access (dconf, glib, GTK) |
| `kde` | KDE desktop access (kconfig, kdeglobals) |
| `X` | X11 server access (`/tmp/.X11-unix/`, `.Xauthority`) |
| `wayland` | Wayland compositor access |
| `freedesktop.org` | XDG base directories, MIME types, icons |
| `fonts` | System and user font directories |
| `dbus` / `dbus-strict` | **System** bus — the socket is a filesystem path (`@{run}/dbus/system_bus_socket`); `-strict` is the tighter variant |
| `dbus-session` / `dbus-session-strict` | **Session** bus — the socket is an abstract-namespace AF_UNIX address (`unix ... addr="@/tmp/dbus-*"`); `-strict` is the tighter variant |

**DBus is its own rule class, and `abstractions/base` does not grant it.** base provides fine-grained `unix` IPC rules but carries no `dbus` rule and no bus-socket path — so a profile that includes only base gets neither the bus socket nor the ability to make calls. Two separate things are needed to talk to a bus:

1. The **socket** — include the matching transport abstraction: `abstractions/dbus` (or `dbus-strict`) for the system bus, `dbus-session` (or `dbus-session-strict`) for the session bus (or write the socket rule yourself).
2. The **method calls** — mediated separately again. Neither `network,` nor a broad `/** rw` nor the socket grant covers them; you still need a `dbus` rule (broad `dbus,` or scoped `dbus send bus=system ...`).

**Signature of a missing `dbus` rule:** the app crashes at init with *no file denial* — e.g. it does a `Hello` handshake on the bus at startup, is denied, and aborts. Because DBus is enforced in userspace by `dbus-daemon`, the denial is a `USER_AVC` that **never reaches `dmesg`** — find it with `sudo ausearch -m USER_AVC -ts recent` (see hardening.md §4).

### Application abstractions

| Abstraction | Purpose |
|-------------|---------|
| `ssl_certs` | Read access to TLS/SSL certificate stores |
| `ssl_keys` | Access to TLS/SSL private keys |
| `python` | Python interpreter and standard library |
| `perl` | Perl interpreter and modules |
| `bash` | Bash shell and startup files |
| `consoles` | Access to console/tty devices |
| `cups-client` | CUPS printing client libraries |
| `nis` | NIS (Yellow Pages) client access |
| `samba` | Samba/CIFS client access |
| `mdns` | mDNS/Avahi name resolution |
| `php` | PHP interpreter and modules |
| `postfix-common` | Postfix MTA shared rules |
| `mysql` | MySQL client library access |

### Audio/video abstractions

| Abstraction | Purpose |
|-------------|---------|
| `audio` | Audio device and PulseAudio/PipeWire access |
| `video` | Video capture device access |
| `graphics` | GPU access (DRI, Mesa, NVIDIA) |
| `vulkan` | Vulkan graphics API access |

### Best practices

- Always include `abstractions/base` -- it is needed by virtually every program.
- Add `abstractions/nameservice` for anything doing DNS resolution or user lookups.
- Use `abstractions/private-files-strict` in profiles for untrusted applications.
- Prefer specific abstractions over hand-written rules for standard subsystems.

---

## 2. Tunables

Tunables are variable definitions stored in `/etc/apparmor.d/tunables/`. They are loaded by `#include <tunables/global>` at the top of every profile.

### Built-in variables

| Variable | Default Value | Purpose |
|----------|---------------|---------|
| `@{HOME}` | `/home/*/` | User home directories |
| `@{HOMEDIRS}` | `/home/` | Parent directory of homes |
| `@{PROC}` | `/proc/` | Procfs mount |
| `@{sys}` | `/sys/` | Sysfs mount |
| `@{run}` | `/run/` | Runtime data directory |
| `@{pid}` | `[1-9]*` | Process ID pattern |
| `@{pids}` | `[1-9]*` | Process IDs pattern (alias) |
| `@{tid}` | `[1-9]*` | Thread ID pattern |
| `@{multiarch}` | `*-linux-gnu*` | Multiarch lib triplet |
| `@{securityfs}` | `/sys/kernel/security/` | Security filesystem |
| `@{apparmorfs}` | `@{securityfs}/apparmor/` | AppArmor filesystem |
| `@{profile_name}` | (runtime) | Current profile name |

### XDG user directory variables

`@{XDG_DESKTOP_DIR}`, `@{XDG_DOWNLOAD_DIR}`, `@{XDG_TEMPLATES_DIR}`, `@{XDG_PUBLICSHARE_DIR}`, `@{XDG_DOCUMENTS_DIR}`, `@{XDG_MUSIC_DIR}`, `@{XDG_PICTURES_DIR}`, `@{XDG_VIDEOS_DIR}`.

### Defining custom variables

```
@{APP_DATA} = /var/lib/myapp /srv/myapp
@{APP_LOG}  = /var/log/myapp

profile myapp /usr/bin/myapp {
  @{APP_DATA}/{,**} rw,
  @{APP_LOG}/*.log  a,
}
```

### Appending to variables

```
@{HOME} += /custom/home/*/
```

### Variable files

| File | Contents |
|------|----------|
| `tunables/global` | Master include -- pulls in all other tunables |
| `tunables/home` | `@{HOME}` and `@{HOMEDIRS}` definitions |
| `tunables/proc` | `@{PROC}` definition |
| `tunables/multiarch.d/` | Multiarch triplet patterns |

---

## 3. Runtime Domain Transitions: change_hat and change_profile

This section covers **API-driven** transitions: the process itself calls a libapparmor function to switch domains. For **exec-time** transitions (`ix`/`Px`/`Cx`/`ux` when running a child binary), see `child-processes.md` — that file also has the authoritative worked examples for named child profiles embedded in a parent.

### Hat subprofiles (`^hat_name`) — `change_hat`

Hats are lightweight child profiles accessed at runtime via the `aa_change_hat()` libapparmor call. Typical use: a web server (Apache `mod_apparmor`) switches into a per-vhost hat when dispatching a request, then returns to the parent profile after.

```apparmor
profile apache /usr/sbin/apache2 {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  capability net_bind_service,
  network inet tcp,

  /var/www/html/** r,
  /var/log/apache2/** a,

  ^vhost_example_com {
    /var/www/example.com/** r,
    /var/log/apache2/example.com/** a,
    deny /var/www/other-site/** rw,
  }
}
```

Hat properties:

- Declared with `^` inside a parent profile.
- Entered with `aa_change_hat(name, magic_token)`, returned from with `aa_change_hat(NULL, magic_token)`.
- Hats can't have their own child profiles (two levels max).
- `change_hat` to an unknown hat name is **denied**.
- Security is **weaker** than full profiles: the hat runs in the same address space as the parent, so an attacker who can run code in the hat may recover the magic token (held in the parent's memory) and escape back to the parent's domain. Don't use hats as a security boundary against arbitrary code execution; use them to reduce accidental over-privilege.

### `change_profile` rule — one-way transition

```apparmor
change_profile -> target_profile,
change_profile /usr/bin/app -> app_restricted,
change_profile /usr/bin/app -> {profile1,profile2},   # alternation
```

Unlike hats, `change_profile` is a **one-way** transition to any loaded profile — no way back. Typical use: an app performs privileged setup, then drops into a restricted profile before touching untrusted input. Stronger than hats because there's no secret to recover.

### change_hat vs change_profile — when to use which

| Aspect | `change_hat` | `change_profile` |
|---|---|---|
| Direction | Into a hat of the **current** profile | One-way transition to any **loaded** profile |
| Reversible | Yes (with magic token) | No |
| Scope | Hats declared inside current profile | Any profile in `/etc/apparmor.d/` |
| Security | Weaker — shared address space, magic token in memory | Stronger — equivalent to a full profile transition |
| Typical use | Web-server vhost dispatch | Privilege drop after trusted setup |

See `child-processes.md` §"Composition: profiles, hats, and stacking" for how these compose with exec-time transitions in multi-process apps.
