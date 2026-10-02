# AppArmor Development Workflow

Profile lifecycle management, naming conventions, tools reference, and a complete production-ready template.

---

## 1. Development Workflow

### Recommended sequence

```
aa-genprof /usr/bin/myapp       # 1. Generate initial profile (sets complain mode)
                                #    Exercise the application in another terminal
                                #    Return to aa-genprof, press S to scan logs
                                #    Accept/reject suggested rules
                                #    Press F when done -- profile moves to enforce

aa-logprof                      # 2. After real-world usage, review new violations
                                #    Accept/reject each suggestion

aa-complain /usr/bin/myapp      # 3. Switch back to complain if issues found

aa-enforce /usr/bin/myapp       # 4. Re-enforce after fixing
```

### Tool reference

| Tool | Purpose |
|------|---------|
| `aa-genprof` | Interactive profile generation. Puts app in complain mode, watches logs, prompts for rules, sets enforce on finish. |
| `aa-logprof` | Scans audit logs for violations against existing profiles and suggests additions. Use iteratively after deployment. |
| `aa-complain` | Switch a profile to complain (log-only) mode. |
| `aa-enforce` | Switch a profile to enforce (block + log) mode. |
| `aa-status` / `apparmor_status` | Show loaded profiles and their modes. |
| `aa-disable` | Disable a profile (unload and symlink to `disable/`). |
| `aa-unconfined` | List running processes that have no profile. |
| `apparmor_parser` | Low-level profile compiler. `-r` to reload, `-R` to remove, `-a` to add. |

### Management commands

```bash
# Reload all profiles
sudo systemctl reload apparmor.service

# Reload a single profile
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.myapp

# Remove (unload) a profile
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.myapp

# Disable a profile persistently
sudo ln -s /etc/apparmor.d/usr.bin.myapp /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.myapp

# Re-enable a disabled profile
sudo rm /etc/apparmor.d/disable/usr.bin.myapp
sudo apparmor_parser -a /etc/apparmor.d/usr.bin.myapp
```

### Local overrides

To customize a packaged profile without modifying the vendor file (and risking conflicts on upgrades), place additional rules in `/etc/apparmor.d/local/`:

```
# In /etc/apparmor.d/local/usr.bin.myapp
/srv/custom-data/** r,
```

The main profile should include it:

```
#include <local/usr.bin.myapp>
```

---

## 2. Profile Naming

### File naming convention

Profile files are stored in `/etc/apparmor.d/` and named by replacing each `/` in the binary path with `.`:

| Binary Path | Profile Filename |
|-------------|-----------------|
| `/usr/bin/myapp` | `usr.bin.myapp` |
| `/usr/sbin/nginx` | `usr.sbin.nginx` |
| `/opt/app/bin/run` | `opt.app.bin.run` |
| `/bin/ping` | `bin.ping` |

### Profile name inside the file

The profile name should match the **full absolute path** to the binary:

```
profile /usr/bin/myapp {
  ...
}
```

Or use the `profile` keyword with a descriptive name and an attachment:

```
profile myapp /usr/bin/myapp {
  ...
}
```

### Rules

- Profile names **must not** start with `:` or `.`.
- Names containing whitespace must be quoted.
- Unattached profiles (not bound to a binary) require the `profile` keyword.
- By convention, the profile name matches the binary path for clarity and tooling compatibility.
- Named profiles referenced by `Px ->` transitions must match exactly.

---

## 3. Quick Reference Card

```
# Full profile template
abi <abi/4.0>,
#include <tunables/global>

@{app_data} = /var/lib/myapp

profile myapp /usr/bin/myapp flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Capabilities
  capability net_bind_service,
  capability setuid setgid,

  # Network
  network inet tcp,
  network inet6 tcp,
  deny network raw,

  # File access
  /usr/bin/myapp                    mr,
  /etc/myapp/{,**}                  r,
  @{app_data}/{,**}                 rw,
  /var/log/myapp/*.log              a,
  /usr/lib/@{multiarch}/lib*.so*    rm,
  owner @{HOME}/.config/myapp/**    rw,

  # Execute transitions
  /usr/bin/helper                   Px,
  /usr/lib/myapp/worker             Cx -> worker,

  # Signals
  signal (receive) set=(term hup) peer=unconfined,

  # DBus
  dbus (send)
       bus=system
       path=/org/freedesktop/login1
       interface=org.freedesktop.login1.Manager
       member=GetSession
       peer=(name=org.freedesktop.login1),

  # Mount (if needed)
  mount fstype=tmpfs -> /tmp/myapp/,
  umount /tmp/myapp/,

  # Deny sensitive paths — /{,**} covers the directory inode (blocks `ls`)
  # AND its contents. See hardening.md pitfall 2b.
  audit deny @{HOME}/.ssh/{,**}   rwmlk,
  audit deny @{HOME}/.gnupg/{,**} rwmlk,

  # Child profile
  profile worker /usr/lib/myapp/worker {
    #include <abstractions/base>
    @{app_data}/work/** rw,
    deny network,
  }

  # Hat for request handling
  ^request_handler {
    @{app_data}/www/** r,
    /tmp/myapp/sessions/** rw,
  }

  # Local overrides
  #include <local/usr.bin.myapp>
}
```

---

## 4. Verifying a Profile Is Actually Enforcing

### Read the confinement label without sudo

Every process exposes its own AppArmor label at `/proc/<pid>/attr/current`. Unlike `aa-status` (which reads kernel internals and needs root), this file is readable by the process itself and any process with read access to `/proc/<pid>/`.

```bash
# Inspect your own shell's confinement
cat /proc/self/attr/current
# Output: "unconfined", or "<profile-name> (enforce)", or "<profile-name> (complain)"
```

**Modern-kernel path**: On kernel ≥5.10 with multiple LSMs active (e.g. `lsm=apparmor,lockdown,yama,bpf`), `/proc/PID/attr/current` can return `EINVAL`. Fall back to the LSM-specific path:

```bash
cat /proc/self/attr/apparmor/current
```

### Critical: profiles attach at `exec()`, not retroactively

Per `apparmor(7)`: *profiles are applied to a process at exec(3) time*. A process that was running before the profile loaded stays `unconfined` until it calls `exec()` — restarting the process. This makes "profile didn't work" indistinguishable from "profile loaded fine, but I'm testing from a stale shell."

Always verify against a **freshly-execed** process, not the session you're in:

```bash
my-binary --version >/dev/null 2>&1 &
PID=$!
sleep 0.2
cat /proc/$PID/attr/current   # → "my-binary (enforce)" if working
kill $PID 2>/dev/null
```

### Verifying a specific deny fires

Don't trust the profile loaded without checking denials actually happen:

```bash
strace -f -e trace=openat -o /tmp/s.out my-binary /forbidden/path
grep forbidden /tmp/s.out
# Want: openat(...) = -1 EACCES  (denied)
# Bad:  openat(...) = 3          (allowed — rule didn't match)
```

A successful FD despite a `deny` rule usually means: the path didn't match (glob too narrow, symlink resolved elsewhere — see hardening.md pitfall 11), or the rule was for the wrong qualifier.

### `sudo aa-exec` is faithful for *deny* checks, not for *allow* checks

`sudo aa-exec -p <profile> -- <cmd>` is the right tool to confirm a **deny fires** — you reproduce the denial in isolation without running the whole app. But it is **not** a faithful stand-in for verifying an **allow works**, because `sudo` changes two things besides the profile:

- **euid becomes 0.** Every `owner @{HOME}/...` rule stops matching (fsuid ≠ file owner), so an access the real user would get is denied under `aa-exec` — the profile looks broken when it isn't. A `@{HOME}` *deny* also now hits `/root` as well. (`@{HOME}` itself is a static tunable, so non-`owner` `@{HOME}` rules still match.)
- **The mount view can differ.** An access your rules genuinely allow (`/** rw`) can fail with `EACCES` and **zero AVCs** — the mount namespace denied it, not AppArmor. An empty audit log next to an `EACCES` is the tell: a missing *allow* would have logged an AVC, so no AVC means the block is elsewhere.

**Rule:** validate file-access and GUI behavior from the **real caller at the real uid** (the app from the user's own shell, or the file-manager action — no sudo, no `aa-exec`). Use `aa-exec`/complain only to *read a deny you have already reproduced*, never to conclude an *allow* is missing.

### Exit 0 is not proof the profile is complete — apps swallow `EACCES`

The natural verification "run it, does it work?" is unreliable for *allow* coverage. Many applications treat a blocked write as non-fatal: they catch the error, skip the operation, and continue with exit 0 and nothing on stderr. A confined CLI that *appears* to work can be silently degraded — response cache not written, telemetry dropped, state files not persisted — with **zero observable signal**. Exit 0 only proves the hot path didn't hard-fail, not that the profile covers everything the app touches.

The most common instance is the `~/.config` ≠ `~/.cache` gap. Profiles get `~/.config/<app>/` because that's where the app reads settings on the first run you test. `~/.cache/<app>/` is written lazily and its failures are swallowed, so it's the rule most often missing:

```
mkdir("/home/.../.cache/myapp", 0777)        = -1 EACCES   # AppArmor denied
openat(".../.cache/myapp/state.json", O_CREAT) = -1 ENOENT  # dir never created
```

When granting cache access, also grant the parent `~/.cache/` dir itself (`owner @{HOME}/.cache/ rw,`) so the app can `mkdir` its own subdir.

So for any confined CLI, don't trust exit 0 — `strace -f -e trace=file,network` one real invocation and grep the output for `EACCES` / `ENOENT` / `EPERM` even when the command "worked". Audit which dirs the app writes lazily (`~/.cache`, `~/.local/state`, the XDG runtime dir) and confirm each has a rule, including the parent dir for the `mkdir`. The deny side of a test suite checks that *forbidden* paths return `EACCES`; it does not check that *allowed* paths actually got written — that side needs this manual functional check.

### Validating a source profile before install

`apparmor_parser -QTK` parses without loading, but it chokes on `#include <local/...>` directives for uninstalled profiles — the `local/` directory is created by `postinst` at install time, so it doesn't exist in source form.

Workaround: supply an include path with `-I` and stub out an empty local override (per `apparmor_parser(8)`, `-I n, --Include n` adds `n` to the include search path):

```bash
mkdir -p /tmp/aa-check/local
: > /tmp/aa-check/local/usr.bin.myapp          # empty stub

sudo apparmor_parser -QTK -I /tmp/aa-check path/to/usr.bin.myapp
```

After `dpkg -i` or equivalent, the real `/etc/apparmor.d/local/usr.bin.myapp` exists and `-I` is no longer needed:

```bash
sudo apparmor_parser -QTK /etc/apparmor.d/usr.bin.myapp
```

---

## 5. Additional Operational Tools

### aa-notify — real-time denial surface

`aa-notify` reads the audit log and shows AppArmor denials as a summary (cron-friendly) or as desktop notifications (`-p`). Useful when diagnosing sporadic denials that are hard to reproduce interactively.

```bash
aa-notify -s 7        # Summary of denials from the last 7 days
aa-notify -l          # Since last login
aa-notify -p -v       # Live desktop notifications, verbose
```

Ship `aa-notify -p` as a user-level systemd unit on dev machines — silent denials stop being silent.

### aa-remove-unknown — clean up orphaned loaded profiles

After you delete a profile file from `/etc/apparmor.d/` or rename one, the old profile often remains loaded in the kernel until next boot. `aa-remove-unknown` reconciles the kernel's loaded set against the on-disk set and unloads anything without a matching file.

```bash
sudo aa-remove-unknown -n     # Dry-run — print what would be removed
sudo aa-remove-unknown        # Actually remove
```

Run after profile deletions or during package uninstall postrm. Safe by default; the `-n` flag is there if you're nervous.

### Attaching a profile via systemd — `AppArmorProfile=`

Normally a profile attaches to a binary by path. When you want a specific service-manager-launched instance to use a specific (possibly non-default) profile — for example, one binary running under two different unit files — use the unit directive:

```ini
# /etc/systemd/system/myapp.service
[Service]
ExecStart=/usr/bin/myapp
AppArmorProfile=myapp-strict
```

systemd calls `aa_change_onexec()` before `execve()`, so the resulting process is confined by the named profile regardless of the path's default attachment. Prefix with `-` (e.g. `AppArmorProfile=-myapp-strict`) to make the directive best-effort — the service still starts if the profile isn't loaded, which is useful on systems where AppArmor may be absent.

Verify after `systemctl start`:

```bash
cat /proc/$(systemctl show -p MainPID --value myapp.service)/attr/current
```

This is the cleanest way to pin a service to a profile that doesn't match the binary path (e.g. renaming, stacked profiles, multi-instance daemons).
