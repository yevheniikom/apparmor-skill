# Electron and Chromium-based Apps

## Contents

1. [When to read this file](#when-to-read-this-file)
2. [Why Chromium-based apps need special handling](#why-chromium-based-apps-need-special-handling) — Ubuntu 23.10+ `unprivileged_userns` restriction, namespace sandbox, setuid sandbox
3. [The minimal "make it launch" profile](#the-minimal-make-it-launch-profile) — `flags=(unconfined)` + `userns,`; best default for most users
4. [AppImages — the moving-target problem](#appimages--the-moving-target-problem) — why not to wildcard `/tmp/.mount_*` or attach to the `.AppImage`; extract into `/opt`
5. [The "fully confined" approach (advanced, fragile)](#the-fully-confined-approach-advanced-fragile) — parent/renderer/GPU child profiles, `/dev/shm`, id-map writes, sandbox capabilities
6. [When to pick which approach](#when-to-pick-which-approach)
7. [chrome-sandbox SUID helper](#chrome-sandbox-suid-helper)
8. [Disabling the kernel restriction (last resort)](#disabling-the-kernel-restriction-last-resort)
9. [Verification checklist](#verification-checklist)
10. [Common pitfalls specific to Electron/Chromium](#common-pitfalls-specific-to-electronchromium)
11. [References](#references)

## When to read this file

Read when writing or debugging an AppArmor profile for any Chromium-based desktop application: Chromium itself, Chrome, all Electron apps (Signal, Bitwarden, Obsidian, VSCode, Slack, Discord, Jitsi, Element, Notion, Spotify), CEF-based apps, or AppImage bundles that wrap any of the above. Also read when you see one of these failures on Ubuntu 23.10+:

- App crashes immediately on launch with exit code 139 / SIGSEGV
- `The setuid sandbox is not running as root` followed by `aborting`
- `Failed to move to new namespace: PID namespaces supported, Network namespace supported, but failed: errno = Operation not permitted`
- `User namespace cloning is disabled by sysctl`
- `bwrap: setting up uid map: Permission denied` (Flatpak-wrapped Electron)
- `kernel.apparmor_restrict_unprivileged_userns=1` blocks namespace creation

## Why Chromium-based apps need special handling

Chromium uses a multi-layer sandbox. The browser process spawns renderer, GPU, utility, and zygote child processes, each of which **re-sandboxes itself** by calling `unshare(CLONE_NEWUSER | CLONE_NEWPID | ...)` to enter unprivileged user namespaces. Inside the namespace, the child drops capabilities and uses seccomp-bpf as the second layer.

Two things can block this on modern Linux:

1. **No SUID sandbox** — Chromium's older `chrome-sandbox` binary needs CAP_SYS_ADMIN via setuid. Most distros disabled this; the userns-based "namespace sandbox" replaced it.
2. **Restricted user namespaces** — Ubuntu 23.10 introduced `kernel.apparmor_restrict_unprivileged_userns=1` (default-on in 24.04+). Unprivileged processes can no longer call `unshare(CLONE_NEWUSER)` *unless* they are confined by an AppArmor profile that contains the explicit `userns,` rule. This single sysctl change is what broke every Electron app on Ubuntu 24.04 — they fall back to `--no-sandbox`, which most refuse to do silently, so they SIGSEGV instead.

The fix is always: **load an AppArmor profile that grants `userns,` to the binary's path**. Without that, Chromium's namespace sandbox cannot initialize and the app dies before showing a window.

## The minimal "make it launch" profile

This is what the Chromium project documents and what Ubuntu's `apparmor.d` packages now ship. It's the smallest profile that lets an Electron/Chromium binary start on Ubuntu 24.04:

```
abi <abi/4.0>,
include <tunables/global>

profile signal-desktop /opt/Signal/signal-desktop flags=(unconfined) {
  userns,

  # Hook for site-local additions without editing the vendor profile.
  # Drop extra rules into /etc/apparmor.d/local/signal-desktop.
  include if exists <local/signal-desktop>
}
```

Critical pieces:

- **`abi <abi/4.0>,`** — required for the `userns` rule to be *enforced*. A 4.x parser without it accepts the rule but compiles it out (pitfall 2); 3.x parsers predate the `userns` rule entirely.
- **`flags=(unconfined)`** — the profile is *attached* to the binary (so `userns_create` is allowed) but does not actually restrict file/network/capability access. This is the Chromium-recommended approach because writing a fully-confined profile for a complex Electron app is brittle and breaks on every app update.
- **`userns,`** — the rule that authorizes `unshare(CLONE_NEWUSER)`.
- **`include if exists <local/...>`** — lets sysadmins layer extra rules without editing the vendor profile. **Don't put deny rules there** for an unconfined stub: they give no protection on any parser and break the app on 4.0.0/4.0.1 (`parser-bugs/4.0.0-4.0.1-unconfined-mediation.md`); an include of only `audit deny` lines crashed the 4.0.1 parser build tested (`parser-bugs/4.0.1-audit-deny-only-segfault.md`). Switching the stub to `flags=(default_allow)` doesn't make the denies work today (`rules.md` §1).

### File naming

Save the profile as `/etc/apparmor.d/<path-with-dots>`:

| Binary | Profile filename |
|--------|-----------------|
| `/opt/Signal/signal-desktop` | `opt.Signal.signal-desktop` |
| `/opt/1Password/1password` | `opt.1Password.1password` |
| `/usr/share/code/code` | `usr.share.code.code` |
| `/snap/obsidian/.../obsidian` | (Snap manages its own profile) |

Load it:

```bash
sudo apparmor_parser -r -T -W /etc/apparmor.d/opt.Signal.signal-desktop
sudo aa-status | grep signal-desktop   # verify it's loaded
```

## AppImages — the moving-target problem

AppImages mount themselves into a random `/tmp/.mount_*` path on each launch, so the binary that needs `userns,` has no stable path.

**Don't wildcard the mount path** (`profile myapp /tmp/.mount_*/AppRun flags=(unconfined) { userns, }`). Attachment is by path alone and `/tmp` is world-writable, so any local user or compromised process can create `/tmp/.mount_x/AppRun`, exec it, and get unrestricted user namespaces — exactly what `apparmor_restrict_unprivileged_userns` exists to withhold.

The same hole opens whenever the attached file is writable by the user: anything running as that user can replace it with its own binary. Root-owned is necessary but not sufficient — the attached binary must also not run code the caller chooses. An exec from an unconfined-mode profile keeps the profile unless another profile attaches, so everything the attached binary execs inherits `userns,`.

That rules out attaching to the `.AppImage` file itself, even root-owned: its runtime mounts and runs whatever image `TARGET_APPIMAGE` names, and `APPIMAGE_EXTRACT_AND_RUN` with `TMPDIR` runs `AppRun` from a directory the caller picks (type2-runtime `src/runtime/runtime.c`).

**Extract the AppImage** and move the tree into `/opt` as root. `--appimage-extract` writes `./squashfs-root/` owned by whoever ran it, so fix the owner:

```bash
./MyApp.AppImage --appimage-extract
sudo mv squashfs-root /opt/myapp && sudo chown -R root:root /opt/myapp
```

Then profile the binary inside, as for any app in `/opt`. This is what most "this AppImage broke on 24.04" guides recommend.

## The "fully confined" approach (advanced, fragile)

If the app is high-risk (e.g., processing untrusted documents) and you're willing to maintain the profile across updates, write a real confined profile. The renderer/utility children must transition into a *child profile* that itself has `userns,` so they can re-sandbox. Without this, the main process launches but every tab/document crashes.

Skeleton:

```
abi <abi/4.0>,
include <tunables/global>

profile myapp /opt/MyApp/myapp flags=(enforce) {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/dri-enumerate>
  include <abstractions/mesa>
  include <abstractions/audio>
  include <abstractions/X>
  include <abstractions/dconf>
  include <abstractions/private-files-strict>

  # Allow the main process to create user namespaces for renderers
  userns,

  capability sys_admin,
  capability sys_chroot,
  capability sys_ptrace,         # for Chromium crashpad handler
  capability setuid setgid,
  capability net_bind_service,   # only if app binds <1024

  # Binary and its bundled libs
  /opt/MyApp/myapp                          mr,
  /opt/MyApp/*.so*                          rm,
  /opt/MyApp/{chrome_,}{100,200}_percent.pak r,
  /opt/MyApp/locales/*.pak                  r,
  /opt/MyApp/resources/**                   r,

  # POSIX shared memory between Chromium processes (pitfall 6): older builds,
  # or the fallback when memfd_create fails. Chrome-branded builds name it
  # .com.google.Chrome.*
  owner /dev/shm/.org.chromium.Chromium.*   rwm,

  # Namespace sandbox: the freshly cloned child writes its own id maps
  # before it execs (still under this profile). The kernel also checks
  # CAP_SYS_ADMIN for the map write, so it needs `capability sys_admin` above.
  @{PROC}/@{pid}/{uid_map,gid_map,setgroups} w,

  # Crashpad / oom_score_adj
  owner @{PROC}/@{pid}/oom_score_adj         w,
  owner @{PROC}/@{pid}/{stat,status,cmdline,fd/,task/} r,
  @{PROC}/sys/kernel/yama/ptrace_scope       r,

  # GPU
  /dev/dri/card*                             rw,
  /dev/dri/renderD*                          rw,
  /dev/nvidia*                               rw,    # if NVIDIA

  # User config / cache
  owner @{HOME}/.config/MyApp/{,**}          rw,
  owner @{HOME}/.cache/MyApp/{,**}           rw,

  # The chrome-sandbox SUID helper, if the bundle has one
  /opt/MyApp/chrome-sandbox                  ix,    # inherit, do not transition

  # Renderer / utility / GPU children re-exec the main binary with --type=
  # They need their OWN profile that also has `userns,`
  /opt/MyApp/myapp                           Cx -> sandbox,    # uppercase = environment scrubbed

  # DBus for desktop integration
  dbus send bus=session,
  dbus receive bus=session,

  # Network
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,    # NetworkManager queries

  include if exists <local/myapp>

  # Child profile for renderers/utilities
  profile sandbox flags=(enforce) {
    include <abstractions/base>

    # The child also creates nested namespaces (Chromium "layer 2" sandbox)
    userns,
    @{PROC}/@{pid}/{uid_map,gid_map,setgroups} w,

    # Inside its user namespace the zygote chroots into an empty dir and
    # sets up namespaces; AppArmor still checks these capabilities there
    capability sys_admin,
    capability sys_chroot,

    # Almost no filesystem access — sandboxed children read via IPC from parent
    /opt/MyApp/myapp                          mr,
    /opt/MyApp/*.so*                          rm,
    /dev/shm/.org.chromium.Chromium.*         rwm,
    /dev/dri/renderD*                         rw,

    owner @{PROC}/@{pid}/{stat,status,cmdline,maps} r,
    @{PROC}/sys/kernel/yama/ptrace_scope      r,

    network inet stream,    # GPU process needs network for some features
    network inet6 stream,
    network unix stream,

    deny @{HOME}/{,**} rwx,
    deny /etc/** w,
  }
}
```

This template is **a starting point**, not a drop-in. Every Chromium-based app puts its files in slightly different paths, links different libs, and uses different DBus services. Expect to spend an afternoon in `aa-complain` mode with `aa-logprof` running.

## When to pick which approach

| Situation | Approach |
|-----------|----------|
| App must just *launch* on Ubuntu 24.04, no security expectations beyond Chromium's own sandbox | `flags=(unconfined)` + `userns,` only |
| Internal corp app handling untrusted input | Fully confined with child profile |
| AppImage | Extract into `/opt` (root-owned) and profile the binary inside — never a `/tmp/.mount_*` wildcard, the AppImage runtime itself, or a user-writable file |
| Snap/Flatpak version available | Use that instead — the package manager ships a maintained profile |
| You're packaging the app for distribution | Ship a `flags=(unconfined)` profile in the .deb postinst; document a `local/` override path |

## chrome-sandbox SUID helper

Electron bundles (electron-builder's packages included) and some Chromium builds ship `chrome-sandbox`, a setuid-root helper that sets up PID and network namespaces with real root privileges — no user namespace. Chromium uses it only as a fallback: if it can create a user namespace it takes the namespace sandbox, otherwise it looks for the helper (`zygote_host_impl_linux.cc`). On Ubuntu 24.04+ with no `userns,` profile that check fails, so:

- a helper installed `-rwsr-xr-x root root` (`ls -la /opt/MyApp/chrome-sandbox`) takes over;
- a helper that lost its SUID bit (common after `cp` without `-p`, or an AppImage extracted by non-root tools) makes the app abort with `The SUID sandbox helper binary was found, but is not configured correctly`.

Granting `userns,` puts the app back on the namespace sandbox. If a confining profile must still allow the fallback, let the main process exec the helper:

```
/opt/MyApp/chrome-sandbox  ix,     # inherit current profile, no transition
```

Use `ix` (inherit), not `Px`. The helper is short-lived and immediately re-execs the actual sandboxed child; transitioning to a separate profile here causes confusing failures.

## Disabling the kernel restriction (last resort)

If you cannot write a profile (e.g., debugging on a throwaway VM), turn off the userns restriction system-wide:

```bash
echo 'kernel.apparmor_restrict_unprivileged_userns = 0' \
  | sudo tee /etc/sysctl.d/60-apparmor-userns.conf
sudo sysctl --system
```

This turns off the per-app gate and lets *any* unprivileged process create user namespaces. That's the pre-24.04 behavior. Acceptable on a developer workstation, not on a server or shared machine — it removes a CVE mitigation layer (CVE-2023-32629 / "GameOver(lay)" class of bugs).

## Verification checklist

After loading a profile for an Electron app:

```bash
# 1. Profile is loaded
sudo aa-status | grep -i myapp

# 2. App launches without --no-sandbox
/opt/MyApp/myapp 2>&1 | head -20
# Look for absence of "namespace sandbox" / "setuid sandbox" errors

# 3. Renderers really got their own user namespace: a renderer's user-ns
#    inode differs from the main process's
MAIN=$(pgrep -o -f /opt/MyApp/myapp)
REND=$(pgrep -f -- '/opt/MyApp/myapp.*--type=renderer' | head -1)   # this app's, not another browser's
readlink /proc/$MAIN/ns/user /proc/$REND/ns/user   # two different user:[...] ids

# 4. No new denials after exercising the app (ausearch, not dmesg: DBus
#    denials are USER_AVC and never reach the kernel ring buffer; hardening.md §4)
sudo ausearch -m AVC,USER_AVC -ts recent | grep myapp
```

If step 3 prints the same `user:[...]` id twice, or finds no renderer, the renderers didn't get their own namespace: the `userns,` rule is missing, the profile didn't attach, or Chromium fell back to the `chrome-sandbox` helper, which creates no user namespace (see "chrome-sandbox SUID helper"). Check `aa-status` for the exact profile name and that it matches the binary path.

## Common pitfalls specific to Electron/Chromium

1. **Profile must declare its attachment path** — `profile myapp { ... }` without one never attaches on `execve`, so the app runs unconfined and gets no `userns,`. Use `profile myapp /opt/MyApp/myapp { ... }` (`workflow.md` §2).

2. **Forgetting `abi <abi/4.0>,`** — with no `abi` line the parser falls back to its default feature ABI; with `abi <abi/3.0>,` it uses the 3.0 feature set. Neither contains `userns`, so the rule compiles (exit 0, no message) and is **dropped**: the app still fails to create its namespace. Verified on parser 4.0.1. Plain `apparmor_parser -QTK` does not show this; `apparmor_parser -QTK --warn=rule-not-enforced <file>` reports it (on 4.0.1: `userns rules not enforced`).

3. **Putting `userns,` only in the parent** — renderers call `unshare(CLONE_NEWUSER)` again, so their child profile needs `userns,` too, or tabs crash while the app launches (`rules-advanced.md` §1).

4. **Using `Px` for the renderer transition** — `Px` picks the profile attached to the child's path, and here that path is the parent's own binary. Chromium and Electron re-exec the same binary path with different `--type=` flags (first `--type=zygote`, which then forks renderers, GPU, and utility children — those forks inherit the zygote's profile without re-exec, so only the *first* zygote-spawning exec needs a transition rule). `Px` (and `Pix`) would therefore loop back into the parent profile. Use `Cx -> sandbox` (a child profile). One child profile typically covers all `--type=*` children since they share the same binary path.

5. **JIT crashes** — V8 needs `PROT_EXEC` on anonymous mappings. AppArmor doesn't restrict this directly, but if you've layered seccomp or another LSM that blocks `mprotect(PROT_EXEC)`, JIT fails. Symptom: the app loads but every page is blank with `[1234:1234:0101/000000.000000:FATAL:v8_initializer.cc(...)] Check failed`.

6. **Don't block `/dev/shm`** — Chromium shares memory between processes through it (older builds, and current ones when `memfd_create` fails). Block it there and the GPU process can't talk to renderers; you get a black/white window with no content.

7. **Snap/Flatpak versions are different** — a Snap of Signal runs under a Snap-managed profile (`snap.signal-desktop.signal-desktop`), not your custom profile. Don't try to confine Snap apps with hand-written profiles; use Snap interfaces instead.

## References

- [Chromium docs: AppArmor User Namespace Restrictions](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)
- [electron/electron#41066: All Electron apps fail on Ubuntu 24.04+](https://github.com/electron/electron/issues/41066)
- [electron-userland/electron-builder#8635: Add apparmor profile](https://github.com/electron-userland/electron-builder/issues/8635)
- [Ubuntu Bug #2046844: AppArmor user namespace restrictions](https://bugs.launchpad.net/apparmor/+bug/2046844/)
- [Ubuntu Blog: Restricted unprivileged user namespaces in 23.10](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
