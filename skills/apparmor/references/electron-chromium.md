# Electron and Chromium-based Apps

## Contents

1. [When to read this file](#when-to-read-this-file)
2. [Why Chromium-based apps need special handling](#why-chromium-based-apps-need-special-handling) — Ubuntu 23.10+ `unprivileged_userns` restriction, namespace sandbox, setuid sandbox
3. [The minimal "make it launch" profile](#the-minimal-make-it-launch-profile) — `flags=(unconfined)` + `userns,`; best default for most users
4. [AppImages — the moving-target problem](#appimages--the-moving-target-problem) — `/tmp/.mount_*` wildcarding, extract-to-opt alternative
5. [The "fully confined" approach (advanced, fragile)](#the-fully-confined-approach-advanced-fragile) — parent/renderer/GPU child profiles, V8 JIT, `/dev/shm`
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

- **`abi <abi/4.0>,`** — required for the `userns` rule to parse. AppArmor 3.x parsers will reject the rule.
- **`flags=(unconfined)`** — the profile is *attached* to the binary (so `userns_create` is allowed) but does not actually restrict file/network/capability access. This is the Chromium-recommended approach because writing a fully-confined profile for a complex Electron app is brittle and breaks on every app update.
- **`userns,`** — the rule that authorizes `unshare(CLONE_NEWUSER)`.
- **`include if exists <local/...>`** — lets sysadmins layer extra rules without editing the vendor profile. **Caveat:** on `apparmor_parser` 4.0.0/4.0.1, dropping a deny rule into that `local/` include silently demotes the whole `flags=(unconfined)` profile to `enforce` and breaks the app. Before shipping a `local/` deny include, check `parser-bugs/4.0.0-4.0.1-unconfined-mediation.md` for the version gate.

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
sudo apparmor_parser -r /etc/apparmor.d/opt.Signal.signal-desktop
sudo aa-status | grep signal-desktop   # verify it's loaded
```

## AppImages — the moving-target problem

AppImages mount themselves into a random `/tmp/.mount_*` path on each launch, so you can't pin a profile to a stable executable path. Three workarounds:

1. **Wildcard the mount path** (works, ugly):
   ```
   profile myapp /tmp/.mount_*/AppRun flags=(unconfined) {
     userns,
   }
   ```

2. **Extract the AppImage** with `--appimage-extract` to `/opt/<app>/` and profile the stable path. This is what most "this AppImage broke on 24.04" guides recommend.

3. **Use `appimage-launcher`** which extracts to `~/.local/bin/<app>/` — then profile that stable path.

For a known-volatile bundle, option 1 is acceptable. For anything you'll run repeatedly, option 2 is cleaner.

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

  # V8 JIT requires PROT_EXEC on anonymous mappings
  /dev/shm/**                               rwm,
  owner /dev/shm/.org.chromium.Chromium.*   rwm,

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
| AppImage you run once a week | Wildcarded `flags=(unconfined)` profile |
| Snap/Flatpak version available | Use that instead — the package manager ships a maintained profile |
| You're packaging the app for distribution | Ship a `flags=(unconfined)` profile in the .deb postinst; document a `local/` override path |

## chrome-sandbox SUID helper

Older Electron versions and some Chromium builds still ship `chrome-sandbox` — a setuid-root helper that creates the namespace using CAP_SYS_ADMIN instead of unprivileged userns. If you see it in the bundle (`ls -la /opt/MyApp/chrome-sandbox` shows `-rwsr-xr-x root root`), the app prefers it over the userns path. AppArmor must let the main process exec it:

```
/opt/MyApp/chrome-sandbox  ix,     # inherit current profile, no transition
```

Use `ix` (inherit), not `Px`. The helper is short-lived and immediately re-execs the actual sandboxed child; transitioning to a separate profile here causes confusing failures.

If the SUID bit is missing (common after `cp` without `-p`, or after extracting an AppImage with non-root tools), Electron will silently fall back to userns sandbox — which then fails on Ubuntu 24.04 unless your profile has `userns,`. So both paths matter.

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

# 3. Renderer is sandboxed (open chrome://sandbox in Electron with --enable-features=ElectronSerialChooser, or use built-in DevTools)
# All rows should show "You are adequately sandboxed."

# 4. No new denials in dmesg after exercising the app
sudo dmesg | grep -i "apparmor.*DENIED" | grep myapp | tail
```

If row 3 shows "Namespace Sandbox: No", the `userns,` rule is missing or the profile didn't attach. Check `aa-status` for the exact profile name and that it matches the binary path.

## Common pitfalls specific to Electron/Chromium

1. **Profile must declare its attachment path** — if you write `profile myapp { ... }` without an attachment specification, the kernel will not auto-attach it on `execve` of any binary. The profile loads but is dormant -- it can only be entered via an explicit `change_profile` call from inside another profile, which Electron apps never do. Result: the binary at `/opt/MyApp/myapp` runs unconfined and `userns,` is not granted. Always use `profile myapp /opt/MyApp/myapp { ... }` so the kernel attaches the profile when that binary is exec'd.

2. **Forgetting `abi <abi/4.0>,`** — older parsers silently ignore unknown rules. Without the ABI declaration, `userns,` may parse but do nothing. `apparmor_parser -QTK` does NOT catch this.

3. **Putting `userns,` only in the parent** — renderers re-call `unshare(CLONE_NEWUSER)`. If the child profile (or inherited parent profile) doesn't have `userns,`, individual tabs/documents crash even though the app launches.

4. **Using `Px` for the renderer transition** — `Px` requires a profile named exactly the same as the binary. Chromium and Electron re-exec the same binary path with different `--type=` flags (first `--type=zygote`, which then forks renderers, GPU, and utility children — those forks inherit the zygote's profile without re-exec, so only the *first* zygote-spawning exec needs a transition rule). `Px` would loop back into the parent profile. Use `Cx -> sandbox` (child profile) or `Pix` (transition with inherit fallback). One child profile typically covers all `--type=*` children since they share the same binary path.

5. **JIT crashes** — V8 needs `PROT_EXEC` on anonymous mappings. AppArmor doesn't restrict this directly, but if you've layered seccomp or another LSM that blocks `mprotect(PROT_EXEC)`, JIT fails. Symptom: the app loads but every page is blank with `[1234:1234:0101/000000.000000:FATAL:v8_initializer.cc(...)] Check failed`.

6. **`/dev/shm` is mandatory** — Chromium uses POSIX shared memory between processes. Block this and the GPU process can't talk to renderers; you get a black/white window with no content.

7. **Snap/Flatpak versions are different** — a Snap of Signal runs under a Snap-managed profile (`snap.signal-desktop.signal-desktop`), not your custom profile. Don't try to confine Snap apps with hand-written profiles; use Snap interfaces instead.

## References

- [Chromium docs: AppArmor User Namespace Restrictions](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)
- [electron/electron#41066: All Electron apps fail on Ubuntu 24.04+](https://github.com/electron/electron/issues/41066)
- [electron-userland/electron-builder#8635: Add apparmor profile](https://github.com/electron-userland/electron-builder/issues/8635)
- [Ubuntu Bug #2046844: AppArmor user namespace restrictions](https://bugs.launchpad.net/apparmor/+bug/2046844/)
- [Ubuntu Blog: Restricted unprivileged user namespaces in 23.10](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
