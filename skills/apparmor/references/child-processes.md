# Multi-Process Apps and Child Process Confinement

## Contents

1. [When to read this file](#when-to-read-this-file)
2. [The five execute transitions](#the-five-execute-transitions) — `ix`, `Px`/`px`, `Cx`/`cx`, `Ux`/`ux`, named transitions; uppercase vs lowercase scrubbing
3. [Multi-process patterns by category](#multi-process-patterns-by-category) — browser sandboxes, sandbox runtimes (bwrap/firejail/nsjail), CI runners, setuid helpers, systemd workers
4. [Composition: profiles, hats, and stacking](#composition-profiles-hats-and-stacking) — when to use exec transitions vs API transitions vs stacked profiles
5. [Common multi-process pitfalls](#common-multi-process-pitfalls) — `Px` needs an existing profile, capabilities/abstractions not inherited across `Cx`/`Px`, missing signal rules, `ux` footguns, `owner`-qualifier breaks after `uid_map`, `/proc/self/fd/N` resolved-target exec, inherited writable FDs
6. [Development workflow for multi-process apps](#development-workflow-for-multi-process-apps)
7. [When to walk away from per-process profiling](#when-to-walk-away-from-per-process-profiling)
8. [References](#references)

## When to read this file

Read whenever the program you're profiling spawns other programs that themselves need confinement — not just one binary running in isolation. This covers:

- Browsers and Electron apps (renderer/GPU/utility children) — but see also `electron-chromium.md`
- Sandbox runtimes: Bubblewrap (`bwrap`), Firejail, nsjail, sandbox-exec wrappers
- Container tooling in rootless mode: rootless Podman, Docker rootless, runc/crun
- Build/test runners: GitHub Actions runners, GitLab runners, Bazel sandboxed actions, Nix builders
- Daemons that fork helpers: Apache+CGI, qemu+swtpm, postgres+walreceiver, systemd services with `ExecStartPost`
- Shell pipelines a daemon orchestrates (anything calling `exec`/`posix_spawn` to a different binary)
- Language runtimes that spawn workers: Node.js `child_process`, Python `multiprocessing` with a custom executable, Erlang ports

The unifying problem: **the parent's confinement does not automatically extend, replace, or compose with what the child needs**. You must decide *what happens at exec* and write a rule for it.

## The five execute transitions

When a confined process calls `execve()`, AppArmor consults the parent profile's exec rule for that path and picks one of five transitions. Understanding the difference between them is the single most important thing in multi-process AppArmor work.

| Mode | Letter | What happens to the child's profile | Environment scrubbed? |
|------|--------|------------------------------------|----------------------|
| Inherit | `ix` | Same profile as parent | No |
| Profile | `Px` / `px` | Switch to a top-level profile named after the child binary | `Px` yes, `px` no |
| Child profile | `Cx` / `cx` | Switch to a profile defined *inside* the parent profile | `Cx` yes, `cx` no |
| Unconfined | `Ux` / `ux` | No profile at all | `Ux` yes, `ux` no |
| Named | `Px -> name` / `Cx -> name` | Switch to a specifically-named profile | per uppercase rule |

**Capital letter = environment scrubbed**: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `TMPDIR`, `IFS`, etc. are stripped before the child sees them. Lowercase keeps them. **Always prefer uppercase** unless you have a specific reason — the lowercase variants exist mainly for legacy compatibility and let an attacker who controls the parent's environment influence the child.

### When to use each

**`ix` (inherit)** — the child runs under the *parent's* profile. Use when:

- The child is a tiny helper and you don't want to maintain a separate profile (`/bin/sh -c "echo done"`)
- The child is a setuid helper that immediately re-execs (`chrome-sandbox`, `pkexec`)
- The child is a wrapper script: `/usr/bin/myapp` is a shell stub that execs `/usr/lib/myapp/bin/real`. `ix` keeps both under the same profile, which is usually what you want.

Risk: if the child has a security flaw, the attacker inherits all of the parent's permissions. Don't `ix` to anything that processes untrusted input.

**`Px` (profile, scrubbed)** — switch to a separate top-level profile. Use when:

- The child is a well-known program with its own profile shipped by the distro (`Px /usr/bin/curl,` will pick up `/etc/apparmor.d/usr.bin.curl` if it exists)
- The child has fundamentally different access needs (parent reads HTTP, child writes to the database)
- You want to enforce least-privilege boundaries between cooperating processes

If no profile exists for the path, `Px` *fails the exec* — the child won't start. Use `Pix` (with inherit fallback) during development; switch to strict `Px` once the child profile is stable.

**`Cx -> name` (child profile, scrubbed)** — switch to a profile *nested inside* the parent. Use when:

- The child only makes sense in the context of this parent (Chromium renderer, qemu vhost-net helper)
- You want the child's profile colocated with the parent for maintainability — one file per app
- The child is an instance of the parent re-executing itself with different argv (Chromium pattern: `chrome --type=renderer` is the same binary)

Without `-> name` the child profile must match the binary name. With `-> name` you can have multiple child profiles for the same binary (e.g., `renderer`, `gpu`, `utility`) and pick which to enter via the rule.

**`Ux` (unconfined)** — drop confinement. Use when:

- The child is a debugger you're attaching for one-off troubleshooting
- The child is the system shell and you cannot reasonably profile it (last resort)

Almost never the right answer in production. If you find yourself reaching for `Ux`, ask whether `ix` (still confined) would work.

**Named transitions** — `Px -> updater`, `Cx -> renderer`. The `->` lets the parent rule decide which profile the child enters, regardless of binary name. Essential when one binary plays multiple roles.

### Worked example: parent + helpers

A backup daemon at `/usr/sbin/backupd` that:

1. Runs `/usr/bin/rsync` to ship files to a remote
2. Runs `/usr/bin/gpg` to encrypt manifests
3. Calls a small shell helper `/usr/libexec/backupd-rotate.sh`

```
abi <abi/4.0>,
include <tunables/global>

profile backupd /usr/sbin/backupd flags=(enforce) {
  include <abstractions/base>
  include <abstractions/nameservice>

  /usr/sbin/backupd                       mr,
  /var/lib/backupd/{,**}                  rw,
  /var/log/backupd/*.log                  a,
  /etc/backupd/config.yaml                r,

  # rsync gets its own top-level profile (assumes one is shipped or we wrote one)
  /usr/bin/rsync                          Px,

  # gpg likewise
  /usr/bin/gpg                            Px,

  # The rotate helper is small and lives only inside our context — child profile
  /usr/libexec/backupd-rotate.sh          Cx -> rotate,

  # /bin/sh used by the helper — inherit, since it's just a launcher
  /bin/{ba,da,}sh                         ix,

  network inet stream,

  profile rotate flags=(enforce) {
    include <abstractions/base>

    /bin/{ba,da,}sh                       ix,
    /usr/bin/{rm,mv,find,date}            ix,

    /var/lib/backupd/snapshots/{,**}      rw,
    /var/log/backupd/*.log                a,

    deny @{HOME}/{,**} rwx,
    deny /etc/** w,
  }
}
```

What this achieves:

- `backupd` itself can't read user homes or write outside `/var/lib/backupd`.
- `rsync` runs with its own permission set — even if compromised, it can't touch the rotate logic.
- The rotate helper is sealed: it can manipulate snapshots and log, nothing else, and explicit `deny` rules block the obvious escalation paths.
- Shell utilities (`rm`, `mv`, `find`) `ix`-inherit so they don't need their own profiles, but they run *inside* the rotate sandbox, so they're constrained too.

## Multi-process patterns by category

### Pattern 1: Browser-style sandbox (Chromium, Firefox, Electron)

The parent process re-execs itself with different `--type=` flags to spawn renderers, GPU, utility children. Each child re-sandboxes via `unshare(CLONE_NEWUSER)`.

Required:

- `userns,` in both parent profile and the child profile
- `Cx -> sandbox` rule on the binary path so the re-exec'd child enters a separate, tighter profile
- `/dev/shm/**` access in both (POSIX shared memory between processes)
- Often `signal` rules to allow the parent to deliver SIGTERM/SIGKILL to children

See `electron-chromium.md` for the full template. The general pattern is:

```
profile parent /opt/app/bin {
  userns,
  /opt/app/bin                Cx -> child,
  # ... parent rules ...

  profile child {
    userns,                                    # children re-sandbox
    /opt/app/bin                mr,            # they re-exec the same binary
    # ... very minimal child rules ...
  }
}
```

### Pattern 2: Sandbox runtime (bwrap, firejail, nsjail)

These tools *are* the sandbox: they call `unshare()` to create namespaces and then exec the user's program inside. Three sub-cases:

**a) The runtime itself is profiled, the inner program is not**

This is the Flatpak model. `bwrap` has an AppArmor profile with `userns,`; the program inside the namespace is unconfined by AppArmor (it's confined by the namespace itself + seccomp + bind mounts). On Ubuntu 24.04 Flatpak shipped `/etc/apparmor.d/bwrap-userns-restrict` exactly for this purpose.

**b) Both the runtime and inner program are profiled**

For high-assurance setups: write a profile for `bwrap` with `userns,`, and have it transition into a profile for the inner binary via `Cx`. Adds defense in depth but ties profile changes to inner-program updates.

**c) The runtime is profiled, the inner program enters a stacked profile**

AppArmor 4.0 supports profile *stacking* via the `aa_stack_profile()` API: the inner program is confined by the *intersection* of the parent's profile and the stacked profile. Stacking is monotonically restrictive — adding a stacked profile can only remove permissions. Useful when a sandbox runtime wants to apply a baseline profile to whatever it runs without breaking the runtime's own permissions.

### Pattern 3: Daemon that exec's untrusted code (CI runner, build sandbox)

The runner is your code; the workload is not. The threat model: a malicious build script tries to escape the runner's sandbox.

```
profile ci-runner /opt/runner/bin/runner flags=(enforce) {
  include <abstractions/base>

  /opt/runner/**                          r,
  /opt/runner/work/{,**}                  rw,

  # The build environment — heavily restricted
  /usr/bin/bash                           Cx -> build,

  profile build flags=(enforce) {
    include <abstractions/base>

    /opt/runner/work/{,**}                rw,
    /tmp/build-*/{,**}                    rw,
    /usr/bin/*                            ix,    # any system tool, inherited
    /usr/lib/**                           rm,

    # Critical denies — /{,**} form blocks both contents AND directory enumeration
    # See hardening.md pitfall 2b for why /** alone is not enough
    deny /opt/runner/secrets/{,**}        rwx,
    deny @{HOME}/.ssh/{,**}               rwx,
    deny @{HOME}/.aws/{,**}               rwx,
    deny /etc/shadow                      rwx,
    deny capability sys_admin,
    deny capability sys_ptrace,

    network inet stream,
    network inet6 stream,
  }
}
```

The pattern: the parent has access to secrets (artifacts to upload, signing keys), the child profile explicitly denies access to those paths even while granting broad ix-execution of system tools. Deny rules win, so even if the build manages to traverse to a secret path, the access is blocked.

### Pattern 4: Setuid helper invoked by an unprivileged process

Examples: `pkexec`, `sudo`, `chrome-sandbox`, `mount.nfs`. The parent execs a setuid binary; the kernel raises EUID; the helper does its thing.

AppArmor handles this with `ix`:

```
/usr/bin/sudo  ix,
```

`Px` here would *break* the setuid behavior on some configurations because the profile transition runs after the SUID promotion. Use `ix` and let the helper run under the parent's profile, or write a dedicated profile for the helper that explicitly grants `capability setuid setgid`.

### Pattern 5: Service manager spawning workers (systemd-style)

When systemd execs your service, the kernel attaches the profile named after the binary path (or whatever `AppArmorProfile=` in the unit specifies). If your service then forks workers via `fork()` (no exec), they inherit the profile automatically — no rule needed. If your service `exec`s a different worker binary, you need the appropriate transition.

Tip: for services with `ExecStartPre=`, `ExecStartPost=`, `ExecStopPost=`, each command in those lines runs through `execve` and needs its own rule. Don't forget to add `/bin/systemctl ix,` if your service calls back into systemd.

## Composition: profiles, hats, and stacking

AppArmor offers three ways to scope confinement within a single process lineage. They solve different problems:

| Mechanism | When child runs | Who triggers it | Reversible? |
|-----------|----------------|-----------------|-------------|
| Child profile (`Cx`) | After `execve` | Parent profile rule | No (until next exec) |
| Hat (`change_hat`) | Mid-execution, no exec | The program itself | Yes, if magic token kept |
| Stacking (`aa_stack_profile`) | Mid-execution or after exec | Either side | No (more restrictive only) |

**Child profiles** are the default tool. Use them whenever there's an `execve` boundary.

**Hats** are mid-execution profile changes — the same process drops privileges by entering a "hat" (subprofile). A web server can `change_hat` into a per-request hat that only allows access to that request's working files. The famous use is Apache's `mod_apparmor`. Hats require the program to know about AppArmor and call `change_hat()` explicitly. Most modern apps don't.

**Stacking** is the newest and most flexible. Two profiles are intersected — the resulting confinement is the AND of both. Useful when:

- A sandbox runtime wants to apply a base policy to *whatever* program runs inside, regardless of what profile that program would normally use.
- You want to layer a "company-wide deny" profile on top of vendor profiles without modifying the vendor file.

Stacking is invoked at runtime via the libapparmor API, not declared inline in profile transition rules. A program calls `aa_stack_profile("strict")` (or writes `stack strict` to `/proc/self/attr/current`), which layers `strict` on top of whatever profile is already active. The kernel then enforces the intersection of both. There is no officially documented `Px -> a&b,` inline-transition syntax for stacking — if you see that pattern in a tutorial, treat it as unverified and check against `apparmor_parser -QTK` before relying on it. In practice, stacking is used by sandbox runtimes (bwrap, container managers) that link against libapparmor and call the API directly, not by hand-written profiles.

## Common multi-process pitfalls

1. **Forgetting that `Px` requires an existing profile.** If `/etc/apparmor.d/usr.bin.helper` doesn't exist, `Px /usr/bin/helper,` fails the exec entirely. Use `Pix` during development.

2. **Profile name vs binary path mismatch.** AppArmor matches by attachment specification, not profile name. `profile foo /usr/bin/bar { ... }` confines `/usr/bin/bar` (the binary), and the profile is *called* `foo` for use in `Px -> foo,` references.

3. **Child profile inherits parent's `userns,` — but only if you put it there.** This is not implicit. Each child profile that needs to create namespaces needs its own `userns,` rule.

4. **`Cx` without `-> name`.** Without the named target, AppArmor looks for a child profile whose name matches the basename of the executed file. For `/opt/app/myapp`, that's `myapp`. If the parent has `Cx /opt/app/myapp,` and a child profile `profile myapp { ... }` exists inside, this works. Otherwise the exec fails.

5. **Mixing `ix` and `Px` in the same lineage.** A long inheritance chain (`A` ix-execs `B` which Px-execs `C`) means `B` runs under `A`'s profile, then `C` switches to a fresh profile. The `B`-under-`A` step often confuses `aa-logprof` — denials get logged against profile `A` even though semantically `B` is the offender. Read denial logs with the actual `comm=` field, not just the profile name.

6. **Forgetting signal rules.** A parent that needs to kill its workers needs `signal (send) set=(term kill) peer=child-profile-name,`. Without this, the parent's `kill()` syscall is denied and workers turn into zombies. Same for systemd needing to send TERM/KILL to your service: `signal (receive) set=(term kill hup) peer=unconfined,`.

7. **Overlooking unix sockets between processes.** If parent and child IPC over a unix socket (very common — Chromium, dbus, qemu), both profiles need `unix` rules. Often missed because the syscall succeeds in `complain` mode but logs nothing useful — the denial comes from `socketpair()` which doesn't show a path.

8. **Capability bleed-through.** Capabilities are *not* inherited across `execve` by default in modern Linux (since file capabilities exist), but AppArmor capability rules are profile-scoped. A child profile that doesn't have `capability sys_admin,` cannot use it even if the parent had it. This is the right behavior — but new users often write child profiles assuming parent capabilities apply.

9. **Child profiles inherit *nothing* from the parent — including deny abstractions.** A `Cx -> child` (or `Px`) transition starts the child from zero: it does **not** inherit the parent's `#include <abstractions/...>`, its `deny` rules, or its capability grants. Only `ix` keeps the parent's ruleset; with `Cix`/`Pix` the inherit is merely a *fallback* used when the named profile doesn't exist. The dangerous case is sensitive-file deny abstractions: if the parent profile does `#include <abstractions/private-files-strict>` (or a custom `deny-user-data` bundle) but a `Cx`-transitioned helper doesn't repeat it, that helper becomes a bypass for the parent's secret-file blocks. A sandbox runtime is the classic gadget — `bwrap --bind / / /bin/cat ~/.ssh/id_rsa` runs `cat` under the bwrap child profile, so unless the child re-includes the deny abstraction, the "sandbox" reads the very files the parent forbids. **Re-include every sensitive-path deny inside each `Cx`/`Px` child profile that grants a narrow extra privilege.** Verify directly with `aa-exec --profile=parent//child -- /bin/cat ~/.ssh/<key>` (expect Permission denied) — `aa-exec` enters the child profile without needing the runtime to actually run.

10. **`owner`-qualified rules silently stop matching inside a namespace sandbox.** The `owner` conditional requires the process fsuid to equal the file's uid. After a sandbox runtime (bwrap, etc.) writes `uid_map`, the process's apparent uid no longer matches the file owner, so `owner @{HOME}/... ixr,` quietly fails to match even for files the user owns. Inside a namespace sandbox, prefer **non-`owner`** rules for paths the sandboxed process must reach (and add the `@{att}`-prefixed companion if needed — see rules.md). This is a general namespace gotcha, not specific to any one rule type.

11. **Exec of `/proc/self/fd/N` matches the *resolved* target, not the `/proc` path.** `/proc/self/fd/N` is a magic symlink; AppArmor (the kernel) resolves symlinks to the real filename *before* mediation, so it never checks an `x` rule on `@{PROC}/self/fd/[0-9]*`. A program that re-execs itself via an fd (some sandbox trampolines do: `exec /proc/self/fd/3 ...`) needs an `x` rule on whatever fd 3 actually points to — find it with `ls -la /proc/<pid>/fd/N` or by intercepting the real argv. Symptom: exit 126 + `Permission denied` on `/proc/self/fd/N`. Note the `owner` trap above compounds this inside sandboxes — use a non-`owner` exec rule on the resolved path. A *pipe* fd (`pipe:[N]`) cannot be `exec`'d at all — that's a kernel limitation, not a missing rule.

12. **Inherited writable FDs need a write rule in the child profile.** Open file descriptors are inherited across `execve` by default, and after a `Px`/`Cx` transition AppArmor mediates each inherited fd against the *child* profile (the `file_inherit` mediation class). If the parent hands the child an inherited stdout pointing at a file (e.g. a harness capturing output to `/tmp/...`) and the child profile lacks write on that path, buffered writes at process shutdown get `EACCES` — surfacing as a late, confusing failure (e.g. a Python interpreter exiting 120) rather than an obvious denial. An anonymous *pipe* has no path, so no path rule matches and piping the output works — which is why `cmd > file` fails under confinement but `cmd | cat` doesn't. Plain `ix` avoids the whole issue because the child runs under the parent's rules. Fix: grant the child write on the inherited target (commonly `/tmp/** rw,` and `/var/tmp/** rw,`); exfil through `/tmp` stays harmless as long as `deny network` and `deny /tmp/** x` are present.

## Development workflow for multi-process apps

1. **Map the process tree first**. Run the app and list children:
   ```bash
   pstree -p $(pgrep -f myapp) -a
   ```
   Note every distinct binary path and what argv it's invoked with.

2. **Profile the parent in `complain` mode first**, with a placeholder `Px` for each child:
   ```
   /opt/myapp/bin              Cx -> stub,
   profile stub flags=(complain) { include <abstractions/base> }
   ```
   Run the app, look at logs, see what each child needs.

3. **Tighten one child at a time**. Don't try to enforce-mode the whole tree at once. Pick the leaf processes (no further children of their own), enforce them, work backward to the root.

4. **Use `aa-logprof` per profile**, not globally. Specify the profile to constrain what changes are proposed:
   ```bash
   sudo aa-logprof -f /var/log/audit/audit.log
   ```

5. **Watch for "phantom" children**. Many frameworks spawn subprocesses you don't see in `ps` because they exit fast (e.g., `git` running `gpg-agent` to sign a commit). Tools that help:
   - `sudo execsnoop-bpfcc -n myapp` (BCC tools) — live trace of every exec
   - `sudo perf trace -e 'syscalls:sys_enter_execve' -p $(pgrep myapp)` — same idea via perf
   - `journalctl -k | grep -i apparmor` — denials list the binary path

## When to walk away from per-process profiling

If your app spawns hundreds of short-lived helpers from many different paths (typical of language toolchains, orchestration systems), per-process AppArmor profiles become unmaintainable. Consider:

- **A single broad profile with deep `deny` rules** — confine the parent only, broadly allow execution under inheritance, deny the specific paths/capabilities you care about.
- **Stacking a baseline policy via a sandbox runtime** — let `bwrap` apply uniform restrictions to whatever runs inside.
- **A different LSM** — SELinux's type system handles this case better than AppArmor's path-based model.
- **Seccomp-bpf at the syscall level** — orthogonal to AppArmor and can be applied to all descendants of a process via `PR_SET_NO_NEW_PRIVS`.

AppArmor shines when you have a small number of distinct programs each with bounded execution patterns. Past a certain complexity threshold, fighting it is not productive.

## References

- [openSUSE AppArmor profile components reference](https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-apparmor-profiles.html) — exec mode definitions
- [Ubuntu manpage: apparmor.d(5)](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html) — full syntax
- [aa_stack_profile(2)](https://man.archlinux.org/man/aa_stack_profile.2.en) — runtime stacking API
- [aa_change_hat(2)](https://man.archlinux.org/man/aa_change_hat.2.en) — hat API, magic-token semantics
- See also `electron-chromium.md` for the Chromium-specific case
