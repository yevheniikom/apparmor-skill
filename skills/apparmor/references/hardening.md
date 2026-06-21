# AppArmor Hardening Reference

Deny rules, audit mode, and common pitfalls -- everything needed to lock down and debug AppArmor profiles.

---

## 1. Deny Rules and Precedence

### Core rule: deny wins at the same priority level

When a `deny` rule and an `allow` rule match the same access **at the same priority**, `deny` takes precedence — regardless of rule order in the file. Default priority is 0, so in a profile that doesn't use the `priority=N` qualifier, `deny` always wins.

```apparmor
/etc/secrets/** r,               # broad allow (priority 0)
deny /etc/secrets/master.key r,  # deny wins for this specific file
```

**Exception — AppArmor 4.0 `priority=N` qualifier**: Rules with a higher numeric priority completely override rules with lower priority where they overlap, regardless of `allow`/`deny`. A `priority=20 allow` beats a `priority=10 deny`. See `rules.md` §1 "Rule priority" for the syntax. This is how shared deny abstractions can be "opted out of" by consumers — but most profiles don't use priorities, so the "deny wins" shorthand is the right default mental model.

### Behavior in different modes

- **Enforce mode**: `deny` blocks access and (by default) does **not** log the denial.
- **Complain mode**: a plain `deny` rule is **still enforced** — it blocks access even though the rest of the profile is log-and-allow. This is the critical difference from regular allow rules, and the reason a profile in complain mode is *not* a no-op for your security-critical denies.

  **One caveat that bites in practice:** an `audit deny` rule (deny *with* the `audit` qualifier) is, on current AppArmor, downgraded in complain mode to "log and allow" — i.e. the audited deny does **not** block. This is a long-standing quirk (observed continuously since at least 2016 — Launchpad bug #1580369 — and not specific to any one AppArmor version), not the documented design. The practical consequence: do not rely on a complain-mode profile to enforce your sensitive-path denies if those denies carry the `audit` qualifier. If you need a deny actively enforced while you iterate, either keep it as a plain `deny` (no `audit`) or run the profile in enforce mode. The reliable mental model: **complain mode is for discovering missing *allow* rules, not for testing whether *denies* fire.**

### Deny + Audit

By default, `deny` suppresses log messages. To log denials, prepend `audit`:

```
audit deny /etc/shadow r,    # Block AND log the attempt
```

### Pattern: broad allow, narrow deny

This is the recommended approach for profiles that need most of a tree but must exclude specific files. **Use `/{,**}` for directories** so the rule covers both the directory inode (needed to block `ls`/`getdents`) and its contents:

```
@{HOME}/{,**} rw,
audit deny @{HOME}/.ssh/{,**}   rwmlk,
audit deny @{HOME}/.gnupg/{,**} rwmlk,
audit deny @{HOME}/.bashrc      w,
```

Why `/{,**}` not `/**`: see §3 pitfall 2b for the full explanation — in short, a bare `/**` misses the directory inode itself, so `ls ~/.ssh/` still enumerates filenames even though reads are blocked.

### Defence in depth: pair `deny` with `deny owner` for sensitive paths

When the profile has a broad `owner`-qualified allow (common for `@{HOME}`), also emit both forms of every sensitive deny:

```
owner @{HOME}/{,**} rw,
audit deny       @{HOME}/.ssh/{,**} rwmlk,
audit deny owner @{HOME}/.ssh/{,**} rwmlk,
```

The plain `deny` catches accesses where the process euid doesn't match the file owner; the `deny owner` catches the matched case. Emitting both is the safe default when you can't audit every code path, even though `deny` is documented to take precedence over `allow` regardless of qualifier. See also §3 pitfall 11 — symlink-resolved paths can bypass `@{HOME}/...` patterns entirely.

---

## 2. Audit Mode

The `audit` keyword forces logging of rule matches (both allowed and denied accesses).

### Profile-level audit flag

Log every rule match within the profile:

```
profile myapp /usr/bin/myapp flags=(enforce,audit) {
  ...
}
```

### Per-rule audit

Log only specific accesses:

```
audit /etc/passwd r,             # Log every read of /etc/passwd
audit capability net_admin,      # Log whenever net_admin is used
audit network inet raw,          # Log raw socket creation
```

### Audit + deny (logged denial)

```
audit deny /etc/shadow rw,       # Block and log the attempt
audit deny capability sys_admin,
audit deny network raw,
```

### Deny without audit (silent denial)

```
deny /etc/shadow rw,             # Block silently -- no log entry
```

### Use cases

- **Development**: Use `flags=(complain,audit)` during profile creation to capture all access patterns.
- **Production monitoring**: Add `audit` to sensitive rules only (e.g., `audit /etc/shadow r,`) to avoid log noise.
- **Security alerting**: Use `audit deny` on known-bad accesses to trigger alerts.

---

## 3. Common Pitfalls

### 1. Overly broad globs

```
# BAD: Grants access to the entire filesystem
/** rw,

# GOOD: Scope to what the app actually needs
/var/lib/myapp/{,**} rw,
```

### 2. Using `*` when `**` is needed

```
# BAD: Only matches /var/lib/myapp/file, not /var/lib/myapp/sub/file
/var/lib/myapp/* rw,

# GOOD: Matches all files recursively
/var/lib/myapp/** rw,
```

### 2b. `deny /dir/**` blocks reads but not enumeration

A rule like `deny @{HOME}/.ssh/**` matches only paths **under** `~/.ssh/`, not the directory inode itself. `getdents()` (the syscall behind `ls` and `readdir()`) requires `r` on the *directory inode*, which is a separate path. So the rule blocks `cat ~/.ssh/id_rsa` but still allows `ls ~/.ssh/` to list filenames — a useful fingerprint for an attacker.

```
# BAD: Contents blocked, enumeration still works
audit deny @{HOME}/.ssh/** rwmlk,

# GOOD: Covers both directory inode AND contents via brace expansion
audit deny @{HOME}/.ssh/{,**} rwmlk,
```

`{,**}` matches either the empty suffix (the directory inode, path `~/.ssh/`) or any descendant. Upstream `abstractions/private-files-strict` uses this form throughout; older profiles with bare `/**` denies are candidates for migration. Rules that target a specific filename (`.netrc`, `.bashrc`, `wallet.dat`) don't need the brace form — there's no directory to enumerate.

### 3. Missing abstractions

```
# BAD: App crashes because it can't resolve DNS
profile myapp /usr/bin/myapp {
  /etc/myapp.conf r,
}

# GOOD: Include base + nameservice
profile myapp /usr/bin/myapp {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  /etc/myapp.conf r,
}
```

### 4. Forgetting deny precedence

```
# SURPRISE: The allow is overridden by the deny -- even though allow comes second
deny /etc/app/** w,
/etc/app/temp.dat w,     # This will STILL be denied

# FIX: Restructure to avoid conflicting deny and allow on the same path
/etc/app/** r,
/etc/app/temp.dat rw,    # No conflicting deny rule
deny /etc/app/secrets/** rw,
```

### 5. Deny still enforced in complain mode — but `audit deny` is not

```
# A PLAIN deny blocks access even when the profile is in complain mode.
# It will NOT show up as a complain-mode log entry.
deny /etc/shadow rw,

# An AUDIT deny is the trap: in complain mode it is downgraded to
# "log and allow" on current AppArmor, so /etc/shadow stays READABLE.
audit deny /etc/shadow rw,   # logs, but does NOT block in complain mode
```

This `audit deny` downgrade is a long-standing quirk (since at least 2016, Launchpad #1580369), not the documented behavior — so it's easy to get burned by it. If you want a sensitive-path deny actively enforced while iterating, drop the `audit` qualifier (plain `deny` *is* enforced in complain) or switch the profile to enforce mode. Treat complain mode as a tool for finding missing *allow* rules, not for verifying *denies*.

### 6. Missing library paths

Programs link against shared libraries at runtime. Without `m` (mmap PROT_EXEC) on libraries, the app crashes.

```
# BAD: App segfaults loading libfoo.so
/usr/lib/libfoo.so r,

# GOOD: Allow exec-mmap for shared libraries
/usr/lib/libfoo.so rm,
/usr/lib/@{multiarch}/lib*.so*  rm,    # Multiarch-aware pattern
```

### 7. Unsafe execute modes

```
# BAD: ux does not scrub LD_PRELOAD -- attacker can inject code
/usr/bin/helper ux,

# BETTER: Use Px for safe profile transition
/usr/bin/helper Px,

# OR: Use Ux if unconfined is truly required (scrubs environment)
/usr/bin/helper Ux,
```

### 8. Silent deny (no log output)

```
# Deny without audit produces NO log messages -- debugging nightmare
deny /secret/** rw,

# Always use audit deny when troubleshooting
audit deny /secret/** rw,
```

### 9. Forgetting `#include <tunables/global>`

Variables like `@{HOME}`, `@{PROC}`, `@{multiarch}` are undefined without this include. The profile will fail to compile.

### 10. Not testing with aa-logprof after deployment

Real workloads exercise code paths that testing misses. Always run `aa-logprof` after a few days of production usage to catch edge cases.

### 11. Symlinks are resolved BEFORE rule matching

AppArmor is path-based, but path matching happens on the **resolved** path — the kernel computes the pathname from the (dentry, vfsmount) pair after following symlinks. This is a deliberate security property: it prevents symlink-based policy bypass (an attacker can't trick the profile by introducing a symlink). But it means rules written against the symlink path never fire.

```
# Scenario: ~/.ssh is a symlink to /data/shared/.ssh

# BAD: Never matches — the kernel sees /data/shared/.ssh/id_rsa
audit deny @{HOME}/.ssh/{,**} rwmlk,

# GOOD: Defence in depth — deny the target path pattern anywhere on the FS
audit deny @{HOME}/.ssh/{,**}   rwmlk,
audit deny /**/.ssh/{,**}       rwmlk,
audit deny /**/.gnupg/{,**}     rwmlk,
```

You cannot block "follow this symlink" — resolution happens before rule matching. The only protection is to enumerate sensitive directory *names* (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, browser profile dirs) and deny them by wildcard path pattern. Combine with the `@{HOME}/...` denies; both are needed for defence in depth.

### 12. `apparmor_parser -r` may reload from cache

The parser caches compiled policy at `/var/cache/apparmor/`. `apparmor_parser -r` reads the cached binary if its timestamp is newer than the source file — which during development can mean edits get silently ignored when your text editor preserves mtime (git checkouts, some IDEs, etc.).

```bash
# BAD during dev iteration — may load stale cached policy
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.myapp

# GOOD — bypass cache explicitly
sudo apparmor_parser -r --skip-cache /etc/apparmor.d/usr.bin.myapp
# or the short flag:
sudo apparmor_parser -rK /etc/apparmor.d/usr.bin.myapp
# or force a full reload of everything:
sudo systemctl reload apparmor
```

Flags (per `apparmor_parser(8)`):
- `-K` / `--skip-cache` — disables cache reading *and* writing, implies `-T`.
- `-T` / `--skip-read-cache` — read from source every time, still write cache.

Package `postinst` scripts typically call plain `apparmor_parser -r` — that's correct for fresh installs (no stale cache to worry about) but unreliable mid-development.

---

## 4. Debugging a "Permission denied" — cross-check three sources

A syscall returning "Permission denied" can come from AppArmor, from another LSM (landlock, lockdown), or from the kernel's own capability/ownership checks. The user-facing string is identical in every case, and even the errno is a weak signal — AppArmor typically returns `EACCES` and the kernel typically returns `EPERM`, but `EACCES` from `openat()` on something like `/proc/<pid>/uid_map` can come from either layer depending on which check fails first. Iterating on profile rules before you've confirmed AppArmor is even the cause is the most common way to burn time.

Gather all three of these and reconcile them:

1. **strace — the exact syscall and errno.** `strace -f -e trace=file,network,unshare <cmd>` shows `= -1 EACCES` vs `= -1 EPERM` on the precise call. High-level tools (`bwrap`, `unshare`) collapse both into "Permission denied" in their printed error, so strace is the only way to see the real errno.

2. **dmesg — the AppArmor denial line.** `sudo dmesg | grep "apparmor.*DENIED"` after reproducing. A line naming the profile and operation confirms AppArmor. But absence is **not** conclusive: a *silent* deny rule (no `audit` qualifier) produces no log line yet still denies (§2). So empty dmesg means "either not AppArmor, or a non-audit deny."

3. **Reproduction outside the suspected profile.** Run the same command from a fresh login shell, or under `aa-exec --profile=unconfined`. If it still fails, your profile isn't the cause — the block is elsewhere (kernel capability gate, another LSM, a sysctl, a missing setuid helper).

Any one source alone misleads: strace gives the errno but not the responsible subsystem; dmesg can be silent on non-audit denies; external reproduction rules AppArmor in or out but doesn't say which layer is at fault. Two of the three agreeing usually pins it. A useful discipline when debugging namespace/userns/uid_map/mount failures: **always get the external reproduction before editing file rules** — if it reproduces from a fresh shell with no AppArmor wrapping, the profile's file rules are not what you should be changing.

Beware too of reproducing from a *tool-spawned* shell (e.g. a Claude Code Bash call) and treating it as representative: such a shell can differ from the real long-running caller in namespace/capability/LSM context, so a failure there may not reproduce from the actual app — and vice versa. `aa-exec --profile=<parent//child>` is the closest stand-in for a real exec-transition path. The null hypothesis when working on a profile should stay "I forgot a rule" until a concrete ruled-out search rejects it — don't jump to "kernel-level, unfixable" from a single failing reproduction.
