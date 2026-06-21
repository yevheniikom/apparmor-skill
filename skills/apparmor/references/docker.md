# AppArmor for Docker / Containers

How AppArmor confines container workloads, what the built-in `docker-default` profile
actually enforces, and how to harden against the path-based bypasses that container
escapes rely on. AppArmor is a **host-kernel feature several runtimes choose to apply** —
not a Docker feature — so a profile name in a container config means nothing unless the
host kernel is enforcing AppArmor (`aa-status` confirms).

## 1. Where the profile comes from

On an AppArmor-capable host, the Docker daemon **generates and loads a profile named
`docker-default`** and applies it to every container unless overridden. Inspect what a
container actually got:

```bash
docker inspect <container> | grep AppArmorProfile
# or, precise:
docker inspect <container> | jq '.[0].AppArmorProfile'

# From inside the container — the live label:
cat /proc/self/attr/current
```

`unconfined` here means no AppArmor confinement (see §4).

### Apply a custom profile

```bash
# Load your profile into the kernel first (-W writes the cache so the daemon sees it):
sudo apparmor_parser -r -W /path/to/your_profile

# Then run the container under it (note the '=' — NOT a colon):
docker run --security-opt apparmor=your_profile <image>

# Disable confinement for one container (debugging only — see §4):
docker run --security-opt apparmor=unconfined <image>
```

The separator is `apparmor=<profile>`, not `apparmor:<profile>`. The profile name is the
name declared inside the profile file (`profile your_profile { ... }`), not the file path.

### Kubernetes

The current field (since k8s v1.30, replacing the deprecated
`container.apparmor.security.beta.kubernetes.io/...` annotations) is:

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault          # or Localhost (+ localhostProfile:) or Unconfined
```

`RuntimeDefault` maps to the runtime's default (`docker-default` on Docker). Enforcement
still depends on the *node* actually supporting AppArmor — a manifest can look
AppArmor-aware while running unconfined on a node without it.

## 2. What `docker-default` enforces

The profile is generated from Moby's `baseTemplate`
(`github.com/moby/profiles` → `apparmor/template.go`). Header:
`flags=(attach_disconnected,mediate_deleted)`. The substantive rules:

| Area | Rule (verbatim from the template) | Effect |
|------|-----------------------------------|--------|
| Network | `network,` + `deny network alg,` | All sockets allowed except the kernel crypto (AF_ALG) family |
| Capabilities | `capability,` | AppArmor allows **all** caps — the *kernel/Docker* cap bounding set is what drops them, not AppArmor |
| Mounts | `deny mount,` | All mount operations blocked |
| `/proc` writes | `deny @{PROC}/* w,`, `deny @{PROC}/sysrq-trigger rwklx,`, `deny @{PROC}/kcore rwklx,`, denies most of `/proc/sys` except `/proc/sys/kernel/shm*` | Writes to top-level `/proc`, `sysrq-trigger`, `kcore`, and almost all of `/proc/sys` are blocked |
| `/sys` | `deny /sys/[^f]*/** wklx,` … `deny /sys/firmware/** rwklx,`, `deny /sys/kernel/security/** rwklx,` | `/sys` write/exec largely denied except cgroup paths |
| ptrace | `ptrace (...) peer="<profile>",` | ptrace confined to the **same** profile — not a host-probing primitive |

The container also gets `signal (receive) peer=unconfined/runc/crun/<daemon>` so the host
and OCI runtime can stop/kill it.

## 3. Why this matters: MAC overrides granted capabilities

The sharpest single point for container review:

> **A capability you were granted is not a capability you can use if the AppArmor profile
> denies the underlying operation.**

`docker run --cap-add SYS_ADMIN` adds `CAP_SYS_ADMIN` to the bounding set, but
`docker-default` has `deny mount,` and denies writes to sensitive `/proc`/`/sys` — so the
classic `CAP_SYS_ADMIN` abuse paths (mounting, writing `core_pattern`, etc.) still fail
*inside a default container*. This is why a capability-based PoC "should work on paper"
yet doesn't: AppArmor is the control silently blocking it. Conversely, this is exactly why
`--security-opt apparmor=unconfined` (or `--privileged`, which also drops the profile) so
often "fixes" a stuck container — and turns a merely-risky config into an exploitable one.

When auditing a container, never conclude from `--cap-add` alone. Check the profile too.

## 4. Hardening against AppArmor bypasses

Because AppArmor is **path-based**, its guarantees are only as good as the path layout.
These are the classes a container escape exploits; harden against each. (Defensive
framing for authorized review — each is a thing to *prevent*, not a recipe.)

### a) Path-based bypass via bind mounts

A rule protecting `/proc/**` or `/sys/**` does **not** protect the same host content when
it is reachable under a *different* path. If the host's procfs/sysfs or root is bind-mounted
into the container (`-v /proc:/host/proc`, `-v /:/host`), the alternate path (`/host/proc/...`)
is outside the rule's glob and the protection evaporates.

- **Harden:** never bind-mount host `/`, `/proc`, `/sys`, the Docker socket, or runtime
  state into a container that doesn't strictly need it. If you must, the AppArmor profile
  must deny the *alternate* path too — enumerate it, the same way `references/hardening.md`
  pitfall 11 handles symlink-resolved sensitive dirs. Evaluate the profile *together with*
  the mount layout, never in isolation.

### b) Shebang / interpreter profile confusion

A profile that confines an interpreter by its binary path may not account for script
execution semantics: a `#!/usr/bin/perl` script can run with execution behavior the
profile author didn't intend for "the interpreter." Profile *intent* and actual *exec
semantics* diverge.

- **Harden:** confine the interpreter's *behavior* (file/exec/capability rules), not just
  its path; don't assume "I confined `/usr/bin/perl`" covers every script it runs. Audit
  interpreter chains and alternate execution paths specifically.

### c) Disable / weaken-and-reload

The profile is only enforced if it's loaded *and* in enforce mode. The operational bypass
class is leaving it off or weak:

- `--security-opt apparmor=unconfined` left in production (the most common real mistake).
- A profile left in `flags=(complain)` after debugging — logs but doesn't block.
- A `change_profile` rule to a *weaker* loaded profile, or an exec transition (`ux`/`Ux`,
  or a `Px`/`Cx` into a broad target) that lands in a less-restrictive domain.
- An attacker who can write `/etc/apparmor.d/` and reload replacing the policy outright.

- **Harden:** audit profiles for the transition/escape-hatch rules, not just the obvious
  `deny` lines. The high-signal grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

  A breakout often hides in a `ux`/`change_profile`/`userns`/`flags=(complain)` rule far
  more than in hundreds of ordinary file rules. Keep `/etc/apparmor.d/` writable only by
  root, and verify the running label (`cat /proc/self/attr/current`) rather than trusting
  the config name.

## 5. Quick container-AppArmor checklist

```bash
aa-status 2>/dev/null                                    # is AppArmor enforcing on the host at all?
docker inspect <container> | jq '.[0].AppArmorProfile'   # what the runtime says it applied
docker run --rm <image> cat /proc/self/attr/current      # what the container actually runs under
cat /sys/kernel/security/apparmor/profiles | sort        # loaded profiles straight from securityfs
```

- `/proc/self/attr/current` = `unconfined` → no AppArmor benefit, regardless of config.
- `aa-status` shows AppArmor disabled → any profile name in the runtime config is cosmetic.
- A `docker-default`-derived custom profile is the right starting point; pull it from
  the moby template above rather than hand-rolling the `/proc`/`/sys`/mount denies.
