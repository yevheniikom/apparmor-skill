# apparmor-skill

![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-7c3aed)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A Claude Code skill for writing, auditing, and debugging AppArmor profiles — the kind of task a base LLM handles badly.**

AppArmor confines a Linux program to *exactly* the files, network, and capabilities you allow — everything else is denied at the kernel level. The catch: a profile that passes `apparmor_parser` can still silently deny everything in production. Out of the box an LLM happily hands you exactly that kind of profile. This skill loads the real failure modes that trip it up, so Claude gets you to a working, enforced profile in minutes instead of days.

Where that pays off:

- Sandbox an untrusted CLI tool (or an AI agent) so it can only touch one project directory and can't phone home.
- Fix an Electron app that stopped launching after the Ubuntu 24.04 upgrade.
- Stop guessing whether to use `ix`, `Px`, or `Cx` — one wrong choice silently breaks the sandbox.
- Audit an existing profile against what the program actually does and find the rules behind silent denials.

## Install

```bash
claude plugin marketplace add yevheniikom/apparmor-skill
claude plugin install apparmor
```

Then just describe the problem in plain language — the skill loads automatically when your request touches AppArmor.

> *“My profile loads fine but the app still gets permission denied, and `dmesg` shows nothing. What's going on?”*
>
> Claude walks the likely causes — a silent `deny` rule with no `audit` qualifier, a symlink resolved before rule matching, a missing abstraction, a cached parser reload — checks the profile against what the program actually does, and gives you the exact rule to add and how to confirm the fix.

> [!IMPORTANT]
> A generated profile is a security boundary — review it before you rely on it. The skill drafts and explains every rule and defaults to **complain mode** first, so you can see what the program actually does before switching to **enforce**. Treat the output as a strong starting point you verify, not a guarantee.

## What it handles

- **Sandboxing untrusted code.** Confines npm/pip tools, downloaded binaries, and AI agents to a chosen directory with network denied by default — so a compromised dependency can't read your SSH keys or exfiltrate tokens.
- **Profiles that pass but don't work.** Audits an existing profile against what the program actually does and finds the missing rules behind silent denials.
- **The Ubuntu 24.04 Electron trap.** Fixes Chromium/Electron apps (Signal, Obsidian, VSCode, Slack, …) that won't launch because of `unprivileged_userns` restrictions — the `userns,` rule, the `chrome-sandbox` SUID helper, AppImage paths.
- **Multi-process confinement done right.** Picks the correct exec transition (`ix`, `Px`, `Cx`, `Ux`) for apps that spawn other programs, plus child profiles and profile stacking.
- **Containers.** Explains and customizes `docker-default`, `--security-opt apparmor=`, the Kubernetes `appArmorProfile` field, and *why MAC overrides granted capabilities* (a `--cap-add SYS_ADMIN` container still can't mount).
- **Hardening, not just allowing.** Deny rules, audit mode, and the **12 documented real-world pitfalls** — with BAD/GOOD examples — that cause most broken profiles.
- **The full lifecycle.** From `aa-genprof` to a production-ready profile in enforce mode, with the right abstractions, tunables, and local overrides.

## Prerequisites

- **[Claude Code](https://docs.anthropic.com/en/docs/claude-code)** — the skill loads as a Claude Code plugin.
- **A Linux host that uses AppArmor** — Ubuntu, Debian, and openSUSE ship it by default. The skill targets AppArmor specifically, *not* SELinux (RHEL, Fedora, CentOS) and not macOS. Check yours with `aa-status`.

The skill only generates and explains profiles, so you can also run it on any machine to author profiles for a remote AppArmor host.

## Under the hood

Beyond the SKILL prompt, the plugin ships seven focused reference documents the skill pulls in on demand — this is where the depth lives:

| File                              | Covers                                                                     |
| --------------------------------- | -------------------------------------------------------------------------- |
| `references/rules.md`             | Full profile syntax: file, network, capability, signal, DBus, mount        |
| `references/hardening.md`         | Deny rules, audit mode, 12 common pitfalls with BAD/GOOD examples          |
| `references/abstractions.md`      | Available abstractions, tunables, runtime domain transitions               |
| `references/workflow.md`          | complain→enforce lifecycle, tool reference, profile template               |
| `references/electron-chromium.md` | Electron/Chromium/AppImage profiles, Ubuntu 24.04+ `userns,` fix           |
| `references/child-processes.md`   | Exec transitions (`ix`, `Px`, `Cx`), multi-process patterns                |
| `references/docker.md`            | `docker-default`, `--security-opt`, Kubernetes, container escape hardening |

## License

MIT — see [LICENSE](LICENSE).
