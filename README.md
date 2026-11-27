# obsidian

[![Go Reference](https://pkg.go.dev/badge/github.com/obsidian-toolkit/obsidian.svg)](https://pkg.go.dev/github.com/obsidian-toolkit/obsidian)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**obsidian** is a policy-driven Debian security and privacy toolkit. It manages
firewall rules, SSH hardening, kernel sysctls, audit rules, log retention,
unattended upgrades, and service sandboxing from a single declarative TOML
policy. All operations are transactional, reversible, and designed to never
accidentally lock you out of a remote server.

## Features

- **Policy-first**: One TOML file describes the desired security posture.
- **Transactional apply**: Snapshot → apply → verify → commit, with automatic
  rollback on any failure.
- **SSH lockout protection**: Detects the active SSH session and refuses
  firewall/SSH changes that would drop it, unless `--allow-lockout` is given.
- **nftables firewall**: Dedicated `inet obsidian` table, default-deny input,
  established/loopback/ICMP/DHCP allowed, public exposure only on the declared
  interface, admin-only via CIDR sets on admin interfaces.
- **Sandbox isolation**: Systemd hardening + AppArmor profiles + optional
  Landlock filesystem rules + seccomp syscall filtering, all generated from
  the policy.
- **Audit baseline**: Additive auditd rules for `/etc/passwd`, `/etc/shadow`,
  `/etc/sudoers`, `/etc/obsidian/`.
- **Log retention**: journald configured with `MaxRetentionSec`,
  `SystemMaxUse`, persistent storage.
- **Unattended upgrades**: Security origins only, no auto-reboot by default.
- **Drift detection**: `obsidian verify` compares the live host to policy;
  `obsidian drift` shows only the differences.
- **Single static binary**: Go 1.27+, CGO-free, runs on Debian stable.

## Quick Start

```bash
# Build
make

# Install (to /usr/local/bin)
sudo make install

# Create a starter policy
sudo obsidian init

# Edit the policy for your host
sudo vim /etc/obsidian/policy.toml

# Preview every change
sudo obsidian plan

# Apply the policy
sudo obsidian apply

# Verify the host matches the policy
sudo obsidian verify

# Show only drift
sudo obsidian drift

# Roll back the last apply
sudo obsidian rollback
```

## Policy Example

```toml
# /etc/obsidian/policy.toml
role = "web-server"
public_interface = "eth0"

[exposure]
https = "public"
ssh = "admin-only"

[admin]
source_cidrs = ["203.0.113.0/24"]
ssh_port = 22
password_auth = false
root_login = "no"

[privacy]
telemetry = "deny"
dns = "local-resolver"
log_retention_days = 14

[services]
nginx = "enabled"
postfix = "disabled"

[sandbox.myapp]
binary = "/usr/local/bin/myapp"
run_as = "myapp"
read_write = ["/var/lib/myapp"]
read_only = ["/etc/myapp"]
network = "outbound-https"
```

`run_as` must be a dedicated service account (create it before applying).
Sandbox egress is enforced by UID in nftables, so every process running as
that account shares the same egress rules; never point `run_as` at a login
account.

See `examples/web-server.toml` for a complete example and `obsidian explain`
for a human-readable breakdown of any policy.

## Commands

| Command | Description |
|---------|-------------|
| `init` | Write a starter policy to `/etc/obsidian/policy.toml` |
| `check` | Parse and validate the policy, show warnings |
| `plan` | Show every change `apply` would make |
| `apply` | Apply the policy transactionally |
| `verify` | Compare the live host to the policy |
| `drift` | Show only drift found by `verify` |
| `status` | Show applied state and recent transactions |
| `rollback` | Restore a previous transaction |
| `isolate NAME` | Apply only one sandbox (shortcut for `apply --sandbox NAME`) |
| `render` | Render managed files without touching the host |
| `explain` | Explain what the policy asks for and why |
| `version` | Print the version |
| `help` | Show help |

## Global Flags

| Flag | Description |
|------|-------------|
| `--config PATH` | Policy file (default `/etc/obsidian/policy.toml`) |
| `--json` | Machine-readable output |
| `--no-color` | Disable color |
| `--verbose` | Show every command and check |
| `--strict` | Treat policy warnings as errors |
| `--yes` | Do not ask for confirmation |
| `--dry-run` | Plan only, never change the host |
| `--allow-lockout` | Permit changes that may end the current SSH session |
| `--allow-degraded` | Continue when an isolation feature is unavailable |
| `--no-packages` | Never install packages |
| `--sandbox NAME` | Limit plan/apply/verify to one sandbox |
| `--timeout SECONDS` | Watchdog grace period (default 120) |

## Safety

- **Never makes a remote server unreachable**: If you run `obsidian apply`
  over SSH, it detects your session (via `SSH_CONNECTION`, `SSH_CLIENT`,
  or process ancestry) and refuses firewall or SSH changes that would drop
  your connection, unless you explicitly pass `--allow-lockout`.
- **Transactional**: Every apply creates a snapshot of all managed files,
  service states, and nftables rulesets. On any failure, the entire
  transaction is rolled back automatically.
- **Explainable**: `obsidian plan` shows a human-readable diff for every
  change; `obsidian explain` describes the policy intent.
- **Reversible**: `obsidian rollback` restores the exact pre-apply state.

## Requirements

- Debian 12 (bookworm) or later with systemd
- Kernel 5.10+ (Landlock requires 5.13+)
- Root privileges for `apply`, `verify`, `rollback`, `status`
- Go 1.27+ for building from source

## Building

```bash
# Requires Go 1.27+
make

# Cross-compile for Linux (from macOS)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 make

# Run tests
make test
```

## License

Apache-2.0 © 2024 The obsidian Authors