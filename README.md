# srvaudit

Remote Linux server security audit via SSH. No agents. No installation on the server.

```bash
pipx install srvaudit
srvaudit scan root@your-server.com
```

## Example Output

```
+--------------------------------- srvaudit ----------------------------------+
| srvaudit report for deploy@prod.example.com:22                              |
| Score: 68/100 (C)  |  Duration: 4.2s  |  Distro: debian 13                 |
+-----------------------------------------------------------------------------+
                                    Findings
+--------------------------------------------------------------------------+
| Severity  | Check          | Issue                       | Fix           |
|-----------+----------------+-----------------------------+---------------|
| CRITICAL  | open_ports     | MySQL (port 3306) exposed   | ufw deny 3306 |
| WARNING   | ssh_config     | Password auth enabled       | sed -i ...    |
| WARNING   | kernel         | System reboot required      | reboot        |
| WARNING   | firewall       | No firewall detected        | apt install   |
|           |                |                             | ufw && ...    |
+--------------------------------------------------------------------------+

5 passed  3 info  0 skipped
```

Every finding includes a **ready-to-use fix command** you can copy and run.

## Quick Start

```bash
# Full audit (16 checks, ~5 seconds)
srvaudit scan root@your-server.com

# Quick scan (critical checks only, <30 sec)
srvaudit scan root@your-server.com --quick

# With sudo for privileged checks (authorized_keys, cron, sudoers)
srvaudit scan deploy@your-server.com --sudo

# JSON output for automation
srvaudit scan root@your-server.com --json -o report.json

# Compare before/after
srvaudit diff before.json after.json
```

## Diff: Before / After

```
srvaudit diff
Before: 2026-03-25 14:00 | Score: 42/100 (D)
After:  2026-03-27 10:30 | Score: 92/100 (A)  [+50]

FIXED (3):
  [CRITICAL] MySQL (port 3306) exposed on 0.0.0.0
  [WARNING]  No firewall detected
  [WARNING]  Password authentication is enabled

NEW (0)
UNCHANGED (1):
  [WARNING]  System reboot required
```

## What It Checks

16 checks across 6 categories:

| Category | Checks | Quick |
|----------|--------|-------|
| **Access** | SSH config (with Include support), authorized keys, users (UID 0), sudoers | 3 of 4 |
| **Network** | Firewall (ufw/firewalld/nftables, Docker-aware), open ports, fail2ban | 3 of 3 |
| **System** | Pending updates, auto-updates, kernel (reboot + hardening), disk usage, capabilities | 1 of 5 |
| **Services** | Docker (privileged, socket, exposed ports), systemd timers | 0 of 2 |
| **Persistence** | Cron jobs (all users), world-writable files | 0 of 2 |
| **Web** | Exposed .env files in /var/www | 0 of 1 |

## Why Not Lynis?

| | srvaudit | Lynis |
|---|---|---|
| Install on server | **No** (SSH only) | Yes (must be on server) |
| Time | **~5 seconds** | 2-5 minutes |
| Output | Structured, prioritized, scored | 500+ lines raw text |
| Fix commands | Copy-paste ready | No |
| Before/after diff | Built-in | No |
| Docker-aware | Yes (firewall, ports) | Limited |

srvaudit is not a Lynis replacement. Lynis does deep compliance auditing (CIS, PCI-DSS).
srvaudit does fast practical checks for DevOps engineers and freelancers who manage servers.

## Installation

```bash
# Recommended
pipx install srvaudit

# Or with pip
pip install srvaudit

# From source
git clone https://github.com/CynepMyx/srvaudit.git
cd srvaudit && pip install -e .
```

Requires Python 3.9+.

## Scoring

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Good shape |
| B | 70-89 | Room for improvement |
| C | 50-69 | Needs attention |
| D | 0-49 | Critical issues (any CRITICAL finding caps score at 45) |

## SSH Options

```bash
srvaudit scan user@host -p 2222           # custom port
srvaudit scan user@host -i ~/.ssh/id_rsa  # specific key
srvaudit scan user@host --password        # prompt for password
srvaudit scan user@host --accept-host-key # trust on first connect
srvaudit scan user@host --timeout 30      # per-command timeout
```

## How It Works

1. Connects via SSH (paramiko, single session)
2. Detects OS distribution
3. Runs ~30 read-only shell commands
4. Parses output locally
5. Scores findings and generates report

Nothing is installed, modified, or written on the target server.

> **Note:** This tool trusts system utilities on the target host. If the system is
> already compromised (rootkit), results may be unreliable.

## Supported Distributions

Ubuntu 18.04+ | Debian 10+ | CentOS/RHEL 7+ | Rocky/Alma 8+ | Fedora | Alpine

## Contributing

Issues and PRs welcome. See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

MIT
