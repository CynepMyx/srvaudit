# srvaudit

Remote Linux server security audit via SSH. No agents. No installation on the server.

```
pip install srvaudit
srvaudit root@your-server.com
```

## Quick Start

```bash
# Full audit
srvaudit root@your-server.com

# Quick scan (critical checks only, <30 sec)
srvaudit root@your-server.com --quick

# With sudo for privileged checks
srvaudit deploy@your-server.com --sudo

# JSON output
srvaudit root@your-server.com --json -o report.json

# Compare before/after
srvaudit diff before.json after.json
```

## What It Checks

- **SSH** - root login, password auth, authorized keys
- **Firewall** - ufw/firewalld/nftables/iptables (Docker-aware)
- **Updates** - pending security patches, auto-updates
- **Access** - sudoers, users with UID 0, empty passwords
- **Network** - open ports, fail2ban
- **Persistence** - cron jobs, systemd timers, world-writable files
- **Docker** - privileged containers, socket permissions
- **Web** - exposed .env files

## How It Works

srvaudit connects via SSH, runs read-only commands, and analyzes the output locally.
Nothing is installed on the target server. All checks use standard Linux utilities.

> **Note:** This tool trusts system utilities on the target. If the system is already
> compromised, results may be unreliable. For rootkit detection, use offline analysis.

## Supported Distributions

Ubuntu 18.04+ | Debian 10+ | CentOS/RHEL 7+ | Rocky/Alma 8+ | Fedora | Alpine

## License

MIT
