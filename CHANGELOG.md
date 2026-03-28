# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- False OK in world_writable check when `find` command fails
- `--sudo` hangs on password prompt — now preflight checks with `sudo -n true`
- `updates` check: `| wc -l` masked package manager errors
- `fail2ban` hardcoded SSH port 22 — now detects actual sshd port
- IPv6 target parsing (`root@[2001:db8::1]`)
- `isalnum()` filter rejected usernames with hyphens (`www-data`, `test-admin`)
- SSH Include directive glob expansion blocked by `shlex.quote`
- Forward reference in registry.py broke on Python 3.9
- Multiple CRITICALs gave same score as one (now penalties stack below 45)
- Shell prompt `$` artifacts in parsed output
- `ufw status: inactive` matched as "active" (substring bug)
- Transport marker leakage after command timeout

### Added
- Coverage summary: shows skipped privileged checks when `--sudo` not used
- Truncation notes: `(showing first N results, may be incomplete)` in sampled output
- `srvaudit diff` command for before/after comparison
- Empty target validation with clear error message
- Diff findings sorted by severity
- Error handling in checks autodiscovery
- MockTransport strict mode for better test isolation

## [0.1.0] - 2026-03-28

### Added
- Initial release on PyPI
- 16 security checks across 6 categories (access, network, system, services, persistence, web)
- SSH-based remote audit — zero-install on target server
- Single shell channel transport with UUID markers
- OS detection (Debian, Ubuntu, CentOS, RHEL, Alpine)
- Scoring 0-100 with grades A-D (CRITICAL caps at 45)
- Fix commands for each finding
- Rich terminal output with colored tables
- JSON output for automation
- `--quick` mode (7 critical checks, <30 sec)
- `--sudo` support for privileged checks
- SSH host key verification (RejectPolicy by default)
- CI/CD: GitHub Actions (lint, test matrix 3.9/3.11/3.13, smoke, release)
- PyPI trusted publishing via GitHub OIDC
