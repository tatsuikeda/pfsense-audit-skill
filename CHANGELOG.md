# Changelog

All notable changes to this project are documented here. Monthly self-update pull requests add their entries here too.

## Unreleased

- First live run against a CE 2.9.0 site firewall. `LESSONS.md` lessons 24 and 25: sshguard locks out the auditor after host key mismatches (block covers only the SSH and GUI ports), and restarting sshguard kills SSH commands that mention it. `SKILL.md` now covers a changed host key, the sshguard timeout, and an opt-in `/32` pass list entry.

- Monthly self-update now runs from the maintainer's Claude Code session (runbook in docs/SELF-UPDATE.md). No API key in GitHub Actions; the Update gate workflow re-checks every auto-update pull request using the gate from main.

- Review fixes: the UniFi collector keeps devices and the other part when one networks or Wi-Fi call fails, and only a CAPTIVE_PORTAL hotspot counts as a guest SSID (Passpoint does not). The self-update gate now allows existing checks only to gain notes, existing lessons only to change the lesson 11 feed table, and rejects @mentions and long encoded strings in the research note. The research job can no longer read outside the checkout, and shared hosting hosts left its fetch allow-list. README and `SKILL.md` no longer claim Plus or 26.10 support before validation, and examples use documentation addresses.

- UniFi checks UNIFI-001 to 005 and 007 via `--unifi` (read-only GETs with an API key from an environment variable). Uses the Integration API (spec 11.0.97) and the legacy API for settings it does not expose. Secrets are dropped on arrival, redirects are refused, TLS is verified unless `--unifi-insecure` is given. Not yet run on a live console; UNIFI-001, 003 and 005 are marked unverified. Offline tests in `tests/test_unifi.py`.

- `SKILL.md`: Claude Code skill that runs the audit, explains findings by priority, and only changes the firewall on explicit request.
- Feed checks hardened: public-address checks before connecting and at every redirect, live peer check before TLS, no proxies, credentials and query strings masked in reports.

- `pfaudit.py`: read-only audit, standard library only. Runs read commands over SSH, parses `config.xml` in memory, evaluates `checks.toml`, prints Markdown or JSON. Optional outside-in probes, feed tests, update check and rogue DHCP scan.
- Catalog moved from YAML to TOML so the tool needs no third-party packages.

- `LESSONS.md`: 23 field lessons (backups, monitoring, DNS, pfBlockerNG, hardware, UniFi, scripting).
- `checks.toml`: 56 checks, 51 confirmed on pfSense CE 2.9.0 or UniFi Network 11.0.97.
- `research/`: verification log for the deep research input, with corrections.

- Repository created: first README, MIT license, `.gitignore` that keeps firewall configs and secrets out of the repo.
