# Changelog

All notable changes to this project are documented here. Monthly self-update pull requests add their entries here too.

## Unreleased

- `SKILL.md`: Claude Code skill that runs the audit, explains findings by priority, and only changes the firewall on explicit request.
- Feed checks hardened: public-address checks before connecting and at every redirect, live peer check before TLS, no proxies, credentials and query strings masked in reports.

- `pfaudit.py`: read-only audit, standard library only. Runs read commands over SSH, parses `config.xml` in memory, evaluates `checks.toml`, prints Markdown or JSON. Optional outside-in probes, feed tests, update check and rogue DHCP scan.
- Catalog moved from YAML to TOML so the tool needs no third-party packages.

- `LESSONS.md`: 23 field lessons (backups, monitoring, DNS, pfBlockerNG, hardware, UniFi, scripting).
- `checks.toml`: 56 checks, 51 confirmed on pfSense CE 2.9.0 or UniFi Network 11.0.97.
- `research/`: verification log for the deep research input, with corrections.

- Repository created: first README, MIT license, `.gitignore` that keeps firewall configs and secrets out of the repo.
