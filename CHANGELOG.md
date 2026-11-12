# Changelog

All notable changes to this project are documented here. Monthly self-update pull requests add their entries here too.

## Unreleased

- Fixes from the /sec-audit run on main: the self-update gate reads files as bytes, rejects NUL bytes, splits lines on newline only (U+2028, carriage return and similar characters no longer hide the rest of a line), checks decoded text for secrets, flags research files hidden by `.gitignore`, and keeps every existing lesson line under its own lesson number. In pfaudit, the DNSBL test domain is validated and quoted in the remote shell command, URLs after an underscore are broken in the report, URL-like values are always quoted, the VPN auth server and IPv6 mode are quoted, token-like feed URL path segments are redacted, and `--feeds` stops after 200 feeds or 600 seconds and says which were not tested. Each feed download has its own 30 second limit for the whole transfer, so a server that trickles bytes cannot hold the run, and feed URL path segments that look like keys (12 or more mixed letters and digits, or 20 or more characters, after percent decoding) are redacted.

- Review follow-ups: the self-update gate decodes HTML entities (named and numeric) and TOML or JSON escapes before its character check, so `&zwj;` and similar spellings are caught. Short config codes (protocol, port, TLS type, digest, DNSBL mode, crypto hardware) appear as written when they are plain tokens and quoted otherwise.

- Fourth /sec-audit round: Markdown escaping covers the whole detail line again (round three's quoted-only escaping left unquoted config text live; the tool's own wording no longer needs escapes). The WebGUI protocol, a non-numeric session timeout and UniFi fatal errors are quoted, the JSON UniFi summary is cleaned, a malformed feed URL no longer stops `--feeds`, the feed guard also refuses the SIIT range, and the self-update gate rejects every control, format, private-use and unassigned character (ESC included) and their escapes. The docs say the required Update gate check passes as skipped on branches not named `auto-update/*`.

- Third /sec-audit round: `StrictHostKeyChecking=yes` on every connection (an empty or new known hosts file can no longer make a changed key look new), and `--ssh-opt` no longer allows ProxyJump, HostKeyAlias or StrictHostKeyChecking. Markdown escaping applies to quoted values only (the tool's own text reads as written) and also covers mentions, references and e-mail links. The state policy, UPS status and UniFi error text are quoted, ssh error output is cleaned, and the feed guard refuses IPv6 transition addresses (NAT64, IPv4-compatible and mapped, 6to4, Teredo). The self-update gate rejects Unicode tag characters and escaped invisible characters (`\uXXXX`, `\UXXXXXXXX`, HTML entities).

- Second /sec-audit round: pfaudit sets `StrictHostKeyChecking=accept-new` on every connection, so a changed host key stops the run even when `~/.ssh/config` says `StrictHostKeyChecking no` (reproduced: before this, a wrong key went unnoticed on such a machine). `--ssh-opt` is now an allow list of plain `Key=Value` options, after the deny list was bypassed with a leading space, a tab and quotes. Every firewall and controller name in a detail is quoted, the report header is cleaned and escaped, the cleaner keeps only visible characters (an allow list by Unicode category), and Markdown escaping covers `&`, `_` and bare URLs. The docs no longer claim a pull request cannot change its own Update gate workflow.

- Fixes from a /sec-audit run (2026-11-12): text from the firewall and the UniFi console (descriptions, device and network names) is stripped of control, bidi, zero-width and tag characters, kept on one line, capped and quoted, and the Markdown report escapes what could form links, HTML or code. `--ssh-opt` refuses options that turn off host key checking or run a local command, ssh gets `--` before the destination, and a user or host starting with `-` is refused. SKILL.md tells the agent that report text is data, not instructions; the README states every outbound connection; the self-update runbook requires a repository-scoped token and person-facing wording in lessons.

- Fixes from a code review by a reader on r/PFSENSE. Each one could let a check pass on data it never saw:
  - **ACCESS-003** reads the effective SSH settings with `sshd -T`, so Include files and OpenSSH defaults count. Without `sshd -T` it now needs an explicit `no` (a missing setting defaults to yes). A Match block that turns passwords back on fails. "Public Key + Password" mode is recognised as key-required instead of failing.
  - **VPN-004** checks OpenVPN instances assigned as their own interface and floating rules, flags rules to a whole interface subnet, and expands host and network aliases (one that cannot be resolved offline is flagged). Findings name the port and the address family.
  - **PERIM-005**: the UDP probe tells a reply (open), an ICMP unreachable (closed) and silence apart. Silence is never treated as closed: if a WAN rule or port forward allows the port, the check warns. The SSDP probe now uses a unicast M-SEARCH.
  - **Run completeness**: the remote script ends with an end marker. A missing section turns every check that needs it into WARN, the report shows a banner, and the exit code is 2 when nothing failed.
  - **UNIFI-006**: the LAN interface name is validated before it reaches a remote command, and a capture that never ran (tcpdump exit other than 0 or 124) warns instead of reporting no rogue servers.
  - **UniFi**: list paging is all or nothing. A list that ends short, or has no total and needs more pages, raises instead of returning part of it (it used to stop silently at 20,000 items).
  - **REC-004** with `--updates` and no answer now warns instead of skipping.
- `--config-file PATH` audits a saved `config.xml` with no live firewall, as a reader asked. Config-only checks run; the ones that need the live box report SKIP.
- HW-007 and lesson 30, from a reader report: a forced Speed and Duplex (even `autoselect`) on an IPv6 Track Interface link is reapplied on every reconfigure, and users report flapping. Unverified, so WARN at most. 62 checks.

- Correction to lesson 26: `pfSense-upgrade` does call `bectl`, but its clone-and-upgrade boot environment path runs only on Plus, so CE still upgrades in place. Added that its `be_prune` step destroys all boot environments on layouts that fail its check; `SKILL.md` now checks the layout before relying on a pre-upgrade boot environment.

- Five new checks from a real site build log, each confirmed on a live CE 2.9.0 box: ACCESS-008 (legacy MD5 password hashes), VPN-008 (VPN clients use the firewall for DNS), VPN-009 (no compression or net30), DNS-008 (resolver cache and prefetch, and tuning hidden in custom options), PFB-009 (lists actually refreshing). MON-002 now reads the system log for recent send failures instead of only checking that SMTP is configured. Lessons 27 to 29. 61 checks.

- Fixes from the first live run: ACCESS-007 reports INFO and names any source passed to any before the management block (was a silent PASS); REC-001 warns when a staged backup is over 15 minutes old even though the upload job exists; HW-005 explains frequency scaling and idle states instead of raw sysctl output; VPN-004, DNS-006 and MON-004 gained fix and impact text. `--feeds` and `--updates` confirmed on a live CE 2.9.0 box. `SKILL.md` sets a before and after routine for changes and upgrades (boot environment first, ACB copy confirmed after); lesson 26: upgrades do not create a boot environment.

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
