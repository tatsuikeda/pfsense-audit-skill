---
name: pfsense-audit
description: Read-only security and reliability audit of a pfSense firewall over SSH, with a prioritized report and plain-language fixes. Use when the user asks to audit, review, health-check or harden a pfSense firewall, check its backups, DNS filtering, VPN, pfBlockerNG feeds or UPS monitoring, or check for a rogue DHCP server. Works on pfSense CE 2.9, Plus 26.x and 26.10.
---

# pfSense audit

Runs `pfaudit.py` (in this skill's directory) against a pfSense firewall and turns the result into a short, prioritized report. The audit is read-only: it only runs read commands on the firewall and parses `config.xml` in memory.

## Before running

Ask only for what you do not already know:

1. **Firewall address** reachable over SSH (LAN IP or hostname).
2. **How to log in.** Prefer an SSH key (`--identity`). If the user only has a password, have them put it in an environment variable and pass the variable's name with `--password-env` (needs `sshpass`). Never ask the user to paste a password into the chat, and never echo it.
3. **Where the user is.** Only add `--external` when this machine is outside the firewall's network (for example at home, or on a phone hotspot). From inside the LAN the probe tests the wrong thing.

Optional flags, add them when the user wants a deeper check:

| Flag | Use when |
|---|---|
| `--feeds` | pfBlockerNG is in use; tests every feed for dead or empty lists |
| `--updates` | the user wants to know about pending pfSense updates (slow) |
| `--dhcp-scan` | there are signs of a rogue DHCP server, or any UniFi or mixed network (listens 45 s) |
| `--json` | you want to post-process the results |

## Run

```bash
python3 "<skill dir>/pfaudit.py" <host> [--user admin] [--identity ~/.ssh/key] [--external] [--feeds]
```

- Requires Python 3.11 or newer. Standard library only; do not install anything.
- Exit code 1 means at least one check failed. That is a result, not an error.
- If SSH fails, report the error and stop. Do not retry with other credentials or disable host key checking.

## Present the results

1. Lead with one sentence: overall state and the number of 🔴 and 🟠 findings.
2. List 🔴 **Fix now** items first, then 🟠 **Fix soon**. For each: what is wrong, why it matters for this kind of site, and the fix with its impact (what restarts or drops). Use the `fix` and `impact` text from the report.
3. Summarize 🟢 passes in one line unless the user asks for detail.
4. Mention ⚪ skipped checks only when a flag would cover them (for example "run again with `--feeds`").
5. Match the user's environment. A small office has different priorities from a clinic or a site with cameras and door controllers. Say when a finding is a judgement call rather than a rule.

Never paste `config.xml`, password hashes, keys or certificates into the conversation. The report is built to leave them out; keep it that way.

## Fixing findings

The audit never changes anything. Only make changes when the user explicitly asks, one finding at a time, and say what will restart first. Before changing a firewall:

- Take a config backup and, on ZFS, a boot environment (`bectl create`).
- Prefer the pfSense GUI or its documented tools. If you must script, read `LESSONS.md` first: never name a top-level PHP variable `$g`, start Unbound custom options with `server:`, do not run `pfctl -k` over the SSH session you are using, and check 2.9 function signatures before calling them.
- Re-run the audit afterwards to confirm the fix.

## References in this directory

- `checks.toml`: every check, its risk, how it is verified, the fix and the versions it was confirmed on. Checks marked `unverified` are reported as warnings at most.
- `LESSONS.md`: the field lessons behind the checks, with symptoms and fixes. Point the user to the matching lesson when a finding has one.
