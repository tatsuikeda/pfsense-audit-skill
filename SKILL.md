---
name: pfsense-audit
description: Read-only security and reliability audit of a pfSense firewall over SSH, with a prioritized report and plain-language fixes. Use when the user asks to audit, review, health-check or harden a pfSense firewall, check its backups, DNS filtering, VPN, pfBlockerNG feeds or UPS monitoring, or check for a rogue DHCP server. Tested on pfSense CE 2.9.0. Plus 26.x and 26.10 are not yet validated (known gaps in docs/VALIDATING-26.10.md).
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
| `--unifi https://<console>` | the site has UniFi switches or Wi-Fi managed by a UniFi OS console (Cloud Key, UDM, UCG, UniFi OS Server); runs UNIFI-001 to 005 and 007 |
| `--json` | you want to post-process the results |

### UniFi controller access

- Use `--unifi` only when the user confirms a UniFi OS console manages the switches or APs. Without it the UniFi checks report SKIP, which is fine.
- **Never ask for the API key in the chat, and never put it on the command line.** Ask the user to create a dedicated local admin with the least role that can create keys, create the key under Network > Settings > Control Plane > Integrations, and load it themselves with `read -rs UNIFI_API_KEY && export UNIFI_API_KEY`. Then pass `--unifi-key-env UNIFI_API_KEY` (the default). A key carries all the rights of the admin who created it; suggest deleting it after the audit.
- TLS: ask for the console certificate or CA file and pass `--unifi-ca FILE`. Only use `--unifi-insecure` if the user explicitly accepts unverified TLS, and say so in the summary.
- If a guest SSID is open on purpose (a click-through portal by design), pass `--unifi-open-ssid NAME` rather than explaining the failure away.
- The audit only sends GET requests and drops passphrases and SSH secrets on arrival. If the legacy API refuses the key, say which checks were skipped; do not try to log in with a password instead.

## Run

```bash
python3 "<skill dir>/pfaudit.py" <host> [--user admin] [--identity ~/.ssh/key] [--external] [--feeds]
```

- Requires Python 3.11 or newer. Standard library only; do not install anything.
- Exit code 1 means at least one check failed. That is a result, not an error.
- If SSH fails, report the error and stop. Do not retry with other credentials or disable host key checking.
- **Host key changed?** Stop. Show the user the old and new fingerprints and ask them to confirm the new one at the console (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Only after they confirm, remove the stale `known_hosts` entry and add the scanned key whose fingerprint matches. Do not loop on connection attempts or key scans: every connection refused before login counts toward sshguard's block (`LESSONS.md` lesson 24).
- **SSH times out but ping works?** sshguard has probably blocked this machine on the SSH and GUI ports. Tell the user, and either wait a few minutes or ask them to clear it from an open session (`pfctl -t sshguard -T delete <address>`). Offer, as an opt-in change, to add this machine's own address as a `/32` to the Login Protection pass list. Suggest a whole VPN subnet only when the audit shows VPN clients are blocked from firewall management (ACCESS-007 passes).

## Present the results

1. Lead with one sentence: overall state and the number of 🔴 and 🟠 findings.
2. List 🔴 **Fix now** items first, then 🟠 **Fix soon**. For each: what is wrong, why it matters for this kind of site, and the fix with its impact (what restarts or drops). Use the `fix` and `impact` text from the report.
3. Summarize 🟢 passes in one line unless the user asks for detail.
4. Mention ⚪ skipped checks only when a flag would cover them (for example "run again with `--feeds`").
5. If the firewall is not CE 2.9.0, say the results are provisional. On Plus and 26.10, VPN-006 "DCO not loaded" is a known false WARN (see `docs/VALIDATING-26.10.md`).
6. Match the user's environment. A small office has different priorities from a clinic or a site with cameras and door controllers. Say when a finding is a judgement call rather than a rule.

Never paste `config.xml`, password hashes, keys, API keys or certificates into the conversation. The report is built to leave them out; keep it that way.

## Fixing findings

The audit never changes anything. Only make changes when the user explicitly asks, one finding at a time, and say what will restart first. Before changing a firewall:

- **Before:** on ZFS, create a boot environment named for the change (`bectl create pre-<change>-<YYYYMMDD>`). Every `write_config` already keeps the previous config in `/cf/conf/backup`, so the boot environment is what covers packages, files and the OS. Do not copy `config.xml` to this machine as a backup: it holds password hashes and keys. ACB and the box's own history are the config backups.
- **After:** re-run the audit, and confirm REC-001 passes (the new config left staging, so ACB has an off-box copy). Keep the boot environment until the change has proven itself; ask before destroying any boot environment.
- **Upgrades** (any version change, and always a major one): on CE, `pfSense-upgrade` does not create a boot environment (its clone-and-upgrade path is Plus only), and on a layout that fails its boot environment check it destroys existing ones (lesson 26). Check `bectl check` and `df -T /cf /var/db/pkg` first. Create `pre-upgrade-<current version>`, confirm ACB has a recent copy, then upgrade. Afterwards confirm the box boots and re-run the full audit. A boot environment does not survive a reinstall, and Netgate says versions after 26.10 upgrade by reinstall plus config restore, so for those the ACB copy (or a config backup the user downloads and stores somewhere safe) is the only rollback.
- Prefer the pfSense GUI or its documented tools. If you must script, read `LESSONS.md` first: never name a top-level PHP variable `$g`, start Unbound custom options with `server:`, do not run `pfctl -k` over the SSH session you are using, keep the word `sshguard` out of any SSH command that restarts sshguard (lesson 25), and check 2.9 function signatures before calling them.
- Re-run the audit afterwards to confirm the fix.

## References in this directory

- `checks.toml`: every check, its risk, how it is verified, the fix and the versions it was confirmed on. Checks marked `unverified` are reported as warnings at most.
- `LESSONS.md`: the field lessons behind the checks, with symptoms and fixes. Point the user to the matching lesson when a finding has one.
