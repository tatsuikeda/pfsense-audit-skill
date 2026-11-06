# Deep research input: verification log

A Gemini Deep Research report (November 2026) was used as one input for the checklist. Every claim is verified against a real pfSense CE 2.9.0 system before it becomes a check. This log records what held up and what did not.

## Verified on pfSense CE 2.9.0 (source code on a live system)

| Claim | Result |
|---|---|
| WebGUI session timeout default is 240 minutes | ✅ `config_get_path('system/webgui/session_timeout', 240)` in `auth.inc` |
| State policy default is Interface Bound since 2.8 | ✅ path is `system/statepolicy` (default `if-bound`) |
| Remote syslog uses `syslog/remoteserver` | ✅ |
| `kea2unbound` exists | ✅ present on 2.9.0 |
| DNSBL VIP must be created manually on 2.9 | ✅ confirmed in practice (see LESSONS) |

## Corrected

| Report said | Actually |
|---|---|
| NAT reflection at `system/natoptions/reflection` | ❌ no such path. It is `system/disablenatreflection` |
| State policy at `system/filter/statepolicy` | ❌ it is `system/statepolicy` |
| OpenVPN CRL at `.../crl_ref` | ❌ it is `crlref` |
| DNSBL mode at `pfblockerngdnsbl/config/0/dnsbl_mode` | ❌ it is `pfblockerngdnsblsettings/config/0/dnsbl_mode` |
| pfBlockerNG TLD limit key `tld_limit`, reset to 3,000,000 on update | ❌ no `tld_limit` key; the TLD ceiling is chosen from installed RAM (for example 12 GB maps to 3,000,000). Reset claim unverified |
| Check WireGuard with `wireguard-go --version` | ❌ pfSense uses the kernel `if_wg` module, not `wireguard-go` |
| Process `unbound_exporter.py` indicates Python mode | ❌ not a pfSense or pfBlockerNG process; check `module-config: "python ...` in `unbound.conf` |

## Not yet verified

- Login protection (sshguard) threshold default of 30
- `kea2unbound` exhausting PHP memory when pfBlockerNG runs in legacy Unbound mode
- DHCP registration in Unbound causing resolver restarts on current versions
- Specific Celeron models affected by the 2.9.0 ACPI SPMC panic (Netgate errata says "some Celeron J devices")
- OpenVPN DCO availability on CE 2.9 versus 26.10
