# Validating pfaudit on pfSense 26.10

This is the release-day checklist for moving pfaudit from "built for 26.10" to "tested on 26.10". It is read-only on the firewall: pfaudit only reads, and `scripts/validate_release.py` only reads local files.

> [!IMPORTANT]
> Run this on a **lab box or VM** with a **synthetic config** (documentation addresses such as 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and example.com names). Never use a client firewall or a client config, and never commit pfaudit output or exported configs. The `validation/` folder is in `.gitignore` for this purpose.

## Status as of 2026-11-05

pfSense 26.10 is **not released**. The docs versions table lists it as "Future release", released "TBD", config revision 24.6, and the release notes index has no 26.10, beta or RC page ([versions][versions], [release notes index][relnotes]). Netgate says 26.10 ships "before the end of November" 2026, as one edition for CE and Plus ([pfSense at 20][at20], 2026-10-29). A search snippet of the Redmine roadmap said October; Redmine could not be fetched, so treat that as unconfirmed.

## Before release day (once)

1. **Build a 2.9.0 lab box.** CE 2.9.0 on ZFS (so `bectl` and boot environments work), on a VM or spare hardware. Give it a WAN on a lab network that a second machine can reach from "outside".
2. **Load a synthetic config** that exercises as many checks as possible: an OpenVPN server, pfBlockerNG with DNSBL in Python mode and a DNSBL VIP, Unbound forwarding over TLS, the System Patches package, AutoConfigBackup, NUT (a dummy UPS driver is fine), SMTP notifications pointing at a lab mail sink, and a remote syslog target. Checks without their feature report SKIP; list those as expected skips in step 5.
3. **Take the baseline.** From a machine outside the lab LAN, with every flag:

   ```bash
   mkdir -p validation
   python3 pfaudit.py <lab-fw> --identity ~/.ssh/lab_key --external --feeds --updates --dhcp-scan \
     [--unifi https://unifi.example.com --unifi-ca console.pem] --json > validation/baseline-2.9.json
   ```

   `--external` probes the WAN from where you run it, so run it from outside the lab LAN (or run twice: once outside for `--external`, once inside for the rest, and merge by check id). Exit code 1 only means a check failed.
4. **Export the config** to `validation/baseline-config.xml` (Diagnostics > Backup & Restore, on the lab box) and record the key-presence manifest. It prints path names and counts only, never values:

   ```bash
   python -I scripts/validate_release.py paths validation/baseline-config.xml > validation/paths-2.9.txt
   ```

## Release day

5. **Create a boot environment**, then upgrade the lab box in place to 26.10 (System > Update). Netgate says CE 2.9 upgrades to 26.10 in place, and that later new versions use a reinstall that saves and restores the config ([pfSense at 20][at20]). Test that path too: install 26.10 fresh on a second VM and restore `baseline-config.xml`.
6. **Record the platform:** `cat /etc/version`, `uname -r`, `php -v | head -1`, and which DHCP backend is selected (System > Advanced > Networking > Server Backend).
7. **Run pfaudit again** with exactly the same flags as step 3, saving `validation/candidate-26.10.json`.
8. **Compare results:**

   ```bash
   python -I scripts/validate_release.py results validation/baseline-2.9.json validation/candidate-26.10.json \
     --tag pfsense-26.10 [--expect-skip ID ...]
   ```

   It reports, by check id:
   - **Missing:** a check absent from one output (pfaudit.py and checks.toml out of step).
   - **Errored:** `Check error: ...` or `No implementation yet` on 26.10. Fix before tagging.
   - **Unexpected SKIP:** ran on 2.9, skipped on 26.10. Pass `--expect-skip ID` only when the reason is understood.
   - **Not exercised:** skipped for a missing flag; rerun with every flag.
   - **Status changed:** review each one against the box. A change is either a real 26.10 difference (update the check) or a pfaudit bug.
   - **verified_on updates:** the exact `verified_on = [...]` line for each check that ran cleanly with an unchanged status, and a separate list to apply only after reviewing its status change. Checks still marked `unverified`, manual checks and UniFi controller checks are never proposed.

   Exit code 0 means clean, 1 means something needs review, 2 means bad input. `--json` gives the same report as JSON.
9. **Confirm every config path.** Export the 26.10 config to `validation/candidate-config.xml` and diff the manifests:

   ```bash
   python -I scripts/validate_release.py paths validation/baseline-config.xml validation/candidate-config.xml
   ```

   Any path present on 2.9.0 and missing on 26.10 blocks the release until the check is updated. It also lists new top-level config sections (look for Nexus, CoreDNS, ThreatGate and DHCP backend keys) and paths built at run time, which need a manual look.
10. **Confirm every command section** by hand on the 26.10 box: each of `kldstat`, `sockstat -4l`, `drill`, `bectl list -H`, `zpool status -x`, `smartctl -H`, `upsc`, `pfSense-upgrade -c`, `ifconfig -a`, `openssl x509` on the certificate files, and that `/var/unbound/pfb_py_zone.txt` still exists, must return non-empty, parseable output in the format pfaudit expects (see `REMOTE_SCRIPT` in `pfaudit.py` and the fixtures in `tests/fixtures/`).
11. **Update the repo, only after steps 8 to 10 pass:**
    - Add `pfsense-26.10` to `verified_on` only for checks whose config path and command were seen on the 26.10 box. Leave the rest unchanged and list them in the pull request.
    - Fix or adjust checks that changed, with a unit test per change (update the matching fixture or add a 26.10 fixture beside the 2.9 ones).
    - Update LESSONS.md lesson 14 (DCO) and the research verification log, citing the 26.10 release notes URL.
    - Only then change the README badge and the version support table from "validating on release" to "tested", and make the `SKILL.md` description match what was actually validated.
    - Run `python -I .github/scripts/validate_catalog.py` and the unit tests.

## Checks most likely to change on 26.10

Ordered by likelihood. Sources are listed at the end; anything marked inference still needs a live box.

| Check | Why it may change | What to confirm |
|---|---|---|
| **VPN-006** DCO | DCO is listed among the 26.10 features ([at20]). It is a per-tunnel checkbox, off by default for new and upgraded tunnels, UDP only, AEAD ciphers only ([dco]). pfaudit currently reports WARN "DCO not loaded" on any version that is not 2.9 (`Ctx.is_29`), so every 26.10 box with OpenVPN but no DCO opt-in gets a false WARN. A unit test pins this behaviour as a canary. | The config.xml key for the DCO checkbox; whether `if_ovpn` is a loadable module (seen by `kldstat`) or built into the kernel (needs `kldstat -v` or `ifconfig -g ovpn`). Then report INFO when DCO is off but the tunnel is compatible. |
| **Version gate** (`Ctx.is_29`) | The only version test is "starts with 2.9". Plus builds report strings like `26.07-RELEASE`, so 26.10 takes every non-2.9 path. | `/etc/version` text on 26.10; replace with a (major, minor) parser that treats 26.10 and later as the merged build. |
| **HW-002** crypto hardware | 26.10 adds Intel IPsec Multi-Buffer and QAT ([at20]). | The `system/crypto_hardware` values for IPsec-MB and QAT. |
| **PFB-001 to PFB-008** | ThreatGate is built in and positioned as pfBlockerNG's successor; pfBlockerNG keeps working until the PHP GUI is retired ([at20]). ThreatGate's full DNS mode needs CoreDNS ([forum]). | That pfBlockerNG paths are unchanged; whether ThreatGate or CoreDNS is active; whether both DNSBL and ThreatGate DNS filtering are on at once. |
| **DNS-001 to DNS-007** | CoreDNS can run in front of Unbound, using it as upstream ([coredns]). If CoreDNS owns port 53, DNS-007's `drill @127.0.0.1` tests CoreDNS, not Unbound. | Which daemon owns :53 (`sockstat -4l`); whether CoreDNS and ThreatGate settings live in config.xml (undocumented). |
| **ACCESS-001, 002, 006, 007** | The new Go GUI is reached on port 8443 when the Nexus controller is on ([newgui]), and comes with a built-in API ([at20]). The external probe already covers TCP 8443, but ACCESS-007's fix text names only 22, 80 and 443, and session timeout or HTTPS for the new GUI may not live under `system/webgui`. | Where the new GUI stores protocol and session timeout; add 8443 to ACCESS-007's fix text. |
| **REC-004** updates | Security fixes come online for free; new versions need a reinstall or a subscription for a one-step online upgrade ([at20]). The `pfSense-upgrade -c` wording, which REC-004 matches with "up to date", may change. | The exact `pfSense-upgrade -c` output on a free 26.10 install, both up to date and with a newer version available. |
| **REC-002** System Patches | Included by default since 2.9.0 ([290]). The base system moved to packages in 26.10 ([at20]). | `installedpackages/patches` still exists. |
| **REC-001** AutoConfigBackup | Merged build. | `system/acb/enable` and the `acbupload` cron entry. |
| **DHCP backend** (no check yet) | Docs call Kea the best practice and ISC DHCP deprecated, with no removal date ([dhcp]). No Netgate source states the 26.10 default. UNIFI-006 sniffs UDP 67 and works for both. | The backend key and value; consider an INFO check that warns when ISC is in use. |

Config schema: 2.9.0, Plus 26.07 and 26.10 all show config revision 24.6 in the versions table ([versions]), which suggests no schema migration. That is an **inference from a placeholder row** for an unreleased version; step 9 is what confirms it.

## Open questions to answer on the box

- The DCO config key, and whether `if_ovpn` is a module or built in.
- Whether ThreatGate, CoreDNS and Nexus settings live in config.xml, and under which paths.
- Whether enabling CoreDNS moves Unbound off port 53.
- The 26.10 default DHCP backend, and whether ISC DHCP is still present.
- The config keys for IPsec-MB and QAT.
- The `pfSense-upgrade -c` wording when a new version needs a reinstall.
- The PHP version (the 2.9.0 notes say both 8.5.7 and 8.4 ([290])).

## Sources

Checked 2026-11-05.

- [versions]: Netgate docs, pfSense versions table, page updated 2026-08-24. https://docs.netgate.com/pfsense/en/latest/releases/versions.html
- [relnotes]: Netgate docs, release notes index, updated 2026-10-01. https://docs.netgate.com/pfsense/en/latest/releases/index.html
- [at20]: Netgate blog, "pfSense at 20", Jim Thompson, 2026-10-29. https://www.netgate.com/blog/pfsense-at-20
- [dco]: Netgate docs, OpenVPN DCO, updated 2025-12-23. https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/dco.html
- [newgui]: Netgate blog, "The new GUI for pfSense Plus", 2026-08-03. https://www.netgate.com/blog/the-new-gui-for-pfsense-plus
- [coredns]: Netgate docs, Nexus CoreDNS, updated 2026-06-19. https://docs.netgate.com/pfsense/en/latest/nexus/coredns/index.html
- [forum]: Netgate forum, "Nexus ThreatGate CoreDNS" (staff reply). https://forum.netgate.com/topic/199689/nexus-threatgate-coredns
- [dhcp]: Netgate docs, DHCP and Advanced Networking. https://docs.netgate.com/pfsense/en/latest/services/dhcp/index.html and https://docs.netgate.com/pfsense/en/latest/config/advanced-networking.html
- [290]: Netgate docs, CE 2.9.0 release notes. https://docs.netgate.com/pfsense/en/latest/releases/2-9-0.html

[versions]: https://docs.netgate.com/pfsense/en/latest/releases/versions.html
[relnotes]: https://docs.netgate.com/pfsense/en/latest/releases/index.html
[at20]: https://www.netgate.com/blog/pfsense-at-20
[dco]: https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/dco.html
[newgui]: https://www.netgate.com/blog/the-new-gui-for-pfsense-plus
[coredns]: https://docs.netgate.com/pfsense/en/latest/nexus/coredns/index.html
[forum]: https://forum.netgate.com/topic/199689/nexus-threatgate-coredns
[dhcp]: https://docs.netgate.com/pfsense/en/latest/services/dhcp/index.html
[290]: https://docs.netgate.com/pfsense/en/latest/releases/2-9-0.html

## Testing the harness itself

`tests/test_checks.py` runs every check against the synthetic good and bad fixtures in `tests/fixtures/`, and fails if a check in `checks.toml` has no implementation (unless `planned = true`) or no expected status. `tests/test_validate_release.py` covers this script. Both are offline:

```bash
.venv/bin/python -I -m unittest discover tests -v
```
