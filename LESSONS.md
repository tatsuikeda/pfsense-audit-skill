# 🧠 Lessons from the field

Each lesson below came from a real deployment: a small-office pfSense build with UniFi switching and Wi-Fi. Each one lists what you see, what is really going on, how the audit detects it, and the fix. Lessons are tagged with the versions they were observed on.

> Client names, addresses and credentials have been removed. Example addresses use documentation ranges.

---

## 💾 Backups and recovery

### 1. AutoConfigBackup says enabled, but nothing uploads
- **You see:** ACB enabled, no errors, no notices.
- **Really:** backups are staged in `/cf/conf/acb/` but the every-minute upload job (`acbupload.php`) is missing from cron, so they pile up and never leave the box. We hit this after enabling ACB by writing the config directly instead of saving the ACB page.
- **Detect:** `grep acbupload /etc/crontab` is empty while `system/acb/enable` is `yes`, or files keep accumulating in `/cf/conf/acb/`.
- **Fix:** save the ACB settings page once, or install the cron job. Then confirm stored backups in Services > AutoConfigBackup.
- **Seen on:** CE 2.9.0

### 2. Restoring a config does not restore loader tunables
- **You see:** a box that needed a loader tunable (for example the 2.9.0 ACPI SPMC workaround on some Celeron J boards) panics again after a reinstall plus config restore.
- **Really:** `/boot/loader.conf.local` is not part of `config.xml`.
- **Fix:** keep loader tunables in your build checklist, not just in the backup.
- **Seen on:** CE 2.9.0 (Netgate errata for the SPMC issue)

## 📣 Monitoring and alerts

### 3. The gateway monitor watches the modem, not the internet
- **You see:** gateway always green.
- **Really:** with a static WAN, dpinger pings the ISP gateway, which stays up when the ISP's network is down.
- **Detect:** the WAN gateway's `monitor` is empty or equals the gateway address.
- **Fix:** set the monitor IP to a stable public address such as `1.1.1.1` (use one your DNS does not depend on).
- **Seen on:** CE 2.9.0

### 4. UPS alerts are off by default
- **You see:** NUT installed and the UPS reads `OL`.
- **Really:** no notification on power events until `installedpackages/nut/config/0/email` is `yes` (this adds `NOTIFYCMD` to `upsmon.conf` and uses the system SMTP settings).
- **Note:** some CyberPower units log a suggestion to set `pollonly`. Only add it if the driver drops out.
- **Seen on:** CE 2.9.0, nut package 2.8.2

## 🌐 DNS

### 5. The ISP intercepts plain DNS
- **You see:** Unbound in resolver mode returns SERVFAIL for everything; a filtering resolver such as Cloudflare for Families appears not to filter.
- **Really:** the ISP-provided gateway answers port 53 itself. Queries to reserved addresses such as `192.0.2.1` still get answers. Seen with a Comcast Business gateway.
- **Detect:** `drill example.com @192.0.2.1` returns an answer.
- **Fix:** forward over DNS over TLS (port 853) with the resolver's TLS hostname. Plain port 53 cannot be trusted on that path.
- **Seen on:** CE 2.9.0

### 6. DNSSEC plus a filtering resolver turns blocks into errors
- **You see:** blocked sites show "server not found" instead of a block page.
- **Really:** the filter answers `0.0.0.0` for blocked names, which fails local DNSSEC validation, so Unbound returns SERVFAIL.
- **Fix:** when forwarding to a validating filtering resolver over TLS, turn off local DNSSEC validation. Trade-off: you then rely on the upstream for validation.
- **Seen on:** CE 2.9.0 with Cloudflare for Families

### 7. Unbound custom options break when you enable forwarding
- **You see:** DNS dies right after turning on forwarding. Unbound will not start.
- **Really:** custom options are appended after the `forward-zone` block. Server directives with no `server:` line are now a syntax error.
- **Detect:** custom options are set and do not start with `server:`. `unbound-checkconf` reports a syntax error.
- **Fix:** start custom options with `server:`.
- **Seen on:** CE 2.9.0

### 8. Clients can bypass your DNS filter
- **Really:** devices that use their own resolver, DNS over TLS (853) or DNS over HTTPS skip both pfBlockerNG and the upstream filter.
- **Fix:** block outbound 853 from LAN, redirect or block outbound 53 to anything but the firewall, and add a DoH blocklist if needed.

## 🚫 pfBlockerNG

### 9. A copied DNSBL config silently leaves DNSBL off
- **You see:** DNSBL settings look right. One log line: `DNSBL disabled: no VIP configured`.
- **Really:** in 3.2.17 the VIP setting is `pfb_dnsvip4`, which references a virtual IP by ID (`_vip<uniqid>`). The older `pfb_dnsvip` (an IP address) is ignored, and 2.9 no longer creates the VIP for you.
- **Fix:** create an IP Alias VIP on `lo0` (for example `10.10.10.1/32`), select it as the DNSBL VIP, force reload.
- **Seen on:** CE 2.9.0, pfBlockerNG 3.2.17_1

### 10. Wildcard blocklists need TLD mode
- **Really:** modern lists (for example hagezi "wildcard onlydomains") expect subdomains to be blocked too. Without TLD processing, only exact names are blocked.
- **Detect:** subdomain of a listed domain resolves normally.
- **Fix:** enable TLD. Note that deeper entries (`ad.example.com`) may still be exact-match only.
- **Seen on:** pfBlockerNG 3.2.17_1

### 11. Many classic feeds are dead or empty (November 2026)
| Feed | State |
|---|---|
| Spamhaus eDROP | Empty; merged into DROP in 2024 |
| abuse.ch URLhaus and ThreatFox hostfiles | HTTP 410 Gone |
| abuse.ch Feodo recommended | A single entry, not updated for months |
| Disconnect.me tracking and malware | Not updated since 2015 to 2020 |
| hagezi legacy `domains/*.txt` | 404; use `wildcard/*-onlydomains.txt` |
| Several GitHub hosts lists (BlockWindows, Spam404, notracking) | Archived or years stale |

The monthly self-update re-tests feeds and updates this table.

### 12. Python Control's timed disable did not re-enable
- **You see:** `drill TXT python_control.disable.<seconds>` returns "out of range" yet disables DNSBL, which stays off.
- **Also:** names resolved while DNSBL was off stay cached after re-enabling until flushed.
- **Fix:** use `python_control.disable` and `python_control.enable` manually, then `unbound-control flush <name>`.
- **Seen on:** pfBlockerNG 3.2.17_1

## ⚡ Hardware and performance

### 13. Fresh installs leave thermal sensors and AES-NI off
- **Detect:** `system/thermal_hardware` and `system/crypto_hardware` are unset; no `dev.cpu.N.temperature` readings.
- **Fix:** set Thermal Sensors to the CPU's driver (`coretemp` on Intel) and Cryptographic Hardware to AES-NI.
- **Seen on:** CE 2.9.0

### 14. OpenVPN DCO is not on CE 2.9
- **Really:** CE 2.9.0 has no DCO support (no `if_ovpn` module, no DCO handling in `openvpn.inc`). Netgate lists data channel offload among the features coming to everyone in 26.10.
- **Seen on:** CE 2.9.0. Re-check on 26.10.

### 15. Whitebox boxes need AT mode to power back on
- **You see:** after a power cut, the firewall stays off.
- **Really:** many mini PCs default to ATX mode. On some boards a jumper (for example `JAT/ATX1`) selects AT mode, which powers on whenever AC is applied. Unrelated jumpers such as `GPIO_PWR` only set GPIO header voltage.
- **Fix:** AT jumper or BIOS "Restore on AC Power Loss: Power On". Test by pulling AC while running.

### 16. CPU frequency scaling is a trade-off, not a default
- Disabling SpeedStep or Speed Shift in the BIOS can steady latency, but raises power and heat. In a closed rack, measure temperatures before and after. The audit reports scaling state; it does not demand a setting.

## 📡 UniFi behind pfSense

### 17. A rogue DHCP server can hide for a year
- **You see:** nothing, until the old firewall goes offline and devices start getting a strange subnet.
- **Really:** a second DHCP server on the LAN loses most races to the firewall, so nobody notices.
- **Detect:** capture DHCP replies not from the firewall's MAC; UniFi records its switch port in the client table.
- **Fix:** disable the port, then UniFi DHCP Guarding with the firewall as the only trusted server, and DHCP Snooping.

### 18. Client isolation does not protect wired devices
- **Really:** Client Device Isolation only stops Wi-Fi clients reaching each other. On a flat LAN, guests still reach printers, cameras, door controllers and the firewall's login page.
- **Fix:** guest VLAN with firewall rules, or UniFi guest/hotspot restrictions.

### 19. Switching an SSID to Hotspot can remove its password
- **You see:** after setting the SSID type to Hotspot, the network is open and a click-through portal is enabled.
- **Also:** the default restricted subnets include `172.16.0.0/12`, which may contain your firewall, so guests can lose DNS until you allow the firewall.
- **Seen on:** UniFi Network 11.0.97 with a third-party gateway

### 20. A wrong DHCP Guarding trusted server breaks DHCP
- **Really:** DHCP Guarding drops offers from any server not listed. A blank or stale trusted IP blocks your own firewall.

## 🧰 For anyone scripting pfSense

### 21. Never name a top-level PHP variable `$g`
`$g` is pfSense's global settings array. Overwriting it makes `write_config()` write `/config.xml` in the filesystem root and log "A valid config file could not be recovered". The real config is untouched, but your change is lost.

### 22. 2.9 function signatures changed
- `local_user_set_password()` expects a wrapper array (`['item' => &$user, ...]`). Passing the user directly stores nothing usable.
- `openvpn_client_export_config()` takes the server **vpnid** (not the array index) and the format `inline`.

### 23. Killing all states kills your own SSH session
`pfctl -k 0.0.0.0/0` from a script over SSH cuts off the session running it.
