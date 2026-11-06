#!/usr/bin/env python3
"""pfaudit: read-only security and reliability audit for pfSense.

Runs one read-only shell script on the firewall over SSH, parses config.xml
in memory (never written to disk), evaluates the checks in checks.toml and
prints a Markdown report (or JSON). Standard library only, Python 3.11+.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tomllib
import urllib.request
# The only XML parsed is config.xml from the firewall being audited. The stdlib
# parser does not fetch external entities, so defusedxml is not needed here.
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERSION = "0.1.0"

# Read-only commands run on the firewall. Each section starts with "@@name".
REMOTE_SCRIPT = r"""
s() { echo "@@$1"; }
s version; cat /etc/version 2>/dev/null; uname -r
s config; cat /cf/conf/config.xml
s sockstat; sockstat -4l 2>/dev/null
s crontab; cat /etc/crontab
s acbstage; ls /cf/conf/acb 2>/dev/null | wc -l
s kldstat; kldstat
s temps; sysctl -a 2>/dev/null | grep -E '^dev\.cpu\.[0-9]+\.temperature'
s cpufreq; sysctl -n dev.cpu.0.freq_levels 2>/dev/null; sysctl -n dev.cpu.0.cx_supported 2>/dev/null; sysctl -n dev.hwpstate_intel.0.epp 2>/dev/null
s aesni_cpu; grep -c AESNI /var/run/dmesg.boot 2>/dev/null
s zpool; zpool status -x 2>&1
s smart; for d in $(sysctl -n kern.disks); do echo "$d $(smartctl -H /dev/$d 2>/dev/null | grep -E 'result|Health Status' | sed 's/.*: //')"; done
s bectl; bectl list -H 2>/dev/null | wc -l
s unbound; pgrep -x unbound >/dev/null && echo running || echo stopped
s dns_local; timeout 8 drill example.com @127.0.0.1 2>/dev/null | grep -oE 'rcode: [A-Z]+' | head -1
s dns_intercept; timeout 5 drill example.com @192.0.2.1 2>/dev/null | grep -E 'rcode|IN[[:space:]]+A[[:space:]]' | grep -v '^;;.*QUEST' | head -2
s dnsbl_test; d=$(awk -F, 'NR==50{print $2}' /var/unbound/pfb_py_zone.txt 2>/dev/null); if [ -n "$d" ]; then echo "domain $d"; echo "direct $(timeout 6 drill $d @127.0.0.1 2>/dev/null | awk '/[[:space:]]IN[[:space:]]+A[[:space:]]/&&!/^;/{print $NF}' | head -1)"; echo "sub $(timeout 6 drill zz-audit-probe.$d @127.0.0.1 2>/dev/null | awk '/[[:space:]]IN[[:space:]]+A[[:space:]]/&&!/^;/{print $NF}' | head -1)"; fi
s sshd; grep -iE '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|AuthenticationMethods|PermitRootLogin)' /etc/ssh/sshd_config 2>/dev/null
s ups; for u in $(upsc -l 2>/dev/null); do echo "$u $(upsc $u@localhost ups.status 2>/dev/null)"; done
s ifconfig; ifconfig -a 2>/dev/null | grep -E '^[a-z]|options='
s certs; for f in /var/etc/cert.crt /var/etc/openvpn/server*/cert; do [ -f "$f" ] && echo "$f|$(openssl x509 -noout -enddate -in $f 2>/dev/null | cut -d= -f2)"; done
s pfinfo; pfctl -si 2>/dev/null | grep -E 'current entries'
"""

UPDATES_SCRIPT = 's() { echo "@@$1"; }\ns updates; timeout 120 pfSense-upgrade -c 2>&1 | tail -3\n'


def dhcp_scan_script(lan_if: str, fw_mac: str) -> str:
    return (
        's() { echo "@@$1"; }\ns dhcpscan; '
        f"timeout 45 tcpdump -nn -e -l -i {lan_if} -c 20 'udp src port 67 and not ether src {fw_mac}' 2>/dev/null\n"
    )


SECRET_KEY = re.compile(r"(pass|secret|key|prv|crt|hash|token|psk|tls|community)", re.I)

# --------------------------------------------------------------------- helpers


@dataclass
class Result:
    status: str  # PASS FAIL WARN INFO SKIP
    detail: str


@dataclass
class Ctx:
    host: str
    sections: dict[str, str]
    root: ET.Element
    args: argparse.Namespace
    external: dict = field(default_factory=dict)
    feeds: list = field(default_factory=list)

    def get(self, path: str, default: str | None = None) -> str | None:
        el = self.root.find(path)
        if el is None:
            return default
        return (el.text or "").strip()

    def has(self, path: str) -> bool:
        return self.root.find(path) is not None

    def all(self, path: str) -> list[ET.Element]:
        return self.root.findall(path)

    def sec(self, name: str) -> str:
        return self.sections.get(name, "").strip()

    @property
    def version(self) -> str:
        return self.sec("version").splitlines()[0] if self.sec("version") else "unknown"

    @property
    def is_29(self) -> bool:
        return self.version.startswith("2.9")


def run_remote(args: argparse.Namespace, script: str) -> str:
    cmd = ["ssh", "-o", "BatchMode=" + ("no" if args.password_env else "yes"), "-o", "ConnectTimeout=10", "-p", str(args.port)]
    for opt in args.ssh_opt or []:
        cmd += ["-o", opt]
    if args.identity:
        cmd += ["-i", args.identity]
    cmd += [f"{args.user}@{args.host}", "sh -s"]
    env = os.environ.copy()
    if args.password_env:
        if not shutil.which("sshpass"):
            sys.exit("--password-env needs sshpass installed; key authentication is recommended")
        env["SSHPASS"] = os.environ.get(args.password_env, "")
        cmd = ["sshpass", "-e"] + cmd
    proc = subprocess.run(cmd, input=script, capture_output=True, text=True, env=env, timeout=400)
    if proc.returncode != 0 and "@@" not in proc.stdout:
        sys.exit(f"SSH failed ({proc.returncode}): {proc.stderr.strip()[:300]}")
    return proc.stdout


def split_sections(out: str) -> dict[str, str]:
    sections, name, buf = {}, None, []
    for line in out.splitlines():
        if line.startswith("@@") and re.fullmatch(r"@@[a-z_0-9]+", line):
            if name:
                sections[name] = "\n".join(buf)
            name, buf = line[2:], []
        elif name:
            buf.append(line)
    if name:
        sections[name] = "\n".join(buf)
    return sections


def enabled(ctx: Ctx, path: str) -> bool:
    """pfSense treats a present element as enabled unless it says otherwise."""
    v = ctx.get(path)
    return v is not None and v.lower() not in ("disabled", "no", "off", "0", "false")


# ---------------------------------------------------------------------- checks

CHECKS: dict[str, callable] = {}


def check(cid: str):
    def wrap(fn):
        CHECKS[cid] = fn
        return fn
    return wrap


def rules(ctx: Ctx, iface: str) -> list[ET.Element]:
    return [r for r in ctx.all("filter/rule") if (r.findtext("interface") or "") == iface and r.find("disabled") is None]


def is_any(rule: ET.Element, side: str) -> bool:
    el = rule.find(side)
    return el is not None and el.find("any") is not None


@check("ACCESS-001")
def _(ctx):
    p = ctx.get("system/webgui/protocol", "https")
    return Result("PASS", "HTTPS") if p == "https" else Result("FAIL", f"WebGUI protocol is {p}")


@check("ACCESS-002")
def _(ctx):
    t = int(ctx.get("system/webgui/session_timeout") or 240)
    if t == 0:
        return Result("FAIL", "Session timeout disabled (sessions never expire)")
    return Result("PASS", f"{t} minutes") if t <= 30 else Result("WARN", f"{t} minutes (default 240); 15 to 30 recommended")


@check("ACCESS-003")
def _(ctx):
    if not ctx.has("system/ssh/enable"):
        return Result("PASS", "SSH disabled")
    cfg = ctx.sec("sshd").lower()
    pw = re.search(r"passwordauthentication\s+yes", cfg) or re.search(r"kbdinteractiveauthentication\s+yes", cfg)
    if pw:
        return Result("FAIL", "SSH enabled and accepts passwords (from sshd_config); use key-only")
    return Result("PASS", "SSH enabled, key authentication only")


@check("ACCESS-004")
def _(ctx):
    t = ctx.get("system/sshguard_threshold")
    return Result("PASS", f"threshold {t}") if t else Result("WARN", "Login protection uses the built-in default threshold; consider tightening")


@check("ACCESS-005")
def _(ctx):
    users = [u for u in ctx.all("system/user") if u.find("disabled") is None]
    names = [u.findtext("name") for u in users]
    admins = []
    for g in ctx.all("system/group"):
        if g.findtext("name") == "admins":
            uids = {m.text for m in g.findall("member")}
            admins = [u.findtext("name") for u in users if u.findtext("uid") in uids]
    if "admin" in names and len(admins) <= 1:
        return Result("WARN", "Only the shared 'admin' account has admin rights; create named admin accounts")
    return Result("PASS", f"admin accounts: {', '.join(sorted(set(admins) | {'admin'} & set(names))) or 'none'}")


@check("ACCESS-006")
def _(ctx):
    if not ctx.external:
        return Result("SKIP", "Run with --external from outside the network")
    opn = [p for p, ok in ctx.external.get("tcp", {}).items() if ok]
    mgmt = [p for p in opn if p in (22, 80, 443, 8080, 8443)]
    return Result("FAIL", f"Reachable from outside: TCP {mgmt}") if mgmt else Result("PASS", f"No management ports open from outside (tested {sorted(ctx.external.get('tcp', {}))})")


@check("ACCESS-007")
def _(ctx):
    wide = [r for r in rules(ctx, "openvpn") if r.findtext("type") == "pass" and is_any(r, "destination")]
    if wide:
        return Result("FAIL", "VPN rule passes to any destination, including the firewall GUI and SSH")
    return Result("PASS", "VPN rules are scoped")


@check("PERIM-001")
def _(ctx):
    miss = [n for n, p in (("private", "interfaces/wan/blockpriv"), ("bogons", "interfaces/wan/blockbogons")) if not ctx.has(p)]
    return Result("FAIL", f"WAN does not block: {', '.join(miss)}") if miss else Result("PASS", "Private and bogon networks blocked on WAN")


@check("PERIM-002")
def _(ctx):
    rows = []
    for r in rules(ctx, "wan"):
        if r.findtext("type") != "pass":
            continue
        dst = r.find("destination")
        port = dst.findtext("port") if dst is not None else ""
        rows.append(f"{r.findtext('protocol') or 'any'}/{port or 'any'} from {'any' if is_any(r, 'source') else 'restricted'} ({r.findtext('descr') or 'no description'})")
    nat = len(ctx.all("nat/rule"))
    detail = "; ".join(rows) if rows else "no WAN pass rules"
    return Result("INFO", f"{detail}; port forwards: {nat}")


@check("PERIM-003")
def _(ctx):
    return Result("INFO", f"State policy: {ctx.get('system/statepolicy') or 'if-bound (default)'}")


@check("PERIM-004")
def _(ctx):
    v6 = ctx.get("interfaces/wan/ipaddrv6")
    if v6 or ctx.has("system/ipv6allow"):
        return Result("INFO", f"IPv6 is enabled (WAN: {v6 or 'none'}); confirm the site uses it")
    return Result("PASS", "IPv6 off")


@check("PERIM-005")
def _(ctx):
    if not ctx.external:
        return Result("SKIP", "Run with --external from outside the network")
    rep = [p for p, ok in ctx.external.get("udp", {}).items() if ok]
    return Result("WARN", f"UDP services answer from outside: {rep}") if rep else Result("PASS", "No UDP replies from outside")


def ovpn_servers(ctx):
    return [s for s in ctx.all("openvpn/openvpn-server") if s.find("disable") is None]


@check("VPN-001")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    issues = []
    for s in srv:
        name = s.findtext("description") or s.findtext("vpnid")
        if (s.findtext("tls_type") or "") != "crypt":
            issues.append(f"{name}: tls_type {s.findtext('tls_type') or 'none'} (use crypt)")
        if (s.findtext("digest") or "").upper() in ("SHA1", "MD5"):
            issues.append(f"{name}: digest {s.findtext('digest')}")
        ciphers = (s.findtext("data_ciphers") or "") + "," + (s.findtext("data_ciphers_fallback") or "")
        if "CBC" in ciphers.upper():
            issues.append(f"{name}: CBC cipher allowed")
        dh = s.findtext("dh_length") or ""
        if dh.isdigit() and int(dh) < 2048:
            issues.append(f"{name}: DH {dh}")
    return Result("FAIL", "; ".join(issues)) if issues else Result("PASS", "TLS-crypt and modern ciphers")


@check("VPN-002")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    miss = [s.findtext("description") or "server" for s in srv if not (s.findtext("crlref") or "")]
    return Result("FAIL", f"No CRL on: {', '.join(miss)}") if miss else Result("PASS", "CRL attached")


@check("VPN-003")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    bad = [s.findtext("description") or "server" for s in srv if (s.findtext("strictusercn") or "") != "yes"]
    return Result("WARN", f"Strict user/CN off: {', '.join(bad)}") if bad else Result("PASS", "Strict user/CN on")


@check("VPN-004")
def _(ctx):
    wide = [r for r in rules(ctx, "openvpn") if r.findtext("type") == "pass" and is_any(r, "destination")]
    return Result("WARN", "VPN users can reach every LAN device") if wide else Result("PASS", "VPN access is scoped")


@check("VPN-005")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    modes = {s.findtext("authmode") or "" for s in srv}
    return Result("INFO", f"Auth: {', '.join(sorted(modes))}; no MFA detected" if modes <= {"Local Database", ""} else f"Auth: {', '.join(sorted(modes))}")


@check("VPN-006")
def _(ctx):
    if not ovpn_servers(ctx):
        return Result("SKIP", "No OpenVPN servers")
    if "if_ovpn" in ctx.sec("kldstat"):
        return Result("PASS", "DCO module loaded")
    if ctx.is_29:
        return Result("INFO", "DCO is not available on CE 2.9; revisit on 26.10")
    return Result("WARN", "DCO not loaded")


@check("VPN-007")
def _(ctx):
    out, issues = [], []
    now = datetime.now(timezone.utc)
    for line in ctx.sec("certs").splitlines():
        path, _, end = line.partition("|")
        try:
            exp = datetime.strptime(end.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        days = (exp - now).days
        label = "WebGUI" if path.endswith("cert.crt") else "OpenVPN " + path.split("/")[-2]
        out.append(f"{label} {days}d")
        if days < 30:
            issues.append(f"{label} expires in {days} days")
    used = {ctx.get("system/webgui/ssl-certref")} | {s.findtext("certref") for s in ovpn_servers(ctx)}
    noauto = [c.findtext("descr") or "cert" for c in ctx.all("cert") if c.findtext("refid") in used and (c.findtext("autorenew") or "") != "enabled"]
    if issues:
        return Result("FAIL", "; ".join(issues))
    if noauto:
        return Result("WARN", f"Auto-renew off for: {', '.join(noauto)} ({', '.join(out)})")
    return Result("PASS", ", ".join(out) or "no certificates found")


def forwarding(ctx):
    return ctx.has("unbound/forwarding")


@check("DNS-001")
def _(ctx):
    inter = "NOERROR" in ctx.sec("dns_intercept") or " IN" in ctx.sec("dns_intercept")
    if not inter:
        return Result("PASS", "Plain DNS reaches the real destination (192.0.2.1 did not answer)")
    if forwarding(ctx) and ctx.has("unbound/forward_tls_upstream"):
        return Result("PASS", "ISP intercepts plain DNS, but forwarding uses TLS so it is unaffected")
    return Result("FAIL", "Plain DNS is intercepted upstream (a reserved address answered); use DNS over TLS forwarding")


@check("DNS-002")
def _(ctx):
    if not forwarding(ctx):
        return Result("INFO", "Unbound is in resolver mode")
    if not ctx.has("unbound/forward_tls_upstream"):
        return Result("WARN", "Forwarding without TLS")
    if not ctx.get("system/dns1host"):
        return Result("WARN", "TLS forwarding without a verified hostname (system/dns1host)")
    return Result("PASS", f"TLS forwarding to {ctx.get('system/dns1host')}")


@check("DNS-003")
def _(ctx):
    if forwarding(ctx) and ctx.has("system/dnsallowoverride"):
        return Result("WARN", "DNS override on: DHCP or PPP servers can be added to forwarders")
    return Result("PASS", "DNS override off")


@check("DNS-004")
def _(ctx):
    if forwarding(ctx) and ctx.has("unbound/dnssec"):
        return Result("INFO", "DNSSEC on while forwarding; a filtering upstream's blocks will show as SERVFAIL (lesson 6)")
    return Result("INFO", f"DNSSEC {'on' if ctx.has('unbound/dnssec') else 'off'}")


@check("DNS-005")
def _(ctx):
    raw = ctx.get("unbound/custom_options") or ""
    try:
        txt = base64.b64decode(raw).decode(errors="replace") if raw else ""
    except Exception:
        txt = raw
    lines = [l.strip() for l in txt.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return Result("PASS", "No custom options")
    if lines[0].lower() == "server:":
        return Result("PASS", "Custom options start with server:")
    return Result("FAIL", "Custom options do not start with server:; Unbound breaks when forwarding is enabled")


@check("DNS-006")
def _(ctx):
    found = []
    for r in rules(ctx, "lan"):
        if r.findtext("type") in ("block", "reject"):
            port = (r.find("destination").findtext("port") if r.find("destination") is not None else "") or ""
            if port in ("53", "853"):
                found.append(port)
    nat53 = [n for n in ctx.all("nat/rule") if (n.find("destination") is not None and n.find("destination").findtext("port") == "53")]
    if "853" in found and ("53" in found or nat53):
        return Result("PASS", "LAN DNS bypass blocked")
    return Result("WARN", "Clients can use other DNS servers or DNS over TLS and bypass filtering")


@check("DNS-007")
def _(ctx):
    if ctx.sec("unbound") != "running":
        return Result("FAIL", "Unbound is not running")
    return Result("PASS", "Unbound running and resolving") if "NOERROR" in ctx.sec("dns_local") else Result("FAIL", f"Local lookup failed: {ctx.sec('dns_local') or 'no answer'}")


PFB = "installedpackages/pfblockerngdnsblsettings/config"


def pfb_installed(ctx):
    return ctx.has(PFB)


@check("PFB-001")
def _(ctx):
    if not pfb_installed(ctx):
        return Result("SKIP", "pfBlockerNG DNSBL not configured")
    m = ctx.get(f"{PFB}/dnsbl_mode")
    return Result("PASS", "Python mode") if m == "dnsbl_python" else Result("WARN", f"DNSBL mode {m or 'unset'}; Python mode recommended")


@check("PFB-002")
def _(ctx):
    if not pfb_installed(ctx) or ctx.get(f"{PFB}/pfb_dnsbl") != "on":
        return Result("SKIP", "DNSBL not enabled")
    ref = ctx.get(f"{PFB}/pfb_dnsvip4") or ""
    vip = None
    for v in ctx.all("virtualip/vip"):
        if "_vip" + (v.findtext("uniqid") or "") == ref:
            vip = v.findtext("subnet")
    listening = "lighttpd_pfb" in ctx.sec("sockstat") or "lighttpd_p" in ctx.sec("sockstat")
    if vip and listening:
        return Result("PASS", f"DNSBL VIP {vip} configured and listening")
    if ctx.get(f"{PFB}/pfb_dnsvip") and not ref:
        return Result("FAIL", "Old pfb_dnsvip setting is ignored by 3.2.17; DNSBL is effectively off (lesson 9)")
    return Result("FAIL", "DNSBL VIP missing or not listening")


@check("PFB-003")
def _(ctx):
    if not pfb_installed(ctx):
        return Result("SKIP", "pfBlockerNG not configured")
    return Result("PASS", "TLD on") if ctx.get(f"{PFB}/pfb_tld") == "on" else Result("WARN", "TLD off; wildcard lists only block exact names")


@check("PFB-004")
def _(ctx):
    if not ctx.args.feeds:
        return Result("SKIP", "Run with --feeds to test feed URLs")
    bad = [f"{u} ({why})" for u, why in ctx.feeds if why]
    return Result("WARN", f"{len(bad)} of {len(ctx.feeds)} feeds look dead or stale: " + "; ".join(bad)) if bad else Result("PASS", f"All {len(ctx.feeds)} feeds reachable")


@check("PFB-005")
def _(ctx):
    if not ctx.has("installedpackages/pfblockerngipsettings/config"):
        return Result("SKIP", "pfBlockerNG IP not configured")
    return Result("PASS", "Kill States on") if ctx.get("installedpackages/pfblockerngipsettings/config/killstates") == "on" else Result("WARN", "Kill States off")


@check("PFB-006")
def _(ctx):
    if not pfb_installed(ctx):
        return Result("SKIP", "pfBlockerNG not configured")
    return Result("PASS", "CNAME validation on") if ctx.get(f"{PFB}/pfb_cname") == "on" else Result("INFO", "CNAME validation off")


@check("PFB-007")
def _(ctx):
    if not pfb_installed(ctx):
        return Result("SKIP", "pfBlockerNG not configured")
    return Result("PASS", "Python Control on") if ctx.get(f"{PFB}/pfb_control") == "on" else Result("INFO", "Python Control off")


@check("PFB-008")
def _(ctx):
    t = ctx.sec("dnsbl_test")
    if not t:
        return Result("SKIP", "No DNSBL zone data to test")
    vals = dict(l.split(" ", 1) for l in t.splitlines() if " " in l)
    direct, sub = vals.get("direct", "").strip(), vals.get("sub", "").strip()
    if not direct:
        return Result("FAIL", f"Listed domain {vals.get('domain')} did not resolve to a block address")
    if sub != direct:
        return Result("WARN", f"Listed domain blocked ({direct}) but its subdomain was not")
    return Result("PASS", f"Listed domain and subdomain both blocked ({direct})")


@check("REC-001")
def _(ctx):
    if ctx.get("system/acb/enable") != "yes":
        return Result("WARN", "AutoConfigBackup is off")
    if "acbupload" not in ctx.sec("crontab"):
        return Result("FAIL", "ACB enabled but the upload cron job is missing; backups never leave the box (lesson 1)")
    staged = int(ctx.sec("acbstage") or 0)
    if staged > 10:
        return Result("WARN", f"ACB enabled but {staged} backups are waiting to upload")
    return Result("PASS", "ACB enabled with upload job")


@check("REC-002")
def _(ctx):
    if not ctx.has("installedpackages/patches"):
        return Result("WARN", "System Patches package not configured")
    return Result("PASS", "Recommended patches auto-apply") if ctx.has("installedpackages/patches/autoapply_recommended") else Result("WARN", "Recommended patches are not set to auto-apply")


@check("REC-003")
def _(ctx):
    n = int(ctx.sec("bectl") or 0)
    if n == 0:
        return Result("INFO", "No boot environments (UFS install?)")
    return Result("PASS", f"{n} boot environments") if n > 1 else Result("INFO", "Only the active boot environment; create one before changes")


@check("REC-004")
def _(ctx):
    u = ctx.sec("updates")
    if not u:
        return Result("SKIP", "Run with --updates to check for pfSense updates")
    return Result("PASS", "Up to date") if "up to date" in u.lower() else Result("WARN", u.splitlines()[-1][:120])


@check("MON-001")
def _(ctx):
    bad = []
    for g in ctx.all("gateways/gateway_item"):
        gw, mon = g.findtext("gateway") or "", g.findtext("monitor") or ""
        if gw and gw != "dynamic" and (not mon or mon == gw):
            bad.append(g.findtext("name") or gw)
    return Result("WARN", f"Gateway monitor pings the gateway itself: {', '.join(bad)} (lesson 3)") if bad else Result("PASS", "Gateway monitors use an internet target")


@check("MON-002")
def _(ctx):
    ok = ctx.get("notifications/smtp/ipaddress") and ctx.get("notifications/smtp/notifyemailaddress")
    return Result("PASS", "SMTP notifications configured") if ok else Result("WARN", "No email notifications configured")


@check("MON-003")
def _(ctx):
    v = ctx.get("notifications/certexpire/enable")
    return Result("WARN", "Certificate expiry alerts disabled") if v == "disabled" else Result("PASS", "Certificate expiry alerts on" + ("" if v else " (default)"))


@check("MON-004")
def _(ctx):
    return Result("PASS", "Remote syslog configured") if ctx.get("syslog/remoteserver") else Result("WARN", "Logs stay on the box only")


@check("HW-001")
def _(ctx):
    temps = [float(m) for m in re.findall(r":\s*([0-9.]+)C", ctx.sec("temps"))]
    if not temps:
        return Result("WARN", "No CPU temperature readings; set Thermal Sensors (coretemp or amdtemp)")
    hi = max(temps)
    return Result("WARN" if hi >= 80 else "PASS", f"CPU {min(temps):.0f} to {hi:.0f} C")


@check("HW-002")
def _(ctx):
    cpu_has = (ctx.sec("aesni_cpu") or "0").strip() not in ("", "0")
    if "aesni" in ctx.sec("kldstat") or ctx.get("system/crypto_hardware"):
        return Result("PASS", f"Crypto hardware: {ctx.get('system/crypto_hardware') or 'aesni module loaded'}")
    return Result("WARN", "CPU supports AES-NI but it is not enabled") if cpu_has else Result("INFO", "No AES-NI detected")


@check("HW-003")
def _(ctx):
    on = []
    cur = None
    ifs = ctx.root.find("interfaces")
    assigned = {i.findtext("if") for i in ifs} if ifs is not None else set()
    for line in ctx.sec("ifconfig").splitlines():
        if not line.startswith(("\t", " ")):
            cur = line.split(":")[0]
        elif cur in assigned:
            flags = line.split("<")[-1]
            if re.search(r"\b(TSO4|TSO6|LRO)\b", flags):
                on.append(cur)
    return Result("WARN", f"TSO or LRO active on: {', '.join(sorted(set(on)))}") if on else Result("PASS", "TSO and LRO off")


@check("HW-004")
def _(ctx):
    issues = []
    if "healthy" not in ctx.sec("zpool") and "no pools" not in ctx.sec("zpool"):
        issues.append("ZFS: " + ctx.sec("zpool").splitlines()[0][:80])
    for line in ctx.sec("smart").splitlines():
        d, _, res = line.partition(" ")
        if res and "PASSED" not in res and "OK" not in res:
            issues.append(f"{d}: SMART {res}")
    return Result("FAIL", "; ".join(issues)) if issues else Result("PASS", "ZFS and SMART healthy")


@check("HW-005")
def _(ctx):
    f = ctx.sec("cpufreq")
    return Result("INFO", "Frequency scaling data: " + (" | ".join(f.splitlines())[:150] if f else "none exposed (scaling likely controlled in BIOS)"))


@check("HW-006")
def _(ctx):
    return Result("INFO", "Manual: pull AC while running and confirm it boots unattended")


@check("UPS-001")
def _(ctx):
    if not ctx.has("installedpackages/nut/config"):
        return Result("SKIP", "NUT not configured")
    st = ctx.sec("ups")
    if " OL" not in f" {st}" and "OL" not in st:
        return Result("FAIL", f"UPS status: {st or 'no response'}")
    if ctx.get("installedpackages/nut/config/email") != "yes":
        return Result("WARN", "UPS online but power-event emails are off (lesson 4)")
    return Result("PASS", f"UPS online, alerts on ({st})")


for _cid in ("UNIFI-001", "UNIFI-002", "UNIFI-003", "UNIFI-004", "UNIFI-005", "UNIFI-007"):
    CHECKS[_cid] = lambda ctx: Result("SKIP", "Needs UniFi controller access (not yet implemented)")


@check("UNIFI-006")
def _(ctx):
    if not ctx.args.dhcp_scan:
        return Result("SKIP", "Run with --dhcp-scan to listen 45 s for rogue DHCP servers")
    lines = [l for l in ctx.sec("dhcpscan").splitlines() if l.strip()]
    if not lines:
        return Result("PASS", "No DHCP replies from other servers")
    macs = sorted({l.split()[1] if len(l.split()) > 1 else "?" for l in lines})
    return Result("FAIL", f"Other DHCP servers answering on LAN: {', '.join(macs)} (lesson 17)")


# ----------------------------------------------------------- external + feeds


def external_tests(ctx: Ctx) -> dict:
    ip = ctx.get("interfaces/wan/ipaddr") or ""
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
        return {"error": "WAN address is dynamic; pass --wan-ip"}
    ip = ctx.args.wan_ip or ip
    tcp = {}
    for p in (21, 22, 23, 80, 443, 3389, 8080, 8443):
        with socket.socket() as s:
            s.settimeout(3)
            tcp[p] = s.connect_ex((ip, p)) == 0
    udp = {}
    probes = {53: bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001"), 123: b"\x1b" + b"\0" * 47, 161: bytes.fromhex("302902010004067075626c6963a01c0204000000010201000201003011300f060b2b060102010101000500"), 1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"}
    for p, payload in probes.items():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.sendto(payload, (ip, p))
                s.recvfrom(1500)
                udp[p] = True
            except OSError:
                udp[p] = False
    return {"ip": ip, "tcp": tcp, "udp": udp}


def feed_tests(ctx: Ctx) -> list:
    urls = set()
    for sec in ("pfblockernglistsv4", "pfblockerngdnsbl"):
        for row in ctx.all(f"installedpackages/{sec}/config/row"):
            if (row.findtext("state") or "Enabled") == "Enabled" and (row.findtext("url") or "").startswith("http"):
                urls.add(row.findtext("url"))
    out = []
    for u in sorted(urls):
        why = ""
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "pfaudit"})
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read(200000)
                if len(body) < 200:
                    why = f"only {len(body)} bytes"
        except Exception as e:  # noqa: BLE001 report any failure
            why = str(getattr(e, "code", "")) or type(e).__name__
        out.append((u, why))
    return out


# --------------------------------------------------------------------- report

ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3, "SKIP": 4}
ICON = {"FAIL": "🔴", "WARN": "🟠", "INFO": "🔵", "PASS": "🟢", "SKIP": "⚪"}
RISK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build(catalog, ctx):
    results = []
    for c in catalog:
        fn = CHECKS.get(c["id"])
        try:
            r = fn(ctx) if fn else Result("SKIP", "No implementation yet")
        except Exception as e:  # noqa: BLE001 one broken check must not stop the audit
            r = Result("SKIP", f"Check error: {type(e).__name__}: {e}")
        unverified = "unverified" in c.get("verified_on", [])
        if unverified and r.status == "FAIL":
            r = Result("WARN", r.detail + " (check not yet verified on a live system)")
        results.append({**c, "status": r.status, "detail": r.detail})
    results.sort(key=lambda x: (ORDER[x["status"]], RISK.get(x["risk"], 9), x["id"]))
    return results


def markdown(results, ctx) -> str:
    counts = {k: sum(1 for r in results if r["status"] == k) for k in ORDER}
    host = ctx.get("system/hostname", "?") + "." + (ctx.get("system/domain") or "")
    out = [f"# pfSense audit: {host.rstrip('.')}", "",
           f"pfSense {ctx.version} · {datetime.now().strftime('%Y-%m-%d %H:%M')} · pfaudit {VERSION}", "",
           " · ".join(f"{ICON[k]} {counts[k]} {k}" for k in ORDER), ""]
    for status, title in (("FAIL", "Fix now"), ("WARN", "Fix soon"), ("INFO", "For your information"), ("PASS", "Good"), ("SKIP", "Not checked")):
        rows = [r for r in results if r["status"] == status]
        if not rows:
            continue
        out += [f"## {ICON[status]} {title}", ""]
        for r in rows:
            out.append(f"- **{r['title']}** `{r['id']}` · {r['risk']} risk  ")
            out.append(f"  {r['detail']}")
            if status in ("FAIL", "WARN") and r.get("fix"):
                out.append(f"  *Fix:* {r['fix']}" + (f" *Impact:* {r['impact']}" if r.get("impact") else ""))
        out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Read-only pfSense audit")
    ap.add_argument("host")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--identity", help="SSH private key")
    ap.add_argument("--password-env", help="Name of an environment variable holding the SSH password (needs sshpass)")
    ap.add_argument("--ssh-opt", action="append", help="Extra ssh -o option, repeatable")
    ap.add_argument("--external", action="store_true", help="Probe the WAN address from this machine (run from outside)")
    ap.add_argument("--wan-ip", help="WAN address for --external when it is dynamic")
    ap.add_argument("--feeds", action="store_true", help="Test pfBlockerNG feed URLs")
    ap.add_argument("--updates", action="store_true", help="Ask the firewall to check for updates (slow)")
    ap.add_argument("--dhcp-scan", action="store_true", help="Listen 45 s on LAN for other DHCP servers")
    ap.add_argument("--json", action="store_true", help="JSON output instead of Markdown")
    args = ap.parse_args()

    catalog = tomllib.loads((HERE / "checks.toml").read_text())["checks"]
    sections = split_sections(run_remote(args, REMOTE_SCRIPT))
    try:
        root = ET.fromstring(sections.pop("config"))
    except (KeyError, ET.ParseError) as e:
        sys.exit(f"Could not read config.xml: {e}")
    ctx = Ctx(args.host, sections, root, args)
    if args.updates:
        ctx.sections.update(split_sections(run_remote(args, UPDATES_SCRIPT)))
    if args.dhcp_scan:
        lan_if = ctx.get("interfaces/lan/if") or ""
        mac = ""
        for line in run_remote(args, f"ifconfig {lan_if} | grep ether").splitlines():
            mac = line.split()[-1]
        if re.fullmatch(r"[a-z0-9]+", lan_if) and re.fullmatch(r"[0-9a-f:]{17}", mac):
            ctx.sections.update(split_sections(run_remote(args, dhcp_scan_script(lan_if, mac))))
    if args.external:
        ctx.external = external_tests(ctx)
    if args.feeds:
        ctx.feeds = feed_tests(ctx)

    results = build(catalog, ctx)
    del root  # the config never leaves memory and is not kept
    if args.json:
        print(json.dumps({"version": ctx.version, "pfaudit": VERSION, "results": results}, indent=2, default=str))
    else:
        print(markdown(results, ctx))
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
