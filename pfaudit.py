#!/usr/bin/env python3
"""pfaudit: read-only security and reliability audit for pfSense.

Runs one read-only shell script on the firewall over SSH, parses config.xml
in memory (never written to disk), evaluates the checks in checks.toml and
prints a Markdown report (or JSON). Standard library only, Python 3.11+.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
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
    unifi: dict = field(default_factory=dict)

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
    if not cfg:  # no lines read: cannot claim key-only (OpenSSH defaults to passwords on)
        return Result("WARN", "SSH enabled, but sshd_config could not be read to confirm key-only login")
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
    if ctx.external.get("error"):
        return Result("SKIP", f"External test not run: {ctx.external['error']}")
    opn = [p for p, ok in ctx.external.get("tcp", {}).items() if ok]
    mgmt = [p for p in opn if p in (22, 80, 443, 8080, 8443)]
    return Result("FAIL", f"Reachable from outside: TCP {mgmt}") if mgmt else Result("PASS", f"No management ports open from outside (tested {sorted(ctx.external.get('tcp', {}))})")


@check("ACCESS-007")
def _(ctx):
    # pf evaluates rules in order: a block to the firewall itself placed above
    # the broad pass protects management even when "pass any" follows it.
    exceptions = []
    for r in rules(ctx, "openvpn"):
        dst = r.find("destination")
        to_self = dst is not None and (dst.findtext("network") or "") == "(self)"
        if r.findtext("type") in ("block", "reject") and to_self:
            note = f" (allowed first: {', '.join(exceptions)})" if exceptions else ""
            return Result("PASS", "VPN users are blocked from firewall management" + note)
        if r.findtext("type") == "pass" and is_any(r, "destination"):
            if is_any(r, "source"):
                return Result("FAIL", "VPN rule passes to any destination, including the firewall GUI and SSH")
            src = r.find("source")
            exceptions.append((src.findtext("address") or src.findtext("network") or "a specific source") if src is not None else "a specific source")
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
    if ctx.external.get("error"):
        return Result("SKIP", f"External test not run: {ctx.external['error']}")
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
    # One "<name> <status flags>" line per UPS; every UPS must report OL.
    rows = [line.split()[1:] for line in st.splitlines() if line.strip()]
    if not rows or any("OL" not in flags for flags in rows):
        return Result("FAIL", f"UPS status: {st or 'no response'}")
    if ctx.get("installedpackages/nut/config/email") != "yes":
        return Result("WARN", "UPS online but power-event emails are off (lesson 4)")
    return Result("PASS", f"UPS online, alerts on ({st})")


IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")
GUEST_NAME = re.compile(r"guest|visitor|public|hotspot", re.I)


def fw_lan_ip(ctx) -> str | None:
    ip = ctx.get("interfaces/lan/ipaddr") or ""
    return ip if IPV4.fullmatch(ip) else None


def fw_vlan_ips(ctx) -> dict[int, str]:
    """VLAN tag to firewall interface address, from vlans/vlan and interfaces/*."""
    tags = {}
    for v in ctx.all("vlans/vlan"):
        tag = (v.findtext("tag") or "").strip()
        if tag.isdigit():
            tags[(v.findtext("vlanif") or "").strip()] = int(tag)
    out = {}
    ifs = ctx.root.find("interfaces")
    for i in ifs if ifs is not None else []:
        ip = (i.findtext("ipaddr") or "").strip()
        tag = tags.get((i.findtext("if") or "").strip())
        if tag is not None and IPV4.fullmatch(ip):
            out[tag] = ip
    return out


def fw_ip_for_vlan(ctx, vlan: int | None) -> str | None:
    """Firewall address a UniFi network should trust: its VLAN interface, or LAN when untagged."""
    if vlan in (None, 0, 1):
        return fw_lan_ip(ctx)
    return fw_vlan_ips(ctx).get(vlan)


def _unifi(ctx, part: str | None = None):
    """(data, None) when UniFi data is usable, else (None, SKIP result)."""
    if not getattr(ctx.args, "unifi", None):
        return None, Result("SKIP", "Run with --unifi https://<controller> and --unifi-key-env to read the UniFi controller")
    u = ctx.unifi or {}
    if u.get("fatal"):
        return None, Result("SKIP", f"UniFi: {u['fatal']}")
    if part and not u.get(part):
        why = "; ".join(u.get("errors", [])) or "no data returned"
        return None, Result("SKIP", f"Needs the UniFi {part} API, which was not available ({why[:200]})")
    return u, None


def _as_bool(v) -> bool:
    return v is True or str(v).lower() in ("true", "1", "yes", "on")


def _vlan(v) -> int | None:
    return int(v) if str(v).strip().isdigit() else None


def unifi_networks(u: dict) -> tuple[list[dict] | None, str]:
    """Networks as {name, vlan, enabled, guard, trusted, purpose}, Integration API first."""
    nets = (u.get("integration") or {}).get("networks")
    if nets is not None:
        out = []
        for n in nets:
            g = n.get("dhcpGuarding")
            trusted = [str(x) for x in (g or {}).get("trustedDhcpServerIpAddresses") or []] if isinstance(g, dict) else []
            out.append({"name": n.get("name") or n.get("id") or "?", "vlan": _vlan(n.get("vlanId")), "enabled": n.get("enabled", True) is not False,
                        "guard": bool(trusted), "trusted": trusted, "purpose": ""})
        return out, "Integration API"
    legacy = (u.get("legacy") or {}).get("networkconf")
    if legacy is not None:
        out = []
        for n in legacy:
            purpose = (n.get("purpose") or "").lower()
            if purpose in ("wan", "remote-user-vpn", "site-vpn", "vpn-client"):
                continue
            vlan = _vlan(n.get("vlan")) if n.get("vlan_enabled", True) is not False else None
            trusted = [str(n[k]) for k in ("dhcpd_ip_1", "dhcpd_ip_2", "dhcpd_ip_3") if n.get(k)]
            out.append({"name": n.get("name") or "?", "vlan": vlan, "enabled": n.get("enabled", True) is not False,
                        "guard": _as_bool(n.get("dhcpguard_enabled")), "trusted": trusted, "purpose": purpose})
        return out, "legacy API"
    return None, ""


@check("UNIFI-001")
def _(ctx):
    u, skip = _unifi(ctx)
    if skip:
        return skip
    nets, src = unifi_networks(u)
    if nets is None:
        return Result("SKIP", "No UniFi network data (needs Network 10.0 or newer for the Integration API, or the legacy API): " + "; ".join(u.get("errors", []))[:200])
    off, wrong, ok, unmapped = [], [], [], []
    for n in nets:
        if not n["enabled"]:
            continue
        want = fw_ip_for_vlan(ctx, n["vlan"])
        if want is None:
            unmapped.append(n["name"])
        elif not n["guard"]:
            off.append(f"{n['name']} (VLAN {n['vlan'] or 'untagged'})")
        elif want not in n["trusted"]:
            wrong.append(f"{n['name']} trusts {', '.join(n['trusted']) or 'nothing'}, firewall is {want}")
        else:
            ok.append(n["name"])
    note = f" (source: {src}" + (f"; no firewall interface for: {', '.join(unmapped)}" if unmapped else "") + ")"
    if off:
        return Result("FAIL", "DHCP Guarding off on: " + "; ".join(off) + note)
    if wrong:
        return Result("WARN", "DHCP Guarding trusts the wrong server: " + "; ".join(wrong) + " (lesson 20)" + note)
    if not ok:
        return Result("INFO", "No UniFi network matched a firewall interface" + note)
    return Result("PASS", f"DHCP Guarding on with the firewall trusted: {', '.join(ok)}" + note)


@check("UNIFI-002")
def _(ctx):
    u, skip = _unifi(ctx, "legacy")
    if skip:
        return skip
    sw = (u["legacy"].get("settings") or {}).get("global_switch")
    if sw is None or "dhcp_snoop" not in sw:
        return Result("SKIP", "global_switch setting not returned by the controller")
    return Result("PASS", "DHCP Snooping on") if _as_bool(sw["dhcp_snoop"]) else Result("WARN", "DHCP Snooping off on UniFi switches (lesson 17)")


@check("UNIFI-003")
def _(ctx):
    u, skip = _unifi(ctx)
    if skip:
        return skip
    intended = {s.lower() for s in getattr(ctx.args, "unifi_open_ssid", None) or []}
    fails, warns, infos = [], [], []
    legacy = (u.get("legacy") or {}).get("wlanconf")
    integ = (u.get("integration") or {}).get("wlans")
    if legacy is not None:
        src = "legacy API"
        wlans = [{"name": w.get("name") or "?", "guest": _as_bool(w.get("is_guest")), "open": (w.get("security") or "").lower() == "open",
                  "iso": _as_bool(w.get("l2_isolation"))} for w in legacy if w.get("enabled", True) is not False]
    elif integ is not None:
        # hotspotConfiguration is CAPTIVE_PORTAL or PASSPOINT (11.0.97 spec). Passpoint
        # (Hotspot 2.0) uses enterprise authentication and is not a guest network.
        src = "Integration API; it has no guest flag, so a captive portal counts as guest"
        wlans = [{"name": w.get("name") or "?",
                  "guest": isinstance(w.get("hotspotConfiguration"), dict)
                  and str(w["hotspotConfiguration"].get("type") or "").upper() == "CAPTIVE_PORTAL",
                  "open": ((w.get("securityConfiguration") or {}).get("type") or "").upper() == "OPEN",
                  "iso": _as_bool(w.get("clientIsolationEnabled"))} for w in integ if w.get("enabled", True) is not False]
    else:
        return Result("SKIP", "No UniFi Wi-Fi data: " + "; ".join(u.get("errors", []))[:200])
    for w in wlans:
        name = w["name"]
        if w["open"] and name.lower() in intended:
            infos.append(f"{name} is open by intent")
        elif w["open"] and w["guest"]:
            fails.append(f"guest SSID {name} is open (no password)")
        elif w["open"]:
            warns.append(f"SSID {name} is open")
        if w["guest"] and not w["iso"]:
            warns.append(f"guest SSID {name} has client isolation off")
        if not w["guest"] and legacy is not None and GUEST_NAME.search(name):
            warns.append(f"{name} looks like a guest SSID but is not marked guest")
    guests = [w["name"] for w in wlans if w["guest"]]
    note = f" (source: {src})"
    if fails:
        return Result("FAIL", "; ".join(fails + warns) + " (lesson 19)" + note)
    if warns:
        return Result("WARN", "; ".join(warns + infos) + note)
    if not guests:
        return Result("INFO", "No SSID is marked guest" + ("; " + "; ".join(infos) if infos else "") + note)
    return Result("PASS", f"Guest SSIDs marked and password protected: {', '.join(guests)}" + ("; " + "; ".join(infos) if infos else "") + note)


def guest_subnets(section: dict, kind: str) -> list:
    """Parse restricted_subnet / allowed_subnet, single or numbered (_1.._n), string or list."""
    nets = []
    for k, v in section.items():
        if not re.fullmatch(rf"{kind}_subnet(_\d+)?", k):
            continue
        for item in v if isinstance(v, list) else re.split(r"[,\s]+", str(v or "")):
            try:
                nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
            except ValueError:
                continue
    return nets


@check("UNIFI-004")
def _(ctx):
    u, skip = _unifi(ctx, "legacy")
    if skip:
        return skip
    leg = u["legacy"]
    ga = (leg.get("settings") or {}).get("guest_access")
    if ga is None:
        return Result("SKIP", "guest_access setting not returned by the controller")
    guest_wlans = [w for w in leg.get("wlanconf") or [] if _as_bool(w.get("is_guest"))]
    guest_nets = [n for n in leg.get("networkconf") or [] if (n.get("purpose") or "").lower() == "guest"]
    if not guest_wlans and not guest_nets:
        return Result("INFO", "No guest SSIDs or guest networks, so guest restrictions are not in use")
    fw = {ip for ip in [fw_lan_ip(ctx)] + [fw_ip_for_vlan(ctx, _vlan(n.get("vlan"))) for n in guest_nets] if ip}
    if not fw:
        return Result("SKIP", "No firewall LAN address in config to compare")
    restricted, allowed = guest_subnets(ga, "restricted"), guest_subnets(ga, "allowed")
    blocked = sorted(ip for ip in fw if any(ipaddress.ip_address(ip) in n for n in restricted)
                     and not any(ipaddress.ip_address(ip) in n for n in allowed))
    if blocked:
        return Result("WARN", f"Guest restricted subnets include the firewall ({', '.join(blocked)}) and it is not in Allowed subnets; guests can lose DNS and DHCP (lesson 19)")
    return Result("PASS", f"Firewall {', '.join(sorted(fw))} reachable for guests ({len(restricted)} restricted, {len(allowed)} allowed subnets)")


LEGACY_BAD_STATE = {0: "disconnected", 9: "inform error", 10: "adoption failed", 11: "isolated"}


@check("UNIFI-005")
def _(ctx):
    u, skip = _unifi(ctx)
    if skip:
        return skip
    expect = set(u.get("controller_hosts") or [])
    legacy = (u.get("legacy") or {}).get("devices")
    if legacy is not None:
        wrong, bad, ok = [], [], 0
        for d in legacy:
            if d.get("adopted") is False:
                continue
            name = d.get("name") or d.get("model") or "device"
            host = urlsplit(str(d.get("inform_url") or "")).hostname or ""
            ip = str(d.get("inform_ip") or "")
            if not host and not ip:
                bad.append(f"{name} reports no inform address")
            elif not ({host, ip} & expect):
                wrong.append(f"{name} informs to {host or ip}")
            else:
                ok += 1
            st = d.get("state")
            if isinstance(st, int) and st in LEGACY_BAD_STATE:
                bad.append(f"{name} {LEGACY_BAD_STATE[st]}")
        if wrong or bad:
            return Result("WARN", "; ".join(wrong + bad) + f" (controller: {', '.join(sorted(expect))})")
        return Result("PASS", f"{ok} devices inform to {', '.join(sorted(expect))} (source: legacy API)")
    devs = (u.get("integration") or {}).get("devices")
    if devs is None:
        return Result("SKIP", "No UniFi device data: " + "; ".join(u.get("errors", []))[:200])
    down = [f"{d.get('name') or d.get('model') or 'device'} {d.get('state')}" for d in devs if d.get("state") not in ("ONLINE", None)]
    if down:
        return Result("WARN", f"Devices not online: {'; '.join(down)}; the inform host needs the legacy API")
    return Result("INFO", f"{len(devs)} devices online; the inform host is only exposed by the legacy API, so it was not compared")


@check("UNIFI-007")
def _(ctx):
    u, skip = _unifi(ctx)
    if skip:
        return skip
    parts = []
    mgmt = ((u.get("legacy") or {}).get("settings") or {}).get("mgmt")
    if mgmt is not None and "auto_upgrade" in mgmt:
        if _as_bool(mgmt["auto_upgrade"]):
            hour = mgmt.get("auto_upgrade_hour")
            parts.append("Device auto-upgrade on" + (f" at hour {hour}" if hour is not None else "") + "; switches and APs reboot on their own")
        else:
            parts.append("Device auto-upgrade off; schedule firmware updates yourself")
        if _as_bool(mgmt.get("x_ssh_enabled")):
            parts.append("device SSH on" + (" and accepts passwords (keys only recommended)" if _as_bool(mgmt.get("x_ssh_auth_password_enabled")) else ", key only"))
    else:
        parts.append("Auto-upgrade setting is only exposed by the legacy API" + (": " + "; ".join(u.get("errors", []))[:160] if u.get("errors") else ""))
    devs = (u.get("integration") or {}).get("devices")
    if devs:
        n = sum(1 for d in devs if d.get("firmwareUpdatable"))
        parts.append(f"{n} of {len(devs)} devices have a firmware update available")
    return Result("INFO", "; ".join(parts))


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
    # --wan-ip first: it exists for the dynamic WAN case (ipaddr "dhcp" or "pppoe").
    ip = getattr(ctx.args, "wan_ip", None) or ctx.get("interfaces/wan/ipaddr") or ""
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
        return {"error": "WAN address is dynamic; pass --wan-ip"}
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


def public_url(url: str) -> bool:
    """True only for http(s) URLs whose host resolves solely to public addresses."""
    import ipaddress
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            return False
    return True


def safe_url(url: str) -> str:
    """URL for display: no credentials, query string or fragment."""
    from urllib.parse import urlsplit, urlunsplit
    p = urlsplit(url)
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return urlunsplit((p.scheme, host, p.path, "", "")) + ("?..." if p.query else "")


def _require_public_peer(sock) -> None:
    import ipaddress
    peer = ipaddress.ip_address(sock.getpeername()[0])
    if not peer.is_global or peer.is_multicast:
        sock.close()
        raise urllib.error.URLError(f"connected to non-public address {peer}; blocked")


class _PublicHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _require_public_peer(self.sock)


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # Plain TCP first, check the peer, and only then start TLS, so nothing
        # (not even a TLS hello) reaches a non-public address.
        http.client.HTTPConnection.connect(self)
        _require_public_peer(self.sock)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PublicHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PublicHTTPConnection, req)


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PublicHTTPSConnection, req, context=self._context)


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_url(newurl):
            raise urllib.error.URLError("redirect to a non-public address blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def feed_tests(ctx: Ctx) -> list:
    urls = set()
    for sec in ("pfblockernglistsv4", "pfblockerngdnsbl"):
        for row in ctx.all(f"installedpackages/{sec}/config/row"):
            if (row.findtext("state") or "Enabled") == "Enabled" and (row.findtext("url") or "").startswith("http"):
                urls.add(row.findtext("url"))
    # No environment proxies, a pre-check on every hop, and a check of the live
    # socket's peer address, so DNS rebinding cannot reach internal hosts.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PublicHTTPHandler, _PublicHTTPSHandler, _CheckedRedirect)
    out = []
    for u in sorted(urls):
        why = ""
        if not public_url(u):
            out.append((safe_url(u), "skipped: not a public address"))
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "pfaudit"})
            with opener.open(req, timeout=20) as r:
                body = r.read(200000)
                if len(body) < 200:
                    why = f"only {len(body)} bytes"
        except Exception as e:  # noqa: BLE001 report any failure
            why = str(getattr(e, "code", "")) or type(e).__name__
        out.append((safe_url(u), why))
    return out


# ---------------------------------------------------------------------- UniFi
#
# Read-only collector for a UniFi Network controller on UniFi OS (Cloud Key,
# UDM, UCG, UniFi OS Server). Every request is a GET with an X-API-KEY header:
#   Integration API: /proxy/network/integration/v1/...  (documented, Network 10.0+
#     for networks and Wi-Fi; spec checked: developer.ui.com/network/v11.0.97)
#   legacy API: /proxy/network/api/s/<site>/...  (undocumented; whether it
#     accepts an API key is unconfirmed, see README)
# There is no session login, because that needs a POST. Secret fields are
# dropped as soon as a response is decoded, and nothing is written to disk.

UNIFI_INT = "/proxy/network/integration"
UNIFI_KEEP = {"x_ssh_enabled", "x_ssh_auth_password_enabled", "x_ssh_bind_wildcard"}
UNIFI_SECRET = re.compile(r"^x_|passphrase|presharedkey|password|passwd|secret|psk|private_?key|token", re.I)


def unifi_scrub(obj):
    """Drop secret fields (x_passphrase, x_ssh_password, passphrase, presharedKeys ...)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in UNIFI_KEEP:
                out[k] = _as_bool(v)
            elif not (isinstance(k, str) and UNIFI_SECRET.search(k)):
                out[k] = unifi_scrub(v)
        return out
    if isinstance(obj, list):
        return [unifi_scrub(v) for v in obj]
    return obj


class UnifiError(Exception):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib copies request headers, including X-API-KEY, onto a redirect, so
    # refuse every redirect (raising HTTPError is the documented way).
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class UnifiClient:
    MAX_BYTES = 20_000_000

    def __init__(self, base: str, key: str, cafile: str | None = None, insecure: bool = False, timeout: int = 20):
        p = urlsplit(base)
        if p.scheme != "https" or not p.hostname:
            raise UnifiError("--unifi must be an https:// URL")
        if p.username or p.password or p.query:
            raise UnifiError("--unifi must not contain credentials or a query string")
        self.base = urlunsplit(("https", p.netloc, p.path.rstrip("/"), "", ""))
        self.host = p.hostname
        if insecure:
            tls = ssl.create_default_context()
            tls.check_hostname = False  # must come before CERT_NONE
            tls.verify_mode = ssl.CERT_NONE
        else:
            tls = ssl.create_default_context(cafile=cafile)
        self.tls = "insecure" if insecure else ("ca-file" if cafile else "system trust")
        self._key = key
        self._timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), _NoRedirect)

    def get(self, path: str, params: dict | None = None):
        url = self.base + path + ("?" + urlencode(params) if params else "")
        req = urllib.request.Request(url, method="GET", headers={"X-API-KEY": self._key, "Accept": "application/json", "User-Agent": f"pfaudit/{VERSION}"})
        try:
            with self._opener.open(req, timeout=self._timeout) as r:
                body = r.read(self.MAX_BYTES + 1)
        except urllib.error.HTTPError as e:
            raise UnifiError(f"HTTP {e.code} on {path}" + (" (redirect not followed)" if 300 <= e.code < 400 else ""), e.code) from None
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                why = str(reason.verify_message or reason).rstrip(".")
                if "hostname" in why.lower():
                    hint = " Use the name the certificate was issued for in the --unifi URL."
                else:
                    hint = " Pass --unifi-ca with the console certificate, or --unifi-insecure."
                    if sys.version_info >= (3, 13):
                        hint += " Python 3.13+ applies strict X.509 checks, which some self-signed console certificates fail."
                raise UnifiError(f"TLS verification failed for {self.host}: {why}.{hint}") from None
            raise UnifiError(f"cannot reach {self.host}: {reason}") from None
        except (OSError, http.client.HTTPException) as e:
            raise UnifiError(f"cannot reach {self.host}: {type(e).__name__}") from None
        if len(body) > self.MAX_BYTES:
            raise UnifiError(f"response too large on {path}")
        try:
            return unifi_scrub(json.loads(body))
        except ValueError:
            raise UnifiError(f"non-JSON response on {path}") from None

    def pages(self, path: str) -> list:
        """All items of an Integration API list (offset/limit, limit max 200)."""
        out, offset = [], 0
        for _ in range(100):
            d = self.get(path, {"offset": offset, "limit": 200})
            data = d.get("data") if isinstance(d, dict) else None
            if not isinstance(data, list) or not data:
                break
            out += data
            offset += len(data)
            if offset >= int(d.get("totalCount") or 0):
                break
        return out

    def legacy(self, path: str) -> list:
        """A legacy API call; unwraps {meta: {rc}, data: [...]}."""
        d = self.get(path)
        if isinstance(d, dict) and isinstance(d.get("meta"), dict) and d["meta"].get("rc") not in (None, "ok"):
            raise UnifiError(f"{path}: {d['meta'].get('msg') or d['meta'].get('rc')}")
        data = d.get("data") if isinstance(d, dict) else d
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def unifi_collect(client, site: str) -> dict:
    """Fetch what the UNIFI checks need. Returns plain dicts, secrets removed."""
    u = {"url": safe_url(client.base), "tls": client.tls, "version": None, "errors": [], "integration": None, "legacy": None,
         "controller_hosts": [client.host]}
    try:
        u["controller_hosts"] += sorted({i[4][0] for i in socket.getaddrinfo(client.host, None)} - {client.host})
    except OSError:
        pass
    try:
        info = client.get(UNIFI_INT + "/v1/info")
        u["version"] = str((info or {}).get("applicationVersion") or "") or None
        sites = client.pages(UNIFI_INT + "/v1/sites")
        match = [s for s in sites if site in (s.get("internalReference"), s.get("name"))] or (sites if len(sites) == 1 else [])
        if not match or not match[0].get("id"):
            u["errors"].append(f"Integration API: site {site!r} not found")
        else:
            base = f"{UNIFI_INT}/v1/sites/{quote(str(match[0]['id']), safe='')}"
            u["integration"] = integ = {"site": match[0].get("name"), "devices": client.pages(base + "/devices")}
            # The first published spec with networks and Wi-Fi is 10.0.162 (9.5.21
            # has neither); earlier 10.0 builds are untested, so try them and let a
            # 404 drop only that part. Each part is all or nothing: a partial list
            # would let a check pass on networks it never saw, so on any failure
            # the key is left out and the checks fall back to the legacy API.
            if _version(u["version"] or "") >= (10, 0):
                for key, path in (("networks", "/networks"), ("wlans", "/wifi/broadcasts")):
                    try:
                        integ[key] = [client.get(f"{base}{path}/{quote(str(x['id']), safe='')}") for x in client.pages(base + path) if x.get("id")]
                    except UnifiError as e:
                        u["errors"].append(f"Integration API {key}: {e}")
            else:
                u["errors"].append(f"Integration API {u['version'] or 'unknown version'} has no networks or Wi-Fi (needs 10.0+)")
    except UnifiError as e:
        u["errors"].append(f"Integration API: {e}")
    leg, prefix = {}, f"/proxy/network/api/s/{quote(site, safe='')}"
    for name, path in (("settings", "/get/setting"), ("networkconf", "/rest/networkconf"), ("wlanconf", "/rest/wlanconf"), ("devices", "/stat/device")):
        try:
            rows = client.legacy(prefix + path)
        except UnifiError as e:
            u["errors"].append(f"legacy API: {e}")
            if e.status in (401, 403) or (e.status and 300 <= e.status < 400):
                break  # the key is refused here; do not keep knocking
            continue
        leg[name] = {r.get("key"): r for r in rows if r.get("key")} if name == "settings" else rows
    u["legacy"] = leg or None
    return u


def unifi_from_args(args) -> dict:
    key = os.environ.get(args.unifi_key_env or "", "")
    if not key:
        return {"fatal": f"no API key in environment variable {args.unifi_key_env}", "tls": "n/a", "errors": []}
    try:
        client = UnifiClient(args.unifi, key, cafile=args.unifi_ca, insecure=args.unifi_insecure)
    except (UnifiError, OSError, ssl.SSLError) as e:
        return {"fatal": str(e), "tls": "n/a", "errors": []}
    u = unifi_collect(client, args.unifi_site)
    if not u["integration"] and not u["legacy"]:
        u["fatal"] = "; ".join(u["errors"])[:300] or "no data"
    return u


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
    if ctx.unifi:
        out += [f"UniFi controller {ctx.unifi.get('url', '?')} · Network {ctx.unifi.get('version') or 'unknown'} · TLS {ctx.unifi.get('tls')}", ""]
        if ctx.unifi.get("tls") == "insecure":
            out += ["> [!WARNING]", "> UniFi TLS verification was disabled with `--unifi-insecure`. The controller's identity was not checked, so these UniFi results and the API key were exposed to anyone able to intercept the connection.", ""]
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
    ap.add_argument("--unifi", metavar="URL", help="UniFi OS console base URL, e.g. https://unifi.example.com (read-only GETs)")
    ap.add_argument("--unifi-key-env", metavar="NAME", default="UNIFI_API_KEY", help="Environment variable holding the UniFi API key (default UNIFI_API_KEY)")
    ap.add_argument("--unifi-site", default="default", help="UniFi site short name (internalReference), default 'default'")
    ap.add_argument("--unifi-ca", metavar="FILE", help="CA bundle or the console's certificate for TLS verification")
    ap.add_argument("--unifi-insecure", action="store_true", help="Skip UniFi TLS verification (explicit opt-in; flagged in the report)")
    ap.add_argument("--unifi-open-ssid", metavar="NAME", action="append", help="SSID that is open on purpose (UNIFI-003 reports it as INFO), repeatable")
    ap.add_argument("--json", action="store_true", help="JSON output instead of Markdown")
    args = ap.parse_args()
    if args.unifi_insecure and args.unifi_ca:
        ap.error("--unifi-insecure and --unifi-ca cannot be combined")

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
    if args.unifi:
        ctx.unifi = unifi_from_args(args)

    results = build(catalog, ctx)
    del root  # the config never leaves memory and is not kept
    if args.json:
        doc = {"version": ctx.version, "pfaudit": VERSION, "results": results}
        if ctx.unifi:  # summary only; raw controller data is never output
            doc["unifi"] = {k: ctx.unifi.get(k) for k in ("url", "version", "tls", "errors", "fatal")}
        print(json.dumps(doc, indent=2, default=str))
    else:
        print(markdown(results, ctx))
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
