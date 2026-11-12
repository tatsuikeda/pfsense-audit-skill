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
s acbold; find /cf/conf/acb -type f -mmin +15 2>/dev/null | wc -l
s kldstat; kldstat
s temps; sysctl -a 2>/dev/null | grep -E '^dev\.cpu\.[0-9]+\.temperature'
s cpufreq; echo "levels $(sysctl -n dev.cpu.0.freq_levels 2>/dev/null)"; echo "cx $(sysctl -n dev.cpu.0.cx_supported 2>/dev/null)"; echo "epp $(sysctl -n dev.hwpstate_intel.0.epp 2>/dev/null)"
s aesni_cpu; grep -c AESNI /var/run/dmesg.boot 2>/dev/null
s zpool; zpool status -x 2>&1
s smart; for d in $(sysctl -n kern.disks); do echo "$d $(smartctl -H /dev/$d 2>/dev/null | grep -E 'result|Health Status' | sed 's/.*: //')"; done
s bectl; bectl list -H 2>/dev/null | wc -l
s unbound; pgrep -x unbound >/dev/null && echo running || echo stopped
s dns_local; timeout 8 drill example.com @127.0.0.1 2>/dev/null | grep -oE 'rcode: [A-Z]+' | head -1
s dns_intercept; timeout 5 drill example.com @192.0.2.1 2>/dev/null | grep -E 'rcode|IN[[:space:]]+A[[:space:]]' | grep -v '^;;.*QUEST' | head -2
s dnsbl_test; d=$(awk -F, 'NR==50{print $2}' /var/unbound/pfb_py_zone.txt 2>/dev/null); if [ -n "$d" ]; then echo "domain $d"; echo "direct $(timeout 6 drill $d @127.0.0.1 2>/dev/null | awk '/[[:space:]]IN[[:space:]]+A[[:space:]]/&&!/^;/{print $NF}' | head -1)"; echo "sub $(timeout 6 drill zz-audit-probe.$d @127.0.0.1 2>/dev/null | awk '/[[:space:]]IN[[:space:]]+A[[:space:]]/&&!/^;/{print $NF}' | head -1)"; fi
s sshd; /usr/sbin/sshd -T 2>/dev/null | grep -iE '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|pubkeyauthentication|permitrootlogin) '
s sshd_file; grep -iE '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|AuthenticationMethods|PermitRootLogin)' /etc/ssh/sshd_config 2>/dev/null
s sshd_match; awk 'tolower($1)=="include"{print "include " $2} tolower($1)=="match"{m=$0} m!="" && tolower($1) ~ /^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|authenticationmethods)$/{print m " :: " $0}' /etc/ssh/sshd_config 2>/dev/null
s ups; for u in $(upsc -l 2>/dev/null); do echo "$u $(upsc $u@localhost ups.status 2>/dev/null)"; done
s ifconfig; ifconfig -a 2>/dev/null | grep -E '^[a-z]|options='
s certs; for f in /var/etc/cert.crt /var/etc/openvpn/server*/cert; do [ -f "$f" ] && echo "$f|$(openssl x509 -noout -enddate -in $f 2>/dev/null | cut -d= -f2)"; done
s pfinfo; pfctl -si 2>/dev/null | grep -E 'current entries'
s unbound_eff; grep -E '^[[:space:]]*(msg-cache-size|rrset-cache-size|prefetch|prefetch-key):' /var/unbound/unbound.conf 2>/dev/null
s ovpn_push; for f in /var/etc/openvpn/server*/config.ovpn; do [ -f "$f" ] || continue; n=${f%/config.ovpn}; n=${n##*server}; echo "$n $(grep 'dhcp-option DNS' "$f" | awk '{print $NF}' | tr -d '"' | tr '\n' ' ')"; done
s pfb_age; echo "$(find /var/db/pfblockerng/dnsbl /var/db/pfblockerng/deny -name '*.txt' -mtime -2 2>/dev/null | wc -l) $(find /var/db/pfblockerng/dnsbl /var/db/pfblockerng/deny -name '*.txt' 2>/dev/null | wc -l)"
s smtpfail; date '+%Y %b %d %H:%M:%S'; grep 'Could not send the message' /var/log/system.log 2>/dev/null | tail -1 | awk '{print $1, $2, $3}'
s end
"""

UPDATES_SCRIPT = 's() { echo "@@$1"; }\ns updates; timeout 120 pfSense-upgrade -c 2>&1 | tail -3\ns end\n'


def dhcp_scan_script(lan_if: str, fw_mac: str) -> str:
    return (
        's() { echo "@@$1"; }\ns dhcpscan; '
        f"timeout 45 tcpdump -nn -e -l -i {lan_if} -c 20 'udp src port 67 and not ether src {fw_mac}' 2>/dev/null\n"
        # tcpdump exits 0 after 20 packets; timeout(1) exits 124 after 45 s of listening.
        # Anything else means the capture never ran, which must not read as "no rogue server".
        "rc=$?; s dhcpscan_rc; echo $rc; s end\n"
    )


# Sections every full run must return. A missing one means the remote run was
# cut short, and a check that reads it reports WARN instead of passing on no data.
REMOTE_SECTIONS = frozenset(re.findall(r"^s ([a-z_0-9]+);", REMOTE_SCRIPT, re.M))


class MissingData(Exception):
    """A check needed a section the remote run did not return."""


SECRET_KEY = re.compile(r"(pass|secret|key|prv|crt|hash|token|psk|tls|community)", re.I)

# --------------------------------------------------------------------- helpers


@dataclass
class Result:
    status: str  # PASS FAIL WARN INFO SKIP
    detail: str


# Text from the firewall or the UniFi controller (rule descriptions, alias, device
# and network names) is written by whoever administers those systems and ends up in
# a report that a person, or the skill's agent, reads and acts on. Strip what can
# hide or reorder text, keep it on one line, bound its length, and quote it.
# Characters kept: letters, marks, numbers, punctuation, symbols and ordinary
# spaces. Dropped: every control, format, private use, surrogate and unassigned
# code point (categories C*), line and paragraph separators, and the code points
# that are visible-looking letters or marks but render as nothing.
_INVISIBLE_EXTRA = frozenset(
    [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2800, 0x3164, 0xFFA0]
    + list(range(0x180B, 0x1810)) + list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0)))


def _visible(ch: str) -> bool:
    import unicodedata
    if ch in " \t\n\r":
        return True  # whitespace is collapsed afterwards
    cat = unicodedata.category(ch)
    return not (cat[0] == "C" or cat in ("Zl", "Zp") or ord(ch) in _INVISIBLE_EXTRA)


def clean(text: str, limit: int = 600) -> str:
    """One line of visible text: anything invisible or a control removed, whitespace collapsed, length capped."""
    t = " ".join("".join(ch if _visible(ch) else "" for ch in str(text)).split())
    return t if len(t) <= limit else t[: limit - 3] + "..."


def val(text, limit: int = 60) -> str:
    """A value taken from the firewall or controller, quoted so it reads as data."""
    return '"' + clean(text, limit).replace('"', "'") + '"'


_MD_ACTIVE = re.compile(r"([\\`*_\[\]<>|~&@#])")  # links, code, HTML, entities, emphasis, cells, mentions, refs


def md_escape(text: str) -> str:
    """Markdown-escape text so it cannot become a link, heading, HTML, entity, mention, reference or code.
    Bare URLs and e-mail addresses are broken up too, because GitHub-flavoured Markdown links them on its own."""
    t = _MD_ACTIVE.sub(r"\\\1", text)
    t = re.sub(r"(?i)\b(https?|ftp)://", lambda m: m.group(1) + "\\://", t)
    return re.sub(r"(?i)\bwww\.", "www\\.", t)



@dataclass
class Ctx:
    host: str
    sections: dict[str, str]
    root: ET.Element
    args: argparse.Namespace
    external: dict = field(default_factory=dict)
    feeds: list = field(default_factory=list)
    unifi: dict = field(default_factory=dict)
    incomplete: bool = False
    offline: bool = False  # audited from a saved config.xml, no live firewall

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
        if name not in self.sections:
            raise MissingData(name)
        return self.sections[name].strip()

    @property
    def version(self) -> str:
        v = self.sections.get("version", "").strip()
        return v.splitlines()[0] if v else "unknown"

    @property
    def is_29(self) -> bool:
        return self.version.startswith("2.9")


# --ssh-opt is an allow list, not a deny list: ssh accepts leading whitespace, tabs,
# quotes and '=' or a space between key and value, and many options load local code
# or run commands, so filtering bad spellings cannot be complete (/sec-audit after run,
# 2026-11-12). Only these keys, only as Key=Value, and only plain values.
_SSH_OPT_ALLOWED = {
    # A known hosts file is allowed because StrictHostKeyChecking is always yes: a
    # file without this host's key stops the run instead of trusting a new key.
    # ProxyJump is not allowed: the jump hop is a separate ssh that ignores these
    # options (and sshpass would answer its password prompt). HostKeyAlias and
    # StrictHostKeyChecking are not allowed: both can make a host look new.
    "userknownhostsfile": None, "port": r"\d{1,5}",
    "connecttimeout": r"\d{1,4}", "serveraliveinterval": r"\d{1,4}", "serveralivecountmax": r"\d{1,3}",
    "identitiesonly": r"yes|no",
}
_SSH_OPT_SYNTAX = re.compile(r"([A-Za-z]+)=([A-Za-z0-9._~/@%+,:-]{1,200})")


def ssh_opt_problem(opt: str) -> str | None:
    """Why an --ssh-opt value is refused, or None when it is on the allow list."""
    m = _SSH_OPT_SYNTAX.fullmatch(opt)
    if not m:
        return "write it as Key=Value with no spaces, quotes or tabs"
    key, value = m.group(1).lower(), m.group(2)
    if key not in _SSH_OPT_ALLOWED:
        return f"{m.group(1)} is not on the allow list ({', '.join(sorted(_SSH_OPT_ALLOWED))})"
    if value.startswith("-"):
        return "the value must not start with '-'"
    pattern = _SSH_OPT_ALLOWED[key]
    if pattern and not re.fullmatch(pattern, value, re.I):
        return f"{m.group(1)}={value} is not allowed (host keys must stay checked)"
    if key == "userknownhostsfile" and value.lower() in ("/dev/null", "none"):
        return "UserKnownHostsFile must name a real file (host keys must stay checked)"
    return None


def run_remote(args: argparse.Namespace, script: str) -> str:
    # ssh keeps the first value it sees for an option, and command-line options come
    # before ~/.ssh/config, so StrictHostKeyChecking=yes goes first and no config file
    # or --ssh-opt can relax it: an unknown or changed host key stops the run. A new
    # firewall's key is added once, after the user confirms its fingerprint (SKILL.md).
    cmd = ["ssh", "-o", "StrictHostKeyChecking=yes"]
    for opt in args.ssh_opt or []:
        cmd += ["-o", opt]
    cmd += ["-o", "BatchMode=" + ("no" if args.password_env else "yes"), "-o", "ConnectTimeout=10", "-p", str(args.port)]
    if args.identity:
        cmd += ["-i", args.identity]
    # "--" ends ssh's options, so a user or host value can never be read as one.
    cmd += ["--", f"{args.user}@{args.host}", "sh -s"]
    env = os.environ.copy()
    if args.password_env:
        if not shutil.which("sshpass"):
            sys.exit("--password-env needs sshpass installed; key authentication is recommended")
        env["SSHPASS"] = os.environ.get(args.password_env, "")
        cmd = ["sshpass", "-e"] + cmd
    proc = subprocess.run(cmd, input=script, capture_output=True, text=True, env=env, timeout=400)
    if proc.returncode != 0 and "@@" not in proc.stdout:
        sys.exit(f"SSH failed ({proc.returncode}): {clean(proc.stderr, 300)}")
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
    return Result("PASS", "HTTPS") if p == "https" else Result("FAIL", f"WebGUI protocol is {val(p, 20)}")


@check("ACCESS-002")
def _(ctx):
    raw = ctx.get("system/webgui/session_timeout") or "240"
    if not raw.isdigit():
        return Result("WARN", f"Session timeout is not a number: {val(raw, 20)}")
    t = int(raw)
    if t == 0:
        return Result("FAIL", "Session timeout disabled (sessions never expire)")
    return Result("PASS", f"{t} minutes") if t <= 30 else Result("WARN", f"{t} minutes (default 240); 15 to 30 recommended")


def sshd_settings(text: str) -> dict[str, str]:
    """First value wins, as in sshd_config. ChallengeResponseAuthentication is the
    old name of KbdInteractiveAuthentication."""
    out: dict[str, str] = {}
    for line in text.lower().splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = "kbdinteractiveauthentication" if parts[0] == "challengeresponseauthentication" else parts[0]
            out.setdefault(key, parts[1].strip())
    return out


def key_required(methods: str) -> bool:
    """AuthenticationMethods where every allowed method list includes publickey."""
    lists = methods.split()
    return bool(lists) and methods != "any" and all("publickey" in m.split(",") for m in lists)


@check("ACCESS-003")
def _(ctx):
    if not ctx.has("system/ssh/enable"):
        return Result("PASS", "SSH disabled")
    # Prefer sshd -T: the effective settings after Include files and OpenSSH defaults.
    # The file alone is not enough, because a setting that is absent defaults to yes.
    eff, src = sshd_settings(ctx.sec("sshd")), "sshd -T"
    if not eff:
        eff, src = sshd_settings(ctx.sec("sshd_file")), "sshd_config"
    if not eff:
        return Result("WARN", "SSH enabled, but neither sshd -T nor sshd_config could be read to confirm key-only login")
    match = [l for l in ctx.sec("sshd_match").splitlines() if l.strip()]
    includes = [l for l in match if l.startswith("include ")]
    overrides = [l.split(" :: ", 1)[-1].strip() for l in match if " :: " in l]
    loosened = [o for o in overrides if o.lower().split()[-1] == "yes"
                or (o.lower().startswith("authenticationmethods") and not key_required(" ".join(o.lower().split()[1:])))]
    if key_required(eff.get("authenticationmethods", "")):
        how = "a key plus a password" if "password" in eff["authenticationmethods"] else "a key"
        base = Result("PASS", f"SSH enabled; every login needs {how} ({src})")
    elif "yes" in (eff.get("passwordauthentication"), eff.get("kbdinteractiveauthentication")):
        return Result("FAIL", f"SSH enabled and accepts passwords ({src}); use key-only")
    elif src == "sshd_config" and not (eff.get("passwordauthentication") == "no" and eff.get("kbdinteractiveauthentication") == "no"):
        return Result("WARN", "sshd_config does not explicitly turn off password and keyboard-interactive login, "
                              "and OpenSSH allows them by default; sshd -T could not be read to confirm")
    else:
        base = Result("PASS", f"SSH enabled, key authentication only ({src})")
    if loosened:
        return Result("FAIL", "A Match block in sshd_config re-enables password login: " + "; ".join(loosened)[:200])
    if includes:  # Match blocks inside included files are not read
        return Result("WARN", base.detail + "; sshd_config includes other files whose Match blocks were not read: " + ", ".join(i.split()[1] for i in includes)[:160])
    return base


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
    return Result("PASS", f"admin accounts: {', '.join(val(n) for n in sorted(set(admins) | {'admin'} & set(names))) or 'none'}")


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
            if exceptions:
                return Result("INFO", "VPN users are blocked from firewall management, except "
                              + ", ".join(exceptions) + " (passed to any before the block); confirm each is deliberate")
            return Result("PASS", "VPN users are blocked from firewall management")
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
        rows.append(f"{r.findtext('protocol') or 'any'}/{port or 'any'} from {'any' if is_any(r, 'source') else 'restricted'} ({val(r.findtext('descr')) if r.findtext('descr') else 'no description'})")
    nat = len(ctx.all("nat/rule"))
    detail = "; ".join(rows) if rows else "no WAN pass rules"
    return Result("INFO", f"{detail}; port forwards: {nat}")


@check("PERIM-003")
def _(ctx):
    return Result("INFO", f"State policy: {val(ctx.get('system/statepolicy')) if ctx.get('system/statepolicy') else 'if-bound (default)'}")


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
    udp = ctx.external.get("udp", {})
    rep = [p for p, ok in udp.items() if ok]
    if rep:
        return Result("WARN", f"UDP services answer from outside: {rep}")
    silent = [p for p, ok in udp.items() if ok is None]
    allowed = [p for p in silent if wan_allows_udp(ctx, p)]
    if allowed:
        return Result("WARN", f"No reply on UDP {allowed}, but WAN rules or port forwards allow it; "
                              "a service that ignores these probes would look the same, so check it by hand")
    closed = [p for p, ok in udp.items() if ok is False]
    return Result("PASS", "No UDP service answered from outside"
                  + (f"; {silent} silent and not allowed by any WAN rule" if silent else "")
                  + (f"; {closed} refused" if closed else ""))


def port_in(spec: str, port: int) -> bool:
    """pfSense port field: empty (any), a number, a range a:b or a-b, or an alias name."""
    if not spec:
        return True
    m = re.fullmatch(r"(\d+)(?:[:-](\d+))?", spec)
    if not m:
        return True  # a port alias: assume it may include the port
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    return lo <= port <= hi


def wan_allows_udp(ctx: Ctx, port: int) -> bool:
    """A pass rule or port forward on WAN that could let this UDP port in."""
    for r in ctx.all("filter/rule") + ctx.all("nat/rule"):
        if r.find("disabled") is not None:
            continue
        is_nat = r.find("target") is not None or r.find("local-port") is not None
        if not is_nat and r.findtext("type") != "pass":
            continue
        if "wan" not in (r.findtext("interface") or "").split(","):
            continue
        if (r.findtext("protocol") or "any") not in ("udp", "tcp/udp", "any", ""):
            continue
        dst = r.find("destination")
        if port_in((dst.findtext("port") if dst is not None else "") or "", port):
            return True
    return False


def ovpn_servers(ctx):
    return [s for s in ctx.all("openvpn/openvpn-server") if s.find("disable") is None]


@check("VPN-001")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    issues = []
    for s in srv:
        name = val(s.findtext("description") or s.findtext("vpnid") or "server")
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
    miss = [val(s.findtext("description") or "server") for s in srv if not (s.findtext("crlref") or "")]
    return Result("FAIL", f"No CRL on: {', '.join(miss)}") if miss else Result("PASS", "CRL attached")


@check("VPN-003")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    bad = [val(s.findtext("description") or "server") for s in srv if (s.findtext("strictusercn") or "") != "yes"]
    return Result("WARN", f"Strict user/CN off: {', '.join(bad)}") if bad else Result("PASS", "Strict user/CN on")


def vpn_ifaces(ctx: Ctx) -> set[str]:
    """The OpenVPN interface group plus any OpenVPN instance assigned as its own interface."""
    names = {"openvpn"}
    ifs = ctx.root.find("interfaces")
    for el in list(ifs) if ifs is not None else []:
        if (el.findtext("if") or "").startswith("ovpn"):
            names.add(el.tag)
    return names


def alias_entries(ctx: Ctx, name: str, seen: frozenset = frozenset()) -> list[str] | None:
    """Addresses in a host or network alias, nested aliases expanded. None if the
    alias cannot be resolved offline (URL tables, unknown names, loops)."""
    if name in seen:
        return None
    for a in ctx.all("aliases/alias"):
        if a.findtext("name") == name:
            if (a.findtext("type") or "") not in ("host", "network"):
                return None
            out = []
            for item in (a.findtext("address") or "").split():
                if re.fullmatch(r"[\d.:a-fA-F]+(/\d+)?", item):
                    out.append(item)
                else:
                    sub_entries = alias_entries(ctx, item, seen | {name})
                    if sub_entries is None:
                        return None
                    out += sub_entries
            return out
    return None


def iface_subnets(ctx: Ctx) -> list:
    import ipaddress
    nets = []
    ifs = ctx.root.find("interfaces")
    for el in list(ifs) if ifs is not None else []:
        ip, bits = el.findtext("ipaddr") or "", el.findtext("subnet") or ""
        if el.tag != "wan" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and bits.isdigit():
            nets.append(ipaddress.ip_network(f"{ip}/{bits}", strict=False))
    return nets


def wide_destination(ctx: Ctx, rule: ET.Element) -> str | None:
    """Why a rule's destination covers a whole network, or None if it is a host or small range."""
    import ipaddress
    dst = rule.find("destination")
    if dst is None or dst.find("not") is not None:
        return "a negated destination (everything except one target)" if dst is not None else None
    if dst.find("any") is not None:
        return "any destination"
    net = dst.findtext("network") or ""
    if net and not net.endswith("ip") and net != "(self)":
        return f"the whole {net} subnet"
    addr = dst.findtext("address") or ""
    if not addr:
        return None
    entries = [addr] if re.fullmatch(r"[\d.:a-fA-F]+(/\d+)?", addr) else alias_entries(ctx, addr)
    if entries is None:
        return f"alias {addr}, which could not be resolved offline"
    lans = iface_subnets(ctx)
    for e in entries:
        try:
            n = ipaddress.ip_network(e, strict=False)
        except ValueError:
            return f"alias {addr}, which could not be resolved offline"
        if n.num_addresses > 16 or any(n.version == l.version and (l.subnet_of(n)) for l in lans):
            return f"{e}" + (f" (in alias {addr})" if e != addr else "")
    return None


@check("VPN-004")
def _(ctx):
    ifaces = vpn_ifaces(ctx)
    wide = []
    for r in ctx.all("filter/rule"):
        if r.find("disabled") is not None or r.findtext("type") != "pass":
            continue
        on = set((r.findtext("interface") or "").split(","))
        if not on & ifaces:  # floating rules list several interfaces
            continue
        why = wide_destination(ctx, r)
        if why:
            label = val(r.findtext("descr")) if r.findtext("descr") else f"rule {clean(r.findtext('tracker') or '?', 20)}"
            port = (r.find("destination").findtext("port") if r.find("destination") is not None else "") or ""
            fam = {"inet6": " (IPv6 only)", "inet46": " (IPv4 and IPv6)"}.get(r.findtext("ipprotocol") or "", "")
            wide.append(f"{label}: {why}" + (f", port {port}" if port else ", all ports") + fam
                        + (" (floating)" if r.find("floating") is not None else ""))
    if wide:
        return Result("WARN", "VPN users can reach whole networks: " + "; ".join(wide)[:300])
    return Result("PASS", f"VPN access is scoped (checked rules on {', '.join(sorted(ifaces))}, including floating rules)")


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
    noauto = [val(c.findtext("descr") or "cert") for c in ctx.all("cert") if c.findtext("refid") in used and (c.findtext("autorenew") or "") != "enabled"]
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
    return Result("PASS", f"TLS forwarding to {val(ctx.get('system/dns1host'))}")


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
    bad = [f"{val(u, 120)} ({clean(why, 80)})" for u, why in ctx.feeds if why]
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
    stale = int(ctx.sec("acbold") or 0)
    if stale:
        return Result("WARN", f"ACB upload job present, but {stale} staged backup(s) are over 15 minutes old; uploads are failing (lesson 1)")
    if staged > 10:
        return Result("WARN", f"ACB enabled but {staged} backups are waiting to upload")
    return Result("PASS", "ACB enabled, upload job present, nothing stuck in staging")


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
    if not getattr(ctx.args, "updates", False):
        return Result("SKIP", "Run with --updates to check for pfSense updates")
    u = ctx.sec("updates")
    if not u:
        return Result("WARN", "Update check returned nothing; run pfSense-upgrade -c on the firewall")
    return Result("PASS", "Up to date") if "up to date" in u.lower() else Result("WARN", u.splitlines()[-1][:120])


@check("MON-001")
def _(ctx):
    bad = []
    for g in ctx.all("gateways/gateway_item"):
        gw, mon = g.findtext("gateway") or "", g.findtext("monitor") or ""
        if gw and gw != "dynamic" and (not mon or mon == gw):
            bad.append(val(g.findtext("name") or gw))
    return Result("WARN", f"Gateway monitor pings the gateway itself: {', '.join(bad)} (lesson 3)") if bad else Result("PASS", "Gateway monitors use an internet target")


@check("MON-002")
def _(ctx):
    ok = ctx.get("notifications/smtp/ipaddress") and ctx.get("notifications/smtp/notifyemailaddress")
    if not ok:
        return Result("WARN", "No email notifications configured")
    lines = ctx.sec("smtpfail").splitlines()
    if len(lines) < 2 or not lines[1].strip():
        return Result("PASS", "SMTP notifications configured, no send failures in the current system log")
    try:
        now = datetime.strptime(lines[0].strip(), "%Y %b %d %H:%M:%S")
        last = datetime.strptime(f"{now.year} {' '.join(lines[1].split())}", "%Y %b %d %H:%M:%S")
        if last > now:  # syslog has no year: a December entry read in January
            last = last.replace(year=now.year - 1)
    except ValueError:
        return Result("WARN", "SMTP configured, but the system log shows a send failure (date unreadable); send a test to confirm (lesson 28)")
    hours = (now - last).total_seconds() / 3600
    if hours <= 24 * 7:
        return Result("WARN", f"Alert email failed to send {hours:.0f} h ago ({last:%b %d %H:%M}); if fixed since, send a test to confirm (lesson 28)")
    return Result("PASS", "SMTP notifications configured, no send failures in the last 7 days")


@check("ACCESS-008")
def _(ctx):
    legacy = [val(u.findtext("name") or "?") for u in ctx.all("system/user")
              if u.find("disabled") is None and ((u.findtext("md5-hash") or "").strip() or (u.findtext("password") or "").strip())]
    if legacy:
        return Result("WARN", f"Legacy password hashes (unsalted MD5 or old crypt) on: {', '.join(legacy)}; reset these passwords")
    return Result("PASS", "All enabled local users use bcrypt or SHA-512 hashes")


def _firewall_addrs(ctx):
    out = set()
    for el in ctx.root.findall("interfaces/*/ipaddr"):
        try:
            out.add(ipaddress.ip_address((el.text or "").strip()))
        except ValueError:
            pass
    for v in ctx.root.findall("virtualip/vip/subnet"):
        try:
            out.add(ipaddress.ip_address((v.text or "").strip()))
        except ValueError:
            pass
    return out


@check("VPN-008")
def _(ctx):
    srv = [s for s in ovpn_servers(ctx) if (s.findtext("mode") or "server_tls_user").startswith("server")]
    if not srv:
        return Result("SKIP", "No remote access OpenVPN servers")
    pushed = {}
    for ln in ctx.sec("ovpn_push").splitlines():
        parts = ln.split()
        if parts:
            pushed[parts[0]] = parts[1:]
    fw = _firewall_addrs(ctx)
    issues = []
    for s in srv:
        name = val(s.findtext("description") or s.findtext("vpnid") or "server")
        vid = s.findtext("vpnid") or ""
        if vid in pushed:
            dns = pushed[vid]
        else:
            dns = [s.findtext(f"dns_server{i}") for i in range(1, 5)]
            dns = [d.strip() for d in dns if d and d.strip()]
        local = set(fw)
        try:
            net = ipaddress.ip_network((s.findtext("tunnel_network") or "").strip(), strict=False)
            local.add(next(net.hosts()))
        except (ValueError, StopIteration):
            pass
        if not dns:
            issues.append(f"{name}: pushes no DNS server, so VPN clients skip the firewall's DNS filtering")
            continue
        other = []
        for d in dns:
            try:
                if ipaddress.ip_address(d) not in local:
                    other.append(d)
            except ValueError:
                other.append(d)
        if other:
            issues.append(f"{name}: pushes DNS {', '.join(other)}, which is not the firewall")
    if issues:
        return Result("WARN", "; ".join(issues) + " (lesson 29)")
    return Result("PASS", "VPN clients are told to use the firewall for DNS")


@check("VPN-009")
def _(ctx):
    srv = ovpn_servers(ctx)
    if not srv:
        return Result("SKIP", "No OpenVPN servers")
    warn, info = [], []
    for s in srv:
        name = val(s.findtext("description") or s.findtext("vpnid") or "server")
        comp = (s.findtext("allow_compression") or "").strip()
        if comp == "yes":
            warn.append(f"{name}: compression allowed (VORACLE risk; set Allow Compression to Refuse)")
        elif comp == "asym":
            info.append(f"{name}: asymmetric compression (decompresses incoming); Refuse is safest once no client sends compressed data")
        if (s.findtext("topology") or "").strip() == "net30":
            warn.append(f"{name}: net30 topology (deprecated; use subnet)")
    if warn:
        return Result("WARN", "; ".join(warn + info))
    if info:
        return Result("INFO", "; ".join(info))
    return Result("PASS", "No compression, subnet topology")


def _size_bytes(v):
    m = re.fullmatch(r"(\d+)([kmg]?)", v.strip().lower())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2)]


@check("DNS-008")
def _(ctx):
    eff = {}
    for ln in ctx.sec("unbound_eff").splitlines():
        k, _, v = ln.strip().partition(":")
        eff[k.strip()] = v.strip()  # last value wins, as in Unbound itself
    if not eff:
        return Result("SKIP", "Unbound configuration not readable")
    msg = _size_bytes(eff.get("msg-cache-size", "4m")) or 0
    pre = eff.get("prefetch", "no") == "yes"
    raw = ctx.get("unbound/custom_options") or ""
    try:
        custom = base64.b64decode(raw).decode(errors="replace") if raw else ""
    except ValueError:
        custom = ""
    in_custom = [k for k in ("msg-cache-size", "rrset-cache-size", "prefetch") if re.search(rf"^\s*{k}\s*:", custom, re.M)]
    desc = f"message cache {msg // 1024 ** 2} MB, prefetch {'on' if pre else 'off'}"
    if msg < 10 * 1024 ** 2 or not pre:
        return Result("WARN", f"Resolver {desc}; a larger cache and prefetch keep common answers fast")
    if in_custom:
        return Result("INFO", f"Resolver {desc}, set in custom options ({', '.join(in_custom)}) that override the GUI, which still shows its own values; move them to DNS Resolver > Advanced Settings (lesson 27)")
    return Result("PASS", f"Resolver {desc}")


@check("PFB-009")
def _(ctx):
    if not pfb_installed(ctx):
        return Result("SKIP", "pfBlockerNG DNSBL not configured")
    if "pfblockerng.php cron" not in ctx.sec("crontab"):
        return Result("FAIL", "pfBlockerNG update job missing from cron; lists never refresh")
    parts = ctx.sec("pfb_age").split()
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return Result("SKIP", "List files not readable")
    fresh, total = int(parts[0]), int(parts[1])
    if total == 0:
        return Result("WARN", "Update job present, but no downloaded list files found")
    if fresh < total:
        return Result("WARN", f"{total - fresh} of {total} lists not updated in 48 h; check the pfBlockerNG log for download errors")
    return Result("PASS", f"Update job present, all {total} lists updated in the last 48 h")


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
    f = dict((ln.split(" ", 1) + [""])[:2] for ln in ctx.sec("cpufreq").splitlines() if ln.strip())
    levels, cx, epp = (f.get(k, "").strip() for k in ("levels", "cx", "epp"))
    parts = []
    if epp:
        parts.append(f"Intel Speed Shift active, EPP {epp} (0 favours performance, 100 favours power saving)")
    elif levels:
        mhz = [lv.split("/")[0] for lv in levels.split()]
        parts.append(f"OS frequency scaling available, {mhz[-1]} to {mhz[0]} MHz")
    else:
        parts.append("No OS frequency scaling exposed (likely fixed or controlled in BIOS)")
    if cx:
        parts.append("idle states " + ", ".join(c.split("/")[0] for c in cx.split()))
    return Result("INFO", "; ".join(parts))


@check("HW-006")
def _(ctx):
    return Result("INFO", "Manual: pull AC while running and confirm it boots unattended")


@check("HW-007")
def _(ctx):
    # Speed and Duplex "Default" stores nothing; any other choice, even "autoselect",
    # stores <media> and is reapplied with ifconfig on every interface reconfigure.
    # With IPv6 Track Interface that happens on prefix changes, and users report flapping.
    ifs = ctx.root.find("interfaces")
    els = {el.tag: el for el in (list(ifs) if ifs is not None else [])}
    involved = set()
    for name, el in els.items():
        if el.find("enable") is not None and (el.findtext("ipaddrv6") or "") == "track6":
            involved |= {name, el.findtext("track6-interface") or ""}
    forced = [f"{n} ({' '.join(x for x in (els[n].findtext('media'), els[n].findtext('mediaopt')) if x)})"
              for n in sorted(involved) if n in els and (els[n].findtext("media") or els[n].findtext("mediaopt"))]
    if not involved:
        return Result("SKIP", "No interface uses IPv6 Track Interface")
    if forced:
        return Result("WARN", f"Speed and Duplex is set on {', '.join(forced)}, which uses or feeds IPv6 tracking; "
                              "users report link flapping with this combination (lesson 30)")
    return Result("PASS", "IPv6 tracking interfaces use the default Speed and Duplex")


@check("UPS-001")
def _(ctx):
    if not ctx.has("installedpackages/nut/config"):
        return Result("SKIP", "NUT not configured")
    st = ctx.sec("ups")
    # One "<name> <status flags>" line per UPS; every UPS must report OL.
    rows = [line.split()[1:] for line in st.splitlines() if line.strip()]
    if not rows or any("OL" not in flags for flags in rows):
        return Result("FAIL", f"UPS status: {val(st, 120) if st else 'no response'}")
    if ctx.get("installedpackages/nut/config/email") != "yes":
        return Result("WARN", "UPS online but power-event emails are off (lesson 4)")
    return Result("PASS", f"UPS online, alerts on ({val(st, 120)})")


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
        return None, Result("SKIP", "Run with --unifi and the console address, plus --unifi-key-env, to read the UniFi controller")
    u = ctx.unifi or {}
    if u.get("fatal"):
        return None, Result("SKIP", f"UniFi: {val(u['fatal'], 200)}")
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
            unmapped.append(val(n["name"]))
        elif not n["guard"]:
            off.append(f"{val(n['name'])} (VLAN {clean(str(n['vlan'] or 'untagged'), 20)})")
        elif want not in n["trusted"]:
            wrong.append(f"{val(n['name'])} trusts {', '.join(val(t, 45) for t in n['trusted']) or 'nothing'}, firewall is {want}")
        else:
            ok.append(val(n["name"]))
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
        raw = w["name"]
        name = val(raw)
        if w["open"] and raw.lower() in intended:
            infos.append(f"{name} is open by intent")
        elif w["open"] and w["guest"]:
            fails.append(f"guest SSID {name} is open (no password)")
        elif w["open"]:
            warns.append(f"SSID {name} is open")
        if w["guest"] and not w["iso"]:
            warns.append(f"guest SSID {name} has client isolation off")
        if not w["guest"] and legacy is not None and GUEST_NAME.search(raw):
            warns.append(f"{name} looks like a guest SSID but is not marked guest")
    guests = [val(w["name"]) for w in wlans if w["guest"]]
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
            name = val(d.get("name") or d.get("model") or "device")
            host = urlsplit(str(d.get("inform_url") or "")).hostname or ""
            ip = str(d.get("inform_ip") or "")
            if not host and not ip:
                bad.append(f"{name} reports no inform address")
            elif not ({host, ip} & expect):
                wrong.append(f"{name} informs to {val(host or ip, 80)}")
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
    down = [f"{val(d.get('name') or d.get('model') or 'device')} {clean(str(d.get('state')), 30)}" for d in devs if d.get("state") not in ("ONLINE", None)]
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
    rc = ctx.sec("dhcpscan_rc")
    if rc not in ("0", "124"):  # 0: 20 packets seen, 124: listened the full 45 s
        return Result("WARN", f"The DHCP capture did not run (tcpdump exit {rc or 'unknown'}); no result")
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
    # UDP has three outcomes: a reply (open), an ICMP port unreachable (closed), or
    # silence. Silence is what a default-deny WAN gives, but also what a service gives
    # when it ignores our probe (wrong SNMP community, restricted NTP). So silence is
    # recorded as None, never as closed, and PERIM-005 cross-checks it against the rules.
    udp = {}
    probes = {53: bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001"), 123: b"\x1b" + b"\0" * 47,
              161: bytes.fromhex("302902010004067075626c6963a01c0204000000010201000201003011300f060b2b060102010101000500"),
              # Unicast M-SEARCH: HOST names the device probed, not the multicast group.
              1900: f"M-SEARCH * HTTP/1.1\r\nHOST:{ip}:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n".encode()}
    for p, payload in probes.items():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.connect((ip, p))  # connected, so an ICMP unreachable surfaces as ConnectionRefusedError
                s.send(payload)
                s.recv(1500)
                udp[p] = True
            except ConnectionRefusedError:
                udp[p] = False
            except OSError:
                udp[p] = None
    return {"ip": ip, "tcp": tcp, "udp": udp}


# IPv6 ranges that carry or translate an IPv4 address (NAT64, IPv4-compatible,
# IPv4-mapped, 6to4, Teredo). Python counts some of them as global, but each can
# lead to a private IPv4 address, so a feed URL there is refused.
_V6_TRANSITION = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b::/96", "64:ff9b:1::/48", "::/96", "::ffff:0:0/96", "::ffff:0:0:0/96", "2002::/16", "2001::/32"))


def is_public_ip(ip) -> bool:
    if not ip.is_global or ip.is_multicast:
        return False
    return not (ip.version == 6 and any(ip in n for n in _V6_TRANSITION))


def public_url(url: str) -> bool:
    """True only for http(s) URLs whose host resolves solely to public addresses."""
    import ipaddress
    from urllib.parse import urlsplit
    try:  # a malformed port or host label raises ValueError or UnicodeError: not public
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except (OSError, ValueError, UnicodeError):
        return False
    for info in infos:
        if not is_public_ip(ipaddress.ip_address(info[4][0])):
            return False
    return True


def safe_url(url: str) -> str:
    """URL for display: no credentials, query string or fragment."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
    except (ValueError, UnicodeError):
        return "(unparseable URL)"
    return urlunsplit((p.scheme, host, p.path, "", "")) + ("?..." if p.query else "")


def _require_public_peer(sock) -> None:
    import ipaddress
    peer = ipaddress.ip_address(sock.getpeername()[0])
    if not is_public_ip(peer):
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

    MAX_PAGES = 1000  # 200,000 items; far beyond any single site

    def pages(self, path: str) -> list:
        """All items of an Integration API list (offset/limit, limit max 200).

        All or nothing: a list cut short would let a check pass on items it never
        saw, so any shortfall raises instead of returning a partial list."""
        out, offset, total = [], 0, None
        for _ in range(self.MAX_PAGES):
            d = self.get(path, {"offset": offset, "limit": 200})
            data = d.get("data") if isinstance(d, dict) else None
            if not isinstance(data, list):
                raise UnifiError(f"unexpected list response on {path}")
            if d.get("totalCount") is not None:
                total = int(d["totalCount"])
            out += data
            offset += len(data)
            if total is not None:
                if offset >= total:
                    return out
                if not data:
                    raise UnifiError(f"{path}: list ended at {offset} of {total} items")
            elif len(data) < 200:  # no total given: a short page is the last one
                return out
        raise UnifiError(f"{path}: more than {self.MAX_PAGES} pages; refusing a partial list")

    def legacy(self, path: str) -> list:
        """A legacy API call; unwraps {meta: {rc}, data: [...]}."""
        d = self.get(path)
        if isinstance(d, dict) and isinstance(d.get("meta"), dict) and d["meta"].get("rc") not in (None, "ok"):
            raise UnifiError(f"{path}: {val(d['meta'].get('msg') or d['meta'].get('rc'), 80)}")
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
        except MissingData as e:
            r = (Result("SKIP", "Needs a live firewall; not checked in a config-file audit") if ctx.offline
                 else Result("WARN", f"Not checked: the firewall did not return '{e}' (remote run incomplete)"))
        except Exception as e:  # noqa: BLE001 one broken check must not stop the audit
            r = Result("SKIP", f"Check error: {type(e).__name__}: {e}")
        r = Result(r.status, clean(r.detail))
        unverified = "unverified" in c.get("verified_on", [])
        if unverified and r.status == "FAIL":
            r = Result("WARN", r.detail + " (check not yet verified on a live system)")
        results.append({**c, "status": r.status, "detail": r.detail})
    results.sort(key=lambda x: (ORDER[x["status"]], RISK.get(x["risk"], 9), x["id"]))
    return results


def markdown(results, ctx) -> str:
    counts = {k: sum(1 for r in results if r["status"] == k) for k in ORDER}
    host = ctx.get("system/hostname", "?") + "." + (ctx.get("system/domain") or "")
    out = [f"# pfSense audit: {md_escape(clean(host.rstrip('.'), 120))}", "",
           f"pfSense {md_escape(clean(ctx.version, 60))} · {datetime.now().strftime('%Y-%m-%d %H:%M')} · pfaudit {VERSION}", "",
           " · ".join(f"{ICON[k]} {counts[k]} {k}" for k in ORDER), ""]
    if ctx.offline:
        out += ["> [!NOTE]", "> Audited from a saved config.xml. Checks that need the live firewall (services, sensors, disks, logs) are listed as not checked.", ""]
    if getattr(ctx, "incomplete", False):
        out += ["> [!WARNING]", "> The remote run did not finish, so some data is missing. Checks that needed it report WARN; run the audit again.", ""]
    if ctx.unifi:
        out += [f"UniFi controller {md_escape(clean(ctx.unifi.get('url', '?'), 120))} · Network {md_escape(clean(ctx.unifi.get('version') or 'unknown', 40))} · TLS {ctx.unifi.get('tls')}", ""]
        if ctx.unifi.get("tls") == "insecure":
            out += ["> [!WARNING]", "> UniFi TLS verification was disabled with `--unifi-insecure`. The controller's identity was not checked, so these UniFi results and the API key were exposed to anyone able to intercept the connection.", ""]
    for status, title in (("FAIL", "Fix now"), ("WARN", "Fix soon"), ("INFO", "For your information"), ("PASS", "Good"), ("SKIP", "Not checked")):
        rows = [r for r in results if r["status"] == status]
        if not rows:
            continue
        out += [f"## {ICON[status]} {title}", ""]
        for r in rows:
            out.append(f"- **{r['title']}** `{r['id']}` · {r['risk']} risk  ")
            out.append(f"  {md_escape(r['detail'])}")
            if status in ("FAIL", "WARN") and r.get("fix"):
                out.append(f"  *Fix:* {r['fix']}" + (f" *Impact:* {r['impact']}" if r.get("impact") else ""))
        out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Read-only pfSense audit")
    ap.add_argument("host", nargs="?", help="Firewall address for SSH (omit with --config-file)")
    ap.add_argument("--config-file", metavar="PATH", help="Audit a saved config.xml (Diagnostics > Backup & Restore) instead of a live firewall; "
                    "checks that need the live box report SKIP")
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
    if bool(args.host) == bool(args.config_file):
        ap.error("give either a firewall host or --config-file, not both")
    for name, v in (("host", args.host or ""), ("--user", args.user or "")):
        if v.startswith("-") or any(c.isspace() or c == "@" for c in v):
            ap.error(f"{name} must not start with '-' or contain spaces or '@'")
    for opt in args.ssh_opt or []:
        why = ssh_opt_problem(opt)
        if why:
            ap.error(f"--ssh-opt {opt!r} refused: {why}")
    if args.config_file and (args.dhcp_scan or args.updates):
        ap.error("--dhcp-scan and --updates need a live firewall")
    if args.config_file and args.external and not args.wan_ip:
        # A saved file may not be your own: never take a probe target from it.
        ap.error("--external with --config-file needs an explicit --wan-ip")

    catalog = tomllib.loads((HERE / "checks.toml").read_text())["checks"]
    if args.config_file:
        cfg = Path(args.config_file)
        if not cfg.is_file() or cfg.stat().st_size > 50_000_000:
            sys.exit(f"Not a readable config file: {cfg}")
        sections = {"config": cfg.read_text(encoding="utf-8", errors="replace")}
    else:
        sections = split_sections(run_remote(args, REMOTE_SCRIPT))
    missing = [] if args.config_file else sorted(REMOTE_SECTIONS - set(sections) - {"config"})
    incomplete = not args.config_file and ("end" not in sections or bool(missing))
    if incomplete:
        print("warning: the remote run did not finish" + (f"; missing: {', '.join(missing)}" if missing else "")
              + ". Checks that need missing data report WARN.", file=sys.stderr)
    try:
        root = ET.fromstring(sections.pop("config"))
    except (KeyError, ET.ParseError) as e:
        sys.exit(f"Could not read config.xml: {e}")
    ctx = Ctx(args.host or "config-file", sections, root, args, offline=bool(args.config_file))
    ctx.incomplete = incomplete
    if args.updates:
        ctx.sections.update(split_sections(run_remote(args, UPDATES_SCRIPT)))
    if args.dhcp_scan:
        # Validate the interface name before it goes into a remote command. If the scan
        # cannot run, its section stays missing and UNIFI-006 reports WARN, not PASS.
        lan_if = ctx.get("interfaces/lan/if") or ""
        mac = ""
        if re.fullmatch(r"[a-z][a-z0-9_.]*", lan_if):
            for line in run_remote(args, f"ifconfig {lan_if} | grep ether").splitlines():
                mac = line.split()[-1]
        if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
            ctx.sections.update(split_sections(run_remote(args, dhcp_scan_script(lan_if, mac))))
        else:
            print(f"warning: DHCP scan skipped, LAN interface {lan_if!r} or its MAC could not be read", file=sys.stderr)
    if args.external:
        ctx.external = external_tests(ctx)
    if args.feeds:
        ctx.feeds = feed_tests(ctx)
    if args.unifi:
        ctx.unifi = unifi_from_args(args)

    results = build(catalog, ctx)
    del root  # the config never leaves memory and is not kept
    if args.json:
        doc = {"version": clean(ctx.version, 60), "pfaudit": VERSION, "complete": not incomplete, "results": results}
        if ctx.unifi:  # summary only; raw controller data is never output
            doc["unifi"] = {k: ([clean(e, 300) for e in v] if isinstance(v, list) else clean(v, 300) if isinstance(v, str) else v)
                            for k in ("url", "version", "tls", "errors", "fatal") for v in [ctx.unifi.get(k)]}
        print(json.dumps(doc, indent=2, default=str))
    else:
        print(markdown(results, ctx))
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 2 if incomplete else 0)


if __name__ == "__main__":
    main()
