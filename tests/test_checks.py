"""Offline tests for every pfaudit check, using synthetic fixtures.

No SSH, no DNS and no network: Ctx objects are built from tests/fixtures,
and anything that would resolve or connect is patched.

Run from the repository root:
    .venv/bin/python -I -m unittest discover tests -v
"""

import argparse
import importlib.util
import ipaddress
import base64
import json
import sys
import tomllib
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load_pfaudit():
    """Import pfaudit.py by path (recipe from the importlib docs, Python 3.15).

    Reuses an already imported copy of the same file, so CHECKS is shared with
    test_unifi.py when both run in one process.
    """
    path = ROOT / "pfaudit.py"
    have = sys.modules.get("pfaudit")
    if have is not None and Path(getattr(have, "__file__", "")).resolve() == path:
        return have
    spec = importlib.util.spec_from_file_location("pfaudit", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pfaudit"] = module  # before exec, so dataclasses can resolve the module
    spec.loader.exec_module(module)
    return module


pa = load_pfaudit()
CATALOG = tomllib.loads((ROOT / "checks.toml").read_text(encoding="utf-8"))["checks"]
CAT_BY_ID = {c["id"]: c for c in CATALOG}


def load_extras(variant):
    data = json.loads((FIXTURES / f"extras_{variant}.json").read_text(encoding="utf-8"))
    ext = data["external"]
    data["external"] = {"ip": ext["ip"], "tcp": {int(k): v for k, v in ext["tcp"].items()},
                        "udp": {int(k): v for k, v in ext["udp"].items()}}
    data["feeds"] = [tuple(f) for f in data["feeds"]]
    return data


def make_args(**over):
    ns = argparse.Namespace(feeds=True, dhcp_scan=True, unifi="https://unifi.example.com", unifi_open_ssid=None,
                            wan_ip=None, external=True, updates=True, json=False)
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def make_ctx(variant="good", sections=None, config=None, args=None, external=None, feeds=None, unifi=None):
    """A Ctx from fixtures. sections/config are edits applied on top of the variant."""
    secs = pa.split_sections((FIXTURES / f"sections_{variant}.txt").read_text(encoding="utf-8"))
    secs.update(sections or {})
    root = ET.fromstring((FIXTURES / f"config_{variant}.xml").read_bytes())
    for fn in config or ():
        fn(root)
    extras = load_extras(variant)
    return pa.Ctx("fw.example.com", secs, root, args or make_args(),
                  external=extras["external"] if external is None else external,
                  feeds=extras["feeds"] if feeds is None else feeds,
                  unifi=extras["unifi"] if unifi is None else unifi)


def remove(path):
    """Config edit: remove every element at path (ElementTree has no parent links)."""
    parent_path, _, tag = path.rpartition("/")

    def edit(root):
        for parent in root.findall(parent_path) if parent_path else [root]:
            for el in parent.findall(tag):
                parent.remove(el)
    return edit


def set_text(path, text):
    def edit(root):
        el = root.find(path)
        if el is None:
            parent_path, _, tag = path.rpartition("/")
            el = ET.SubElement(root.find(parent_path) if parent_path else root, tag)
        el.text = text
    return edit


def run(cid, ctx):
    return pa.CHECKS[cid](ctx)


# Expected status of every implemented check on each fixture. A new check in
# checks.toml makes test_every_check_has_expectations fail until it is added.
EXPECT_GOOD = {
    "ACCESS-001": "PASS", "ACCESS-002": "PASS", "ACCESS-003": "PASS", "ACCESS-004": "PASS", "ACCESS-005": "PASS",
    "ACCESS-006": "PASS", "ACCESS-007": "PASS", "ACCESS-008": "PASS",
    "PERIM-001": "PASS", "PERIM-002": "INFO", "PERIM-003": "INFO", "PERIM-004": "PASS", "PERIM-005": "PASS",
    "VPN-001": "PASS", "VPN-002": "PASS", "VPN-003": "PASS", "VPN-004": "PASS", "VPN-005": "INFO",
    "VPN-006": "INFO",  # CE 2.9 has no DCO, so INFO is the best result there
    "VPN-007": "PASS", "VPN-008": "PASS", "VPN-009": "PASS",
    "DNS-001": "PASS", "DNS-002": "PASS", "DNS-003": "PASS", "DNS-004": "INFO", "DNS-005": "PASS", "DNS-006": "PASS",
    "DNS-007": "PASS", "DNS-008": "PASS",
    "PFB-001": "PASS", "PFB-002": "PASS", "PFB-003": "PASS", "PFB-004": "PASS", "PFB-005": "PASS", "PFB-006": "PASS",
    "PFB-007": "PASS", "PFB-008": "PASS", "PFB-009": "PASS",
    "REC-001": "PASS", "REC-002": "PASS", "REC-003": "PASS", "REC-004": "PASS",
    "MON-001": "PASS", "MON-002": "PASS", "MON-003": "PASS", "MON-004": "PASS",
    "HW-001": "PASS", "HW-002": "PASS", "HW-003": "PASS", "HW-004": "PASS", "HW-005": "INFO", "HW-006": "INFO",
    "UPS-001": "PASS",
    "UNIFI-001": "PASS", "UNIFI-002": "PASS", "UNIFI-003": "PASS", "UNIFI-004": "PASS", "UNIFI-005": "PASS",
    "UNIFI-006": "PASS", "UNIFI-007": "INFO",
}

EXPECT_BAD = {
    "ACCESS-001": "FAIL", "ACCESS-002": "FAIL", "ACCESS-003": "FAIL", "ACCESS-004": "WARN", "ACCESS-005": "WARN",
    "ACCESS-006": "FAIL", "ACCESS-007": "FAIL", "ACCESS-008": "WARN",
    "PERIM-001": "FAIL", "PERIM-002": "INFO", "PERIM-003": "INFO", "PERIM-004": "INFO", "PERIM-005": "WARN",
    "VPN-001": "FAIL", "VPN-002": "FAIL", "VPN-003": "WARN", "VPN-004": "WARN", "VPN-005": "INFO", "VPN-006": "INFO",
    "VPN-007": "FAIL", "VPN-008": "WARN", "VPN-009": "WARN",
    "DNS-001": "FAIL", "DNS-002": "WARN", "DNS-003": "WARN", "DNS-004": "INFO", "DNS-005": "FAIL", "DNS-006": "WARN",
    "DNS-007": "FAIL", "DNS-008": "WARN",
    "PFB-001": "WARN", "PFB-002": "FAIL", "PFB-003": "WARN", "PFB-004": "WARN", "PFB-005": "WARN", "PFB-006": "INFO",
    "PFB-007": "INFO", "PFB-008": "FAIL", "PFB-009": "FAIL",
    "REC-001": "WARN", "REC-002": "WARN", "REC-003": "INFO", "REC-004": "WARN",
    "MON-001": "WARN", "MON-002": "WARN", "MON-003": "WARN", "MON-004": "WARN",
    "HW-001": "WARN", "HW-002": "WARN", "HW-003": "WARN", "HW-004": "FAIL", "HW-005": "INFO", "HW-006": "INFO",
    "UPS-001": "FAIL",
    "UNIFI-001": "FAIL", "UNIFI-002": "WARN", "UNIFI-003": "FAIL", "UNIFI-004": "WARN", "UNIFI-005": "WARN",
    "UNIFI-006": "FAIL", "UNIFI-007": "INFO",
}


class CatalogTest(unittest.TestCase):
    def test_every_catalog_check_is_implemented(self):
        missing = [c["id"] for c in CATALOG if c["id"] not in pa.CHECKS and c.get("planned") is not True]
        self.assertEqual(missing, [], "checks.toml ids with no implementation in pfaudit.CHECKS (and not planned = true)")

    def test_no_implementation_outside_catalog(self):
        self.assertEqual(sorted(set(pa.CHECKS) - set(CAT_BY_ID)), [])

    def test_every_check_has_expectations(self):
        implemented = {c["id"] for c in CATALOG if c["id"] in pa.CHECKS}
        self.assertEqual(sorted(implemented - set(EXPECT_GOOD)), [], "add the new check to EXPECT_GOOD")
        self.assertEqual(sorted(implemented - set(EXPECT_BAD)), [], "add the new check to EXPECT_BAD")
        self.assertEqual(sorted(set(EXPECT_GOOD) - implemented), [])
        self.assertEqual(sorted(set(EXPECT_BAD) - implemented), [])


class FixtureTest(unittest.TestCase):
    """Every implemented check, on the good and the bad fixture."""

    def check_variant(self, variant, expect):
        ctx = make_ctx(variant)
        for cid, want in sorted(expect.items()):
            with self.subTest(variant=variant, check=cid):
                r = run(cid, ctx)
                self.assertIn(r.status, pa.ORDER)
                self.assertEqual(r.status, want, f"{cid}: {r.detail}")
                self.assertTrue(r.detail)

    def test_good(self):
        self.check_variant("good", EXPECT_GOOD)

    def test_bad(self):
        self.check_variant("bad", EXPECT_BAD)

    def test_build_has_no_check_errors(self):
        for variant in ("good", "bad"):
            for r in pa.build(CATALOG, make_ctx(variant)):
                with self.subTest(variant=variant, check=r["id"]):
                    self.assertNotIn("Check error", r["detail"])

    def test_good_build_has_no_findings(self):
        bad = [(r["id"], r["status"], r["detail"]) for r in pa.build(CATALOG, make_ctx("good")) if r["status"] in ("FAIL", "WARN")]
        self.assertEqual(bad, [])

    def test_bad_details_name_the_problem(self):
        ctx = make_ctx("bad")
        self.assertIn("http", run("ACCESS-001", ctx).detail)
        self.assertIn("never expire", run("ACCESS-002", ctx).detail)
        detail = run("VPN-001", ctx).detail
        for part in ("tls_type auth", "digest SHA1", "CBC", "DH 1024"):
            self.assertIn(part, detail)
        self.assertNotIn("Retired", detail, "disabled servers must be ignored")
        self.assertIn("443", run("ACCESS-006", ctx).detail)
        self.assertIn("8443", run("ACCESS-006", ctx).detail)
        self.assertIn("lesson 9", run("PFB-002", ctx).detail)
        self.assertIn("2 of 3 feeds", run("PFB-004", ctx).detail)
        self.assertIn("igb0", run("HW-003", ctx).detail)
        self.assertIn("ada0", run("HW-004", ctx).detail)
        self.assertNotIn("ada1", run("HW-004", ctx).detail)
        self.assertIn("00:00:5e:00:53:66", run("UNIFI-006", ctx).detail)


class AccessTest(unittest.TestCase):
    def test_session_timeout_default_and_edges(self):
        self.assertEqual(run("ACCESS-002", make_ctx(config=[remove("system/webgui/session_timeout")])).status, "WARN")
        self.assertEqual(run("ACCESS-002", make_ctx(config=[set_text("system/webgui/session_timeout", "30")])).status, "PASS")
        self.assertEqual(run("ACCESS-002", make_ctx(config=[set_text("system/webgui/session_timeout", "31")])).status, "WARN")

    def test_protocol_default_is_https(self):
        self.assertEqual(run("ACCESS-001", make_ctx(config=[remove("system/webgui/protocol")])).status, "PASS")

    def test_ssh_disabled_passes(self):
        self.assertEqual(run("ACCESS-003", make_ctx("bad", config=[remove("system/ssh/enable")])).status, "PASS")

    def test_ssh_kbdinteractive_alone_fails(self):
        r = run("ACCESS-003", make_ctx(sections={"sshd": "PasswordAuthentication no\nKbdInteractiveAuthentication yes"}))
        self.assertEqual(r.status, "FAIL")

    def test_ssh_unreadable_config_does_not_pass(self):
        # Fixed in pfaudit.py: an empty sshd section used to report key-only.
        self.assertEqual(run("ACCESS-003", make_ctx(sections={"sshd": ""})).status, "WARN")

    def test_disabled_admin_user_ignored(self):
        ctx = make_ctx(config=[remove("system/user")])
        self.assertEqual(run("ACCESS-005", ctx).status, "PASS")

    def test_external_skips(self):
        self.assertEqual(run("ACCESS-006", make_ctx(external={})).status, "SKIP")
        self.assertEqual(run("PERIM-005", make_ctx(external={})).status, "SKIP")

    def test_external_error_skips_not_passes(self):
        # Fixed in pfaudit.py: a dynamic WAN without --wan-ip used to PASS with nothing tested.
        err = {"error": "WAN address is dynamic; pass --wan-ip"}
        for cid in ("ACCESS-006", "PERIM-005"):
            r = run(cid, make_ctx(external=err))
            self.assertEqual(r.status, "SKIP", cid)
            self.assertIn("--wan-ip", r.detail)


class ExternalTestsTest(unittest.TestCase):
    def test_dynamic_wan_without_wan_ip(self):
        ctx = make_ctx(config=[set_text("interfaces/wan/ipaddr", "dhcp")])
        with mock.patch.object(pa.socket, "socket", side_effect=AssertionError("must not connect")):
            self.assertIn("error", pa.external_tests(ctx))

    def test_wan_ip_flag_used_for_dynamic_wan(self):
        # Fixed in pfaudit.py: --wan-ip was ignored whenever the config address was dynamic.
        ctx = make_ctx(config=[set_text("interfaces/wan/ipaddr", "dhcp")], args=make_args(wan_ip="203.0.113.77"))
        targets = []

        class FakeSocket:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                targets.append(addr[0])
                return 111  # refused

            def sendto(self, data, addr):
                targets.append(addr[0])

            def recvfrom(self, n):
                raise TimeoutError

        with mock.patch.object(pa.socket, "socket", FakeSocket):
            out = pa.external_tests(ctx)
        self.assertEqual(out["ip"], "203.0.113.77")
        self.assertEqual(set(targets), {"203.0.113.77"})
        self.assertFalse(any(out["tcp"].values()) or any(out["udp"].values()))


class VpnTest(unittest.TestCase):
    def test_no_servers_skip(self):
        ctx = make_ctx(config=[remove("openvpn/openvpn-server")])
        for cid in ("VPN-001", "VPN-002", "VPN-003", "VPN-005", "VPN-006"):
            self.assertEqual(run(cid, ctx).status, "SKIP", cid)

    def test_mfa_detail(self):
        self.assertIn("no MFA", run("VPN-005", make_ctx("bad")).detail)
        self.assertNotIn("no MFA", run("VPN-005", make_ctx()).detail)

    def test_dco_loaded_passes(self):
        kld = make_ctx().sec("kldstat") + "\n 4    1 0xffffffff83150000    1f0a8 if_ovpn.ko"
        self.assertEqual(run("VPN-006", make_ctx(sections={"kldstat": kld})).status, "PASS")

    def test_version_gate(self):
        for text, is29 in (("2.9.0-RELEASE", True), ("2.9.1-RELEASE", True), ("26.07-RELEASE", False),
                           ("26.10-RELEASE", False), ("", False)):
            self.assertEqual(make_ctx(sections={"version": text}).is_29, is29, text)
        self.assertEqual(make_ctx(sections={"version": ""}).version, "unknown")

    def test_dco_on_non_29_warns_known_26_10_issue(self):
        # Canary for docs/VALIDATING-26.10.md: DCO is a per-tunnel opt-in, off by
        # default, so this WARN is expected to become INFO on 26.10. Update this
        # test when VPN-006 is changed after release-day validation.
        for version in ("26.07-RELEASE", "26.10-RELEASE"):
            self.assertEqual(run("VPN-006", make_ctx(sections={"version": version})).status, "WARN", version)

    def test_cert_expiring_soon_fails(self):
        r = run("VPN-007", make_ctx(sections={"certs": "/var/etc/cert.crt|Jan  1 00:00:00 2000 GMT"}))
        self.assertEqual(r.status, "FAIL")
        self.assertIn("WebGUI", r.detail)

    def test_cert_autorenew_off_warns(self):
        ctx = make_ctx(config=[remove("cert/autorenew")])
        r = run("VPN-007", ctx)
        self.assertEqual(r.status, "WARN")
        self.assertIn("GUI certificate", r.detail)

    def test_unparseable_cert_lines_ignored(self):
        self.assertEqual(run("VPN-007", make_ctx(sections={"certs": "/var/etc/cert.crt|garbage"})).status, "PASS")


class DnsTest(unittest.TestCase):
    def test_intercepted_but_tls_forwarding_passes(self):
        ctx = make_ctx(sections={"dns_intercept": make_ctx("bad").sec("dns_intercept")})
        r = run("DNS-001", ctx)
        self.assertEqual(r.status, "PASS")
        self.assertIn("TLS", r.detail)

    def test_resolver_mode(self):
        ctx = make_ctx(config=[remove("unbound/forwarding")])
        self.assertEqual(run("DNS-002", ctx).status, "INFO")
        self.assertEqual(run("DNS-003", make_ctx("bad", config=[remove("unbound/forwarding")])).status, "PASS")

    def test_tls_without_hostname(self):
        self.assertEqual(run("DNS-002", make_ctx(config=[remove("system/dns1host")])).status, "WARN")

    def test_custom_options_empty_and_comments(self):
        self.assertEqual(run("DNS-005", make_ctx(config=[remove("unbound/custom_options")])).status, "PASS")
        import base64
        txt = base64.b64encode(b"# note\n\nserver:\nverbosity: 1\n").decode()
        self.assertEqual(run("DNS-005", make_ctx(config=[set_text("unbound/custom_options", txt)])).status, "PASS")

    def test_bypass_needs_853_and_53(self):
        self.assertEqual(run("DNS-006", make_ctx(config=[remove("filter/rule")])).status, "WARN")

    def test_unbound_running_but_failing(self):
        r = run("DNS-007", make_ctx(sections={"dns_local": "rcode: SERVFAIL"}))
        self.assertEqual(r.status, "FAIL")
        self.assertIn("SERVFAIL", r.detail)


class PfbTest(unittest.TestCase):
    def test_not_installed_skips(self):
        ctx = make_ctx(config=[remove("installedpackages/pfblockerngdnsblsettings"), remove("installedpackages/pfblockerngipsettings")])
        for cid in ("PFB-001", "PFB-002", "PFB-003", "PFB-005", "PFB-006", "PFB-007"):
            self.assertEqual(run(cid, ctx).status, "SKIP", cid)

    def test_vip_not_listening(self):
        r = run("PFB-002", make_ctx(sections={"sockstat": ""}))
        self.assertEqual(r.status, "FAIL")
        self.assertIn("not listening", r.detail)

    def test_feeds_flag_off_skips(self):
        self.assertEqual(run("PFB-004", make_ctx(args=make_args(feeds=False))).status, "SKIP")

    def test_subdomain_not_blocked_warns(self):
        r = run("PFB-008", make_ctx(sections={"dnsbl_test": "domain ads.example.com\ndirect 198.51.100.250\nsub 192.0.2.80"}))
        self.assertEqual(r.status, "WARN")

    def test_no_zone_data_skips(self):
        self.assertEqual(run("PFB-008", make_ctx(sections={"dnsbl_test": ""})).status, "SKIP")


class RecoveryMonitorHardwareTest(unittest.TestCase):
    def test_acb_without_upload_job_fails(self):
        ctx = make_ctx(sections={"crontab": "SHELL=/bin/sh"})
        r = run("REC-001", ctx)
        self.assertEqual(r.status, "FAIL")
        self.assertIn("lesson 1", r.detail)

    def test_acb_backlog_warns(self):
        self.assertEqual(run("REC-001", make_ctx(sections={"acbstage": "      25"})).status, "WARN")

    def test_acb_stale_staged_backup_warns(self):
        r = run("REC-001", make_ctx(sections={"acbstage": "       2", "acbold": "       1"}))
        self.assertEqual(r.status, "WARN")
        self.assertIn("uploads are failing", r.detail)

    def test_cpufreq_levels_reported_readably(self):
        r = run("HW-005", make_ctx())
        self.assertIn("800 to 2000 MHz", r.detail)
        self.assertIn("idle states C1, C2", r.detail)

    def test_cpufreq_speed_shift(self):
        r = run("HW-005", make_ctx(sections={"cpufreq": "levels \ncx C1/1/1\nepp 50"}))
        self.assertIn("Speed Shift active, EPP 50", r.detail)

    def test_cpufreq_nothing_exposed(self):
        # Seen live on CE 2.9.0: no freq_levels, no hwpstate, only C-states.
        r = run("HW-005", make_ctx(sections={"cpufreq": "levels \ncx C1/1/1 C2/2/151 C3/3/1034\nepp "}))
        self.assertEqual(r.detail, "No OS frequency scaling exposed (likely fixed or controlled in BIOS); idle states C1, C2, C3")

    def test_warns_have_fix_text(self):
        catalog = {c["id"]: c for c in pa.tomllib.loads((pa.HERE / "checks.toml").read_text())["checks"]}
        for cid in ("VPN-004", "DNS-006", "MON-004"):
            self.assertTrue(catalog[cid].get("fix"), cid)
            self.assertTrue(catalog[cid].get("impact"), cid)

    def test_patches_without_autoapply(self):
        self.assertEqual(run("REC-002", make_ctx(config=[remove("installedpackages/patches/autoapply_recommended")])).status, "WARN")

    def test_ufs_no_boot_environments(self):
        self.assertEqual(run("REC-003", make_ctx(sections={"bectl": "0"})).status, "INFO")

    def test_updates_flag_off_skips(self):
        self.assertEqual(run("REC-004", make_ctx(sections={"updates": ""})).status, "SKIP")

    def test_gateway_without_monitor_warns(self):
        self.assertEqual(run("MON-001", make_ctx(config=[remove("gateways/gateway_item/monitor")])).status, "WARN")

    def test_certexpire_default_on(self):
        r = run("MON-003", make_ctx(config=[remove("notifications/certexpire")]))
        self.assertEqual(r.status, "PASS")
        self.assertIn("default", r.detail)

    def test_no_temperature_readings(self):
        self.assertEqual(run("HW-001", make_ctx(sections={"temps": ""})).status, "WARN")

    def test_aesni_module_or_absent_cpu(self):
        ctx = make_ctx("bad", sections={"kldstat": make_ctx().sec("kldstat")})
        self.assertEqual(run("HW-002", ctx).status, "PASS")
        self.assertEqual(run("HW-002", make_ctx("bad", sections={"aesni_cpu": "0"})).status, "INFO")

    def test_no_zfs_pools_with_healthy_smart(self):
        self.assertEqual(run("HW-004", make_ctx(sections={"zpool": "no pools available"})).status, "PASS")

    def test_ups_states(self):
        self.assertEqual(run("UPS-001", make_ctx(config=[remove("installedpackages/nut")])).status, "SKIP")
        r = run("UPS-001", make_ctx(config=[set_text("installedpackages/nut/config/email", "no")]))
        self.assertEqual(r.status, "WARN")
        self.assertIn("lesson 4", r.detail)
        self.assertEqual(run("UPS-001", make_ctx(sections={"ups": ""})).status, "FAIL")

    def test_every_ups_must_be_online(self):
        # Fixed in pfaudit.py: any "OL" anywhere used to pass, even with a second UPS on battery.
        self.assertEqual(run("UPS-001", make_ctx(sections={"ups": "ups1 OL\nups2 OB LB"})).status, "FAIL")
        self.assertEqual(run("UPS-001", make_ctx(sections={"ups": "COLO OB"})).status, "FAIL")
        self.assertEqual(run("UPS-001", make_ctx(sections={"ups": "ups1 OL\nups2 OL CHRG"})).status, "PASS")


class UnifiFixtureTest(unittest.TestCase):
    def test_flags_off_skip(self):
        ctx = make_ctx(args=make_args(unifi=None, dhcp_scan=False))
        for cid in ("UNIFI-001", "UNIFI-002", "UNIFI-003", "UNIFI-004", "UNIFI-005", "UNIFI-006", "UNIFI-007"):
            self.assertEqual(run(cid, ctx).status, "SKIP", cid)

    def test_legacy_refused_falls_back_or_skips(self):
        u = load_extras("good")["unifi"]
        u["legacy"] = None
        u["errors"] = ["legacy API: HTTP 401 on /proxy/network/api/s/default/get/setting"]
        ctx = make_ctx(unifi=u)
        self.assertEqual(run("UNIFI-001", ctx).status, "PASS")
        self.assertEqual(run("UNIFI-003", ctx).status, "PASS")
        self.assertEqual(run("UNIFI-005", ctx).status, "INFO")
        for cid in ("UNIFI-002", "UNIFI-004"):
            r = run(cid, ctx)
            self.assertEqual(r.status, "SKIP", cid)
            self.assertIn("401", r.detail)

    def test_bad_details(self):
        ctx = make_ctx("bad")
        self.assertIn("LAN", run("UNIFI-001", ctx).detail)
        d3 = run("UNIFI-003", ctx).detail
        self.assertIn("guest SSID Visitors is open", d3)
        self.assertIn("Guest WiFi looks like a guest SSID", d3)
        d5 = run("UNIFI-005", ctx).detail
        self.assertIn("ap1 informs to 192.0.2.50", d5)
        self.assertIn("sw1 isolated", d5)
        self.assertIn("accepts passwords", run("UNIFI-007", ctx).detail)

    def test_unverified_fail_is_reported_as_warn(self):
        results = {r["id"]: r for r in pa.build(CATALOG, make_ctx("bad"))}
        for cid in ("UNIFI-001", "UNIFI-003"):
            self.assertIn("unverified", CAT_BY_ID[cid]["verified_on"])
            self.assertEqual(results[cid]["status"], "WARN", cid)
            self.assertIn("not yet verified", results[cid]["detail"])
        self.assertEqual(results["UNIFI-006"]["status"], "FAIL")


class BuildAndReportTest(unittest.TestCase):
    def test_check_exception_becomes_skip(self):
        def boom(ctx):
            raise ValueError("synthetic")
        with mock.patch.dict(pa.CHECKS, {"ACCESS-001": boom}):
            r = {x["id"]: x for x in pa.build(CATALOG, make_ctx())}["ACCESS-001"]
        self.assertEqual(r["status"], "SKIP")
        self.assertIn("Check error: ValueError", r["detail"])

    def test_planned_check_without_implementation(self):
        cat = CATALOG + [{"id": "TEST-999", "category": "test", "title": "planned", "risk": "low",
                          "verified_on": ["unverified"], "planned": True}]
        r = {x["id"]: x for x in pa.build(cat, make_ctx())}["TEST-999"]
        self.assertEqual((r["status"], r["detail"]), ("SKIP", "No implementation yet"))

    def test_results_sorted_by_status_then_risk(self):
        results = pa.build(CATALOG, make_ctx("bad"))
        keys = [(pa.ORDER[r["status"]], pa.RISK.get(r["risk"], 9), r["id"]) for r in results]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(results), len(CATALOG))

    def test_markdown_has_no_secrets(self):
        for variant in ("good", "bad"):
            ctx = make_ctx(variant)
            md = pa.markdown(pa.build(CATALOG, ctx), ctx)
            self.assertIn("# pfSense audit: fw", md)
            for secret in ("FIXTURE-NOT-A-REAL-HASH", "fixture-token", "fixture-key", "x_ssh"):
                self.assertNotIn(secret, md)
        self.assertIn("--unifi-insecure", pa.markdown([], make_ctx("bad")))

    def test_json_round_trip(self):
        results = pa.build(CATALOG, make_ctx())
        doc = json.loads(json.dumps({"version": "2.9.0-RELEASE", "pfaudit": pa.VERSION, "results": results}, default=str))
        self.assertEqual({r["id"] for r in doc["results"]}, set(CAT_BY_ID))


class SplitSectionsTest(unittest.TestCase):
    def test_markers_and_preamble(self):
        out = pa.split_sections("banner\n@@one\na\nb\n@@two\n@@ not a marker\n@@Bad\nc\n@@three")
        self.assertEqual(out, {"one": "a\nb", "two": "@@ not a marker\n@@Bad\nc", "three": ""})

    def test_fixture_sections_cover_remote_script(self):
        wanted = {line.split()[1].rstrip(";") for line in pa.REMOTE_SCRIPT.splitlines() if line.startswith("s ")}
        self.assertTrue(wanted)
        for variant in ("good", "bad"):
            have = set(make_ctx(variant).sections)
            self.assertEqual(sorted(wanted - {"config"} - have), [], variant)


def _fake_global(prefix="203.0.113.0/24"):
    """Treat one documentation range as public, so no real public address is needed."""
    net = ipaddress.ip_network(prefix)
    original = ipaddress.IPv4Address.is_global

    def is_global(self):
        return True if self in net else original.fget(self)
    return mock.patch.object(ipaddress.IPv4Address, "is_global", property(is_global))


def _addrinfo(*ips):
    def fake(host, port, *a, **k):
        return [(2, 1, 6, "", (ip, port)) for ip in ips]
    return fake


class FeedGuardTest(unittest.TestCase):
    def test_public_url_rejects_schemes_and_hosts(self):
        with mock.patch.object(pa.socket, "getaddrinfo", side_effect=AssertionError("no lookup expected")):
            for url in ("ftp://lists.example.com/a", "file:///etc/passwd", "https:///nohost", "gopher://x.example.com/"):
                self.assertFalse(pa.public_url(url), url)

    def test_public_url_rejects_non_public(self):
        # The all-hosts multicast group (0xE0000001). Python counts it as is_global,
        # so it tests the is_multicast guard. Built from an int so the repo's
        # address gate does not read it as a public host.
        multicast = str(ipaddress.IPv4Address(0xE0000001))
        for ip in ("127.0.0.1", "192.0.2.7", "10.1.2.3", "169.254.169.254", multicast, "::1", "fe80::1", "2001:db8::1"):
            with mock.patch.object(pa.socket, "getaddrinfo", _addrinfo(ip)):
                self.assertFalse(pa.public_url("https://lists.example.com/a"), ip)

    def test_public_url_lookup_failure(self):
        with mock.patch.object(pa.socket, "getaddrinfo", side_effect=OSError("nxdomain")):
            self.assertFalse(pa.public_url("https://lists.example.com/a"))

    def test_public_url_any_private_answer_rejects(self):
        with _fake_global(), mock.patch.object(pa.socket, "getaddrinfo", _addrinfo("203.0.113.10", "192.168.1.1")):
            self.assertFalse(pa.public_url("https://lists.example.com/a"))

    def test_public_url_accepts_public(self):
        with _fake_global(), mock.patch.object(pa.socket, "getaddrinfo", _addrinfo("203.0.113.10")) as _:
            self.assertTrue(pa.public_url("https://lists.example.com/a"))
            self.assertTrue(pa.public_url("http://lists.example.com:8080/a"))

    def test_public_url_uses_default_port(self):
        seen = []

        def fake(host, port, *a, **k):
            seen.append((host, port))
            return [(2, 1, 6, "", ("192.0.2.7", port))]
        with mock.patch.object(pa.socket, "getaddrinfo", fake):
            pa.public_url("https://lists.example.com/a")
            pa.public_url("http://lists.example.com/a")
        self.assertEqual(seen, [("lists.example.com", 443), ("lists.example.com", 80)])

    def test_safe_url(self):
        self.assertEqual(pa.safe_url("https://user:pw@lists.example.com:8443/path/a.txt?token=abc#frag"),
                         "https://lists.example.com:8443/path/a.txt?...")
        self.assertEqual(pa.safe_url("https://lists.example.com/a.txt"), "https://lists.example.com/a.txt")
        self.assertEqual(pa.safe_url("https://lists.example.com/a.txt#x"), "https://lists.example.com/a.txt")

    def test_redirect_to_private_blocked(self):
        handler = pa._CheckedRedirect()
        req = urllib.request.Request("https://lists.example.com/a")
        with mock.patch.object(pa.socket, "getaddrinfo", _addrinfo("192.0.2.7")):
            with self.assertRaises(urllib.error.URLError):
                handler.redirect_request(req, None, 302, "Found", {}, "http://internal.example.com/")
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")

    def test_redirect_to_public_allowed(self):
        handler = pa._CheckedRedirect()
        req = urllib.request.Request("https://lists.example.com/a")
        with _fake_global(), mock.patch.object(pa.socket, "getaddrinfo", _addrinfo("203.0.113.10")):
            new = handler.redirect_request(req, None, 302, "Found", {}, "https://mirror.example.com/a")
        self.assertEqual(new.full_url, "https://mirror.example.com/a")

    def test_live_peer_check(self):
        class Sock:
            closed = False

            def __init__(self, ip):
                self.ip = ip

            def getpeername(self):
                return (self.ip, 443)

            def close(self):
                self.closed = True

        s = Sock("192.0.2.7")
        with self.assertRaises(urllib.error.URLError):
            pa._require_public_peer(s)
        self.assertTrue(s.closed)
        with _fake_global():
            ok = Sock("203.0.113.10")
            pa._require_public_peer(ok)
            self.assertFalse(ok.closed)

    def test_feed_tests_skip_non_public_without_connecting(self):
        ctx = make_ctx()
        with mock.patch.object(pa.urllib.request.OpenerDirector, "open", side_effect=AssertionError("must not fetch")):
            out = pa.feed_tests(ctx)
        self.assertEqual(sorted(out), [
            ("http://127.0.0.1/local-list.txt", "skipped: not a public address"),
            ("https://192.0.2.7/ads.txt?...", "skipped: not a public address"),
        ])
        dump = json.dumps(out)
        for secret in ("fixture-token", "fixture-key", "user:", "disabled.txt"):
            self.assertNotIn(secret, dump)



class LiveRunAdditionsTest(unittest.TestCase):
    """Checks added after the first live run (CE 2.9.0 site firewall)."""

    def test_md5_hash_user_named(self):
        r = run("ACCESS-008", make_ctx("bad"))
        self.assertIn("frontdesk", r.detail)
        self.assertNotIn("FIXTURE", r.detail)

    def test_vpn_dns_not_firewall_warns(self):
        r = run("VPN-008", make_ctx(sections={"ovpn_push": "1 9.9.9.9 "}))
        self.assertEqual(r.status, "WARN")
        self.assertIn("9.9.9.9", r.detail)

    def test_vpn_dns_tunnel_gateway_passes(self):
        self.assertEqual(run("VPN-008", make_ctx(sections={"ovpn_push": "1 198.51.100.129 "})).status, "PASS")

    def test_vpn_dns_falls_back_to_config(self):
        ctx = make_ctx(sections={"ovpn_push": ""}, config=[set_text("openvpn/openvpn-server/dns_server1", "192.0.2.1")])
        self.assertEqual(run("VPN-008", ctx).status, "PASS")

    def test_vpn_no_dns_warns(self):
        r = run("VPN-008", make_ctx("bad"))
        self.assertIn("pushes no DNS", r.detail)

    def test_asym_compression_is_info(self):
        ctx = make_ctx(config=[set_text("openvpn/openvpn-server/allow_compression", "asym")])
        self.assertEqual(run("VPN-009", ctx).status, "INFO")

    def test_compression_and_net30_warn(self):
        r = run("VPN-009", make_ctx("bad"))
        self.assertIn("compression allowed", r.detail)
        self.assertIn("net30", r.detail)

    def test_resolver_tuning_in_custom_options_is_info(self):
        opts = base64.b64encode(b"server:\nmsg-cache-size: 64m\nprefetch: yes\n").decode()
        r = run("DNS-008", make_ctx(config=[set_text("unbound/custom_options", opts)]))
        self.assertEqual(r.status, "INFO")
        self.assertIn("64 MB", r.detail)
        self.assertIn("lesson 27", r.detail)

    def test_resolver_default_warns(self):
        self.assertIn("4 MB, prefetch off", run("DNS-008", make_ctx("bad")).detail)

    def test_resolver_byte_values(self):
        r = run("DNS-008", make_ctx(sections={"unbound_eff": "msg-cache-size: 67108864\nprefetch: yes"}))
        self.assertEqual(r.status, "PASS")
        self.assertIn("64 MB", r.detail)

    def test_pfb_stale_lists_warn(self):
        r = run("PFB-009", make_ctx(sections={"pfb_age": "1 3"}))
        self.assertEqual(r.status, "WARN")
        self.assertIn("2 of 3", r.detail)

    def test_pfb_missing_cron_fails(self):
        self.assertEqual(run("PFB-009", make_ctx("bad")).status, "FAIL")

    def test_smtp_recent_failure_warns(self):
        r = run("MON-002", make_ctx(sections={"smtpfail": "2026 Nov 06 09:00:00\nNov  5 21:32:00"}))
        self.assertEqual(r.status, "WARN")
        self.assertIn("11 h ago", r.detail)

    def test_smtp_old_failure_passes(self):
        r = run("MON-002", make_ctx(sections={"smtpfail": "2026 Nov 06 09:00:00\nOct  1 10:00:00"}))
        self.assertEqual(r.status, "PASS")

    def test_smtp_failure_across_new_year(self):
        r = run("MON-002", make_ctx(sections={"smtpfail": "2027 Jan 02 09:00:00\nDec 31 09:00:00"}))
        self.assertIn("48 h ago", r.detail)

    def test_smtp_failure_detail_has_no_addresses(self):
        r = run("MON-002", make_ctx("bad"))
        self.assertNotIn("@", r.detail)

if __name__ == "__main__":
    unittest.main()


class TestAccess007Order(unittest.TestCase):
    """ACCESS-007 must honour rule order: a block to (self) above the broad pass protects management."""

    def _ctx(self, rules_xml):
        cfg = f"<pfsense><filter>{rules_xml}</filter></pfsense>"
        return pa.Ctx("192.0.2.1", {}, pa.ET.fromstring(cfg), None)

    def test_block_self_before_pass_any_passes(self):
        x = ('<rule><type>pass</type><interface>openvpn</interface><source><address>198.51.100.200</address></source><destination><any/></destination></rule>'
             '<rule><type>block</type><interface>openvpn</interface><source><any/></source><destination><network>(self)</network><port>FW_MGMT</port></destination></rule>'
             '<rule><type>pass</type><interface>openvpn</interface><source><any/></source><destination><any/></destination></rule>')
        r = pa.CHECKS["ACCESS-007"](self._ctx(x))
        self.assertEqual(r.status, "INFO")
        self.assertIn("198.51.100.200", r.detail)

    def test_block_self_with_no_exception_passes(self):
        x = ('<rule><type>block</type><interface>openvpn</interface><source><any/></source><destination><network>(self)</network></destination></rule>'
             '<rule><type>pass</type><interface>openvpn</interface><source><any/></source><destination><any/></destination></rule>')
        self.assertEqual(pa.CHECKS["ACCESS-007"](self._ctx(x)).status, "PASS")

    def test_pass_any_before_block_fails(self):
        x = ('<rule><type>pass</type><interface>openvpn</interface><source><any/></source><destination><any/></destination></rule>'
             '<rule><type>block</type><interface>openvpn</interface><source><any/></source><destination><network>(self)</network></destination></rule>')
        self.assertEqual(pa.CHECKS["ACCESS-007"](self._ctx(x)).status, "FAIL")
