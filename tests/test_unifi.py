"""Offline tests for the UniFi collector and checks. No network access.

Run: .venv/bin/python -I -m unittest discover -s tests
"""

import argparse
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pfaudit as pa  # noqa: E402  (local module; c7-ok)

CONFIG = """<pfsense>
  <interfaces>
    <lan><if>igb1</if><ipaddr>192.0.2.1</ipaddr></lan>
    <opt1><if>igb1.20</if><ipaddr>198.51.100.1</ipaddr></opt1>
  </interfaces>
  <vlans><vlan><if>igb1</if><tag>20</tag><vlanif>igb1.20</vlanif></vlan></vlans>
</pfsense>"""

SITE = {"id": "11111111-2222-3333-4444-555555555555", "internalReference": "default", "name": "Default"}
LEG = "/proxy/network/api/s/default"
INT = "/proxy/network/integration/v1"
SITE_BASE = f"{INT}/sites/{SITE['id']}"


def page(items):
    return {"offset": 0, "limit": 200, "count": len(items), "totalCount": len(items), "data": items}


def legacy(items):
    return {"meta": {"rc": "ok"}, "data": items}


class FakeClient(pa.UnifiClient):
    """Serves canned responses through the real pages() and legacy() logic."""

    def __init__(self, routes, refused=()):
        self.base, self.host, self.tls = "https://unifi.example.com", "unifi.example.com", "ca-file"
        self.routes, self.refused, self.calls = routes, set(refused), []

    def get(self, path, params=None):
        self.calls.append(path)
        if path in self.refused:
            raise pa.UnifiError(f"HTTP 401 on {path}", 401)
        if path not in self.routes:
            raise pa.UnifiError(f"HTTP 404 on {path}", 404)
        return pa.unifi_scrub(json.loads(json.dumps(self.routes[path])))


def full_routes():
    return {
        f"{INT}/info": {"applicationVersion": "11.0.97"},
        f"{INT}/sites": page([SITE]),
        f"{SITE_BASE}/devices": page([{"id": "d1", "name": "sw1", "model": "USW", "state": "ONLINE", "firmwareUpdatable": True}]),
        f"{SITE_BASE}/networks": page([{"id": "n1"}, {"id": "n2"}]),
        f"{SITE_BASE}/networks/n1": {"id": "n1", "name": "LAN", "vlanId": 1, "enabled": True, "management": "UNMANAGED",
                                     "dhcpGuarding": {"trustedDhcpServerIpAddresses": ["192.0.2.1"]}},
        f"{SITE_BASE}/networks/n2": {"id": "n2", "name": "Guest", "vlanId": 20, "enabled": True, "management": "UNMANAGED",
                                     "dhcpGuarding": {"trustedDhcpServerIpAddresses": ["198.51.100.1"]}},
        f"{SITE_BASE}/wifi/broadcasts": page([{"id": "w1"}]),
        f"{SITE_BASE}/wifi/broadcasts/w1": {"id": "w1", "name": "Office", "enabled": True, "clientIsolationEnabled": False,
                                            "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "SECRET-PASS-1",
                                                                      "presharedKeys": [{"key": "SECRET-PSK"}]}},
        f"{LEG}/get/setting": legacy([
            {"key": "global_switch", "dhcp_snoop": True},
            {"key": "guest_access", "restricted_subnet_1": "172.16.0.0/12", "restricted_subnet_2": "192.0.2.0/24",
             "allowed_subnet_1": "192.0.2.1/32", "x_password": "SECRET-PORTAL"},
            {"key": "mgmt", "auto_upgrade": True, "auto_upgrade_hour": 3, "x_ssh_enabled": True,
             "x_ssh_auth_password_enabled": True, "x_ssh_password": "SECRET-SSH", "x_ssh_keys": ["ssh-ed25519 SECRET"]},
        ]),
        f"{LEG}/rest/networkconf": legacy([
            {"name": "LAN", "purpose": "corporate", "dhcpguard_enabled": True, "dhcpd_ip_1": "192.0.2.1"},
            {"name": "Guest", "purpose": "guest", "vlan_enabled": True, "vlan": "20", "dhcpguard_enabled": True,
             "dhcpd_ip_1": "198.51.100.1", "x_ipsec_pre_shared_key": "SECRET-IPSEC"},
            {"name": "WAN", "purpose": "wan"},
        ]),
        f"{LEG}/rest/wlanconf": legacy([
            {"name": "Office", "enabled": True, "is_guest": False, "security": "wpapsk", "x_passphrase": "SECRET-PASS-2"},
            {"name": "Visitors", "enabled": True, "is_guest": True, "security": "wpapsk", "l2_isolation": True, "x_iapp_key": "SECRET-IAPP"},
        ]),
        f"{LEG}/stat/device": legacy([
            {"name": "sw1", "model": "USW", "adopted": True, "state": 1, "inform_url": "http://unifi.example.com:8080/inform"},
            {"name": "ap1", "model": "U7", "adopted": True, "state": 1, "inform_url": "http://192.0.2.50:8080/inform", "inform_ip": "192.0.2.50"},
        ]),
    }


def make_ctx(unifi=None, **args):
    ns = argparse.Namespace(unifi="https://unifi.example.com" if unifi is not False else None, unifi_open_ssid=None)
    for k, v in args.items():
        setattr(ns, k, v)
    return pa.Ctx("fw.example.com", {}, ET.fromstring(CONFIG), ns, unifi=unifi or {})


def collect(routes, refused=()):
    u = pa.unifi_collect(FakeClient(routes, refused), "default")
    u["controller_hosts"] = ["unifi.example.com"]  # no DNS in tests
    return u


class ScrubTest(unittest.TestCase):
    def test_no_secret_survives(self):
        dump = json.dumps(collect(full_routes()))
        for leak in ("SECRET", "x_passphrase", "x_ssh_password", "x_ssh_keys", "x_iapp_key", "x_ipsec", "passphrase", "presharedKeys"):
            self.assertNotIn(leak, dump)

    def test_keeps_ssh_booleans_and_setting_key(self):
        out = pa.unifi_scrub({"key": "mgmt", "x_ssh_enabled": 1, "x_ssh_auth_password_enabled": True, "x_ssh_password": "p"})
        self.assertEqual(out, {"key": "mgmt", "x_ssh_enabled": True, "x_ssh_auth_password_enabled": True})


class CollectTest(unittest.TestCase):
    def test_stops_when_legacy_key_refused(self):
        client = FakeClient(full_routes(), refused={f"{LEG}/get/setting"})
        u = pa.unifi_collect(client, "default")
        self.assertIsNone(u["legacy"])
        self.assertNotIn(f"{LEG}/rest/networkconf", client.calls)
        self.assertEqual(len(u["integration"]["networks"]), 2)

    def test_old_controller_skips_networks(self):
        routes = full_routes()
        routes[f"{INT}/info"] = {"applicationVersion": "9.5.21"}
        u = collect(routes)
        self.assertNotIn("networks", u["integration"])
        self.assertTrue(any("10.0" in e for e in u["errors"]))

    def test_one_failed_detail_call_keeps_devices_and_other_part(self):
        routes = full_routes()
        del routes[f"{SITE_BASE}/wifi/broadcasts/w1"]
        u = collect(routes, refused={f"{LEG}/get/setting"})
        self.assertIsNotNone(u["integration"])
        self.assertNotIn("wlans", u["integration"])
        self.assertEqual(len(u["integration"]["networks"]), 2)
        self.assertTrue(any("wlans" in e and "404" in e for e in u["errors"]))
        self.assertNotIn("fatal", u)
        r5 = pa.CHECKS["UNIFI-005"](make_ctx(u))
        self.assertEqual(r5.status, "INFO")
        self.assertIn("1 devices online", r5.detail)
        r7 = pa.CHECKS["UNIFI-007"](make_ctx(u))
        self.assertIn("1 of 1 devices have a firmware update", r7.detail)
        self.assertEqual(pa.CHECKS["UNIFI-001"](make_ctx(u)).status, "PASS")
        self.assertEqual(pa.CHECKS["UNIFI-003"](make_ctx(u)).status, "SKIP")

    def test_failed_network_detail_drops_networks_only(self):
        routes = full_routes()
        del routes[f"{SITE_BASE}/networks/n2"]
        u = collect(routes)
        self.assertNotIn("networks", u["integration"])
        self.assertEqual(len(u["integration"]["wlans"]), 1)
        r = pa.CHECKS["UNIFI-001"](make_ctx(u))
        self.assertIn("legacy API", r.detail)

    def test_rejects_plain_http_and_credentials(self):
        for url in ("http://unifi.example.com", "https://user:pw@unifi.example.com"):
            with self.assertRaises(pa.UnifiError):
                pa.UnifiClient(url, "k")


class ChecksTest(unittest.TestCase):
    def run_check(self, cid, u, **args):
        return pa.CHECKS[cid](make_ctx(u, **args))

    def test_skip_without_flag(self):
        for cid in ("UNIFI-001", "UNIFI-002", "UNIFI-003", "UNIFI-004", "UNIFI-005", "UNIFI-007"):
            r = pa.CHECKS[cid](make_ctx(False))
            self.assertEqual(r.status, "SKIP")
            self.assertIn("--unifi", r.detail)

    def test_good_site(self):
        u = collect(full_routes())
        for cid in ("UNIFI-001", "UNIFI-002", "UNIFI-003", "UNIFI-004"):
            self.assertEqual(self.run_check(cid, u).status, "PASS", cid)
        r7 = self.run_check("UNIFI-007", u)
        self.assertEqual(r7.status, "INFO")
        self.assertIn("accepts passwords", r7.detail)

    def test_guarding_off_and_wrong_server(self):
        routes = full_routes()
        del routes[f"{SITE_BASE}/networks/n1"]["dhcpGuarding"]
        self.assertEqual(self.run_check("UNIFI-001", collect(routes)).status, "FAIL")
        routes = full_routes()
        routes[f"{SITE_BASE}/networks/n1"]["dhcpGuarding"]["trustedDhcpServerIpAddresses"] = ["192.0.2.99"]
        self.assertEqual(self.run_check("UNIFI-001", collect(routes)).status, "WARN")

    def test_legacy_networks_when_integration_too_old(self):
        routes = full_routes()
        routes[f"{INT}/info"] = {"applicationVersion": "9.5.21"}
        routes[f"{LEG}/rest/networkconf"]["data"][0]["dhcpguard_enabled"] = False
        r = self.run_check("UNIFI-001", collect(routes))
        self.assertEqual(r.status, "FAIL")
        self.assertIn("legacy API", r.detail)

    def test_open_guest_ssid_fails_unless_intended(self):
        routes = full_routes()
        routes[f"{LEG}/rest/wlanconf"]["data"][1]["security"] = "open"
        u = collect(routes)
        self.assertEqual(self.run_check("UNIFI-003", u).status, "FAIL")
        self.assertEqual(self.run_check("UNIFI-003", u, unifi_open_ssid=["Visitors"]).status, "PASS")

    def test_open_hotspot_fails_on_integration_only(self):
        routes = full_routes()
        w = routes[f"{SITE_BASE}/wifi/broadcasts/w1"]
        w["securityConfiguration"] = {"type": "OPEN"}
        w["hotspotConfiguration"] = {"type": "CAPTIVE_PORTAL"}
        self.assertEqual(self.run_check("UNIFI-003", collect(routes, refused={f"{LEG}/get/setting"})).status, "FAIL")

    def test_passpoint_ssid_is_not_guest(self):
        routes = full_routes()
        w = routes[f"{SITE_BASE}/wifi/broadcasts/w1"]
        w["securityConfiguration"] = {"type": "WPA2_ENTERPRISE"}
        w["hotspotConfiguration"] = {"type": "PASSPOINT"}
        r = self.run_check("UNIFI-003", collect(routes, refused={f"{LEG}/get/setting"}))
        self.assertEqual(r.status, "INFO")
        self.assertNotIn("isolation off", r.detail)
        w["hotspotConfiguration"] = {"type": "CAPTIVE_PORTAL"}
        r = self.run_check("UNIFI-003", collect(routes, refused={f"{LEG}/get/setting"}))
        self.assertEqual(r.status, "WARN")
        self.assertIn('guest SSID "Office" has client isolation off', r.detail)

    def test_guest_restrictions_block_firewall(self):
        routes = full_routes()
        routes[f"{LEG}/get/setting"]["data"][1].pop("allowed_subnet_1")
        r = self.run_check("UNIFI-004", collect(routes))
        self.assertEqual(r.status, "WARN")
        self.assertIn("192.0.2.1", r.detail)

    def test_guest_subnets_single_or_list(self):
        nets = pa.guest_subnets({"restricted_subnet": "10.0.0.0/8, 172.16.0.0/12", "restricted_subnet_3": ["192.168.0.0/16"]}, "restricted")
        self.assertEqual(len(nets), 3)

    def test_inform_host_mismatch(self):
        u = collect(full_routes())
        r = self.run_check("UNIFI-005", u)
        self.assertEqual(r.status, "WARN")
        self.assertIn('"ap1" informs to "192.0.2.50"', r.detail)
        u["controller_hosts"].append("192.0.2.50")
        self.assertEqual(self.run_check("UNIFI-005", u).status, "PASS")

    def test_fatal_skips(self):
        u = {"fatal": "no API key in environment variable UNIFI_API_KEY", "errors": []}
        self.assertEqual(self.run_check("UNIFI-001", u).status, "SKIP")


if __name__ == "__main__":
    unittest.main()


class PagesTest(unittest.TestCase):
    """pages() is all or nothing (r/PFSENSE review, 2026-11-12)."""

    def _client(self, responses):
        client = FakeClient({})
        it = iter(responses)
        client.get = lambda path, params=None: next(it)
        return client

    def test_many_pages_collected(self):
        full = [{"data": [{"i": 0}] * 200, "totalCount": 450}, {"data": [{"i": 1}] * 200, "totalCount": 450},
                {"data": [{"i": 2}] * 50, "totalCount": 450}]
        self.assertEqual(len(self._client(full).pages("/x")), 450)

    def test_short_list_raises(self):
        resp = [{"data": [{"i": 0}] * 200, "totalCount": 450}, {"data": [], "totalCount": 450}]
        with self.assertRaises(pa.UnifiError):
            self._client(resp).pages("/x")

    def test_no_total_reads_until_short_page(self):
        resp = [{"data": [{"i": 0}] * 200}, {"data": [{"i": 1}] * 10}]
        self.assertEqual(len(self._client(resp).pages("/x")), 210)

    def test_page_cap_raises_instead_of_truncating(self):
        client = self._client([{"data": [{"i": 0}] * 200, "totalCount": 10**9}] * 3)
        client.MAX_PAGES = 3
        with self.assertRaises(pa.UnifiError):
            client.pages("/x")
