"""Offline tests for scripts/validate_release.py, using pfaudit results built from fixtures."""

import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_checks as tc  # noqa: E402  (fixture helpers from this folder; c7-ok)

ROOT = HERE.parent


def load_script():
    spec = importlib.util.spec_from_file_location("validate_release", ROOT / "scripts" / "validate_release.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_release"] = module
    spec.loader.exec_module(module)
    return module


vr = load_script()


def pfaudit_json(ctx, version):
    results = tc.pa.build(tc.CATALOG, ctx)
    return json.loads(json.dumps({"version": version, "pfaudit": tc.pa.VERSION, "results": results}, default=str))


def by_id(doc):
    return {r["id"]: r for r in doc["results"]}


class CompareResultsTest(unittest.TestCase):
    def setUp(self):
        self.base = pfaudit_json(tc.make_ctx(), "2.9.0-RELEASE")

    def compare(self, new, **kw):
        return vr.compare_results(tc.CATALOG, by_id(self.base), by_id(new), "pfsense-26.10", **kw)

    def test_identical_run_is_clean_and_proposes_tags(self):
        rep = self.compare(copy.deepcopy(self.base))
        self.assertFalse(vr.needs_attention(rep))
        proposed = {r["id"]: r["verified_on"] for r in rep["propose"]}
        self.assertEqual(proposed["ACCESS-001"], ["ce-2.9.0", "pfsense-26.10"])
        # never proposed: unverified, manual, UniFi controller checks
        for cid in ("VPN-005", "HW-005", "HW-006", "UNIFI-001", "UNIFI-002", "UNIFI-007"):
            self.assertNotIn(cid, proposed)
        self.assertIn("UNIFI-006", proposed)  # a pfSense-side command, tagged ce-2.9.0

    def test_status_change_needs_review(self):
        new = pfaudit_json(tc.make_ctx(sections={"version": "26.10-RELEASE"}), "26.10-RELEASE")
        rep = self.compare(new)
        changed = {r["id"]: r for r in rep["changed"]}
        self.assertEqual((changed["VPN-006"]["baseline"], changed["VPN-006"]["candidate"]), ("INFO", "WARN"))
        self.assertIn("VPN-006", {r["id"] for r in rep["propose_after_review"]})
        self.assertNotIn("VPN-006", {r["id"] for r in rep["propose"]})
        self.assertTrue(vr.needs_attention(rep))

    def test_errors_skips_and_missing(self):
        new = copy.deepcopy(self.base)
        rows = by_id(new)
        rows["DNS-007"].update(status="SKIP", detail="Check error: KeyError: 'x'")
        rows["REC-003"].update(status="SKIP", detail="No zpool")
        rows["PFB-004"].update(status="SKIP", detail="Run with --feeds to test feed URLs")
        new["results"] = [r for r in new["results"] if r["id"] != "MON-004"]
        rep = self.compare(new)
        self.assertEqual([r["id"] for r in rep["errored"]], ["DNS-007"])
        self.assertEqual([r["id"] for r in rep["unexpected_skip"]], ["REC-003"])
        self.assertEqual([r["id"] for r in rep["not_exercised"]], ["PFB-004"])
        self.assertEqual(rep["missing"], [{"id": "MON-004", "where": "candidate"}])
        proposed = {r["id"] for r in rep["propose"] + rep["propose_after_review"]}
        self.assertFalse(proposed & {"DNS-007", "REC-003", "PFB-004", "MON-004"})
        rep2 = self.compare(new, expect_skip={"REC-003"})
        self.assertEqual(rep2["unexpected_skip"], [])

    def test_planned_checks_ignored(self):
        cat = tc.CATALOG + [{"id": "TEST-999", "category": "t", "title": "t", "risk": "low", "planned": True,
                             "verified_on": ["unverified"]}]
        rep = vr.compare_results(cat, by_id(self.base), by_id(self.base), "pfsense-26.10")
        self.assertFalse(vr.needs_attention(rep))

    def test_already_tagged_not_proposed(self):
        cat = copy.deepcopy(tc.CATALOG)
        next(c for c in cat if c["id"] == "ACCESS-001")["verified_on"].append("pfsense-26.10")
        rep = vr.compare_results(cat, by_id(self.base), by_id(self.base), "pfsense-26.10")
        self.assertIn({"id": "ACCESS-001", "why": "already tagged"}, rep["not_proposed"])


class CliTest(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vr.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def write(self, d, name, doc):
        p = Path(d) / name
        p.write_text(json.dumps(doc), encoding="utf-8")
        return str(p)

    def test_results_clean_and_changed(self):
        base = pfaudit_json(tc.make_ctx(), "2.9.0-RELEASE")
        new = pfaudit_json(tc.make_ctx(sections={"version": "26.10-RELEASE"}), "26.10-RELEASE")
        with tempfile.TemporaryDirectory() as d:
            b, n = self.write(d, "b.json", base), self.write(d, "n.json", new)
            same = self.write(d, "same.json", {**base, "version": "26.10-RELEASE"})
            code, out, _ = self.run_cli("results", b, same)
            self.assertEqual(code, 0, out)
            self.assertIn('ACCESS-001: verified_on = ["ce-2.9.0", "pfsense-26.10"]', out)
            self.assertIn("Result: clean", out)
            code, out, _ = self.run_cli("results", b, n)
            self.assertEqual(code, 1)
            self.assertIn("VPN-006: INFO -> WARN", out)
            code, out, _ = self.run_cli("results", b, n, "--json")
            self.assertEqual(json.loads(out)["changed"][0]["id"], "VPN-006")

    def test_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            junk = self.write(d, "junk.json", {"nope": 1})
            code, _, err = self.run_cli("results", junk, junk)
            self.assertEqual(code, 2)
            self.assertIn("not `pfaudit.py --json` output", err)
            ok = self.write(d, "ok.json", pfaudit_json(tc.make_ctx(), "2.9.0-RELEASE"))
            code, _, err = self.run_cli("results", ok, ok, "--tag", "26.10")
            self.assertEqual(code, 2)

    def test_paths_manifest_and_diff(self):
        good, bad = str(tc.FIXTURES / "config_good.xml"), str(tc.FIXTURES / "config_bad.xml")
        code, out, _ = self.run_cli("paths", good, "--json")
        self.assertEqual(code, 0)
        rep = json.loads(out)
        present = {r["path"] for r in rep["present"]}
        for p in ("system/webgui/protocol", "installedpackages/pfblockerngdnsblsettings/config/dnsbl_mode", "openvpn/openvpn-server"):
            self.assertIn(p, present)
        self.assertIn("installedpackages/{sec}/config/row", rep["dynamic"])
        self.assertNotIn("FIXTURE-NOT-A-REAL-HASH", out)
        code, out, _ = self.run_cli("paths", good, good)
        self.assertEqual(code, 0)
        code, out, _ = self.run_cli("paths", good, bad)
        self.assertEqual(code, 1)
        self.assertIn("system/acb/enable (1 -> 0)", out)
        for value in ("203.0.113", "198.51.100", "example.com", "FIXTURE"):
            self.assertNotIn(value, out, "paths output must never print config values")

    def test_new_top_level_section_reported(self):
        with tempfile.TemporaryDirectory() as d:
            src = (tc.FIXTURES / "config_good.xml").read_text(encoding="utf-8")
            p = Path(d) / "new.xml"
            p.write_text(src.replace("</pfsense>", "<coredns><enable></enable></coredns></pfsense>"), encoding="utf-8")
            code, out, _ = self.run_cli("paths", str(tc.FIXTURES / "config_good.xml"), str(p), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["new_top_level"], ["coredns"])


if __name__ == "__main__":
    unittest.main()
