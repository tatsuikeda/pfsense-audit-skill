#!/usr/bin/env python3
"""Gate for the monthly self-update: fail unless the working tree changes
stay inside the allowed paths and follow the repository's content rules.

Run from the repository root after the research patch is applied and before
anything is committed. Standard library only, Python 3.11+.

Usage: python -I check_update_scope.py --month YYYY-MM [--root DIR]

Rules enforced (each failure is printed, exit code 1 on any):
  1. Only checks.toml, LESSONS.md, CHANGELOG.md and new files under
     research/ may change. No deletions, renames, symlinks or mode changes.
  2. research/<month>.md exists and cites at least one https source.
  3. History is kept: no check id removed from checks.toml, no line removed
     from CHANGELOG.md, existing research/ files untouched.
  4. Human-reviewed text is append only. In checks.toml an existing check
     may only gain text at the end of its notes; every other field
     (title, risk, verify, fix, impact, verified_on, ...) and the top-level
     keys must stay identical. New checks are verified_on = ["unverified"].
     In LESSONS.md the only allowed edits are new lessons (a new "### N."
     number) and rows of the lesson 11 feed table (plus its month).
  5. CHANGELOG.md changes whenever checks.toml or LESSONS.md changes.
  6. Added text has no em or en dashes, no spaced double hyphens, no
     invisible or bidirectional control characters, no non-documentation
     IP or MAC addresses, nothing that looks like a credential, and no long
     base64 or hex runs outside URLs.
  7. The research note, which becomes the pull request body, has no
     @mentions outside code spans or fenced code blocks (a mention notifies
     that account as soon as the pull request opens).
"""
# c7-ok: standard library only.

from __future__ import annotations

import argparse
import difflib
import ipaddress
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ALLOWED_FILES = {"checks.toml", "LESSONS.md", "CHANGELOG.md"}
RESEARCH_RE = re.compile(r"^research/[A-Za-z0-9._-]+\.md$")
MAX_NEW_FILE_BYTES = 200_000

DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
    "2001:db8::/32",  # RFC 3849
)]
# Well-known public resolvers and special addresses the docs legitimately name.
ALLOWED_ADDRS = {ipaddress.ip_address(a) for a in (
    "0.0.0.0", "127.0.0.1", "1.1.1.1", "1.0.0.1", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "::", "::1",
)}
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.]*\d)")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
DOC_MAC_PREFIX = "00:00:5e:00:53:"  # RFC 7042 documentation block
BAD_CHARS = {
    "\u2014": "em dash", "\u2013": "en dash", "\u2012": "figure dash", "\u2015": "horizontal bar",
    **{chr(c): "invisible or bidi control U+%04X" % c for c in (
        *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065), *range(0x2066, 0x206A), 0xFEFF, 0x00AD,
    )},
}
DOUBLE_HYPHEN_RE = re.compile(r"(?:^|\s)--(?:\s|$)")
SECRET_RE = re.compile(
    r"(sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gh[ousr]_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\$2[aby]\$\d\d\$[./A-Za-z0-9]{20,})"
)
# Defense in depth against an encoded or reshaped secret: a long run of
# base64 alphabet with mixed case and digits, or a long hex run. URLs are
# removed first, since source links legitimately carry long paths.
URL_RE = re.compile(r"https?://\S+")
B64_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{40,}={0,2}")
HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])")
# GitHub @mention of a user or team. An e-mail address (word character
# before the @) and anything in a code span are not mentions.
MENTION_RE = re.compile(r"(?<![\w`])@[A-Za-z0-9][A-Za-z0-9-]*")
LESSON_HEAD_RE = re.compile(r"^### (\d+)\.")
FEED_LESSON = "11"
FEED_HEADING_RE = re.compile(r"^### 11\. Many classic feeds are dead or empty \([A-Z][a-z]+ \d{4}\)$")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def changed_entries() -> list[tuple[str, str]]:
    """(status, path) for tracked changes against HEAD plus untracked files."""
    out = []
    for line in git("diff", "--name-status", "--no-renames", "HEAD").splitlines():
        status, _, path = line.partition("\t")
        out.append((status, path))
    for path in git("ls-files", "--others", "--exclude-standard").splitlines():
        out.append(("A?", path))
    return out


def added_lines(path: str, untracked: bool) -> list[str]:
    if untracked:
        return Path(path).read_text(encoding="utf-8").splitlines()
    diff = git("diff", "--unified=0", "--no-color", "HEAD", "--", path)
    return [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]


def removed_lines(path: str) -> list[str]:
    diff = git("diff", "--unified=0", "--no-color", "HEAD", "--", path)
    return [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]


def looks_encoded(line: str) -> bool:
    text = URL_RE.sub("", line)
    for m in B64_RUN_RE.finditer(text):
        run = m.group(0)
        if re.search(r"\d", run) and re.search(r"[a-z]", run) and re.search(r"[A-Z]", run):
            return True
    return bool(HEX_RUN_RE.search(text))


def mentions(lines: list[str]) -> list[tuple[int, str]]:
    """(line number, mention) outside fenced code blocks and code spans."""
    out, fenced = [], False
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced:
            continue
        for m in MENTION_RE.finditer(re.sub(r"`[^`]*`", "", line)):
            out.append((n, m.group(0)))
    return out


def scan_text(path: str, lines: list[str]) -> list[str]:
    errors = []
    if RESEARCH_RE.match(path):
        for n, handle in mentions(lines):
            errors.append(f"{path} (added line {n}): @mention {handle} outside a code span (it would notify that account)")
    for n, line in enumerate(lines, 1):
        where = f"{path} (added line {n})"
        for ch, name in BAD_CHARS.items():
            if ch in line:
                errors.append(f"{where}: contains {name}")
        # A double hyphen inside a code span (a CLI flag such as `--feeds`) is fine.
        prose = re.sub(r"`[^`]*`", "", line)
        if DOUBLE_HYPHEN_RE.search(prose):
            errors.append(f"{where}: double hyphen used as punctuation")
        for m in IPV4_RE.finditer(line):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if ip.is_global and ip not in ALLOWED_ADDRS and not any(ip in net for net in DOC_NETS):
                errors.append(f"{where}: public IPv4 {ip} (use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24)")
        for m in IPV6_RE.finditer(line):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if ip.is_global and ip not in ALLOWED_ADDRS and not any(ip in net for net in DOC_NETS):
                errors.append(f"{where}: public IPv6 {ip} (use 2001:db8::/32)")
        for m in MAC_RE.finditer(line):
            mac = m.group(1).lower().replace("-", ":")
            if not mac.startswith(DOC_MAC_PREFIX) and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                errors.append(f"{where}: MAC address {mac} (use 00:00:5e:00:53:xx)")
        if SECRET_RE.search(line):
            errors.append(f"{where}: looks like a credential or key")
        elif looks_encoded(line):
            errors.append(f"{where}: long base64 or hex run (possible encoded secret)")
    return errors


def catalog(text: str) -> dict[str, dict]:
    return {c["id"]: c for c in tomllib.loads(text).get("checks", []) if "id" in c}


def catalog_changes(old_text: str, new_text: str) -> list[str]:
    """Errors for checks.toml edits beyond new checks and appended notes."""
    old_doc, new_doc = tomllib.loads(old_text), tomllib.loads(new_text)
    errors = []
    if {k: v for k, v in old_doc.items() if k != "checks"} != {k: v for k, v in new_doc.items() if k != "checks"}:
        errors.append("checks.toml: top-level keys changed; only [[checks]] entries may change")
    ids = [c.get("id") for c in new_doc.get("checks", [])]
    for cid in sorted({i for i in ids if ids.count(i) > 1}, key=str):
        errors.append(f"checks.toml: check id {cid} appears more than once")
    old, new = catalog(old_text), catalog(new_text)
    for cid in sorted(set(old) - set(new)):
        errors.append(f"checks.toml: check {cid} was removed (never delete history)")
    for cid in sorted(set(new) - set(old)):
        if new[cid].get("verified_on") != ["unverified"]:
            errors.append(f"checks.toml: new check {cid} must have verified_on = [\"unverified\"]")
    for cid in sorted(set(new) & set(old)):
        o, n = old[cid], new[cid]
        if n.get("verified_on") != o.get("verified_on"):
            errors.append(f"checks.toml: {cid} verified_on changed; only a human may confirm a check")
        changed = sorted(k for k in set(o) | set(n) if k not in ("notes", "verified_on") and o.get(k) != n.get(k))
        if changed:
            errors.append(f"checks.toml: {cid} field(s) {', '.join(changed)} changed; existing checks may only gain notes")
        old_notes, new_notes = o.get("notes", ""), n.get("notes", "")
        if not isinstance(new_notes, str) or not new_notes.startswith(old_notes):
            errors.append(f"checks.toml: {cid} notes were rewritten; add text after the existing notes instead")
    return errors


def _lesson_map(lines: list[str]) -> list[str | None]:
    """For each line, the number of the lesson it belongs to, or None."""
    out, current = [], None
    for line in lines:
        if line.startswith("#"):
            m = LESSON_HEAD_RE.match(line)
            current = m.group(1) if m else None
        out.append(current)
    return out


def lessons_changes(old_text: str, new_text: str) -> list[str]:
    """Errors for LESSONS.md edits other than new lessons and feed table rows."""
    old, new = old_text.splitlines(), new_text.splitlines()
    old_map, new_map = _lesson_map(old), _lesson_map(new)
    old_numbers = {n for n in old_map if n}
    errors = []

    def feed_line(line: str, lesson: str | None) -> bool:
        if lesson != FEED_LESSON:
            return False
        s = line.strip()
        return (s.startswith("|") and s.endswith("|")) or bool(FEED_HEADING_RE.match(line))

    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for i in range(i1, i2):
            if old[i].strip() and not feed_line(old[i], old_map[i]):
                where = f"lesson {old_map[i]}" if old_map[i] else "outside any lesson"
                errors.append(f"LESSONS.md: line {i + 1} ({where}) was changed or removed; existing lessons are append only")
        for j in range(j1, j2):
            if not new[j].strip() or feed_line(new[j], new_map[j]):
                continue
            if new_map[j] and new_map[j] not in old_numbers:
                continue  # part of a new lesson
            where = f"existing lesson {new_map[j]}" if new_map[j] else "outside any lesson"
            errors.append(f"LESSONS.md: new line {j + 1} added to {where}; add a new lesson instead")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Scope and content gate for the monthly self-update")
    ap.add_argument("--month", required=True, help="YYYY-MM of this run")
    ap.add_argument("--root", default=".", type=Path)
    args = ap.parse_args()
    if not re.fullmatch(r"\d{4}-\d{2}", args.month):
        print("ERROR: --month must be YYYY-MM")
        return 1
    os.chdir(args.root.resolve())

    errors: list[str] = []
    entries = changed_entries()
    if not entries:
        print("No changes.")
        return 0
    changed = {p for _, p in entries}

    # 1. scope
    for status, path in entries:
        untracked = status == "A?"
        if path in ALLOWED_FILES:
            if status not in ("M",):
                errors.append(f"{path}: status {status}, only in-place modification is allowed")
        elif RESEARCH_RE.match(path):
            if status not in ("A", "A?"):
                errors.append(f"{path}: existing research files are history and must not change (status {status})")
        else:
            errors.append(f"{path}: outside the allowed paths (checks.toml, LESSONS.md, CHANGELOG.md, research/*.md)")
            continue
        p = Path(path)
        if p.is_symlink() or (p.exists() and not p.is_file()):
            errors.append(f"{path}: must be a regular file")
            continue
        if not p.exists():
            continue
        if untracked and p.stat().st_size > MAX_NEW_FILE_BYTES:
            errors.append(f"{path}: larger than {MAX_NEW_FILE_BYTES} bytes")
        try:
            errors += scan_text(path, added_lines(path, untracked))
        except UnicodeDecodeError:
            errors.append(f"{path}: not valid UTF-8 text")
    mode_changes = [l for l in git("diff", "--summary", "HEAD").splitlines() if "mode change" in l]
    errors += [f"file mode change not allowed: {l.strip()}" for l in mode_changes]

    # 2. research note with sources
    note = Path(f"research/{args.month}.md")
    if not note.is_file():
        errors.append(f"{note}: missing; every update must record its sources there")
    elif not re.search(r"https://\S+", note.read_text(encoding="utf-8", errors="replace")):
        errors.append(f"{note}: cites no https source")

    # 3 and 4. history, append-only edits and verification status
    if "checks.toml" in changed:
        try:
            errors += catalog_changes(git("show", "HEAD:checks.toml"), Path("checks.toml").read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, subprocess.CalledProcessError, UnicodeDecodeError) as e:
            errors.append(f"checks.toml: cannot compare with HEAD: {e}")
    if "LESSONS.md" in changed:
        try:
            errors += lessons_changes(git("show", "HEAD:LESSONS.md"), Path("LESSONS.md").read_text(encoding="utf-8"))
        except (subprocess.CalledProcessError, UnicodeDecodeError) as e:
            errors.append(f"LESSONS.md: cannot compare with HEAD: {e}")
    if "CHANGELOG.md" in changed:
        gone = [l for l in removed_lines("CHANGELOG.md") if l.strip()]
        if gone:
            errors.append(f"CHANGELOG.md: {len(gone)} existing line(s) removed; only additions are allowed")

    # 5. changelog required
    if changed & {"checks.toml", "LESSONS.md"} and "CHANGELOG.md" not in changed:
        errors.append("CHANGELOG.md: must describe changes to checks.toml or LESSONS.md")

    for e in errors:
        print(f"ERROR: {e}")
    print(f"{len(changed)} changed path(s): {', '.join(sorted(changed))}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
