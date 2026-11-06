#!/usr/bin/env python3
"""Validate checks.toml against its schema and against pfaudit.CHECKS.

Standard library only, Python 3.11+. Used by CI and by the monthly
self-update workflow. Exit code 0 means valid, 1 means at least one error.

Usage: python -I .github/scripts/validate_catalog.py [--root DIR]
"""
# c7-ok: pfaudit is this repository's own module; everything else is stdlib.

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REQUIRED = {"id": str, "category": str, "title": str, "risk": str}
OPTIONAL = {
    "why": str,
    "verify": dict,
    "fix": str,
    "impact": str,
    "notes": str,
    "lesson": int,
    "verified_on": list,
    # planned = true marks a researched check that has no implementation in
    # pfaudit.py yet. pfaudit reports it as "No implementation yet".
    "planned": bool,
}
RISKS = {"high", "medium", "low", "info"}
VERIFY_KEYS = {"config", "command", "external", "manual", "controller"}
ID_RE = re.compile(r"^[A-Z]+-\d{3}$")
VERSION_TAG_RE = re.compile(r"^(unverified|[a-z][a-z0-9-]*-\d+(\.\d+)*)$")


def load_catalog(root: Path) -> tuple[dict, list[str]]:
    try:
        data = tomllib.loads((root / "checks.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        return {}, [f"checks.toml does not parse: {e}"]
    return data, []


def validate(root: Path) -> list[str]:
    data, errors = load_catalog(root)
    if errors:
        return errors
    if data.get("schema") != 1:
        errors.append(f"schema must be 1, found {data.get('schema')!r}")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        return errors + ["checks.toml has no [[checks]] tables"]

    lesson_numbers = set()
    lessons = root / "LESSONS.md"
    if lessons.exists():
        lesson_numbers = {int(m) for m in re.findall(r"^### (\d+)\.", lessons.read_text(encoding="utf-8"), re.M)}

    seen: set[str] = set()
    for n, c in enumerate(checks, 1):
        where = f"check #{n} ({c.get('id', '?')})"
        for key, typ in REQUIRED.items():
            if not isinstance(c.get(key), typ) or (typ is str and not c[key].strip()):
                errors.append(f"{where}: '{key}' is required and must be a non-empty {typ.__name__}")
        for key, val in c.items():
            if key in REQUIRED:
                continue
            if key not in OPTIONAL:
                errors.append(f"{where}: unknown key '{key}'")
            elif not isinstance(val, OPTIONAL[key]) or (OPTIONAL[key] is int and isinstance(val, bool)):
                errors.append(f"{where}: '{key}' must be {OPTIONAL[key].__name__}")
        cid = c.get("id")
        if isinstance(cid, str):
            if not ID_RE.match(cid):
                errors.append(f"{where}: id must look like ABC-001")
            if cid in seen:
                errors.append(f"{where}: duplicate id")
            seen.add(cid)
        if c.get("risk") not in RISKS:
            errors.append(f"{where}: risk must be one of {sorted(RISKS)}")
        verify = c.get("verify")
        if isinstance(verify, dict):
            bad = [k for k, v in verify.items() if k not in VERIFY_KEYS or not isinstance(v, str)]
            if bad:
                errors.append(f"{where}: verify keys must be {sorted(VERIFY_KEYS)} with string values, bad: {bad}")
        vo = c.get("verified_on")
        if isinstance(vo, list):
            if not vo or not all(isinstance(v, str) and VERSION_TAG_RE.match(v) for v in vo):
                errors.append(f"{where}: verified_on must be a non-empty list of tags like 'ce-2.9.0' or 'unverified'")
            elif "unverified" in vo and len(vo) > 1:
                errors.append(f"{where}: 'unverified' cannot be combined with confirmed versions")
        if c.get("planned") is True and vo != ["unverified"]:
            errors.append(f"{where}: planned checks must have verified_on = [\"unverified\"]")
        lesson = c.get("lesson")
        if isinstance(lesson, int) and not isinstance(lesson, bool) and lesson_numbers and lesson not in lesson_numbers:
            errors.append(f"{where}: lesson {lesson} has no '### {lesson}.' heading in LESSONS.md")

    errors += check_implementations(root, checks)
    return errors


def check_implementations(root: Path, checks: list[dict]) -> list[str]:
    """Every catalog id needs a pfaudit.CHECKS entry or planned = true."""
    sys.path.insert(0, str(root))
    try:
        import pfaudit  # noqa: PLC0415 this repository's own module
    except Exception as e:  # noqa: BLE001 report any import failure as a finding
        return [f"pfaudit.py does not import: {type(e).__name__}: {e}"]
    finally:
        sys.path.pop(0)
    implemented = set(pfaudit.CHECKS)
    ids = {c.get("id") for c in checks}
    errors = []
    for c in checks:
        cid, planned = c.get("id"), c.get("planned") is True
        if cid not in implemented and not planned:
            errors.append(f"{cid}: no implementation in pfaudit.CHECKS (add one, or mark the check planned = true)")
        if cid in implemented and planned:
            errors.append(f"{cid}: implemented in pfaudit.py but still marked planned = true")
    for cid in sorted(implemented - ids):
        errors.append(f"{cid}: implemented in pfaudit.py but missing from checks.toml")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate checks.toml and its pfaudit.py implementations")
    ap.add_argument("--root", default=Path(__file__).resolve().parents[2], type=Path, help="repository root")
    args = ap.parse_args()
    root = args.root.resolve()
    errors = validate(root)
    for e in errors:
        print(f"ERROR: {e}")
    if not errors:
        n = len(tomllib.loads((root / "checks.toml").read_text(encoding="utf-8"))["checks"])
        print(f"checks.toml OK: {n} checks, each implemented in pfaudit.py or marked planned")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
