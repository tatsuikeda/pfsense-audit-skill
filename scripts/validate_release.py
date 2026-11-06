#!/usr/bin/env python3
"""Compare pfaudit results across pfSense releases (release-day validation).

Standard library only, Python 3.11+. Offline: it reads files and never
connects to anything. See docs/VALIDATING-26.10.md for the full checklist.

Two subcommands:

  results  Compare two `pfaudit.py --json` outputs: a baseline from CE 2.9 and
           a candidate from the new release, both taken from the same
           (restored) configuration with the same flags. Reports checks that
           are missing, errored, skipped unexpectedly or changed status, and
           prints the verified_on update to make in checks.toml.

  paths    Key-presence manifest of the config.xml paths pfaudit reads (from
           pfaudit.py's source and the `config` verify strings in checks.toml).
           With two config files, lists paths present in the baseline and
           missing in the candidate. Only path names and counts are printed,
           never values.

Usage:
  python -I scripts/validate_release.py results BASE.json NEW.json [--tag pfsense-26.10] [--expect-skip ID ...] [--json]
  python -I scripts/validate_release.py paths BASE-config.xml [NEW-config.xml] [--json]

Exit codes: 0 nothing needs attention, 1 something needs review, 2 bad input.
"""
# c7-ok: standard library only (argparse, json, re, tomllib, xml.etree).

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
# Only config.xml files exported from a lab firewall are parsed. The stdlib
# parser does not fetch external entities.
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG = "pfsense-26.10"
TAG_RE = re.compile(r"^[a-z][a-z0-9-]*-\d+(\.\d+)*$")
ERROR_PREFIXES = ("Check error:", "No implementation yet")
FLAG_SKIP = "Run with --"


class InputError(Exception):
    pass


def load_catalog(path: Path) -> list[dict]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))["checks"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as e:
        raise InputError(f"cannot read catalog {path}: {e}") from None


def load_results(path: Path) -> tuple[str, dict[str, dict]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read {path}: {e}") from None
    rows = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not all(isinstance(r, dict) and "id" in r and "status" in r for r in rows):
        raise InputError(f"{path} is not `pfaudit.py --json` output (no results list)")
    return str(doc.get("version") or "unknown"), {r["id"]: r for r in rows}


def compare_results(catalog: list[dict], base: dict[str, dict], new: dict[str, dict], tag: str,
                    expect_skip: set[str] = frozenset(), base_prefix: str = "ce-") -> dict:
    """Pure comparison; returns a report dict (also used by the tests)."""
    rep = {"missing": [], "errored": [], "unexpected_skip": [], "not_exercised": [], "changed": [],
           "unchanged": [], "propose": [], "propose_after_review": [], "not_proposed": []}
    for c in catalog:
        cid = c["id"]
        if c.get("planned") is True:
            continue
        b, n = base.get(cid), new.get(cid)
        if n is None:
            rep["missing"].append({"id": cid, "where": "candidate"})
            continue
        if b is None:
            rep["missing"].append({"id": cid, "where": "baseline"})
        bs, ns, nd = (b or {}).get("status"), n["status"], str(n.get("detail") or "")
        row = {"id": cid, "baseline": bs, "candidate": ns, "detail": nd[:160]}
        if nd.startswith(ERROR_PREFIXES):
            rep["errored"].append(row)
        elif ns == "SKIP" and nd.startswith(FLAG_SKIP):
            rep["not_exercised"].append(row)
        elif ns == "SKIP" and bs not in (None, "SKIP") and cid not in expect_skip:
            rep["unexpected_skip"].append(row)
        elif bs is not None and bs != ns:
            rep["changed"].append({**row, "baseline_detail": str(b.get("detail") or "")[:160]})
        else:
            rep["unchanged"].append(row)

        tags = list(c.get("verified_on") or [])
        why = None
        if not tags:
            why = "manual or no verified_on"
        elif "unverified" in tags:
            why = "still unverified on any version; confirm by hand first"
        elif tag in tags:
            why = "already tagged"
        elif not any(t.startswith(base_prefix) for t in tags):
            why = f"not a pfSense check (no {base_prefix}* tag)"
        elif ns == "SKIP" or nd.startswith(ERROR_PREFIXES):
            why = "did not run on the candidate"
        if why:
            rep["not_proposed"].append({"id": cid, "why": why})
            continue
        line = {"id": cid, "verified_on": tags + [tag]}
        (rep["propose_after_review"] if bs is not None and bs != ns else rep["propose"]).append(line)
    return rep


def needs_attention(rep: dict) -> bool:
    return any(rep[k] for k in ("missing", "errored", "unexpected_skip", "changed", "not_exercised"))


def toml_list(tags: list[str]) -> str:
    return "[" + ", ".join(json.dumps(t) for t in tags) + "]"


def print_results(rep: dict, base_ver: str, new_ver: str, tag: str) -> None:
    out = [f"Baseline: {base_ver}", f"Candidate: {new_ver}", f"Tag to add: {tag}", ""]
    if not base_ver.startswith("2.9"):
        out.append("Note: the baseline is not a 2.9 run; the checklist expects a CE 2.9 baseline.")
    if base_ver == new_ver:
        out.append("Note: baseline and candidate report the same version; check you ran the new release.")
    sections = (
        ("missing", "Missing results (pfaudit.py and checks.toml out of step?)", lambda r: f"{r['id']} missing from {r['where']}"),
        ("errored", "Errored on the candidate (fix before tagging)", lambda r: f"{r['id']}: {r['detail']}"),
        ("unexpected_skip", "Skipped on the candidate but ran on the baseline",
         lambda r: f"{r['id']}: {r['baseline']} -> SKIP: {r['detail']}"),
        ("not_exercised", "Not exercised (rerun pfaudit with every flag)", lambda r: f"{r['id']}: {r['detail']}"),
        ("changed", "Status changed (review each one)",
         lambda r: f"{r['id']}: {r['baseline']} -> {r['candidate']}\n      was: {r['baseline_detail']}\n      now: {r['detail']}"),
    )
    for key, title, fmt in sections:
        rows = rep[key]
        out.append(f"## {title}: {len(rows)}")
        out += [f"  - {fmt(r)}" for r in rows]
        out.append("")
    out.append(f"## checks.toml verified_on updates ({len(rep['propose'])} ready, {len(rep['propose_after_review'])} after review)")
    out.append("Apply only after every config path and command was seen on the live candidate box.")
    out += [f'  {r["id"]}: verified_on = {toml_list(r["verified_on"])}' for r in rep["propose"]]
    if rep["propose_after_review"]:
        out.append("  After reviewing the status change:")
        out += [f'  {r["id"]}: verified_on = {toml_list(r["verified_on"])}' for r in rep["propose_after_review"]]
    out.append("")
    out.append(f"## Not proposed: {len(rep['not_proposed'])}")
    out += [f"  - {r['id']}: {r['why']}" for r in rep["not_proposed"]]
    out.append("")
    out.append("Result: " + ("needs attention" if needs_attention(rep) else "clean"))
    print("\n".join(out))


# ------------------------------------------------------------------ paths

PATH_CALL = re.compile(r"""ctx\.(?:get|has|all)\(\s*(f?)"([^"]+)\"""")
CONST = re.compile(r'^([A-Z][A-Z0-9_]*) = "([^"{}]+)"$', re.M)
TOML_PATH = re.compile(r"(?<![\w/.:{])([a-z][a-z0-9_-]*(?:/[a-z0-9_*-]+)+)")


def pfaudit_paths(source: str) -> tuple[set[str], set[str]]:
    """Config paths read by pfaudit.py: (resolved, dynamic ones that could not be resolved)."""
    consts = dict(CONST.findall(source))
    paths, dynamic = set(), set()
    for is_f, p in PATH_CALL.findall(source):
        if is_f:
            p = re.sub(r"\{([A-Z][A-Z0-9_]*)\}", lambda m: consts.get(m.group(1), m.group(0)), p)
            if "{" in p:
                dynamic.add(p)
                continue
        paths.add(p)
    return paths, dynamic


def catalog_paths(catalog: list[dict]) -> set[str]:
    """Best-effort paths from the `config` verify strings, with /0/ and /*/ dropped."""
    out = set()
    for c in catalog:
        text = (c.get("verify") or {}).get("config") or ""
        for m in TOML_PATH.findall(text):
            parts = [p for p in m.split("/") if p not in ("0", "*")]
            if len(parts) > 1 or (parts and "/" in m):
                out.add("/".join(parts))
    return out


def presence(root: ET.Element, path: str) -> int:
    def count(p: str) -> int:
        try:
            return len(root.findall(p))
        except SyntaxError:  # not a valid ElementPath; treat as absent
            return 0
    n = count(path)
    if n == 0 and not path.startswith("installedpackages/"):
        n = count("installedpackages/" + path)  # catalog strings drop this prefix
    return n


def load_config(path: Path) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as e:
        raise InputError(f"cannot read {path}: {e}") from None


def compare_paths(paths: set[str], base: ET.Element, new: ET.Element | None) -> dict:
    rep = {"present": [], "absent": [], "lost": [], "gained": [], "new_top_level": []}
    for p in sorted(paths):
        b = presence(base, p)
        if new is None:
            (rep["present"] if b else rep["absent"]).append({"path": p, "count": b})
            continue
        n = presence(new, p)
        row = {"path": p, "baseline": b, "candidate": n}
        if b and not n:
            rep["lost"].append(row)
        elif n and not b:
            rep["gained"].append(row)
        elif b:
            rep["present"].append(row)
        else:
            rep["absent"].append(row)
    if new is not None:
        rep["new_top_level"] = sorted({el.tag for el in new} - {el.tag for el in base})
    return rep


def print_paths(rep: dict, dynamic: set[str], two: bool) -> None:
    out = []
    if two:
        out.append(f"## Present in baseline, missing in candidate (blocks the release): {len(rep['lost'])}")
        out += [f"  - {r['path']} ({r['baseline']} -> 0)" for r in rep["lost"]]
        out.append(f"## Present only in candidate: {len(rep['gained'])}")
        out += [f"  - {r['path']}" for r in rep["gained"]]
        out.append(f"## New top-level config sections in candidate: {len(rep['new_top_level'])}")
        out += [f"  - {t}" for t in rep["new_top_level"]]
    out.append(f"## Present: {len(rep['present'])}")
    out += [f"  - {r['path']}" for r in rep["present"]]
    out.append(f"## Absent everywhere (cannot be confirmed with this config): {len(rep['absent'])}")
    out += [f"  - {r['path']}" for r in rep["absent"]]
    if dynamic:
        out.append(f"## Built at run time, check by hand: {len(dynamic)}")
        out += [f"  - {p}" for p in sorted(dynamic)]
    print("\n".join(out))


# ------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Release-day validation helper for pfaudit (offline).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("results", help="compare two pfaudit --json outputs")
    r.add_argument("baseline", type=Path, help="pfaudit --json output from CE 2.9")
    r.add_argument("candidate", type=Path, help="pfaudit --json output from the new release")
    r.add_argument("--catalog", type=Path, default=ROOT / "checks.toml")
    r.add_argument("--tag", default=DEFAULT_TAG, help=f"verified_on tag to propose (default {DEFAULT_TAG})")
    r.add_argument("--base-prefix", default="ce-", help="only propose for checks already tagged with this prefix (default ce-)")
    r.add_argument("--expect-skip", action="append", default=[], metavar="ID", help="a SKIP on the candidate that is expected, repeatable")
    r.add_argument("--json", action="store_true")
    p = sub.add_parser("paths", help="config.xml key-presence manifest or diff")
    p.add_argument("baseline", type=Path, help="config.xml from the baseline box")
    p.add_argument("candidate", type=Path, nargs="?", help="config.xml from the new release")
    p.add_argument("--catalog", type=Path, default=ROOT / "checks.toml")
    p.add_argument("--pfaudit", type=Path, default=ROOT / "pfaudit.py")
    p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        catalog = load_catalog(args.catalog)
        if args.cmd == "results":
            if not TAG_RE.match(args.tag):
                raise InputError(f"--tag {args.tag!r} does not match the verified_on format (for example pfsense-26.10)")
            bver, base = load_results(args.baseline)
            nver, new = load_results(args.candidate)
            rep = compare_results(catalog, base, new, args.tag, set(args.expect_skip), args.base_prefix)
            if args.json:
                print(json.dumps({"baseline": bver, "candidate": nver, "tag": args.tag, **rep}, indent=2))
            else:
                print_results(rep, bver, nver, args.tag)
            return 1 if needs_attention(rep) else 0
        try:
            source = args.pfaudit.read_text(encoding="utf-8")
        except OSError as e:
            raise InputError(f"cannot read {args.pfaudit}: {e}") from None
        code_paths, dynamic = pfaudit_paths(source)
        paths = code_paths | catalog_paths(catalog)
        paths = {p for p in paths if "installedpackages/" + p not in paths}  # same path, catalog spelling
        base_root = load_config(args.baseline)
        new_root = load_config(args.candidate) if args.candidate else None
        rep = compare_paths(paths, base_root, new_root)
        if args.json:
            print(json.dumps({**rep, "dynamic": sorted(dynamic)}, indent=2))
        else:
            print_paths(rep, dynamic, new_root is not None)
        return 1 if rep["lost"] else 0
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
