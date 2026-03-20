"""
core.py
────────────────────────────────────────────────────────────────────────────────
USN lookup-table builder, grype output parser, and classifier.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── PURL regex ───────────────────────────────────────────────────────────────
_PURL_RE = re.compile(
    r"pkg:deb/ubuntu/(?P<n>[^@?]+)@(?P<version>[^?]+)\?(?P<qualifiers>.*)"
)

# grype table header pattern
_TABLE_HEADER_RE = re.compile(
    r"^\s*NAME\s+INSTALLED\s+FIXED-IN\s+TYPE\s+VULNERABILITY\s+SEVERITY\s*$",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════════════════════
# USN DB
# ══════════════════════════════════════════════════════════════════════════════

def _parse_purl(purl_string: str):
    match = _PURL_RE.match(purl_string)
    if not match:
        return None
    d = match.groupdict()
    qual_dict = {}
    for pair in d["qualifiers"].split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            qual_dict[k] = v
    return {
        "name":    d["n"],
        "version": d["version"],
        "arch":    qual_dict.get("arch"),
        "distro":  qual_dict.get("distro"),
    }


def build_usn_db(usn_dir: Path):
    """
    Returns
    -------
    lookup : defaultdict
        lookup[pkg_name][pkg_version] = {"archs": set(), "distros": set()}
    raw_db : dict
        Flat dict keyed by product @id → USN metadata.
    """
    lookup: dict = defaultdict(
        lambda: defaultdict(lambda: {"archs": set(), "distros": set()})
    )
    raw_db: dict = {}

    files = list(usn_dir.glob("*.json"))
    if not files:
        print(f"[warn] No USN JSON files found in {usn_dir}", file=sys.stderr)

    for file in files:
        try:
            with file.open("r", encoding="utf-8") as f:
                usn_doc = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[warn] Skipping {file.name}: {exc}", file=sys.stderr)
            continue

        for statement in usn_doc.get("statements", []):
            vuln      = statement.get("vulnerability", {})
            usn_id    = vuln.get("name", "")
            cves      = ", ".join(vuln.get("aliases", []))
            timestamp = statement.get("timestamp", "")
            status    = statement.get("status", "")

            for product in statement.get("products", []):
                pid = product.get("@id", "")
                raw_db[pid] = {
                    "usn":    usn_id,
                    "cves":   cves,
                    "date":   timestamp,
                    "status": status,
                }
                purl = _parse_purl(pid)
                if not purl:
                    continue
                name    = purl["name"]
                version = purl["version"]
                arch    = purl["arch"]
                distro  = purl["distro"]
                if arch:
                    lookup[name][version]["archs"].add(arch)
                if distro:
                    lookup[name][version]["distros"].add(distro)

    return lookup, raw_db


def is_fixed(lookup, pkg_name: str, pkg_version: str, arch: str | None = None) -> bool:
    if pkg_name in lookup and pkg_version in lookup[pkg_name]:
        if arch:
            return arch in lookup[pkg_name][pkg_version]["archs"]
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# GRYPE PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_grype_json(path: Path) -> list[dict]:
    """Parse ``grype -o json`` output."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for match in data.get("matches", []):
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        pkg_name    = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        cve_id      = vuln.get("id", "")
        severity    = vuln.get("severity", "Unknown").capitalize()
        fix_state   = vuln.get("fix", {}).get("state", "unknown")
        fix_vers    = vuln.get("fix", {}).get("versions", [])
        pkg_type    = artifact.get("type", "")
        location    = ", ".join(
            loc.get("realPath", "") for loc in artifact.get("locations", [])
        )

        arch = None
        for cpe in artifact.get("cpes", []):
            parts = cpe.split(":")
            if len(parts) > 10:
                candidate = parts[10]
                if candidate not in ("*", "-", ""):
                    arch = candidate
                    break

        rows.append({
            "pkg_name":     pkg_name,
            "pkg_version":  pkg_version,
            "cve_id":       cve_id,
            "severity":     severity,
            "fix_state":    fix_state,
            "fix_versions": fix_vers,
            "pkg_type":     pkg_type,
            "location":     location,
            "arch":         arch,
        })
    return rows


def parse_grype_table(path: Path) -> list[dict]:
    """Parse ``grype -o table`` (default) text output."""
    lines = path.read_text(encoding="utf-8").splitlines()

    rows = []
    header_found = False
    col_starts: list[int] = []

    for line in lines:
        if not header_found:
            if _TABLE_HEADER_RE.match(line):
                header_found = True
                col_starts = [m.start() for m in re.finditer(r"\S+", line)]
            continue

        if not line.strip() or line.startswith("─") or line.startswith("-"):
            continue

        def _col(idx: int) -> str:
            start = col_starts[idx]
            end   = col_starts[idx + 1] if idx + 1 < len(col_starts) else None
            return line[start:end].strip() if end else line[start:].strip()

        try:
            pkg_name    = _col(0)
            pkg_version = _col(1)
            fix_in      = _col(2)
            pkg_type    = _col(3)
            cve_id      = _col(4)
            severity    = _col(5).capitalize()
        except IndexError:
            continue

        if not pkg_name or not cve_id:
            continue

        rows.append({
            "pkg_name":     pkg_name,
            "pkg_version":  pkg_version,
            "cve_id":       cve_id,
            "severity":     severity,
            "fix_state":    "fixed" if fix_in else "not-fixed",
            "fix_versions": [fix_in] if fix_in else [],
            "pkg_type":     pkg_type,
            "location":     "",
            "arch":         None,
        })
    return rows


def parse_grype_file(path: Path) -> list[dict]:
    """Auto-detect format (JSON vs table) and return normalised rows."""
    try:
        rows = parse_grype_json(path)
        if rows:
            return rows
    except (json.JSONDecodeError, KeyError):
        pass
    return parse_grype_table(path)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def classify_rows(
    rows: list[dict], lookup
) -> tuple[list[dict], list[dict]]:
    """
    Returns ``(active_vulns, fixed_by_usn)``.

    A row is considered a false-positive / patched when the USN data shows the
    package+version combination is already fixed.
    """
    active, fixed = [], []
    for row in rows:
        if is_fixed(lookup, row["pkg_name"], row["pkg_version"], row.get("arch")):
            fixed.append(row)
        else:
            active.append(row)
    return active, fixed
