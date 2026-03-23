"""
core.py
────────────────────────────────────────────────────────────────────────────────
USN lookup-table builder, grype output parser, and classifier.

Lookup structure (new)
──────────────────────
  db[(cve_id, pkg_name)] = [
      {"version": "1.2.3-1ubuntu1+esm2", "arch": "amd64", "distro": "jammy"},
      ...
  ]

A grype finding (cve_id, pkg_name, pkg_version) is considered ESM-patched when:
  1. The (cve_id, pkg_name) pair exists in the DB, AND
  2. At least one DB entry has a fix_version V such that pkg_version >= V
     under Debian/ESM-aware version ordering.

ESM version ordering
────────────────────
For versions that share the same base (everything before +esmN / ~esmN):
  base+esm3  >  base+esm2  >  base+esm1  >  base
So if the USN recorded the fix at base+esm1 and the machine has base+esm3,
the CVE is already fixed.

For versions without an ESM suffix we fall back to a best-effort Debian epoch
+ numeric segment comparison.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── regexes ──────────────────────────────────────────────────────────────────
_PURL_RE = re.compile(
    r"pkg:deb/ubuntu/(?P<n>[^@?]+)@(?P<version>[^?]+)\?(?P<qualifiers>.*)"
)
_TABLE_HEADER_RE = re.compile(
    r"^\s*NAME\s+INSTALLED\s+FIXED-IN\s+TYPE\s+VULNERABILITY\s+SEVERITY\s*$",
    re.IGNORECASE,
)
# matches  +esm3  or  ~esm3  at the end of a version string
_ESM_RE = re.compile(r"[+~]esm(\d+)$", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════════════
# VERSION COMPARISON
# ══════════════════════════════════════════════════════════════════════════════

def _parse_esm(version: str) -> tuple[str, int | None]:
    """
    Split a version string into (base, esm_number).

    '1.2.3-1ubuntu1+esm2'  →  ('1.2.3-1ubuntu1', 2)
    '1.2.3-1ubuntu1'       →  ('1.2.3-1ubuntu1', None)
    """
    m = _ESM_RE.search(version)
    if m:
        return version[: m.start()], int(m.group(1))
    return version, None


def _debian_version_key(version: str) -> tuple:
    """
    Return a sortable key for a Debian-style version string.
    Handles:  epoch:upstream-debian
    Splits numeric and non-numeric parts so '10' > '9'.
    """
    # strip epoch
    if ":" in version:
        _epoch_str, version = version.split(":", 1)
        epoch = int(_epoch_str) if _epoch_str.isdigit() else 0
    else:
        epoch = 0

    def _tokenise(s: str) -> list:
        """Break a string into alternating (str, int) tokens for comparison."""
        tokens = []
        for part in re.split(r"(\d+)", s):
            if part.isdigit():
                tokens.append((1, int(part)))
            else:
                tokens.append((0, part))
        return tokens

    return (epoch,) + tuple(_tokenise(version))


def version_is_gte(installed: str, fix_version: str) -> bool:
    """
    Return True when *installed* >= *fix_version* under ESM-aware Debian ordering.

    Rule 1 – same base, ESM suffix only:
        installed base == fix base  →  compare esm numbers (None treated as 0).
        esm3 >= esm2 >= esm1 >= (no esm)

    Rule 2 – different bases (upstream or debian revision changed):
        fall back to _debian_version_key comparison.
    """
    inst_base, inst_esm = _parse_esm(installed)
    fix_base,  fix_esm  = _parse_esm(fix_version)

    if inst_base == fix_base:
        # Same base: compare only the ESM counter
        inst_n = inst_esm if inst_esm is not None else 0
        fix_n  = fix_esm  if fix_esm  is not None else 0
        return inst_n >= fix_n

    # Different bases: use generic Debian version ordering
    return _debian_version_key(installed) >= _debian_version_key(fix_version)


# ══════════════════════════════════════════════════════════════════════════════
# USN DB
# ══════════════════════════════════════════════════════════════════════════════

def _parse_purl(purl_string: str) -> dict | None:
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


def build_usn_db(usn_dir: Path) -> dict:
    """
    Build and return the CVE+package → fix-versions index.

    Structure
    ---------
    db[(cve_id, pkg_name)] = [
        {"version": str, "arch": str|None, "distro": str|None},
        ...
    ]

    Each entry records one version at which the (cve, package) pair was fixed
    according to the USN VEX data.  A single CVE may appear in multiple USN
    statements (e.g. different distro releases), so the list can have several
    entries with different versions.
    """
    db: dict[tuple[str, str], list[dict]] = defaultdict(list)

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
            vuln   = statement.get("vulnerability", {})
            status = statement.get("status", "")

            # Collect every CVE this statement covers (USN id + aliases)
            cve_ids: set[str] = set()
            usn_name = vuln.get("name", "")
            if usn_name:
                cve_ids.add(usn_name)
            for alias in vuln.get("aliases", []):
                if alias:
                    cve_ids.add(alias)

            if not cve_ids:
                continue

            for product in statement.get("products", []):
                purl = _parse_purl(product.get("@id", ""))
                if not purl:
                    continue

                entry = {
                    "version": purl["version"],
                    "arch":    purl["arch"],
                    "distro":  purl["distro"],
                    "status":  status,
                }
                for cve_id in cve_ids:
                    db[(cve_id, purl["name"])].append(entry)

    return db


def is_fixed(
    db: dict,
    cve_id: str,
    pkg_name: str,
    pkg_version: str,
    arch: str | None = None,
) -> bool:
    """
    Return True when the USN DB confirms that *pkg_version* of *pkg_name*
    is already patched for *cve_id*.

    Match criteria (all must hold):
    1. (cve_id, pkg_name) exists in the DB.
    2. At least one recorded fix_version V satisfies: pkg_version >= V
       under ESM-aware Debian version ordering.
    3. If *arch* is supplied, the DB entry's arch must match (or be unset).
    """
    key = (cve_id, pkg_name)
    entries = db.get(key)
    if not entries:
        return False

    for entry in entries:
        fix_ver = entry["version"]

        # arch guard: skip entries for a different arch
        if arch and entry.get("arch") and entry["arch"] != arch:
            continue

        if version_is_gte(pkg_version, fix_ver):
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
    rows: list[dict], db: dict
) -> tuple[list[dict], list[dict]]:
    """
    Returns ``(active_vulns, esm_patched)``.

    A row is ESM-patched when the USN DB confirms (cve_id, pkg_name, pkg_version)
    is already fixed, using CVE-scoped and ESM-version-aware matching.
    """
    active, fixed = [], []
    for row in rows:
        if is_fixed(db, row["cve_id"], row["pkg_name"], row["pkg_version"], row.get("arch")):
            fixed.append(row)
        else:
            active.append(row)
    return active, fixed
