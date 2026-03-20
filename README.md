# usn-filter

Filter [grype](https://github.com/anchore/grype) vulnerability scan results against
Ubuntu Security Notices (USN) VEX data to eliminate false positives.

## How it works

Canonical publishes a [VEX bundle](https://security-metadata.canonical.com/vex/vex-all.tar.xz)
that records which package versions have already been patched for each CVE.
`usn-filter` downloads this bundle once, caches it in
`~/.cache/usn-filter/`, and cross-references every grype finding against it.
Entries that are already fixed according to the USN data are removed (or shown
separately with `--show-fixed`).

## Installation

```bash
git clone https://github.com/your-org/usn-filter
cd usn-filter
pip install .
```

> **Requirements:** Python ≥ 3.10. No third-party dependencies – pure stdlib.

## Quick start

```bash
# 1. Run grype (JSON recommended; table also works)
grype my-container -o json > output.json

# 2. Filter (downloads VEX data automatically on first run)
usn-filter --grype output.json
```

## Usage

```
usn-filter --grype FILE [OPTIONS]

Options:
  --grype FILE        Path to grype output (table .txt or JSON)  [required]
  --usn-dir DIR       Use a custom pre-extracted USN directory instead of
                      the auto-managed cache
  --refresh-vex       Force re-download and re-unpack of the VEX bundle
  --show-fixed        Print USN-patched entries in a separate section
                      instead of hiding them
  --out FILE          Write report to FILE (ANSI colours disabled)
  --version           Show version and exit
  --help              Show this message and exit
```

## Examples

```bash
# Table output (auto-detected)
usn-filter --grype scan.txt

# JSON output – recommended for accuracy
grype my-image -o json | tee scan.json
usn-filter --grype scan.json

# Show what was filtered out
usn-filter --grype scan.json --show-fixed

# Force a fresh download of VEX data
usn-filter --grype scan.json --refresh-vex

# Save report to file
usn-filter --grype scan.json --out report.txt
```

## Cache location

| Path | Contents |
|------|----------|
| `~/.cache/usn-filter/vex-all.tar.xz` | Downloaded archive |
| `~/.cache/usn-filter/vex/usn/` | Extracted USN JSON files |

Delete either path (or run `--refresh-vex`) to force a fresh download.

## Output

```
══════════════════════════════════════════════════════════════
  ACTIVE VULNERABILITIES  (12 entries)
══════════════════════════════════════════════════════════════
  PACKAGE                         INSTALLED VERSION    CVE                   SEVERITY      FIX
  ──────────────────────────────────────────────────────────
  openssl                         3.0.2-0ubuntu1.10    CVE-2024-1234         High
  ...

══════════════════════════════════════════════════════════════
  SUMMARY
══════════════════════════════════════════════════════════════

  Total findings (before USN filter) : 47
  Removed as USN-patched             : 35
  Remaining active vulnerabilities   : 12

  Severity        Active   USN-Patched
  -----------   --------  ------------
  Critical             1             3
  High                 5            18
  Medium               4            10
  Low                  2             4
```

## License

MIT
