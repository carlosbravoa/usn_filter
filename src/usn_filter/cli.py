"""
cli.py
────────────────────────────────────────────────────────────────────────────────
Command-line entry point for usn-filter.
"""

import argparse
import sys
from pathlib import Path

from .vex_cache import ensure_vex
from .core import build_usn_db, parse_grype_file, classify_rows
from .report import colour_factory, print_report
from . import __version__


_DESCRIPTION = """\
Filter grype vulnerability results against Ubuntu Security Notices (USN).

On first run the tool downloads the Canonical VEX bundle (~/.cache/usn-filter/)
and unpacks it automatically. Subsequent runs use the cached copy.
"""

_EPILOG = """\
Examples
────────
  # Basic run (auto-downloads VEX data on first use):
  usn-filter --grype output.txt

  # Use grype JSON output (recommended – more reliable parsing):
  grype my-container -o json > output.json
  usn-filter --grype output.json

  # Show USN-patched entries in a separate section:
  usn-filter --grype output.json --show-fixed

  # Force re-download of VEX data:
  usn-filter --grype output.json --refresh-vex

  # Save report to file (ANSI colours disabled automatically):
  usn-filter --grype output.json --out report.txt

  # Point at a custom / pre-extracted USN directory:
  usn-filter --grype output.json --usn-dir /path/to/vex/usn
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="usn-filter",
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--grype", required=True, metavar="FILE",
        help="Path to grype output file (table .txt or JSON).",
    )
    parser.add_argument(
        "--usn-dir", default=None, metavar="DIR",
        help=(
            "Path to a directory containing USN VEX JSON files. "
            "When omitted the tool uses (and auto-downloads to) "
            "~/.cache/usn-filter/vex/usn/."
        ),
    )
    parser.add_argument(
        "--refresh-vex", action="store_true",
        help="Force re-download and re-unpack of the VEX bundle even if cached.",
    )
    parser.add_argument(
        "--show-fixed", action="store_true",
        help="Print USN-patched entries in a dedicated section instead of hiding them.",
    )
    parser.add_argument(
        "--out", metavar="FILE", default=None,
        help="Write report to FILE instead of stdout (disables ANSI colours).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    grype_path = Path(args.grype)
    if not grype_path.exists():
        sys.exit(f"[error] grype file not found: {grype_path}")

    # ── Resolve USN directory ─────────────────────────────────────────────────
    if args.usn_dir:
        usn_dir = Path(args.usn_dir)
        if not usn_dir.exists():
            sys.exit(f"[error] USN directory not found: {usn_dir}")
    else:
        try:
            usn_dir = ensure_vex(force_refresh=args.refresh_vex)
        except Exception as exc:
            sys.exit(f"[error] Could not obtain VEX data: {exc}")

    # ── ANSI colours ──────────────────────────────────────────────────────────
    use_colour = sys.stdout.isatty() and args.out is None
    c = colour_factory(use_colour)

    # ── Build USN lookup ──────────────────────────────────────────────────────
    print(f"[*] Loading USN data from  : {usn_dir}", file=sys.stderr)
    lookup, _ = build_usn_db(usn_dir)
    print(f"[*] USN packages indexed   : {len(lookup)}", file=sys.stderr)

    # ── Parse grype report ────────────────────────────────────────────────────
    print(f"[*] Parsing grype report   : {grype_path}", file=sys.stderr)
    rows = parse_grype_file(grype_path)
    print(f"[*] Grype findings parsed  : {len(rows)}", file=sys.stderr)

    # ── Classify ──────────────────────────────────────────────────────────────
    active, fixed = classify_rows(rows, lookup)
    print(
        f"[*] Active / ESM-patched   : {len(active)} / {len(fixed)}",
        file=sys.stderr,
    )

    # ── Print report ──────────────────────────────────────────────────────────
    out_stream = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        print_report(active, fixed, args.show_fixed, c, out_stream)
    finally:
        if args.out:
            out_stream.close()
            print(f"[*] Report saved to        : {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
