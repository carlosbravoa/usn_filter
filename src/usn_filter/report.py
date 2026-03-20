"""
report.py
────────────────────────────────────────────────────────────────────────────────
Console report formatter with ANSI colours.
"""

from typing import IO

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

SEVERITY_COLOUR_KEY = {
    "Critical":   "red",
    "High":       "yellow",
    "Medium":     "cyan",
    "Low":        "blue",
    "Negligible": "grey",
    "Unknown":    "grey",
}


def colour_factory(enabled: bool) -> dict[str, str]:
    codes = dict(
        reset="\033[0m", bold="\033[1m",
        red="\033[91m",  yellow="\033[93m", cyan="\033[96m",
        green="\033[92m", magenta="\033[95m", blue="\033[94m",
        grey="\033[90m", white="\033[97m",
    )
    if enabled:
        return dict(codes)
    return {k: "" for k in codes}


def severity_counts(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for row in rows:
        sev = row.get("severity", "Unknown").capitalize()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _sev_sort_key(row: dict) -> int:
    sev = row.get("severity", "Unknown").capitalize()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _fmt_row(row: dict, c: dict) -> str:
    sev        = row.get("severity", "Unknown")
    colour_key = SEVERITY_COLOUR_KEY.get(sev, "white")
    sev_str    = f"{c[colour_key]}{sev:<12}{c['reset']}"
    pkg_type   = (row.get("pkg_type", "") or "unknown").strip()
    return (
        f"  {c['bold']}{row['pkg_name']:<30}{c['reset']}"
        f"  {row['pkg_version']:<30}"
        f"  {c['cyan']}{row['cve_id']:<20}{c['reset']}"
        f"  {sev_str}"
        f"  {c['magenta']}{pkg_type:<14}{c['reset']}"
    )


def print_report(
    active: list[dict],
    fixed: list[dict],
    show_fixed: bool,
    c: dict,
    out: IO,
) -> None:
    divider = c["grey"] + "─" * 110 + c["reset"]
    header  = (
        f"  {'PACKAGE':<30}  {'INSTALLED VERSION':<30}  {'CVE':<20}  {'SEVERITY':<12}  {'TYPE':<14}"
    )

    # ── Active vulnerabilities ────────────────────────────────────────────────
    print(f"\n{c['bold']}{c['red']}{'═'*110}{c['reset']}", file=out)
    print(f"{c['bold']}  ACTIVE VULNERABILITIES  ({len(active)} entries){c['reset']}", file=out)
    print(f"{c['bold']}{c['red']}{'═'*110}{c['reset']}", file=out)

    if not active:
        print(f"\n  {c['green']}✔  No active vulnerabilities found.{c['reset']}\n", file=out)
    else:
        print(f"{c['grey']}{header}{c['reset']}", file=out)
        print(divider, file=out)
        for row in sorted(active, key=_sev_sort_key):
            print(_fmt_row(row, c), file=out)

    # ── Fixed / patched by ESM ────────────────────────────────────────────────
    if show_fixed:
        print(f"\n{c['bold']}{c['green']}{'═'*110}{c['reset']}", file=out)
        print(
            f"{c['bold']}  PATCHED BY ESM (false positives removed)"
            f"  ({len(fixed)} entries){c['reset']}",
            file=out,
        )
        print(f"{c['bold']}{c['green']}{'═'*110}{c['reset']}", file=out)
        if not fixed:
            print(f"\n  {c['grey']}No ESM-patched entries.{c['reset']}\n", file=out)
        else:
            print(f"{c['grey']}{header}{c['reset']}", file=out)
            print(divider, file=out)
            for row in sorted(fixed, key=_sev_sort_key):
                print(
                    f"{c['grey']}{_fmt_row(row, c)}  ✔ ESM patched{c['reset']}",
                    file=out,
                )

    # ── Summary ───────────────────────────────────────────────────────────────
    total_original = len(active) + len(fixed)
    active_counts  = severity_counts(active)
    fixed_counts   = severity_counts(fixed)

    print(f"\n{c['bold']}{'═'*110}{c['reset']}", file=out)
    print(f"{c['bold']}  SUMMARY{c['reset']}", file=out)
    print(f"{c['bold']}{'═'*110}{c['reset']}", file=out)
    print(f"\n  Total findings (before ESM filter) : {c['bold']}{total_original}{c['reset']}", file=out)
    print(f"  Removed as ESM-patched             : {c['green']}{c['bold']}{len(fixed)}{c['reset']}", file=out)
    print(f"  Remaining active vulnerabilities   : {c['red']}{c['bold']}{len(active)}{c['reset']}", file=out)

    print(f"\n  {'Severity':<14}  {'Active':>8}  {'ESM-Patched':>12}", file=out)
    print(f"  {'-'*14}  {'-'*8}  {'-'*12}", file=out)
    for sev in SEVERITY_ORDER:
        a_count = active_counts.get(sev, 0)
        f_count = fixed_counts.get(sev, 0)
        if a_count == 0 and f_count == 0:
            continue
        colour_key = SEVERITY_COLOUR_KEY.get(sev, "white")
        sev_label  = f"{c[colour_key]}{sev:<14}{c['reset']}"
        print(
            f"  {sev_label}  {c['bold']}{a_count:>8}{c['reset']}"
            f"  {c['green']}{f_count:>12}{c['reset']}",
            file=out,
        )

    print(file=out)
