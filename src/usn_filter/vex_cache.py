"""
vex_cache.py
────────────────────────────────────────────────────────────────────────────────
Manages downloading and unpacking the Canonical VEX bundle.

Layout on disk  (~/.cache/usn-filter/):
  vex-all.tar.xz          – downloaded archive (kept for cache check)
  vex/                    – unpacked tree (contains usn/*.json files)
"""

import lzma
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

VEX_URL      = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
CACHE_DIR    = Path.home() / ".cache" / "usn-filter"
ARCHIVE_PATH = CACHE_DIR / "vex-all.tar.xz"
VEX_DIR      = CACHE_DIR / "vex"
USN_DIR      = VEX_DIR / "usn"


def _progress(downloaded: int, total: int) -> None:
    """Simple inline progress bar written to stderr."""
    if total <= 0:
        print(f"\r[*] Downloaded {downloaded / 1_048_576:.1f} MB", end="", file=sys.stderr)
        return
    pct   = downloaded / total * 100
    bar   = int(pct / 2)
    mb    = downloaded / 1_048_576
    total_mb = total / 1_048_576
    print(
        f"\r[*] Downloading  [{'█' * bar:<50}] {pct:5.1f}%  {mb:.1f}/{total_mb:.1f} MB",
        end="",
        file=sys.stderr,
    )


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "usn-filter/1.0"})
        with urllib.request.urlopen(req) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            chunk_size = 65_536
            downloaded = 0
            with tmp.open("wb") as f:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    _progress(downloaded, total)
        print(file=sys.stderr)  # newline after progress bar
        tmp.rename(dest)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _unpack(archive: Path, dest: Path) -> None:
    """Unpack a .tar.xz (lzma-compressed tar) archive."""
    dest.mkdir(parents=True, exist_ok=True)
    print(f"[*] Unpacking archive to   : {dest}", file=sys.stderr)
    # tarfile natively handles .tar.xz via lzma
    with tarfile.open(archive, "r:xz") as tar:
        members = tar.getmembers()
        total   = len(members)
        for i, member in enumerate(members, 1):
            tar.extract(member, path=dest, filter="data")
            if i % 500 == 0 or i == total:
                print(
                    f"\r[*] Extracting  {i:>6}/{total}  files",
                    end="",
                    file=sys.stderr,
                )
    print(file=sys.stderr)


def ensure_vex(force_refresh: bool = False) -> Path:
    """
    Ensure the VEX USN data is present and return the path to the usn/ directory.

    Logic
    ─────
    1. If ~/.cache/usn-filter/vex/usn/ already exists (and --refresh not
       requested), use it as-is.
    2. Otherwise download vex-all.tar.xz, unpack it, and return the usn/ path.

    Parameters
    ----------
    force_refresh : bool
        If True, re-download and re-unpack even when a cached copy exists.

    Returns
    -------
    Path
        Path to the directory containing USN JSON files.
    """
    if not force_refresh and USN_DIR.exists() and any(USN_DIR.glob("*.json")):
        print(f"[*] Using cached VEX data  : {USN_DIR}", file=sys.stderr)
        return USN_DIR

    # Download if archive is missing or a refresh is requested
    if force_refresh or not ARCHIVE_PATH.exists():
        print(f"[*] Downloading VEX bundle : {VEX_URL}", file=sys.stderr)
        _download(VEX_URL, ARCHIVE_PATH)
        print(f"[*] Saved to               : {ARCHIVE_PATH}", file=sys.stderr)
    else:
        print(f"[*] Archive already cached : {ARCHIVE_PATH}", file=sys.stderr)

    # Always re-unpack when we reach here (first run or force refresh)
    if VEX_DIR.exists():
        import shutil
        shutil.rmtree(VEX_DIR)
    _unpack(ARCHIVE_PATH, CACHE_DIR)

    if not USN_DIR.exists():
        raise RuntimeError(
            f"After unpacking {ARCHIVE_PATH}, expected {USN_DIR} was not found. "
            "The archive structure may have changed."
        )

    print(f"[*] VEX data ready         : {USN_DIR}", file=sys.stderr)
    return USN_DIR
