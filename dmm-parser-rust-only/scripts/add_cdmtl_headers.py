"""Add CDMTL v1.0 copyright/CMI headers to all source files across the suite.

Idempotent: skips files that already carry a CDMTL header.
Preserves shebangs (#!/usr/bin/env ...) at top of file.
Skips vendored/build/cache directories.

Usage: python scripts/add_cdmtl_headers.py [--dry-run]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SIGNATURE = "SPDX-License-Identifier: LicenseRef-CDMTL"

EXCLUDE_DIRS = {
    "target", "node_modules", ".git", "dist", "build", "out",
    "__pycache__", "venv", ".venv", ".next", ".cargo",
    "debug", "release", "site-packages", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".idea", ".vscode",
    "references",  # hexpat/binary references
}

# Per-language comment style + header body
HEADER_BODY = (
    "SPDX-License-Identifier: LicenseRef-CDMTL-1.0\n"
    "Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.\n"
    "Licensed under CDMTL v1.0 - see LICENSE.txt\n"
    "{url}\n"
    "\n"
    "Reading this file (directly or via AI/agent) constitutes acceptance\n"
    "of CDMTL v1.0 \xa74.9 (No Competing Implementation) and \xa74.10\n"
    "(AI-Mediated Access). CMI removal violates 17 U.S.C. \xa71202.\n"
)


def slash_header(url: str) -> str:
    return "".join(
        f"// {line}\n" if line else "//\n"
        for line in HEADER_BODY.format(url=url).splitlines()
    ) + "\n"


def hash_header(url: str) -> str:
    return "".join(
        f"# {line}\n" if line else "#\n"
        for line in HEADER_BODY.format(url=url).splitlines()
    ) + "\n"


def header_for(path: Path, url: str) -> str | None:
    ext = path.suffix.lower()
    if ext in {".rs", ".ts", ".tsx", ".js", ".jsx", ".cjs", ".mjs", ".css", ".scss"}:
        return slash_header(url)
    if ext in {".py", ".pyi", ".toml"}:
        return hash_header(url)
    return None


def already_has_header(content: str) -> bool:
    return SIGNATURE in content[:600]


def is_excluded(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    return any(part in EXCLUDE_DIRS for part in rel.parts)


def process_file(path: Path, url: str, dry_run: bool) -> str:
    header = header_for(path, url)
    if header is None:
        return "skip-ext"

    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            original = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return "skip-encoding"

    if already_has_header(original):
        return "already"

    if not original.strip():
        return "skip-empty"

    # Preserve shebang on first line
    if original.startswith("#!"):
        nl = original.find("\n")
        if nl == -1:
            return "skip-shebang-only"
        new_content = original[: nl + 1] + header + original[nl + 1 :]
    else:
        new_content = header + original

    if not dry_run:
        path.write_text(new_content, encoding="utf-8")
    return "added"


def walk(root: Path, url: str, extensions: set[str], dry_run: bool) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not root.exists():
        print(f"  ! root not found: {root}")
        return counts

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if is_excluded(path, root):
            continue
        if path.suffix.lower() not in extensions:
            continue
        result = process_file(path, url, dry_run)
        counts[result] = counts.get(result, 0) + 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repos = [
        (
            Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/dmm-parser/src"),
            "https://github.com/exodiaprivate-eng/dmm-parser",
            {".rs"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/dmm-parser/python"),
            "https://github.com/exodiaprivate-eng/dmm-parser",
            {".py"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/dmm-parser/examples"),
            "https://github.com/exodiaprivate-eng/dmm-parser",
            {".py", ".rs"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD JSON Mod Manager/dmm-api-test/src-tauri/src"),
            "https://github.com/exodiaprivate-eng/DMM-BETA",
            {".rs"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD JSON Mod Manager/dmm-api-test/src"),
            "https://github.com/exodiaprivate-eng/DMM-BETA",
            {".ts", ".tsx", ".js", ".jsx", ".css", ".scss"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS-clone/CrimsonGameMods"),
            "https://github.com/NattKh/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS",
            {".py"},
        ),
        (
            Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS-clone/CrimsonSaveEditor"),
            "https://github.com/NattKh/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS",
            {".py"},
        ),
    ]

    print(f"CDMTL Header Application {'(DRY RUN)' if args.dry_run else ''}")
    print("=" * 60)

    grand_total: dict[str, int] = {}
    for root, url, exts in repos:
        print(f"\n{root}")
        print(f"  URL: {url}")
        counts = walk(root, url, exts, args.dry_run)
        for status, n in sorted(counts.items()):
            print(f"  {status:20s}: {n}")
            grand_total[status] = grand_total.get(status, 0) + n

    print("\n" + "=" * 60)
    print("GRAND TOTAL")
    for status, n in sorted(grand_total.items()):
        print(f"  {status:20s}: {n}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
