"""Strip DRAFT markers and reviewer notes from LICENSE_DRAFT_v1.md and deploy
the clean CDMTL v1.0 text to all RicePaddySoftware repositories. Existing
LICENSE files are preserved as LICENSE_PRIOR.txt for the relicensing record.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

DRAFT_PATH = Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/dmm-parser/docs/LICENSE_DRAFT_v1.md")

REPOS = [
    Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/dmm-parser"),
    Path(r"C:/Users/corin/Desktop/CD JSON Mod Manager/dmm-api-test"),
    Path(r"C:/Users/corin/Desktop/CD DUMPING TOOLS/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS-clone"),
]

# Optional: prior license filenames per repo
PRIOR_NAMES = {
    "dmm-parser": "LICENSE",
    "dmm-api-test": "LICENSE",
    "CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS-clone": "LICENSE.txt",
}


def clean_license(draft_text: str) -> str:
    """Strip DRAFT preamble and Notes to Reviewer section."""
    lines = draft_text.splitlines()
    out: list[str] = []
    skip_block = False

    for i, line in enumerate(lines):
        # Strip the DRAFT status callout
        if "STATUS: DRAFT" in line:
            # Skip this line and the following continuation
            continue
        if line.startswith("> This document is a working draft"):
            continue

        # Strip the Notes to Reviewer section and everything after
        if line.startswith("# NOTES TO REVIEWER"):
            break

        out.append(line)

    text = "\n".join(out).strip() + "\n"

    # Replace "DRAFT" in title with "v1.0 (Effective 2026-05-01)"
    text = text.replace(
        "# CRIMSON DESERT MODDING TOOLS LICENSE v1.0 (DRAFT)",
        "# CRIMSON DESERT MODDING TOOLS LICENSE v1.0\n## (CDMTL v1.0)\n\n**Effective Date: 2026-05-01**",
    )

    # Remove leftover horizontal rule from where DRAFT block was
    text = text.replace("---\n\n## A Modified Copyleft License", "## A Modified Copyleft License")

    return text


def deploy_to_repo(repo_path: Path, license_text: str) -> tuple[str, str]:
    """Replace LICENSE.txt and preserve prior as LICENSE_PRIOR.txt."""
    repo_name = repo_path.name
    prior_name = PRIOR_NAMES.get(repo_name, "LICENSE")
    prior_path = repo_path / prior_name
    target_path = repo_path / "LICENSE.txt"

    actions = []

    # Preserve existing LICENSE
    if prior_path.exists() and prior_path != target_path:
        backup = repo_path / f"LICENSE_PRIOR_2026-05-01.txt"
        if not backup.exists():
            shutil.move(str(prior_path), str(backup))
            actions.append(f"moved {prior_name} -> LICENSE_PRIOR_2026-05-01.txt")
    elif target_path.exists():
        # If LICENSE.txt is the existing file (SWISS clone case)
        backup = repo_path / "LICENSE_PRIOR_2026-05-01.txt"
        if not backup.exists():
            shutil.copy(str(target_path), str(backup))
            actions.append("copied LICENSE.txt -> LICENSE_PRIOR_2026-05-01.txt")

    # Write new CDMTL
    target_path.write_text(license_text, encoding="utf-8")
    actions.append(f"wrote LICENSE.txt ({len(license_text)} bytes)")

    return repo_name, "; ".join(actions)


def main() -> int:
    if not DRAFT_PATH.exists():
        print(f"ERROR: draft not found: {DRAFT_PATH}", file=sys.stderr)
        return 1

    draft_text = DRAFT_PATH.read_text(encoding="utf-8")
    license_text = clean_license(draft_text)

    print(f"CDMTL v1.0 production text: {len(license_text)} bytes\n")

    for repo in REPOS:
        if not repo.exists():
            print(f"  ! repo not found: {repo}")
            continue
        name, actions = deploy_to_repo(repo, license_text)
        print(f"  {name}: {actions}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
