#!/usr/bin/env python3
"""Deterministic, dependency-free repository integrity checks for Nectar CI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path.cwd().resolve()
MAX_PARSE_BYTES = 10 * 1024 * 1024
TEXT_SUFFIXES = {
    ".apex",
    ".cls",
    ".component",
    ".css",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".rb",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
CONFLICT_BLOCK = re.compile(
    rb"(?ms)^<{7}(?: [^\r\n]*)?\r?\n.*?^={7}\r?\n.*?^>{7}(?: [^\r\n]*)?\r?$"
)
JSONC_CONFIG_NAME = re.compile(
    r"^(?:tsconfig|jsconfig)(?:\.[A-Za-z0-9_-]+)*\.json$",
    re.IGNORECASE,
)


def tracked_entries() -> list[tuple[str, Path]]:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    entries: list[tuple[str, Path]] = []
    for value in result.stdout.split(b"\0"):
        if not value:
            continue
        metadata, raw_path = value.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        entries.append((mode, Path(os.fsdecode(raw_path))))
    return entries


def is_within_root(path: Path) -> bool:
    try:
        path.relative_to(ROOT)
        return True
    except ValueError:
        return False


def main() -> int:
    errors: list[str] = []
    entries = tracked_entries()
    folded: dict[str, Path] = {}
    skipped_large: list[Path] = []
    gitlinks: list[Path] = []

    for mode, relative in entries:
        folded_name = relative.as_posix().casefold()
        previous = folded.get(folded_name)
        if previous is not None and previous.as_posix() != relative.as_posix():
            errors.append(f"case-colliding paths: {previous} and {relative}")
        else:
            folded[folded_name] = relative

        if mode == "160000":
            gitlinks.append(relative)
            continue

        absolute = ROOT / relative
        if not absolute.exists() and not absolute.is_symlink():
            errors.append(f"tracked path is missing: {relative}")
            continue

        if absolute.is_symlink():
            resolved = absolute.resolve(strict=False)
            if not is_within_root(resolved):
                errors.append(f"symlink escapes repository: {relative} -> {resolved}")
            continue

        if not absolute.is_file():
            continue

        size = absolute.stat().st_size
        suffix = absolute.suffix.lower()

        if suffix in TEXT_SUFFIXES and size <= MAX_PARSE_BYTES:
            data = absolute.read_bytes()
            if CONFLICT_BLOCK.search(data):
                errors.append(f"complete unresolved merge conflict: {relative}")
        elif suffix in TEXT_SUFFIXES and size > MAX_PARSE_BYTES:
            skipped_large.append(relative)

        if suffix == ".json" and size <= MAX_PARSE_BYTES:
            try:
                text = absolute.read_text(encoding="utf-8-sig")
                if not JSONC_CONFIG_NAME.fullmatch(absolute.name):
                    json.loads(text)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                errors.append(f"invalid JSON: {relative}: {exc}")

        if suffix == ".xml" and size <= MAX_PARSE_BYTES:
            try:
                ET.parse(absolute)
            except (ET.ParseError, OSError) as exc:
                errors.append(f"invalid XML: {relative}: {exc}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Repository validation failed with {len(errors)} error(s).", file=sys.stderr)
        return 1

    for path in skipped_large:
        print(f"SKIP: text parsing limited to 10 MiB: {path}")
    for path in gitlinks:
        print(f"INFO: pinned gitlink recorded but submodule content not executed: {path}")
    print(f"Repository validation passed for {len(entries)} tracked path(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
