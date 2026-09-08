#!/usr/bin/env python3
"""Small, deterministic secret and release-artifact scan for the working tree."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)
ASSIGNMENT = re.compile(
    r"(?im)\b(?:api[_-]?key|secret|token|password|private[_-]?key)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{20,})"
)
FORBIDDEN_SUFFIXES = (".crp", ".key", ".pem", ".p12", ".pfx", ".token")


def repository_files() -> list[Path]:
    # Include untracked files so a pre-commit check catches newly added
    # credentials or release artifacts before they enter the index.
    ignored_dirs = {".git", "node_modules", "public", "dist", "build", "coverage", "__pycache__", ".venv", ".pytest_cache"}
    return sorted(path for path in ROOT.rglob("*") if path.is_file() and not any(part in ignored_dirs for part in path.parts))


def main() -> int:
    findings: list[str] = []
    files = repository_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(f"tracked release/secret file: {relative}")
        if path == SELF:
            # The scanner contains its own detection expressions.
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(f"cannot read {relative}: {exc}")
            continue
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="ignore")
        if PRIVATE_KEY.search(text):
            findings.append(f"private-key material: {relative}")
        for pattern in TOKEN_PATTERNS:
            if pattern.search(text):
                findings.append(f"credential-shaped token: {relative}")
                break
        if ASSIGNMENT.search(text):
            findings.append(f"credential assignment: {relative}")
    if findings:
        print("secret scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print(f"secret scan passed ({len(files)} repository files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
