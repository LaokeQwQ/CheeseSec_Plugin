#!/usr/bin/env python3
"""Enforce repository-level GitHub Actions supply-chain guardrails."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION_REF = re.compile(r"^\s*uses:\s*([^#\s]+)", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    findings: list[str] = []
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    if not workflows:
        findings.append("no workflow files found")
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if "pull_request_target" in text:
            findings.append(f"{relative}: pull_request_target is forbidden")
        if "permissions: {}" not in text:
            findings.append(f"{relative}: workflow must declare permissions: {{}}")
        if re.search(r"\bsecrets\.[A-Za-z0-9_]+", text):
            findings.append(f"{relative}: CI validation must not access repository secrets")
        if re.search(r"\b(?:curl|wget)\b[^\n]*(?:\||bash|sh)", text, re.IGNORECASE):
            findings.append(f"{relative}: remote scripts must not be executed in CI")
        if re.search(r"\bpip(?:3)?\s+install\b", text) and "--require-hashes" not in text:
            findings.append(f"{relative}: pip installs must use --require-hashes")
        if "actions/checkout@" in text and "persist-credentials: false" not in text:
            findings.append(f"{relative}: checkout must disable persisted credentials")
        for reference in ACTION_REF.findall(text):
            if "@" not in reference:
                findings.append(f"{relative}: action reference is missing an immutable SHA: {reference}")
                continue
            name, ref = reference.rsplit("@", 1)
            if name.startswith("./"):
                findings.append(f"{relative}: local action requires a separately reviewed policy: {reference}")
            elif not SHA.fullmatch(ref):
                findings.append(f"{relative}: action is not pinned to a 40-hex SHA: {reference}")
    if findings:
        print("workflow policy failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print(f"workflow policy passed ({len(workflows)} workflow files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
