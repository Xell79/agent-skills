#!/usr/bin/env python3
"""Scan a skill folder for security and packaging risks."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUSPICIOUS_PATTERNS = [
    ("hardcoded-secret", re.compile(r"(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE)),
    ("dangerous-shell", re.compile(r"(rm\s+-rf|curl\s+.+\|\s*sh|Invoke-WebRequest.+iex|subprocess\.Popen)", re.IGNORECASE)),
    ("network-fetch", re.compile(r"https?://", re.IGNORECASE)),
    ("dynamic-exec", re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE)),
    ("encoded-payload", re.compile(r"base64\.b64decode|frombase64string", re.IGNORECASE)),
]
CODE_FILE_SUFFIXES = {".py", ".ps1", ".sh", ".bat", ".cmd", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}


class VendorPackError(Exception):
    pass


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def scan_files(skill_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    packaging_issues: list[dict[str, Any]] = []
    permission_bins: list[str] = []
    skill_file = skill_path / "SKILL.md"
    if not skill_file.exists():
        packaging_issues.append({"issue": "Missing SKILL.md", "severity": "high"})
    else:
        skill_text = read_text(skill_file)
        in_bins = False
        for raw_line in skill_text.splitlines():
            stripped = raw_line.strip()
            if stripped == "bins:":
                in_bins = True
                continue
            if in_bins and re.match(r"^[A-Za-z_].*:$", stripped):
                in_bins = False
            if in_bins:
                match = re.match(r'-\s+"([^"]+)"', stripped)
                if match:
                    permission_bins.append(match.group(1))
        if "metadata:" not in skill_text:
            packaging_issues.append({"issue": "Missing frontmatter metadata", "severity": "medium"})
    for path in skill_path.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(skill_path).as_posix()
        if "__pycache__" in relative:
            packaging_issues.append({"issue": "Generated cache directory present", "severity": "low", "file": relative})
            continue
        if path.name.startswith("."):
            packaging_issues.append({"issue": "Hidden file included in package", "severity": "low", "file": relative})
        if path.suffix.lower() not in CODE_FILE_SUFFIXES:
            continue
        text = read_text(path)
        if not text:
            continue
        for category, pattern in SUSPICIOUS_PATTERNS:
            if category == "network-fetch" and path.suffix.lower() == ".md":
                continue
            match = pattern.search(text)
            if match:
                severity = "high" if category in {"hardcoded-secret", "dynamic-exec"} else "medium"
                findings.append({"severity": severity, "category": category, "title": f"Potential {category.replace('-', ' ')} pattern detected", "file": relative, "evidence": match.group(0)[:200], "recommendation": "Review this file and justify or remove the flagged behavior before distribution."})
        if path.suffix.lower() in {".exe", ".dll", ".bin"}:
            findings.append({"severity": "high", "category": "binary-artifact", "title": "Binary artifact included in skill package", "file": relative, "evidence": "Binary files increase install risk and reduce auditability.", "recommendation": "Remove binary payloads or document and sign them separately."})
        if path.suffix.lower() in {".yaml", ".yml", ".json", ".toml"} and any(term in text.lower() for term in ("require_escalated", "sudo", "administrator", "full-access")):
            findings.append({"severity": "medium", "category": "elevated-permissions", "title": "Potential elevated permission declaration detected", "file": relative, "evidence": "Found elevated permission wording in configuration text.", "recommendation": "Confirm whether the skill really needs elevated permissions and document the reason explicitly."})
    return findings, packaging_issues, sorted(set(permission_bins))


def build_marketplace_readiness(skill_path: Path, findings: list[dict[str, Any]], packaging_issues: list[dict[str, Any]]) -> dict[str, Any]:
    required = [skill_path / "SKILL.md", skill_path / "references" / "output-contract.md"]
    missing = [item.name for item in required if not item.exists()]
    blockers = len([item for item in findings if item["severity"] == "high"])
    return {"status": "ready" if not blockers and not missing else "needs-review", "missing_required_files": missing, "high_risk_finding_count": blockers, "packaging_issue_count": len(packaging_issues)}


def format_report(result: dict[str, Any]) -> str:
    lines = ["# Skill Security Vendor Pack", "", "## Input Summary", f"- Skill path: {result['input']['skill_path']}", "", "## Risk Summary", f"- Overall status: {result['summary']['status']}", f"- High-risk findings: {result['summary']['high_risk_finding_count']}", f"- Packaging issues: {len(result['packaging_issues'])}", "", "## Permission Review", f"- Declared bins: {', '.join(result['permission_review']['declared_bins']) if result['permission_review']['declared_bins'] else 'None detected'}", "", "## Priority Findings"]
    for finding in result["risk_findings"] or []:
        lines.append(f"- {finding['severity']} | {finding['category']} | {finding['file']} | {finding['evidence']}")
    if not result["risk_findings"]:
        lines.append("- No suspicious patterns detected in the scanned text files.")
    lines.extend(["", "## Packaging Issues"])
    for issue in result["packaging_issues"] or []:
        file_part = f" | {issue.get('file')}" if issue.get("file") else ""
        lines.append(f"- {issue['severity']} | {issue['issue']}{file_part}")
    if not result["packaging_issues"]:
        lines.append("- No packaging issues detected.")
    lines.extend(["", "## Marketplace Readiness", f"- Status: {result['marketplace_readiness']['status']}", f"- Missing required files: {', '.join(result['marketplace_readiness']['missing_required_files']) if result['marketplace_readiness']['missing_required_files'] else 'None'}", "", "## Next Actions"])
    if result["risk_findings"]:
        for finding in result["risk_findings"][:5]:
            lines.append(f"- Review {finding['file']}: {finding['recommendation']}")
    else:
        lines.append("- Keep the package text-only and rerun this scan before release.")
    return "\n".join(lines) + "\n"


def write_output(path: str | None, content: str) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-path", required=True)
    parser.add_argument("--out-json")
    parser.add_argument("--out-md")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    skill_path = Path(args.skill_path)
    if not skill_path.exists():
        raise VendorPackError(f"Skill path not found: {args.skill_path}")
    findings, packaging_issues, permission_bins = scan_files(skill_path)
    readiness = build_marketplace_readiness(skill_path, findings, packaging_issues)
    result = {"input": {"skill_path": str(skill_path)}, "summary": {"status": readiness["status"], "high_risk_finding_count": readiness["high_risk_finding_count"], "confidence_note": "This review scans package contents for observable patterns and packaging gaps, not runtime behavior."}, "risk_findings": findings, "permission_review": {"declared_bins": permission_bins}, "packaging_issues": packaging_issues, "marketplace_readiness": readiness, "generated_at": datetime.now(timezone.utc).isoformat()}
    markdown = format_report(result)
    if args.out_json:
        write_output(args.out_json, json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))
    if args.out_md:
        write_output(args.out_md, markdown)
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VendorPackError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
