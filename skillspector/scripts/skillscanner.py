#!/usr/bin/env python3
"""SkillSpector-style static scanner for AI agent skills.

A single-file, dependency-light reference implementation of the static rules
in the SkillSpector skill (references/ast10-rules.md). It scans a directory
(or a single file) of skill artifacts and emits JSON, SARIF v2.1.0, or
Markdown reports keyed on the OWASP Agentic Skills Top 10 (AST01-AST10).

This is a *static-only* scanner. It does not run the optional LLM semantic
pass (Phase 3 of the audit workflow). Use NVIDIA SkillSpector for the LLM
stage, or run the semantic pass manually as described in SKILL.md.

Usage:
    python3 skillscanner.py scan ./my-skill/ --format json --output report.json
    python3 skillscanner.py scan ./skills/ --format sarif --output report.sarif
    python3 skillscanner.py scan ./skills/ --format markdown
    python3 skillscanner.py scan ./skills/ --threshold 50   # exit 1 if any skill exceeds

Requires Python 3.10+. No third-party dependencies.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCANNER_NAME = "skillscanner"
SCANNER_VERSION = "1.0.0"
RULES_HELP_URI = "https://github.com/OWASP/www-project-agentic-skills-top-10"

SCANNABLE_SUFFIXES = (".md", ".json", ".js", ".py", ".sh", ".ts", ".yaml", ".yml")


# --------------------------------------------------------------------------- #
# Rule definitions
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    name: str
    description: str
    action: str
    pattern: re.Pattern[str]


def _r(
    rule_id: str,
    category: str,
    severity: str,
    name: str,
    description: str,
    action: str,
    pattern: str,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        category=category,
        severity=severity,
        name=name,
        description=description,
        action=action,
        pattern=re.compile(pattern),
    )


RULES: list[Rule] = [
    # AST01 - Malicious Skills
    _r(
        "AST01-001",
        "AST01",
        "HIGH",
        "DestructiveCommand",
        "Destructive shell command detected.",
        "Remove the command; scope cleanup to a named temp dir if needed.",
        r"\b(rm\s+-rf\b|mkfs\.\w+|dd\s+if=.*of=/dev/|"
        r">\s*/dev/sd[a-z]|format\s+[A-Z]:|del\s+/[fFsS]\s)",
    ),
    _r(
        "AST01-002",
        "AST01",
        "CRITICAL",
        "RemoteCodeExecOnInstall",
        "Pipes a remote script into a shell.",
        "Replace with a pinned, hash-verified download.",
        r"(curl|wget)\b[^|\n]*\|\s*(sh|bash|python\d?|node)\b",
    ),
    _r(
        "AST01-003",
        "AST01",
        "HIGH",
        "DynamicCodeExec",
        "eval()/exec() of possibly untrusted input.",
        "Remove; if unavoidable, sandbox the interpreter.",
        r"\b(eval|exec)\s*\(",
    ),
    _r(
        "AST01-004",
        "AST01",
        "CRITICAL",
        "SensitiveFileRead",
        "Reads a credential file belonging to another tool.",
        "Remove the read; require the operator to pass config explicitly.",
        r"~/\.(ssh|aws|gnupg|config)/"
        r"|(id_rsa|credentials|\.env\b|\.npmrc|\.pypirc|\.netrc)",
    ),
    _r(
        "AST01-005",
        "AST01",
        "CRITICAL",
        "NetworkExfilShape",
        "POST paired with a secret field name.",
        "Remove; if telemetry is required, make it anonymized and opt-in.",
        r"(requests\.post|urllib\.request\.urlopen|fetch\(|curl\s+-X\s*POST)\b",
    ),
    # AST02 - Supply Chain (static shape; OSV lookup is out of scope here)
    _r(
        "AST02-001",
        "AST02",
        "MEDIUM",
        "UnpinnedDependency",
        "Floating/minimum dependency pin (>=, *, latest, main/master ref).",
        "Pin to an exact version, ideally with a hash.",
        r"(>=|~=|\blatest\b|\*)\s*[\w.\-]+|^git\+https?://.*@?(main|master)\b",
    ),
    # AST03 - Over-Privileged
    _r(
        "AST03-001",
        "AST03",
        "HIGH",
        "BlanketPermissionGrant",
        "Blanket permission grant (* / full_access / all / root / admin).",
        "Replace with the minimal permission set the skill needs.",
        r'"permissions"\s*:\s*\[.*(\*|"full_access"|"all"|"root"|"admin")\b',
    ),
    _r(
        "AST03-002",
        "AST03",
        "MEDIUM",
        "PrivilegeEscalationVerb",
        "Privilege escalation verb (sudo, setuid, chmod 777).",
        "Document why elevated privileges are needed.",
        r"\b(sudo\b|su\s+-|os\.setuid|os\.setgid|chmod\s+777|chmod\s+[0-7]{4})",
    ),
    # AST04 - Insecure Metadata (static shape of hidden payload)
    _r(
        "AST04-003",
        "AST04",
        "HIGH",
        "HiddenInstructionsMarkup",
        "Hidden instructions via zero-width chars, HTML comments, or hidden CSS.",
        "Remove. Legitimate skills do not hide instructions.",
        r"(\u200b|\u200c|\u200d|\ufeff|<!--.*?-->|display:\s*none)",
    ),
    _r(
        "AST04-001",
        "AST04",
        "CRITICAL",
        "OverrideInstruction",
        "Prompt-injection override phrasing detected.",
        "Remove. No skill should override host instructions.",
        r"(?i)(ignore (all |previous |prior )?instructions"
        r"|forget your (system )?prompt"
        r"|you are now in (developer|debug|god) mode"
        r"|disregard the (above|previous))",
    ),
    # AST05 - Unsafe Deserialization
    _r(
        "AST05-001",
        "AST05",
        "HIGH",
        "UnsafePickleMarshal",
        "Unsafe pickle/marshal/shelve deserialization.",
        "Replace with JSON/TOML plus a schema validator.",
        r"\b(pickle\.loads?|marshal\.loads?|shelve\.open)\b",
    ),
    _r(
        "AST05-002",
        "AST05",
        "HIGH",
        "UnsafeYamlLoad",
        "yaml.load() called without a safe Loader.",
        "Use yaml.safe_load or pass Loader=yaml.SafeLoader.",
        r"yaml\.load\s*\((?!.*Loader)",
    ),
    # AST07 - Update Drift
    _r(
        "AST07-002",
        "AST07",
        "MEDIUM",
        "FloatingVersionRef",
        "Floating version ref in skill manifest.",
        "Pin to a concrete version or commit.",
        r'"?version"?\s*[:=]\s*"(latest|\*)"',
    ),
    # AST10 - Cross-Platform Reuse (very rough static heuristic)
    _r(
        "AST10-001",
        "AST10",
        "MEDIUM",
        "RuntimeSpecificAssumption",
        "Declares a runtime-specific manifest but markets itself as generic.",
        "Scope to the source runtime or revalidate per target.",
        r"(cursor-rules|\.cursorrules|claude-plugin|openclaw|clawhub)",
    ),
]


# --------------------------------------------------------------------------- #
# Severity / scoring
# --------------------------------------------------------------------------- #
SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
}

# AST01-005 only fires as CRITICAL when a secret field name is also on the line.
SECRET_FIELD_RE = re.compile(
    r"(?i)(token|secret|password|api[_-]?key|\.ssh|credentials)"
)


def band_for(score: int) -> str:
    if score <= 20:
        return "SAFE"
    if score <= 50:
        return "REVIEW"
    if score <= 80:
        return "RISKY"
    return "BLOCK"


# --------------------------------------------------------------------------- #
# Finding / report models
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    file: str
    line: int
    description: str
    evidence: str
    action: str


@dataclass
class SkillReport:
    name: str
    version: str
    score: int = 0
    level: str = "SAFE"
    findings: list[Finding] = field(default_factory=list)


def score_report(report: SkillReport) -> None:
    base = 0
    for f in report.findings:
        base += SEVERITY_WEIGHT.get(f.severity, 0)
    report.score = min(base, 100)
    report.level = band_for(report.score)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def iter_scannable_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix in SCANNABLE_SUFFIXES:
            yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in SCANNABLE_SUFFIXES:
            yield path


def scan_line(line: str) -> list[tuple[Rule, str]]:
    """Return (rule, evidence_snippet) for every rule that matches the line."""
    hits: list[tuple[Rule, str]] = []
    for rule in RULES:
        if rule.pattern.search(line):
            # AST01-005: require a secret field name to escalate to CRITICAL.
            if rule.rule_id == "AST01-005" and not SECRET_FIELD_RE.search(line):
                continue
            snippet = line.strip()[:200]
            hits.append((rule, snippet))
    return hits


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"warn: cannot read {path}: {exc}", file=sys.stderr)
        return findings

    rel = str(path.relative_to(root) if root != path else path.name)
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, evidence in scan_line(line):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    file=rel,
                    line=lineno,
                    description=rule.description,
                    evidence=evidence,
                    action=rule.action,
                )
            )
    return findings


def detect_skill_name_and_version(skill_root: Path) -> tuple[str, str]:
    """Best-effort name/version from SKILL.md frontmatter or a manifest."""
    skill_md = skill_root / "SKILL.md"
    if skill_md.is_file():
        head = skill_md.read_text(encoding="utf-8", errors="replace")[:2000]
        name = _frontmatter_value(head, "name") or skill_root.name
        version = _frontmatter_value(head, "version") or "unknown"
        return name, version
    return skill_root.name, "unknown"


def _frontmatter_value(head: str, key: str) -> str | None:
    match = re.search(rf"^---\n.*?^{key}:\s*(.+?)$.*?^---", head, re.M | re.S)
    if match:
        return match.group(1).strip().strip("\"'")
    return None


def scan_skill(skill_root: Path) -> SkillReport:
    name, version = detect_skill_name_and_version(skill_root)
    report = SkillReport(name=name, version=version)
    base = skill_root if skill_root.is_dir() else skill_root.parent
    for path in iter_scannable_files(skill_root):
        report.findings.extend(scan_file(path, base))
    score_report(report)
    return report


def scan_target(target: Path) -> list[SkillReport]:
    """Scan a path. If it points at a skills collection (a directory of skill
    directories each containing a SKILL.md), produce one report per skill.
    Otherwise treat the whole target as a single skill."""
    if target.is_file():
        return [scan_skill(target)]
    # Heuristic: a directory is a collection if any immediate child is a dir.
    children = [p for p in target.iterdir() if p.is_dir()]
    if children:
        return [scan_skill(child) for child in sorted(children)]
    return [scan_skill(target)]


# --------------------------------------------------------------------------- #
# Report emitters
# --------------------------------------------------------------------------- #
def emit_json(reports: list[SkillReport], root: Path) -> str:
    payload = {
        "scan_metadata": {
            "scanner": SCANNER_NAME,
            "scanner_version": SCANNER_VERSION,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_mode": "static-only",
            "skill_root": str(root),
        },
        "skills": [
            {
                "name": r.name,
                "version": r.version,
                "score": r.score,
                "level": r.level,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in reports
        ],
        "summary": _summary(reports),
    }
    return json.dumps(payload, indent=2)


def _summary(reports: list[SkillReport]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in reports:
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    worst = max((r.score for r in reports), default=0)
    return {
        "total_skills": len(reports),
        **counts,
        "worst_score": worst,
        "worst_level": band_for(worst),
    }


_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def emit_sarif(reports: list[SkillReport], root: Path) -> str:
    rules = []
    seen = set()
    for rule in RULES:
        if rule.rule_id in seen:
            continue
        seen.add(rule.rule_id)
        rules.append(
            {
                "id": rule.rule_id,
                "name": rule.name,
                "shortDescription": {"text": rule.description},
                "fullDescription": {"text": rule.action},
                "helpUri": RULES_HELP_URI,
                "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            }
        )

    results = []
    for r in reports:
        for f in r.findings:
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _SARIF_LEVEL[f.severity],
                    "message": {"text": f"{f.description} (evidence: {f.evidence!r})"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(Path(root) / f.file)},
                                "region": {"startLine": f.line},
                            }
                        }
                    ],
                    "properties": {
                        "skill": r.name,
                        "category": f.category,
                        "severity": f.severity,
                        "action": f.action,
                    },
                }
            )

    payload = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": SCANNER_NAME,
                        "version": SCANNER_VERSION,
                        "informationUri": RULES_HELP_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def emit_markdown(reports: list[SkillReport], root: Path) -> str:
    lines: list[str] = []
    lines.append("## SkillSpector Audit Report (static-only)")
    lines.append("")
    lines.append(
        f"**Scanner:** {SCANNER_NAME} {SCANNER_VERSION}  "
        f"| **Scanned at:** {datetime.now(timezone.utc).isoformat()}  "
        f"| **Root:** `{root}`"
    )
    lines.append("")

    # Dashboard
    lines.append("### Dashboard")
    lines.append("")
    lines.append("| # | Skill | Score | Level | C | H | M | L | Top finding |")
    lines.append("|---|-------|-------|-------|---|---|---|---|-------------|")
    ordered = sorted(reports, key=lambda r: r.score, reverse=True)
    for i, r in enumerate(ordered, start=1):
        c = sum(1 for f in r.findings if f.severity == "CRITICAL")
        h = sum(1 for f in r.findings if f.severity == "HIGH")
        m = sum(1 for f in r.findings if f.severity == "MEDIUM")
        low = sum(1 for f in r.findings if f.severity == "LOW")
        top = r.findings[0] if r.findings else None
        top_txt = f"[{top.rule_id}] {top.evidence[:40]}" if top else "—"
        lines.append(
            f"| {i} | {r.name} | {r.score} | {r.level} "
            f"| {c} | {h} | {m} | {low} | {top_txt} |"
        )
    lines.append("")
    s = _summary(reports)
    safe = sum(1 for r in reports if r.level == "SAFE")
    lines.append(
        f"**Scanned: {s['total_skills']} | SAFE: {safe} "
        f"| Needs review: {s['total_skills'] - safe}**"
    )
    lines.append("")

    # Detail per non-SAFE skill
    for r in ordered:
        if r.level == "SAFE":
            continue
        lines.append(f"### {r.name} {r.version} — {r.score}/100 {r.level}")
        lines.append("")
        grouped: dict[str, list[Finding]] = {}
        for f in r.findings:
            grouped.setdefault(f.severity, []).append(f)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            for f in grouped.get(sev, []):
                lines.append(
                    f"- **[{f.rule_id}] {sev}** `{f.file}:{f.line}` — {f.description}"
                )
                lines.append(f"  - Evidence: `{f.evidence}`")
                lines.append(f"  - Action: {f.action}")
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    reports = scan_target(root)

    if args.format == "json":
        out = emit_json(reports, root)
    elif args.format == "sarif":
        out = emit_sarif(reports, root)
    else:
        out = emit_markdown(reports, root)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)

    if args.threshold is not None:
        worst = max((r.score for r in reports), default=0)
        if worst > args.threshold:
            print(
                f"error: worst score {worst} exceeds threshold {args.threshold}",
                file=sys.stderr,
            )
            return 1
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    print(f"{'Rule ID':<14} {'Sev':<9} {'Name':<28} Description")
    print("-" * 80)
    for rule in RULES:
        print(
            f"{rule.rule_id:<14} {rule.severity:<9} {rule.name:<28} {rule.description}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillscanner",
        description=(
            "Static-only AST10 scanner for AI agent skills. "
            "Reference implementation of the SkillSpector skill rules."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a skill or skills directory.")
    p_scan.add_argument("path", help="Skill directory or file to scan.")
    p_scan.add_argument(
        "--format",
        choices=("json", "sarif", "markdown"),
        default="markdown",
    )
    p_scan.add_argument(
        "--output", "-o", help="Write report to this path instead of stdout."
    )
    p_scan.add_argument(
        "--threshold",
        type=int,
        help="Exit code 1 if any skill's score exceeds this value (CI gate).",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="List the built-in detection rules.")
    p_rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
