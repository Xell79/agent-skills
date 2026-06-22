# Scanner Integration

How to wire the SkillSpector methodology into CI/CD, pre-commit hooks, skill
registries, and report pipelines. Copy-paste ready. All snippets assume Python
3.12+ where Python is needed.

## CI/CD Pipeline Integration

### GitHub Actions — scan gate with SARIF upload

Runs on every PR that touches `skills/**`. Fails the build above the operator's
threshold and uploads SARIF so findings appear in GitHub Security tab.

```yaml
name: Skill Security Scan
on:
  pull_request:
    paths: ['skills/**']
  push:
    branches: [main]
    paths: ['skills/**']

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  skillspector:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install SkillSpector
        run: pip install git+https://github.com/NVIDIA/SkillSpector
      - name: Scan skills (static)
        run: skillspector scan ./skills --no-llm --format sarif --output skillspector.sarif
      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillspector.sarif
      - name: Upload report artifact
        uses: actions/upload-artifact@v4
        with:
          name: skillspector-report
          path: skillspector.sarif
```

### GitHub Actions — fail on score threshold

Add this step after the scan to fail the build when any skill exceeds the
threshold (here, 50 = REVIEW band):

```yaml
      - name: Gate on risk score
        run: |
          python - <<'PY'
          import json, sys
          # SkillSpector can also emit JSON; switch --format json above
          report = json.load(open("skillspector.json"))
          worst = max((s.get("score", 0) for s in report.get("skills", [])), default=0)
          print(f"worst score: {worst}")
          sys.exit(1 if worst > 50 else 0)
          PY
```

### GitLab CI

Produces a SARIF report and registers it as a SAST artifact so it shows in the
merge-request widget.

```yaml
stages:
  - security

skillspector:
  stage: security
  image: python:3.12
  before_script:
    - pip install git+https://github.com/NVIDIA/SkillSpector
  script:
    - skillspector scan ./skills --no-llm --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Pre-commit hook (local)

Fast static-only scan on staged skill files. Keeps the LLM stage out of the
commit-time path.

```bash
pip install pre-commit
```

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: skillspector-scan
        name: SkillSpector scan (static)
        entry: skillspector scan . --no-llm
        language: system
        files: \.(md|json|yaml|yml|py|sh|js|ts)$
        pass_filenames: false
```

## Registry / Marketplace Integration

On skill publish, clone the submitted skill into a sandbox, run the full
static + LLM scan, and reject the publish if any CRITICAL finding is present or
the score exceeds the registry's threshold.

```python
import json
import subprocess
import tempfile
from pathlib import Path


def gate_publish(skill_url: str, threshold: int = 50) -> dict:
    """Run SkillSpector on a published skill and decide accept/reject.

    Returns a decision dict. Raise PublishingRejected on reject.
    """
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "report.json"
        subprocess.run(
            [
                "skillspector", "scan", skill_url,
                "--format", "json",
                "--output", str(report_path),
            ],
            check=True,
            capture_output=True,
        )
        report = json.loads(report_path.read_text())

    worst_skill = max(
        report.get("skills", []),
        key=lambda s: s.get("score", 0),
        default={"name": "<none>", "score": 0, "findings": []},
    )

    decision = {
        "accepted": worst_skill["score"] <= threshold,
        "score": worst_skill["score"],
        "top_skill": worst_skill["name"],
        "critical_findings": [
            f for f in worst_skill.get("findings", [])
            if f.get("severity") == "CRITICAL"
        ],
    }

    if not decision["accepted"] or decision["critical_findings"]:
        # Reject the publish; surface the reason to the author.
        raise PublishingRejected(decision)
    return decision


class PublishingRejected(Exception):
    """Raised when a skill fails the registry security gate."""
```

Registry webhook equivalent (Node.js), adapted from the OWASP integration
guide:

```javascript
const express = require('express');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

app.post('/webhook/skill-published', (req, res) => {
  const { skillId, skillUrl } = req.body;
  const reportPath = `/tmp/${skillId}-report.json`;

  execFile('skillspector', [
    'scan', skillUrl,
    '--format', 'json',
    '--output', reportPath,
  ], (error) => {
    if (error) {
      console.error(`Scan failed: ${error}`);
      return rejectSkill(skillId, 'Security scan failed');
    }
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    const worst = Math.max(
      ...report.skills.map((s) => s.score || 0), 0,
    );
    if (worst > 50) {
      rejectSkill(skillId, `Risk score ${worst} exceeds threshold`);
    } else {
      approveSkill(skillId);
    }
  });

  res.status(200).send('Scan initiated');
});

app.listen(3000);
```

## Custom Scanner Fallback

When neither SkillSpector nor a platform-native scanner is available, use the
bundled `scripts/skillscanner.py`. It implements the static rules from
`ast10-rules.md`, emits JSON or SARIF, and runs on Python 3.10+ with no
third-party dependencies.

```bash
# Static scan, JSON report
python3 scripts/skillscanner.py scan ./my-skill/ --format json --output report.json

# SARIF for CI
python3 scripts/skillscanner.py scan ./skills/ --format sarif --output report.sarif

# Markdown for human review
python3 scripts/skillscanner.py scan ./skills/ --format markdown
```

It is intentionally a single file so it can be vendored into a repo without a
package step. Fork it, add project-specific rules, and pin a version.

## Report Output Formats

### JSON report schema

```json
{
  "scan_metadata": {
    "scanner": "SkillSpector",
    "scanner_version": "1.0.0",
    "scan_timestamp": "2026-06-22T10:00:00Z",
    "scan_mode": "static-only",
    "skill_root": "./my-skill/"
  },
  "skills": [
    {
      "name": "my-skill",
      "version": "1.2.0",
      "score": 38,
      "level": "REVIEW",
      "findings": [
        {
          "rule_id": "AST03-001",
          "category": "AST03",
          "severity": "HIGH",
          "file": "manifest.json",
          "line": 12,
          "description": "Blanket 'full_access' permission grant",
          "evidence": "\"permissions\": [\"full_access\"]",
          "action": "Replace with the minimal permission set the skill needs."
        }
      ]
    }
  ],
  "summary": {
    "total_skills": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "worst_score": 38,
    "worst_level": "REVIEW"
  }
}
```

### SARIF (v2.1.0) skeleton

SARIF is what makes findings show up in GitHub Code Scanning, GitLab SAST, and
Azure DevOps. Each AST rule maps to a SARIF rule entry; each finding maps to a
result.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SkillSpector",
          "version": "1.0.0",
          "informationUri": "https://github.com/NVIDIA/SkillSpector",
          "rules": [
            {
              "id": "AST01-002",
              "name": "RemoteCodeExecutionOnInstall",
              "shortDescription": { "text": "Pipes a remote script into a shell" },
              "defaultConfiguration": { "level": "error" },
              "helpUri": "https://owasp.org/www-project-agentic-skills-top-10/"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "AST01-002",
          "level": "error",
          "message": { "text": "curl|sh pattern detected on install" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "install.sh" },
                "region": { "startLine": 14 }
              }
            }
          ],
          "partialFingerprints": { "primaryLocationLineHash": "abc123" }
        }
      ]
    }
  ]
}
```

SARIF severity mapping:

| AST severity | SARIF `level` |
| ------------ | ------------- |
| CRITICAL     | `error`       |
| HIGH         | `error`       |
| MEDIUM       | `warning`     |
| LOW          | `note`        |

### Markdown report (single skill)

```markdown
## SkillSpector Audit Report

### Target: my-skill 1.2.0
### Risk Score: 38/100 (REVIEW)

**Scan mode:** static-only | **Scanned at:** 2026-06-22T10:00:00Z

---

#### HIGH

- **[AST03-001]** `manifest.json:12` — Blanket `full_access` permission grant.
  - Evidence: `"permissions": ["full_access"]`
  - Action: Replace with the minimal permission set the skill needs.

#### LOW

- **[AST07-002]** `manifest.json:3` — Floating version ref `version: latest`.
  - Action: Pin to a concrete version.

---

### Summary

- CRITICAL: 0 | HIGH: 1 | MEDIUM: 0 | LOW: 1
- Risk Score: 38/100 — REVIEW: manual review required before install.
```

## Coverage Matrix

Which AST risks each integration path closes. Use this to justify the pipeline
to reviewers.

| AST risk | Static scan | + LLM pass | CI gate | Registry gate | Sandbox (runtime) |
| -------- |:-----------:|:----------:|:-------:|:-------------:|:-----------------:|
| AST01    | partial     | full       | yes     | yes           | mitigates         |
| AST02    | yes (OSV)   | yes        | yes     | yes           | —                 |
| AST03    | yes         | yes        | yes     | yes           | mitigates         |
| AST04    | partial     | full       | yes     | yes           | —                 |
| AST05    | yes         | yes        | yes     | yes           | mitigates         |
| AST06    | flags gap   | flags gap  | —       | —             | **required**      |
| AST07    | partial     | partial    | yes     | yes           | —                 |
| AST08    | meta        | meta       | closes  | closes        | —                 |
| AST09    | —           | —          | partial | partial       | partial           |
| AST10    | partial     | yes        | yes     | yes           | —                 |

Legend: **yes** = directly detected; **partial** = some sub-rules; **mitigates**
= runtime layer reduces blast radius; **closes** = the integration itself
removes the gap; **—** = out of scope for that layer.

The takeaway: no single column is a full defense. Combine a pre-install scanner
(this skill), a CI gate, a registry gate, and a runtime sandbox.
