---
name: "skill-security-vendor-pack"
description: "Commercial skill security vendor pack for marketplace buyers and agencies. Scan a skill folder for risky permissions, suspicious patterns, packaging issues, and marketplace-readiness gaps, then produce a client-ready security review in Markdown and JSON."
version: "1.0.0"
metadata:
  openclaw:
    requires:
      bins:
        - "python"
        - "python3"
      config:
        - "output.json"
---


# Skill Security Vendor Pack

Use this skill to review a marketplace skill folder before sale, installation, or client delivery.

## Runtime

- Run from the package root.
- Requires `python` or `python3`.
- No third-party Python packages are required.

## Quick Start

```bash
python scripts/skill_security_vendor_pack.py \
  --skill-path "./local-seo-audit-marketplace" \
  --out-json output.json \
  --out-md report.md
```

## Inputs

Required:

- `--skill-path`

Optional:

- `--out-json`
- `--out-md`

## Output Contract

- Read `references/output-contract.md` for the JSON shape and required report sections.

## Guardrails

- Report suspicious patterns as evidence-backed flags, not proof of malicious intent.
- Distinguish packaging issues from direct execution risk.
- Keep file references relative to the scanned skill path.

## Commercial License Notice

This skill is a proprietary commercial product. Purchase grants a non-transferable license for personal or internal business use only. Redistribution, resale, sublicensing, republishing, and bundle-sharing are not permitted without separate written permission from the author.
