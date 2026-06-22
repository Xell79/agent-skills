# Output Contract

## JSON Shape

Top-level fields:

- `input`
- `summary`
- `risk_findings`
- `permission_review`
- `packaging_issues`
- `marketplace_readiness`
- `generated_at`

### `risk_findings[]`

Required fields:

- `severity`
- `category`
- `title`
- `file`
- `evidence`
- `recommendation`

## Markdown Report Sections

1. `Input Summary`
2. `Risk Summary`
3. `Permission Review`
4. `Priority Findings`
5. `Packaging Issues`
6. `Marketplace Readiness`
7. `Next Actions`
