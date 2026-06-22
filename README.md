# Agent Skills Collection

Curated collection of 45 AI agent skills for network automation, infrastructure management, security auditing, and development workflows. Each skill is a self-contained `SKILL.md` file with YAML frontmatter that AI agents (Kilo, Claude Code, OpenClaw, Cursor, Codex CLI) can load on demand.

**Upstream:** [github.com/Xell79/agent-skills](https://github.com/Xell79/agent-skills)

## Installation

### From GitHub (recommended)

```bash
git clone https://github.com/Xell79/agent-skills.git ~/.agents/skills
```

### Manual

Copy the desired skill directory (including `SKILL.md`) into `~/.agents/skills/`:

```bash
mkdir -p ~/.agents/skills/my-skill
cp -r /path/to/my-skill ~/.agents/skills/
```

### Requirements

- Python 3.10+ (for `scripts/skillscanner.py` and pyATS skills)
- No third-party dependencies for the skills themselves — they are pure Markdown instructions
- Optional: `agents-cli` for Google ADK skills (`uv tool install google-agents-cli`)

## Skill Directory

| Skill | Category | Description |
|-------|----------|-------------|
| ansible-zen | Ansible | Zen of Ansible principles and code review |
| frontend-design | Design | Distinctive visual design guidance |
| google-agents-cli-adk-code | Google ADK | Agent code patterns and ADK API reference |
| google-agents-cli-deploy | Google ADK | Agent deployment (Cloud Run, GKE) |
| google-agents-cli-eval | Google ADK | Agent evaluation and Quality Flywheel |
| google-agents-cli-observability | Google ADK | Monitoring, tracing, logging |
| google-agents-cli-publish | Google ADK | Publishing to Gemini Enterprise |
| google-agents-cli-scaffold | Google ADK | Project scaffolding and templates |
| google-agents-cli-workflow | Google ADK | Full development lifecycle |
| grill-me | Planning | Relentless spec/design interrogation |
| junos-network | Network | Juniper JunOS automation via PyEZ/NETCONF |
| netbox | NetBox | Hub skill for the NetBox ecosystem |
| netbox-administration | NetBox | Server administration and auth |
| netbox-api-integration | NetBox | REST and GraphQL API patterns |
| netbox-asset-lifecycle | NetBox | Equipment procurement tracking |
| netbox-assurance | NetBox | Drift detection and deviation management |
| netbox-automation-patterns | NetBox | Event-driven and IaC automation |
| netbox-branching | NetBox | Isolated branch schemas |
| netbox-changes | NetBox | Change request management |
| netbox-config-templates | NetBox | Jinja2 config generation |
| netbox-custom-objects | NetBox | No-code data model extensibility |
| netbox-custom-scripts | NetBox | Custom scripts for automation |
| netbox-data-modeling | NetBox | Data model design and organization |
| netbox-diode | NetBox | Data ingestion via Diode SDK |
| netbox-discovery | NetBox | Automated network discovery |
| netbox-migration | NetBox | Data migration methodology |
| netbox-ndx | NetBox | Infrastructure component catalog |
| netbox-plugin-development | NetBox | Plugin development guide |
| netbox-review-datamodel | NetBox | Data model audit and review |
| netbox-review-integration | NetBox | Integration code review |
| netboxlabs-platform-mcp | NetBox | NetBox Labs Platform MCP server |
| network | Network | Topology diagrams (PlantUML/mxgraph) |
| network-bgp-diagnostics | Network | BGP troubleshooting patterns |
| network-collection-triage | Network | Ansible network collection triage |
| network-config-validation | Network | Pre-deployment config checks |
| network-engineer | Network | Cloud networking and security |
| network-engineer-v2 | Network | Network engineer workflow (v2) |
| network-engineering | Network | Architecture and troubleshooting |
| network-interface-health | Network | Interface error diagnosis |
| pyats-network | Network | Cisco pyATS device automation |
| python-code-style | Code Style | Python linting and formatting |
| security-audit | Security | OWASP ASI01-ASI10 skill audit |
| skill-security-vendor-pack | Security | Marketplace security review |
| skill-share | Collaboration | Skill creation and Slack sharing |
| skillspector | Security | OWASP AST10 skill audit methodology |

## Dependency Clusters

| Cluster | Skills | Pattern |
|---------|--------|---------|
| Google ADK | 7 skills | Dense mesh (all reference each other) |
| NetBox | 19 skills | Hub-and-spoke (netbox hub + 18 sub-skills) |
| Network | 9 skills | Hub-and-spoke (network hub + 8 sub-skills) |
| Security | 3 skills | Linear chain (skillspector -> security-audit + skill-security-vendor-pack) |

## Circular Dependencies

| Cycle | Nature |
|-------|--------|
| netbox <-> netbox-administration | Hub <-> sub-skill (expected) |
| netbox-branching <-> netbox-changes | Changes work on top of Branching |
| netbox-review-datamodel <-> netbox-review-integration | Cross-review pair |
| google-agents-cli-* (7 skills) | Dense mesh (all reference each other) |

## Orphaned Skills (no incoming or outgoing dependencies)

- ansible-zen (symlink to external path)
- frontend-design
- grill-me
- python-code-style
- skill-share

## Contributing

1. Create a new directory: `mkdir -p my-skill`
2. Add `SKILL.md` with YAML frontmatter (`name:`, `description:`)
3. Test the skill loads correctly in your agent platform
4. Submit a PR to [github.com/Xell79/agent-skills](https://github.com/Xell79/agent-skills)

### SKILL.md Template

```markdown
---
name: my-skill
description: >
  Brief description of what this skill does and when to use it.
---

# My Skill

## When to Use

- Use case 1
- Use case 2

## How It Works

Instructions for the agent...
```

## License

Individual skills retain their original licenses. Check each skill's `SKILL.md` frontmatter for license details. The collection itself is maintained by [Xell79](https://github.com/Xell79).
