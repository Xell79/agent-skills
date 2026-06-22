# NetBox Labs Product Catalog

Reference for all platform products and their interfaces.

## Products

| Product | Category | Primary Interface | Skill |
|---------|----------|-------------------|-------|
| **NetBox** (OSS) | Source of Truth | REST API, GraphQL | `netbox-api-integration`, `netbox-data-modeling` |
| **NetBox Branching** | Change Management | REST API (X-NetBox-Branch header) | `netbox-branching` |
| **NetBox Changes** | Change Management | REST API | `netbox-changes` |
| **NetBox Custom Objects** | Data Model Extensibility | REST API | `netbox-custom-objects` |
| **NetBox Validation** | Compliance / Policy | REST API | `netbox-validation` |
| **Diode** | Data Ingestion | gRPC (Python/Go SDKs) | `netbox-diode` |
| **Orb Agent** | Discovery | Config file (YAML) | `netbox-discovery` |
| **NetBox Assurance** | Drift Detection | NetBox UI (deviation review); fed by Diode/Discovery | `netbox-assurance` |
| **NetBox Asset Lifecycle** | Procurement / Asset Management | REST API (`/api/plugins/asset-lifecycle/`) + UI | `netbox-asset-lifecycle` |
| **NetBox Data Exchange (NDX)** | Reference Data Catalog | Open catalog (YAML) + REST API (`/api/plugins/ndx/`) | `netbox-ndx` |
| **netbox-mcp-server** | Agent Interface | MCP protocol (SSE/stdio) | [GitHub](https://github.com/netboxlabs/netbox-mcp-server) |
| **NetBox Labs Platform MCP Server** | Agent Interface | MCP protocol (streamable HTTP) | `netboxlabs-platform-mcp` |
| **NetBox Cloud** | Managed Deployment | Console UI, REST API | *(no skill yet)* |
| **NetBox Copilot** | Interactive AI | Chat interface | (future skill) |
| **Visual Explorer** | Visualization | Micro-frontend | (no skill needed — UI only) |

## Product Relationships

```text
                    ┌──────────────┐
                    │   NetBox     │ ← Source of Truth
                    │  (REST/GQL) │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴──────┐
    │ Branching  │   │   Diode   │   │ Validation │
    │ + Changes  │   │ (ingest)  │   │ (policy)   │
    └────────────┘   └─────┬─────┘   └────────────┘
                           │
                    ┌──────┴───────┐
                    │  Orb Agent   │
                    │ (discovery)  │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │  Assurance   │
                    │ (drift)      │
                    └──────────────┘

    ┌──────────────┐
    │ MCP Server   │ ← Agent ↔ NetBox interface
    └──────────────┘
```
