<div align="center">
  <h1>@cyanheads/mitre-cwe-mcp-server</h1>
  <p><b>Explore MITRE CWE weaknesses and CAPEC attack patterns, mitigations, code examples, and mappings via MCP. STDIO or Streamable HTTP.</b>
  <div>7 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.1-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/mitre-cwe-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.3.1-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/mitre-cwe-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/mitre-cwe-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.3-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/mitre-cwe-mcp-server/releases/latest/download/mitre-cwe-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=mitre-cwe-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvbWl0cmUtY3dlLW1jcC1zZXJ2ZXIiXX0=) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22mitre-cwe-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fmitre-cwe-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

---

## Overview

MITRE's CWE and CAPEC catalogs connect software and hardware weaknesses with attack mechanics. Search root causes, inspect mitigations and code examples, navigate CWE views and live hierarchies, and follow recorded CWE → CAPEC → ATT&CK mappings.

### Tools

| Tool | Description |
|:---|:---|
| `cwe_list_reference` | Discover views, filter vocabulary, workflow guidance, and catalog refresh health |
| `cwe_get_weakness` | Retrieve CWE weaknesses or categories with selected sections and complete example pages |
| `cwe_get_attack_pattern` | Retrieve CAPEC prerequisites, execution steps, mitigations, and recorded mappings |
| `cwe_search_weaknesses` | Search weaknesses by text, platform, abstraction, consequences, status, or view |
| `cwe_search_attack_patterns` | Search CAPEC by text, CWE or ATT&CK mapping, abstraction, severity, or likelihood |
| `cwe_get_view` | Read a CWE view's metadata and direct members in published order |
| `cwe_get_hierarchy` | Traverse live CWE parents, children, ancestors, or descendants within a view |

## Capability reference

### `cwe_list_reference` <sub>tool</sub>

- `topic`: `views`, `abstraction_levels`, `mitigation_phases`, `platforms`, `relationship_natures`, `filter_values`, `workflow`, or `versions`; optional all-token label `filter`
- Lists use `limit` (default 20, capped at 100) and `cursor`; `pagination.nextCursor` continues them. `versions` also returns `catalogs` with loaded versions, dates, counts, and refresh errors

---

### `cwe_get_weakness` <sub>tool</sub>

- Submit 1–200 CWE IDs or bare numbers; up to 20 distinct IDs are processed. `sections` supports `summary`, `consequences`, `mitigations`, `relations`, `examples`, `detection`, `observed`, `platforms`, and `mappings`; defaults to the first four, while `[]` requests an outline
- `entries[].kind` is `full` or `outline`; `notFound[].reason` is `not_found` or `wrong_type`, and `deferredIds` carries whole IDs for another call. Categories are retrievable organizational records; views belong in `cwe_get_view`
- Select `examples` with optional `exampleLanguage`; `exampleOffset` defaults to 0 and `exampleLimit` to 3 (no fixed upper cap). Complete examples retain ordered prose and code; continue with `examplePage.nextOffset`

---

### `cwe_get_attack_pattern` <sub>tool</sub>

- Submit 1–200 CAPEC IDs or bare numbers; up to 20 distinct IDs are processed, including Deprecated and Obsolete records. `sections`: `summary`, `prerequisites`, `execution`, `skills`, `consequences`, `mitigations`, `examples`, `relations`, or `mappings`; defaults to summary, prerequisites, execution, mitigations, and mappings
- `sections: []` requests an outline. `entries[].kind`, per-ID `notFound`, and `deferredIds` distinguish complete selections, outlines, misses, and continuation; mappings preserve recorded CWE and ATT&CK IDs

---

### `cwe_search_weaknesses` <sub>tool</sub>

- Optional all-token `filter`, exact `language`, `technology`, `abstraction`, `consequenceImpact`, `status`, and `viewId`; omit filters to browse. View filtering includes same-view weakness membership closure; categories are excluded
- All statuses are included by default. Results order by name matches, description matches, extended-description matches, then numeric ID; previews contain the first sentence. `limit` defaults to 20, caps at 100; continue with `pagination.nextCursor`

---

### `cwe_search_attack_patterns` <sub>tool</sub>

- Optional all-token `filter`, `cweId`, `attackTechniqueId`, `abstraction`, `severity`, and `likelihood`; CWE mappings are exact, while a parent ATT&CK technique includes recorded subtechniques
- `includeInactive` defaults to `false`, excluding Deprecated and Obsolete patterns. Results order by name matches, description matches, then numeric ID; `limit` defaults to 20, caps at 100; continue with `pagination.nextCursor`

---

### `cwe_get_view` <sub>tool</sub>

- One CWE view `id`, with `limit` (default 20, capped at 100) and `cursor`; discover IDs through `cwe_list_reference` topic `views`
- Returns objective, audience, source filter, and direct `members` in source order, continued by `pagination.nextCursor`. `found: false` carries `not_found` or `wrong_type`; navigation views list top-level members, with descendants accessible through hierarchy traversal

---

### `cwe_get_hierarchy` <sub>tool</sub>

- One CWE `id` and `direction`: `parents`, `children`, `ancestors`, or `descendants`; `viewId` defaults to `1000`, with `all` available explicitly. `primaryOnly` is valid only for ancestors
- Returns view-scoped `nodes` and parent-to-child `edges`, `found`, `retrievedAt`, and `hierarchyFingerprint`; empty relations succeed, while upstream failures remain errors. Node names come from the loaded catalog and can lag live IDs
- `limit` defaults to 20, caps at 100 edges. Follow `pagination.nextCursor`; continuations re-fetch the traversal, and `invalid_cursor` requires restarting without a cursor when topology or the catalog changes

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

MITRE-specific:

- No API key or signup. Both XML catalogs load into memory before the server accepts requests; startup and every restart require access to MITRE's CWE and CAPEC download sources. Catalogs have no persistent disk cache or bundled copy
- CWE version checks run every 24 hours; CAPEC conditional refreshes run every seven days. Failed refreshes retain the loaded data and appear in `cwe_list_reference` topic `versions`
- Live CWE REST hierarchy traversal preserves multiple parents and view identity; catalog XML supplies local search and detail records
- MITRE source statuses and absent sections remain explicit. Categories and views organize weaknesses; CAPEC mappings and execution flows are incomplete, and missing mappings cannot establish absence of a relationship or current ATT&CK validity

Agent-friendly output:

- Provenance: catalog versions, dates, load time, source links, and attribution accompany results
- Bounded responses: ordinary responses target 24,000 serialized bytes across both output surfaces, including enrichment. Whole IDs or page items are deferred; default detail selections can become outlines. Explicit detail selections remain complete, and a single complete record or page item can exceed the budget with disclosure to preserve progress
- Continuation: use `deferredIds`, `pagination.nextCursor`, or `examplePage.nextOffset`; stale or incompatible cursors fail with `invalid_cursor`. Unsupported vocabulary fails with `unknown_filter` and discovery guidance
- Content parity: rendered `content[]` and `structuredContent` preserve the same selected values, including ordered example code. Catalog prose and code are reference data, never instructions to execute

## Getting started

Add the following to your MCP client configuration file.

```json
{
  "mcpServers": {
    "mitre-cwe-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/mitre-cwe-mcp-server@latest"],
      "env": { "MCP_TRANSPORT_TYPE": "stdio", "MCP_LOG_LEVEL": "info" }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "mitre-cwe-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/mitre-cwe-mcp-server@latest"],
      "env": { "MCP_TRANSPORT_TYPE": "stdio", "MCP_LOG_LEVEL": "info" }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "mitre-cwe-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "MCP_TRANSPORT_TYPE=stdio", "ghcr.io/cyanheads/mitre-cwe-mcp-server:latest"]
    }
  }
}
```

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 bun run start:http
# Server listens at http://localhost:3010/mcp after both catalogs load
```

### Prerequisites

- [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+).
- Outbound HTTPS access to `cwe.mitre.org` and `capec.mitre.org` for initial catalogs, and `cwe-api.mitre.org` for version checks and live hierarchy calls.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/mitre-cwe-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd mitre-cwe-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

4. **Configure environment:**

```sh
cp .env.example .env
# edit .env for optional transport, authentication, and logging settings
```

## Configuration

No server-specific environment variables are required. Catalog sources, refresh intervals, and response limits are fixed; framework storage settings do not persist these catalogs.

| Variable | Description | Default |
|:---|:---|:---|
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | HTTP server port. | `3010` |
| `MCP_HTTP_HOST` | HTTP bind address. | `127.0.0.1` |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. | `stateless` |
| `MCP_AUTH_MODE` | Authentication: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (`debug`, `info`, `warning`, `error`, etc.). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<app-root>/logs` |
| `STORAGE_PROVIDER_TYPE` | Storage backend: `in-memory`, `filesystem`, `supabase`, `cloudflare-kv/r2/d1`. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for every server setting and the common framework overrides.

## Running the server

### Local development

- **Build and run the production version**:

  ```sh
  # One-time build
  bun run rebuild

  # Run the built server
  bun run start:http
  # or
  bun run start:stdio
  ```

- **Run checks and tests**:
  ```sh
  bun run devcheck  # Lints, formats, type-checks, and more
  bun run test      # Runs the test suite
  ```

## Project structure

| Directory | Purpose |
|:---|:---|
| `src/mcp-server/tools/definitions` | Seven read-only tools. |
| `src/mcp-server/tools` | Shared output schemas, section projection, budgets, and pagination. |
| `src/services/catalog` | Catalog acquisition, XML normalization, indexes, refresh lifecycle, and live hierarchy. |
| `tests/` | Unit and integration tests, mirroring the `src/` structure. |
| `docs/` | Design and generated directory reference. |

## Development guide

See [`CLAUDE.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for logging, `ctx.state` for storage
- Register new tools and resources in the `createApp()` arrays in `src/index.ts`
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](./LICENSE) file for details.

CWE data: Copyright © 2006–2026, The MITRE Corporation. CAPEC data: Copyright © 2007–2026, The MITRE Corporation. CWE and CAPEC are MITRE trademarks; their data licenses and disclaimers are reproduced in [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
