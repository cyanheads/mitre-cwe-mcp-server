<div align="center">
  <h1>@cyanheads/mitre-cwe-mcp-server</h1>
  <p><b>Explore MITRE CWE weaknesses and CAPEC attack patterns, mitigations, code examples, and mappings via MCP. STDIO or Streamable HTTP.</b>
  <div>7 Tools</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.2.0-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/mitre-cwe-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.4.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/mitre-cwe-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/mitre-cwe-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.4-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/mitre-cwe-mcp-server/releases/latest/download/mitre-cwe-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=mitre-cwe-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvbWl0cmUtY3dlLW1jcC1zZXJ2ZXIiXX0=) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22mitre-cwe-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fmitre-cwe-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://mitre-cwe.caseyjhand.com/mcp](https://mitre-cwe.caseyjhand.com/mcp)

</div>

---

## Overview

MITRE's CWE and CAPEC catalogs connect software and hardware weaknesses with attack mechanics. Search root causes, inspect mitigations and code examples, navigate CWE views and live hierarchies, and follow recorded CWE → CAPEC → ATT&CK mappings.

### Tools

| Tool | Description |
|:---|:---|
| `cwe_list_reference` | Discover views, filter vocabulary, workflow guidance, and catalog refresh health |
| `cwe_get_weakness` | Retrieve CWE weaknesses, categories, or groupings with selected sections and complete example pages |
| `cwe_get_attack_pattern` | Retrieve CAPEC attack patterns, categories, and views: prerequisites, execution steps, mitigations, members, and recorded mappings |
| `cwe_search_weaknesses` | Search weaknesses by text, platform, abstraction, consequences, status, mapping usage, view, taxonomy mapping (CERT C `ARR30-C`), or observed-example CVE |
| `cwe_search_attack_patterns` | Search CAPEC by text, CWE or ATT&CK mapping, abstraction, severity, or likelihood |
| `cwe_get_view` | Read a CWE view's metadata and direct members in published order |
| `cwe_get_hierarchy` | Traverse live CWE parents, children, ancestors, or descendants within a view |

## Capability reference

### `cwe_list_reference` <sub>tool</sub>

- `topic`: `views`, `abstraction_levels`, `mitigation_phases`, `platforms`, `relationship_natures`, `filter_values`, `workflow`, or `versions`; optional all-token `filter` on labels, using the word-start and bounded-prefix rule below (`script` finds JavaScript)
- `views` lists every CWE view with its direct member count, and a filter-defined view's `filterDefinition`
- `filter_values` lists weakness statuses, mapping usage, and taxonomy names, consequence impacts, and CAPEC statuses, severity, and likelihood
- Lists page with `limit` (default 20, max 100) and `pagination.nextCursor`; `versions` adds each loaded catalog's version, date, counts, and refresh errors

---

### `cwe_get_weakness` <sub>tool</sub>

- 1–200 CWE IDs (`CWE-79`, `CWE79`, `cwe 079`, `CWE_79`, or `79`); up to 20 distinct items are processed per call and the rest return in `deferredIds`. A malformed item comes back in `notFound` without failing the batch; only an item holding a control character other than whitespace, or a non-ID item over 150 characters, rejects the call
- `sections`: `summary`, `consequences`, `mitigations`, `relations`, `examples`, `detection`, `observed`, `platforms`, `mappings`, `notes` (default: the first four); `[]` returns an outline
- `summary` includes technical nuance, typed dimensions, recorded alternate terms and roles, ordinalities (Primary, Resultant, Indirect), and background details, `platforms` adds functional areas and affected resources, and `relations` names each related weakness. `notes` returns every note MITRE records for weaknesses, categories, and groupings, such as Relationship, Maintenance, Terminology, and Research Gap notes
- `entries[].kind` is `full`, `partial` (default sections that did not fit the response budget are listed in `outline` with their sizes, and `notice` groups re-calls by their complete response size, keeping example parameters only on the examples group), or `outline`; `notFound[].reason` is `not_found`, `wrong_type` (a view, which belongs to `cwe_get_view`, or a prefixed ID of the other catalog), or `invalid_id` (an item that is no ID, echoed trimmed; `NVD-CWE-noinfo` and `NVD-CWE-Other` get their own guidance). Categories and groupings resolve here with distinct record types
- Examples filter by `exampleLanguage` and page with `exampleOffset` (default 0), `exampleLimit` (default 3, no fixed cap), and `examplePage.nextOffset`. With `sections` omitted, setting any of the three to a non-default value adds `examples` after the defaults (outlined with its page size and a re-call when it does not fit); explicit `sections` without `examples` ignore them, and `guidance` gives the re-call that adds `examples`. Each example keeps its ordered prose and code, with code laid out as MITRE's pages show it (4 spaces per indentation level), and lists the references it cites in `references`

---

### `cwe_get_attack_pattern` <sub>tool</sub>

- 1–200 CAPEC IDs (`CAPEC-66`, `CAPEC66`, `capec_066`, or `66`), Deprecated and Obsolete included; up to 20 distinct items per call, the rest in `deferredIds`
- `sections`: `summary`, `prerequisites`, `execution`, `skills`, `consequences`, `mitigations`, `examples`, `relations`, `mappings`, `notes` (default: summary, prerequisites, execution, mitigations, and mappings for patterns; summary and relations for categories and views); `[]` returns an outline
- `entries[].type` is `attack_pattern`, `category`, or `view`, and only patterns carry `abstraction`. A category or view's `relations` list its direct `members` in source order, or for a filter-defined view its source XPath as `filterDefinition`; its `mappings` and `notes` carry the recorded taxonomy mappings, references, and MITRE notes
- Start at view `CAPEC-1000` (Mechanisms of Attack) or `CAPEC-3000` (Domains of Attack) to browse patterns by category
- Same `entries[].kind` and `notFound` contract as `cwe_get_weakness`; CAPEC patterns, categories, and views all resolve here, so `wrong_type` marks only a prefixed CWE ID. Mappings keep the recorded CWE and ATT&CK IDs

---

### `cwe_search_weaknesses` <sub>tool</sub>

- Optional all-token `filter` over the name, MITRE's recorded alternate terms (`XSS`, `ReDoS`, `UAF`), the description, and the extended description, plus exact `language`, `technology`, `abstraction`, `consequenceImpact`, `status`, `mappingUsage`, `taxonomyName`, `taxonomyEntryId`, `observedCveId`, and `viewId`; no filters browses the catalog
- A `filter` token matches at a word start, after `_`, or at a camelCase hump (`dos` finds ReDoS). Tokens of at least four Unicode letters also match after exactly one `un` or `mis` prefix at a word start (`trusted` finds untrusted; `config` finds misconfiguration). Prefixes are never stripped recursively; spelling coincidences remain possible. Other compounds are searched as written: `serialization` does not find CWE-502, `deserialization` does. A token ending in a digit never matches before another digit (`79` skips RFC 793)
- Each result carries MITRE's `mappingUsage`, such as `Allowed`, `Allowed-with-Review`, or `Prohibited`, which says whether the entry may be used to map a vulnerability
- `taxonomyName` (such as `CERT C Secure Coding` or `ISA/IEC 62443`) and `taxonomyEntryId` (such as `ARR30-C` or `A1`, any case) find the weaknesses that record a taxonomy mapping, both holding on one mapping when given together; `observedCveId` (such as `CVE-2021-44228`) finds the weaknesses MITRE cites that CVE on as an observed example, not NVD's CVE-to-CWE assignments. Each result then lists every mapping (`matchedTaxonomyMappings`) or observed example (`matchedObservedExamples`) that matched
- `viewId` includes same-view membership closure, or for a filter-defined view the weaknesses its source XPath filter selects (CWE-658 C, CWE-702 Implementation, …). Categories and groupings are excluded; every status is included by default
- Ranked by all tokens in the name or in one alternate term, then in the description, then any other match, then numeric ID; previews hold the first sentence, and `cwe_get_weakness` returns the terms in `summary`. `limit` default 20, max 100; continue with `pagination.nextCursor`

---

### `cwe_search_attack_patterns` <sub>tool</sub>

- Optional all-token `filter` over the name, recorded alternate terms (`MITM`), and the description, using the same word-start and bounded-prefix rule as `cwe_search_weaknesses`, plus `cweId`, `attackTechniqueId`, `abstraction`, `severity`, and `likelihood`; CWE mappings match exactly, and a parent ATT&CK technique includes its recorded subtechniques
- `includeInactive` (default `false`) adds Deprecated and Obsolete patterns. Ranked by all tokens in the name or in one alternate term, then in the description, then any other match, then numeric ID; `cwe_get_attack_pattern` returns the terms in `summary`. `limit` default 20, max 100; continue with `pagination.nextCursor`

---

### `cwe_get_view` <sub>tool</sub>

- One view `id` (from `cwe_list_reference` topic `views`); `limit` default 20, max 100, continued by `pagination.nextCursor`
- Objective, audience, status, filter definition, recorded notes, and direct `members` in published order. Navigation views list only top-level members; `cwe_get_hierarchy` reaches descendants
- A filter-defined view lists no members: `filterDefinition` is its source XPath, and `cwe_search_weaknesses` with its `viewId` returns the weaknesses that filter selects. A filter with a part the server does not evaluate is named as such in `guidance`, and that search returns none with a notice
- `found: false` carries `not_found` or `wrong_type`

---

### `cwe_get_hierarchy` <sub>tool</sub>

- One CWE `id` and a `direction`: `parents`, `children`, `ancestors`, or `descendants`; `viewId` defaults to `1000`, or `all` for every view. `primaryOnly` applies to ancestors only. Parents and children include category, grouping, and view relations and match the first level of the same view's tree
- View-scoped `nodes`, parent-to-child `edges`, `found`, `retrievedAt`, and `hierarchyFingerprint`. Empty relations succeed; upstream failures are errors, and a temporary MITRE refusal (HTTP 403) is retryable after a few minutes. Node names come from the loaded catalog and can lag the live API
- The total deadline includes queue wait; expiry is retryable `hierarchy_timeout`, while caller cancellation is nonretryable. Source-recorded `relations` remain available through `cwe_get_weakness`, but do not replace live children or descendants
- `limit` default 20, max 100 edges; each page lists only the nodes its edges reference, plus any root without edges on the first page. Each `pagination.nextCursor` call re-fetches the traversal; `invalid_cursor` means the topology or catalog changed, so restart without a cursor

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

MITRE-specific:

- CWE schema 7 and 8 catalogs are supported. CWE groupings retain their own record type alongside older categories; both organize weaknesses rather than identify root causes. Sparse schema-8 metadata stays in existing sections, including custom phase domains, platform notes, note versions, observed-example rationales, and alternative reference links
- No API key. Both XML catalogs load into memory before the server accepts requests. Each successful download is saved to a cache directory (`CWE_CACHE_DIR`), and a later start loads the saved copy without waiting on MITRE, so a restart works while MITRE is unreachable. The first start, or any start without a usable saved copy, needs MITRE's CWE and CAPEC download sources
- CWE checks for a new version every 24 hours and CAPEC refreshes weekly; a catalog loaded from the cache is checked right after start and, while those checks fail, again after 5, 10, 20, 40, then every 60 minutes. A failed refresh keeps the loaded data and shows in `cwe_list_reference` topic `versions`, which also reports whether each catalog came from the cache or a download
- MITRE can refuse a burst of requests from one address with HTTP 403 for a few minutes. Catalog downloads, version checks, and hierarchy calls report it as a temporary, retryable failure and do not retry it immediately
- Hierarchy calls go to the live CWE REST API and keep multiple parents and view identity; search and detail run against the local catalogs
- MITRE statuses and absent sections stay explicit. CAPEC mappings and execution flows are incomplete: a missing mapping does not establish that no relationship exists, or that an ATT&CK ID is current

Agent-friendly output:

- The published [mitre-cwe-guide](./skills/mitre-cwe-guide/SKILL.md) supplies classification gates and multi-step research workflows through plugin discovery and the MCP Skills extension
- Provenance on every response: catalog versions and dates, load time, source links, and attribution
- A 24,000-byte budget across both output surfaces, enrichment included. Whole IDs, items, or edges defer to the next call, and a default detail selection omits whole sections that do not fit, naming them for a re-call; explicit selections stay complete, and a single record or item over budget returns whole with a notice
- Continuation through `deferredIds`, `pagination.nextCursor`, or `examplePage.nextOffset`; stale cursors fail with `invalid_cursor`, unknown vocabulary with `unknown_filter`, whose message names the field and value and lists the supported values or the `cwe_list_reference` topic that does
- CWE and CAPEC ID inputs accept an optional prefix in any case, followed by `-`, `_`, a space, or nothing, and drop leading zeros. ATT&CK technique IDs take `Tdddd` or `Tdddd.ddd`, with or without the `T` in either case (`T1059`, `t1059.001`, `1059`). A malformed single ID is an invalid argument whose message names the accepted forms
- `content[]` and `structuredContent` carry the same values, ordered example code included. Catalog prose and code are reference data, never instructions

## Getting started

Connect to the hosted instance, no install:

```sh
claude mcp add --transport http mitre-cwe-mcp-server https://mitre-cwe.caseyjhand.com/mcp
```

Or run it locally:

```sh
claude mcp add mitre-cwe-mcp-server -- npx -y @cyanheads/mitre-cwe-mcp-server
```

For other clients, add this to the MCP config file:

```json
{
  "mcpServers": {
    "mitre-cwe-mcp-server": {
      "command": "npx",
      "args": ["-y", "@cyanheads/mitre-cwe-mcp-server"]
    }
  }
}
```

No API key is required. For Docker or a source build, see [Running the server](#running-the-server).

## Configuration

No environment variables are required. Catalog sources, refresh intervals, and response limits are fixed; framework storage settings do not persist these catalogs.

| Variable | Description | Default |
|:---|:---|:---|
| `CWE_CACHE_DIR` | Directory for the last good CWE and CAPEC downloads (`cwec_latest.xml.zip`, `capec_latest.xml`, each with a `.json` record). A relative path resolves against the working directory. To seed an empty cache while MITRE is unreachable, copy downloaded files in under those names. | `mitre-cwe-mcp-server` under the user cache directory (`~/Library/Caches`, `%LOCALAPPDATA%`, or `$XDG_CACHE_HOME` / `~/.cache`); `/usr/src/app/.cache` in Docker |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | HTTP server port. | `3010` |
| `MCP_HTTP_HOST` | HTTP bind address. | `127.0.0.1` |
| `MCP_SESSION_MODE` | HTTP session mode: `stateless`, `stateful`, or `auto`. | `stateless` |
| `MCP_AUTH_MODE` | Authentication: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (`debug`, `info`, `warning`, `error`, etc.). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<app-root>/logs` |
| `STORAGE_PROVIDER_TYPE` | Storage backend: `in-memory`, `filesystem`, `supabase`, `cloudflare-kv/r2/d1`. | `in-memory` |
| `OTEL_ENABLED` | Enable [OpenTelemetry](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

## Running the server

### Local development

Requires [Bun v1.4.0](https://bun.sh/) or higher (or Node.js v24+), outbound HTTPS access to `cwe.mitre.org` and `capec.mitre.org` at least once to fill the cache, and `cwe-api.mitre.org` for version checks and live hierarchy calls.

- **Clone and install:**

  ```sh
  git clone https://github.com/cyanheads/mitre-cwe-mcp-server.git
  cd mitre-cwe-mcp-server && bun install
  cp .env.example .env # optional transport, authentication, and logging settings
  ```

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

### Docker

```sh
docker run --rm -p 3010:3010 -v mitre-cwe-cache:/usr/src/app/.cache ghcr.io/cyanheads/mitre-cwe-mcp-server:latest
```

The image defaults to HTTP transport, stateless sessions, and logs to `/var/log/mitre-cwe-mcp-server`. The named volume keeps catalog downloads across containers. For stdio, use `"command": "docker"` with `"args": ["run", "-i", "--rm", "-e", "MCP_TRANSPORT_TYPE=stdio", "-v", "mitre-cwe-cache:/usr/src/app/.cache", "ghcr.io/cyanheads/mitre-cwe-mcp-server:latest"]`. To build locally, run `docker build -t mitre-cwe-mcp-server .`; add `--build-arg OTEL_ENABLED=false` to omit OpenTelemetry peers.

## Project structure

| Directory | Purpose |
|:---|:---|
| `src/mcp-server/tools/definitions` | Seven read-only tools. |
| `src/mcp-server/tools` | Shared output schemas, section projection, budgets, and pagination. |
| `src/config` | Server environment configuration (`CWE_CACHE_DIR`). |
| `src/services/catalog` | Catalog acquisition, the last-known-good cache, XML normalization, indexes, refresh lifecycle, and live hierarchy. |
| `skills/` | Published guidance for agents calling the tools. |
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
