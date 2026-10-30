---
name: mitre-cwe-guide
description: Use cwe_* tools to classify vulnerability root causes, investigate CWE-to-CAPEC attack mechanics, and navigate MITRE views. Use when mapping a finding to CWE, checking taxonomy or observed-CVE evidence, or following recorded CAPEC and ATT&CK relationships.
license: Apache-2.0
metadata:
  author: "cyanheads"
  version: "1.0"
---

## Scope

Use MITRE CWE and CAPEC catalog evidence to explain weakness mechanisms, compare candidate root causes, and research attack prerequisites and mitigations. No key is required. These tools do not scan an application, establish that a finding is exploitable, supply authoritative CVE assignments, or validate current ATT&CK coverage.

## Identifiers

Discover candidate CWE IDs through `cwe_search_weaknesses`; discover CWE view IDs through `cwe_list_reference`. A CWE view and a weakness share the CWE namespace but serve different purposes. CAPEC IDs come from weakness relations, `cwe_search_attack_patterns`, or CAPEC category/view members. Keep the prefix when carrying an ID between tools: a bare number takes the receiving tool's catalog family.

## Gates

- Before assigning a CWE to a vulnerability, retrieve the candidate's summary and inspect its description, ordinalities, and mapping notes. Compare the mechanism with the finding; search order alone does not establish the root cause. Respect the source's mapping usage and rationale. CWE groupings (categories in older catalogs), CAPEC categories, and views organize records and cannot stand in for a vulnerability root cause.
- Before treating an observed CVE or taxonomy match as a classification, read the matched evidence and candidate definition. MITRE's observed examples are not NVD's CVE-to-CWE assignments. Resolve the taxonomy name as well as its entry ID when the intended taxonomy or edition matters: an entry such as A1 can occur in more than one taxonomy.
- Before concluding that no weakness or attack pattern applies, distinguish an absent recorded mapping from an unsuccessful text search, restrictive filters, excluded inactive CAPEC patterns, or unevaluated view membership. Follow the returned guidance; absence of a crosswalk is not evidence of no relationship.
- Before claiming complete coverage, retrieve the sections and continuations needed for that claim. A default detail response can omit sections, a view's direct members need not include its descendants, and a search page need not contain every match.
- Before making a freshness-sensitive claim, inspect `cwe_list_reference` versions and refresh health. Preserve the catalog dates and source status in the conclusion; a live hierarchy and loaded record details can disagree. Verify a recorded ATT&CK mapping against current ATT&CK material before presenting it as current coverage.

## Core chain

For a reported vulnerability, search from the described failure mechanism, then retrieve promising CWE definitions. Compare their mapping notes and ordinalities with the finding before selecting a root cause. Retrieve applicable mitigation, platform, detection, or example sections to support the explanation. Keep the narrative beside each example's code: the source can present vulnerable, corrected, and attack code in the same example.

From the selected CWE, follow its recorded CAPEC relations or use `cwe_search_attack_patterns`, then retrieve candidate prerequisites and execution flow with `cwe_get_attack_pattern`. Check that the described preconditions and method fit the scenario before carrying the mapping into the assessment.

## Workflows

**Finding candidates when the first search misses.** Text filters require all tokens; use mechanism terms rather than a full incident narrative. Search compounds as written, and try the catalog's recorded alternate terminology. Discover exact platform and other vocabulary with `cwe_list_reference` rather than guessing labels. If recorded CVE or taxonomy evidence is absent, search from the vulnerability description and report the distinction between a candidate classification and a recorded mapping.

**Exploring related attacks.** CWE-to-CAPEC search matches the exact recorded CWE ID, without expanding its hierarchy. If the task covers a weakness family, discover the relevant CWE descendants in the intended view and examine their mappings separately. Keep each pattern's recorded CWE relationship attached to it. For ATT&CK-led research, a parent technique search includes recorded subtechniques; retain the specific technique IDs returned rather than attributing every result directly to the parent.

**Reading lists and navigating classifications.** Discover a CWE view, then read its objective, audience, and source status with `cwe_get_view` before using it as the requested list. Preserve its published direct-member order when reporting that list. Use `cwe_search_weaknesses` for the view's weakness membership closure and `cwe_get_hierarchy` for paths or relatives. An empty member array on a filter-defined view requires inspecting its filter and guidance; it does not establish an empty classification. Keep view identity attached to hierarchy edges, including multiple parents.

**Browsing CAPEC by mechanism or domain.** Retrieve CAPEC-1000 or CAPEC-3000 with `cwe_get_attack_pattern`, follow its member categories, then retrieve their pattern members. CWE view discovery does not list CAPEC views. Read a CAPEC record's type before treating it as attack mechanics; categories and views provide navigation.

**Working through partial results or an unavailable hierarchy.** Follow the response's section re-calls, deferred IDs, example continuation, and list cursors as needed. If live hierarchy fails, retrieve source-recorded weakness relations and catalog health, label the evidence as recorded relations, and leave the live traversal unresolved. Recorded relations do not replace live children or descendants. Restart a traversal after an incompatible cursor rather than combining different snapshots.
