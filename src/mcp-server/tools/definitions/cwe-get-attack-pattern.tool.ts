/**
 * @fileoverview Retrieve selected complete CAPEC mechanics and recorded mappings.
 * @module mcp-server/tools/definitions/cwe-get-attack-pattern.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { getCatalogService } from '@/services/index.js';
import { attackPatternEntrySchema, batchOutput } from '../catalog-schemas.js';
import {
  attackPatternSections,
  detailEnrichment,
  getAttackPatternDetails,
} from '../detail-projection.js';
import {
  detailEnrichmentTrailer,
  formatCatalog,
  idsSchema,
  inputEnum,
  list,
  text,
} from '../shared.js';
/** Retrieve CAPEC details without treating missing mappings as evidence of no relationship. */
export const cweGetAttackPattern = tool('cwe_get_attack_pattern', {
  title: 'Retrieve CAPEC attack patterns',
  description:
    'Retrieve CAPEC attack patterns, categories, and views by ID, such as CAPEC-66, CAPEC66, or 66, including Deprecated and Obsolete records; each entry’s type says which. Processes the first 20 distinct positions in submission order and lists later positions in deferredIds; a CWE ID or an item that is no ID returns in notFound with recovery guidance; only an item holding a control character other than whitespace, or a non-ID item over 150 characters, rejects the whole call. Patterns default to summary, prerequisites, execution, mitigations, and mappings. Request relations on a pattern for its recorded relationships and direct childAttackPatterns. Categories and views default to summary (the category summary or view objective) and relations (members in source order, or a filter-defined view’s source XPath filterDefinition). Views CAPEC-1000 (Mechanisms of Attack) and CAPEC-3000 (Domains of Attack) are entry points for browsing patterns by category. Request notes for recorded MITRE notes. Selected sections are complete; an empty sections array requests an outline with section sizes. Recorded CWE and ATT&CK mappings are incomplete and do not establish current ATT&CK validation.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    ids: idsSchema('CAPEC'),
    sections: list(
      inputEnum(attackPatternSections).describe('A supported CAPEC detail section.'),
      'Selected sections; omit for defaults, or pass an empty array for an outline.',
    ).optional(),
  }),
  output: batchOutput(attackPatternEntrySchema),
  enrichment: {
    totalCount: z.number().int().describe('Distinct submitted identifiers before the batch cap.'),
    truncated: z.boolean().describe('Whether the 20-position cap deferred identifiers.').optional(),
    shown: z.number().int().describe('Identifiers processed.').optional(),
    cap: z.number().int().describe('Maximum identifiers processed per call.').optional(),
    notice: text('How to continue with deferred IDs.').optional(),
  },
  enrichmentTrailer: detailEnrichmentTrailer,
  handler(input, ctx) {
    const result = getAttackPatternDetails(getCatalogService().snapshot(), input);
    ctx.enrich(detailEnrichment(result));
    return result;
  },
  format: formatCatalog,
});
