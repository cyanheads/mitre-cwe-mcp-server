/**
 * @fileoverview Retrieve complete selected CWE sections and source-ordered example pages.
 * @module mcp-server/tools/definitions/cwe-get-weakness.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getCatalogService } from '@/services/index.js';
import { batchOutput, weaknessEntrySchema } from '../catalog-schemas.js';
import { detailEnrichment, getWeaknessDetails, weaknessSections } from '../detail-projection.js';
import {
  detailEnrichmentTrailer,
  formatCatalog,
  idsSchema,
  inputEnum,
  list,
  text,
} from '../shared.js';
/** Retrieve CWE weaknesses and categories; resolver misses do not fail the batch. */
export const cweGetWeakness = tool('cwe_get_weakness', {
  title: 'Retrieve CWE weaknesses',
  description:
    'Retrieve CWE weaknesses or categories by ID, such as CWE-79, CWE79, or 79. Processes up to 20 distinct IDs within a 24,000-byte response budget and discloses deferred IDs; a view, a CAPEC ID, or an item that is no ID returns in notFound with recovery guidance; only an item holding a control character other than whitespace, or a non-ID item over 150 characters, rejects the whole call. Defaults to summary, consequences, mitigations, and relations; a default section that does not fit the budget is omitted whole and named with its size and a re-call (kind partial). Summary carries recorded alternate terms such as XSS, ordinalities (Primary, Resultant, Indirect), and background details; the notes section, outside the defaults, returns every note MITRE records, such as Relationship, Maintenance, Terminology, and Research Gap notes. Explicit sections remain complete, including one oversized record with disclosure; an empty sections array requests an outline. Select examples and use exampleOffset/exampleLimit for complete source-ordered example pages. Categories are organizational entries, not vulnerability root causes.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    ids: idsSchema('CWE'),
    sections: list(
      inputEnum(weaknessSections).describe('A supported CWE detail section.'),
      'Selected sections; omit for defaults, or pass an empty array for an outline.',
    ).optional(),
    exampleLanguage: text(
      'Exact source example code language; discover values through cwe_list_reference topic platforms.',
    ).optional(),
    exampleOffset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe('Offset in each entry’s language-filtered examples.'),
    exampleLimit: z
      .number()
      .int()
      .min(1)
      .default(3)
      .describe('Complete examples per entry; no upper bound beyond the finite source array.'),
  }),
  output: batchOutput(weaknessEntrySchema),
  enrichment: {
    totalCount: z.number().int().describe('Distinct submitted identifiers before the batch cap.'),
    truncated: z
      .boolean()
      .describe('Whether the count or response budget deferred identifiers.')
      .optional(),
    shown: z.number().int().describe('Identifiers processed.').optional(),
    cap: z.number().int().describe('Maximum identifiers processed per call.').optional(),
    notice: text('Whole-identifier continuation and budget disclosure.').optional(),
  },
  enrichmentTrailer: detailEnrichmentTrailer,
  errors: [
    {
      reason: 'unknown_filter',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The example language is absent from the loaded source vocabulary.',
      recovery:
        'Call cwe_list_reference with topic platforms, then repeat cwe_get_weakness with a supported exampleLanguage.',
      thrownBy: 'service',
    },
  ],
  handler(input, ctx) {
    const result = getWeaknessDetails(getCatalogService().snapshot(), input);
    ctx.enrich(detailEnrichment(result));
    return result;
  },
  format: formatCatalog,
});
