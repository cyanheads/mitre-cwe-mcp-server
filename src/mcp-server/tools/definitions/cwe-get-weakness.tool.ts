/**
 * @fileoverview Retrieve complete selected CWE sections and source-ordered example pages.
 * @module mcp-server/tools/definitions/cwe-get-weakness.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getCatalogService } from '@/services/index.js';
import { batchOutput, weaknessEntrySchema } from '../catalog-schemas.js';
import { getWeaknessDetails, weaknessSections } from '../detail-projection.js';
import { formatCatalog, idsSchema, inputEnum, list, text } from '../shared.js';
/** Retrieve CWE weaknesses and categories; resolver misses do not fail the batch. */
export const cweGetWeakness = tool('cwe_get_weakness', {
  title: 'Retrieve CWE weaknesses',
  description:
    'Retrieve CWE weaknesses or categories by CWE-N or bare numeric IDs. Processes the first 20 distinct IDs and discloses deferred IDs. Defaults to summary, consequences, mitigations, and relations; explicit sections return complete selected content, while an empty sections array requests an outline. Select examples and use exampleOffset/exampleLimit for complete source-ordered example pages. Categories are organizational entries, not vulnerability root causes.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    ids: idsSchema,
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
    truncated: z.boolean().describe('Whether the batch cap deferred identifiers.').optional(),
    shown: z.number().int().describe('Identifiers processed.').optional(),
    cap: z.number().int().describe('Maximum identifiers processed per call.').optional(),
  },
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
    ctx.enrich.total(result.entries.length + result.notFound.length + result.deferredIds.length);
    if (result.deferredIds.length) ctx.enrich.truncated({ shown: 20, cap: 20 });
    return result;
  },
  format: formatCatalog,
});
