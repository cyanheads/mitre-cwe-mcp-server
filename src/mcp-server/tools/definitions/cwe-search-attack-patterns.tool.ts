/**
 * @fileoverview Search recorded CAPEC patterns and partial crosswalks before paging.
 * @module mcp-server/tools/definitions/cwe-search-attack-patterns.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  type AttackPatternFilters,
  type CatalogSnapshot,
  escapeMarkdown,
  getCatalogService,
  resolveVocabulary,
  searchAttackPatterns,
  someTokenMatches,
} from '@/services/index.js';
import {
  ATTACK_ID_FORMS,
  CWE_ID_FORMS,
  catalogEnrichmentTrailer,
  filterPhrase,
  filterSchema,
  firstSentence,
  formatCatalog,
  list,
  normalizeAttackId,
  normalizeFilter,
  normalizeId,
  OPTIONAL_ATTACK_ID,
  OPTIONAL_CWE_ID,
  optionalInputEnum,
  optionalText,
  pageResponse,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  termsRepeat,
  text,
} from '../shared.js';

const INCLUDE_INACTIVE =
  'Repeat cwe_search_attack_patterns with includeInactive true to include Deprecated and Obsolete patterns.';

/**
 * Explain a zero-hit search. A text filter alone is named as applied, and its notice suggests only a
 * repeat that can return patterns: includeInactive when only excluded patterns match it, fewer terms
 * when one of its tokens matches on its own, otherwise different terms.
 */
function searchNotice(snapshot: CatalogSnapshot, filters: AttackPatternFilters): string {
  const { filter, includeInactive, ...others } = filters;
  if (filter !== undefined && !Object.keys(others).length) {
    if (
      !includeInactive &&
      searchAttackPatterns(snapshot, { filter, includeInactive: true }).length
    )
      return `Only Deprecated or Obsolete patterns, which are excluded by default, matched ${filterPhrase(filter)}. ${INCLUDE_INACTIVE}`;
    return `No CAPEC pattern matched ${filterPhrase(filter)}. Repeat cwe_search_attack_patterns with ${termsRepeat(
      filter,
      () => someTokenMatches(snapshot, 'capec', filter, includeInactive),
    )}.`;
  }
  return [
    filters.cweId || filters.attackTechniqueId
      ? 'No CAPEC mapping was recorded for these filters; this does not establish that no attack pattern applies. Repeat cwe_search_attack_patterns without the mapping filter or with a text filter.'
      : `No CAPEC patterns matched the applied filters (${Object.entries(filters)
          .map(([key, value]) => `${key}: ${escapeMarkdown(String(value))}`)
          .join(
            ', ',
          )}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_attack_patterns with fewer filters.`,
    !includeInactive && INCLUDE_INACTIVE,
  ]
    .filter(Boolean)
    .join(' ');
}

/** Search source CAPEC patterns without treating missing mappings as negative evidence. */
export const cweSearchAttackPatterns = tool('cwe_search_attack_patterns', {
  title: 'Search CAPEC attack patterns',
  description:
    'Search CAPEC attack patterns by every whitespace-separated text token, recorded CWE or ATT&CK mapping, abstraction, severity, or likelihood. A text token matches at a word start, never inside a word, so search a compound or negated form such as deserialization or untrusted as written. Parent ATT&CK techniques include recorded subtechniques; CWE mappings are exact without hierarchy expansion. Omit filters to browse. Deprecated and Obsolete patterns are excluded by default. Mappings are incomplete and do not validate current ATT&CK coverage. Results order by all tokens in the name or in one recorded alternate term such as MITM, then all in the description, then any other match, then numeric ID; use cwe_get_attack_pattern for complete sections and follow nextCursor for remaining matches.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    filter: filterSchema(
      'All-token case-insensitive filter over the name, recorded alternate terms, and description; each token matches at a word start or camelCase hump (path finds XPath), never inside a word. Blank means unset.',
    ),
    cweId: z
      .string()
      .regex(OPTIONAL_CWE_ID, CWE_ID_FORMS)
      .describe(
        'Exact recorded CWE mapping, a CWE ID such as CWE-79 or 79 from cwe_search_weaknesses; blank means unset.',
      )
      .optional(),
    attackTechniqueId: z
      .string()
      .regex(OPTIONAL_ATTACK_ID, ATTACK_ID_FORMS)
      .describe(
        'Recorded Tdddd or Tdddd.ddd mapping from cwe_get_attack_pattern mappings, also accepting bare numeric form; blank means unset.',
      )
      .optional(),
    abstraction: optionalInputEnum(['Meta', 'Standard', 'Detailed']).describe(
      'Exact CAPEC abstraction; blank means unset.',
    ),
    severity: text(
      'Exact source severity; discover with cwe_list_reference topic filter_values.',
    ).optional(),
    likelihood: text(
      'Exact source likelihood; discover with cwe_list_reference topic filter_values.',
    ).optional(),
    includeInactive: z
      .boolean()
      .default(false)
      .describe('Include Deprecated and Obsolete patterns; default false.'),
    ...pagingShape,
  }),
  output: z.object({
    results: list(
      z
        .object({
          id: text('Canonical CAPEC ID.'),
          name: text('Source name.'),
          abstraction: text('Source abstraction.'),
          status: text('Source status.'),
          sourceUrl: text('Official definition URL.'),
          descriptionPreview: text('First complete sentence of the CommonMark description.'),
          severity: text('Source typical severity.').optional(),
          likelihood: text('Source attack likelihood.').optional(),
          relatedWeaknesses: list(
            z
              .object({ id: text('Recorded CWE ID.'), name: text('Resolved CWE name.').optional() })
              .describe('Recorded CWE mapping.'),
            'Recorded CWE mappings.',
          ).optional(),
          attackTechniqueIds: list(
            text('Recorded ATT&CK ID.'),
            'Recorded ATT&CK IDs; not a current validation.',
          ).optional(),
        })
        .describe('Matching CAPEC preview.'),
      'Matching pattern page.',
    ),
    pagination: paginationSchema,
    provenance: provenanceSchema,
  }),
  enrichment: {
    appliedFilters: z
      .object({
        filter: text('Normalized filter.').optional(),
        cweId: text('Canonical CWE ID.').optional(),
        attackTechniqueId: text('Canonical ATT&CK ID.').optional(),
        abstraction: text('Canonical abstraction.').optional(),
        severity: text('Canonical severity.').optional(),
        likelihood: text('Canonical likelihood.').optional(),
        includeInactive: z.boolean().describe('Applied inactive-record inclusion.'),
        limit: z.number().int().describe('Effective page limit.'),
      })
      .describe('Applied filters and defaults.'),
    notice: text('Empty-result or cap guidance.').optional(),
    totalCount: z.number().int().describe('Matching count before paging.'),
    truncated: z.boolean().describe('Whether more matches remain.').optional(),
    shown: z.number().int().describe('Page item count.').optional(),
    cap: z.number().int().describe('Effective limit.').optional(),
  },
  enrichmentTrailer: catalogEnrichmentTrailer,
  errors: [
    {
      reason: 'unknown_filter',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Unsupported CAPEC vocabulary value.',
      recovery:
        'Call cwe_list_reference for supported CAPEC filter vocabulary, then repeat cwe_search_attack_patterns.',
      thrownBy: 'service',
    },
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Cursor is incompatible with inputs or catalog.',
      recovery: 'Repeat cwe_search_attack_patterns without cursor to start a new result set.',
      thrownBy: 'service',
    },
  ],
  handler(input, ctx) {
    const snapshot = getCatalogService().snapshot();
    const filters: AttackPatternFilters = { includeInactive: input.includeInactive };
    const filter = normalizeFilter(input.filter);
    if (filter) filters.filter = filter;
    for (const [field, vocabulary] of [
      ['abstraction', 'capecAbstractions'],
      ['severity', 'capecSeverities'],
      ['likelihood', 'capecLikelihoods'],
    ] as const) {
      const value = optionalText(input[field]);
      if (value) filters[field] = resolveVocabulary(snapshot, vocabulary, field, value);
    }
    const cweId = optionalText(input.cweId);
    const attackTechniqueId = optionalText(input.attackTechniqueId);
    if (cweId) filters.cweId = normalizeId(cweId);
    if (attackTechniqueId) filters.attackTechniqueId = normalizeAttackId(attackTechniqueId);
    const matches = searchAttackPatterns(snapshot, filters);
    const notice = matches.length ? undefined : searchNotice(snapshot, filters);
    const previews = matches.map((entry) => ({
      id: entry.id,
      name: entry.name,
      abstraction: entry.abstraction,
      status: entry.status,
      sourceUrl: entry.sourceUrl,
      descriptionPreview: firstSentence(entry.description),
      ...(entry.typicalSeverity !== undefined ? { severity: entry.typicalSeverity } : {}),
      ...(entry.likelihoodOfAttack !== undefined ? { likelihood: entry.likelihoodOfAttack } : {}),
      ...(entry.relatedWeaknesses !== undefined
        ? { relatedWeaknesses: entry.relatedWeaknesses.map((item) => ({ ...item })) }
        : {}),
      ...(entry.attackTechniqueIds !== undefined
        ? { attackTechniqueIds: [...entry.attackTechniqueIds] }
        : {}),
    }));
    const { output, enrichment } = pageResponse(previews, input, {
      binding: ['cwe_search_attack_patterns', filters],
      provenance: snapshot.provenance,
      appliedFilters: { ...filters, includeInactive: input.includeInactive },
      notice,
      output: (page) => ({
        results: page.items,
        pagination: page.pagination,
        provenance: snapshot.provenance,
      }),
    });
    ctx.enrich(enrichment);
    return output;
  },
  format: formatCatalog,
});
