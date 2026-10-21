/**
 * @fileoverview Search recorded CAPEC patterns and partial crosswalks before paging.
 * @module mcp-server/tools/definitions/cwe-search-attack-patterns.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  type AttackPatternFilters,
  getCatalogService,
  resolveVocabulary,
  searchAttackPatterns,
} from '@/services/index.js';
import {
  type CatalogPage,
  catalogEnrichmentTrailer,
  deliveredSize,
  formatCatalog,
  list,
  normalizeAttackId,
  normalizeId,
  optionalInputEnum,
  optionalText,
  pageEnrichment,
  pageItems,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
} from '../shared.js';

const sentenceSegmenter = new Intl.Segmenter('en', { granularity: 'sentence' });

/** Search source CAPEC patterns without treating missing mappings as negative evidence. */
export const cweSearchAttackPatterns = tool('cwe_search_attack_patterns', {
  title: 'Search CAPEC attack patterns',
  description:
    'Search CAPEC attack patterns by every whitespace-separated text token, recorded CWE or ATT&CK mapping, abstraction, severity, or likelihood. Parent ATT&CK techniques include recorded subtechniques; CWE mappings are exact without hierarchy expansion. Omit filters to browse. Deprecated and Obsolete patterns are excluded by default. Mappings are incomplete and do not validate current ATT&CK coverage. Results order by all tokens in name, then description, then numeric ID; use cwe_get_attack_pattern for complete sections and follow nextCursor for remaining matches.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    filter: text('All-token case-insensitive name and description filter; blank means unset.')
      .max(500)
      .optional(),
    cweId: text(
      'Exact recorded CWE mapping, CWE-N or bare integer from cwe_search_weaknesses; blank means unset.',
    ).optional(),
    attackTechniqueId: text(
      'Recorded Tdddd or Tdddd.ddd mapping from cwe_get_attack_pattern mappings, also accepting bare numeric form; blank means unset.',
    ).optional(),
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
          descriptionPreview: text('First complete description sentence.'),
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
    const filter = optionalText(input.filter)?.toLowerCase().split(/\s+/).join(' ');
    if (filter) filters.filter = filter;
    for (const [field, vocabulary] of [
      ['abstraction', 'capecAbstractions'],
      ['severity', 'capecSeverities'],
      ['likelihood', 'capecLikelihoods'],
    ] as const) {
      const value = optionalText(input[field]);
      if (value) filters[field] = resolveVocabulary(snapshot, vocabulary, value);
    }
    const cweId = optionalText(input.cweId);
    const attackTechniqueId = optionalText(input.attackTechniqueId);
    if (cweId) filters.cweId = normalizeId(cweId, 'CWE');
    if (attackTechniqueId) filters.attackTechniqueId = normalizeAttackId(attackTechniqueId);
    const matches = searchAttackPatterns(snapshot, filters);
    const notices: string[] = [];
    if (!matches.length) {
      notices.push(
        filters.cweId || filters.attackTechniqueId
          ? 'No CAPEC mapping was recorded for these filters; this does not establish that no attack pattern applies. Repeat cwe_search_attack_patterns without the mapping filter or with a text filter.'
          : `No CAPEC patterns matched the applied filters (${Object.entries(filters)
              .map(([key, value]) => `${key}: ${value}`)
              .join(
                ', ',
              )}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_attack_patterns with fewer filters.`,
      );
      if (!input.includeInactive)
        notices.push(
          'Repeat cwe_search_attack_patterns with includeInactive true to include Deprecated and Obsolete patterns.',
        );
    }
    const previews = matches.map((entry) => ({
      id: entry.id,
      name: entry.name,
      abstraction: entry.abstraction,
      status: entry.status,
      sourceUrl: entry.sourceUrl,
      descriptionPreview:
        sentenceSegmenter.segment(entry.description).containing(0)?.segment.trim() ??
        entry.description,
      ...(entry.typicalSeverity !== undefined ? { severity: entry.typicalSeverity } : {}),
      ...(entry.likelihoodOfAttack !== undefined ? { likelihood: entry.likelihoodOfAttack } : {}),
      ...(entry.relatedWeaknesses !== undefined
        ? { relatedWeaknesses: entry.relatedWeaknesses.map((item) => ({ ...item })) }
        : {}),
      ...(entry.attackTechniqueIds !== undefined
        ? { attackTechniqueIds: [...entry.attackTechniqueIds] }
        : {}),
    }));
    const output = (page: CatalogPage<(typeof previews)[number]>) => ({
      results: page.items,
      pagination: page.pagination,
      provenance: snapshot.provenance,
    });
    const enrichment = (page: CatalogPage<(typeof previews)[number]>) =>
      pageEnrichment(
        page,
        input.limit,
        { ...filters, includeInactive: input.includeInactive, limit: Math.min(input.limit, 100) },
        notices.join(' '),
      );
    const page = pageItems(
      previews,
      input,
      ['cwe_search_attack_patterns', filters, Math.min(input.limit, 100)],
      snapshot.provenance,
      (candidate) => deliveredSize(output(candidate), enrichment(candidate)),
    );
    ctx.enrich(enrichment(page));
    return output(page);
  },
  format: formatCatalog,
});
