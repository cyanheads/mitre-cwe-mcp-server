/**
 * @fileoverview Search the complete loaded CWE weakness catalog before pagination.
 * @module mcp-server/tools/definitions/cwe-search-weaknesses.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import {
  getCatalogService,
  resolveVocabulary,
  searchWeaknesses,
  type WeaknessFilters,
} from '@/services/index.js';
import {
  formatCatalog,
  list,
  normalizeId,
  optionalInputEnum,
  optionalText,
  pageItems,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
} from '../shared.js';

const filtersShape = {
  filter: text(
    'All whitespace-separated tokens must match name, description, or extended description; blank means unset.',
  )
    .max(500)
    .optional(),
  language: text(
    'Exact platform language name or class; discover with cwe_list_reference topic platforms.',
  ).optional(),
  technology: text(
    'Exact platform technology name or class; discover with cwe_list_reference topic platforms.',
  ).optional(),
  abstraction: optionalInputEnum(['Pillar', 'Class', 'Base', 'Variant', 'Compound']).describe(
    'Exact CWE abstraction level; blank means unset.',
  ),
  consequenceImpact: text(
    'Exact consequence impact; discover with cwe_list_reference topic filter_values.',
  ).optional(),
  status: text(
    'Exact source status; omission includes all statuses, including Deprecated.',
  ).optional(),
  viewId: text(
    'CWE view ID or bare integer; matches its same-view weakness membership closure.',
  ).optional(),
};

/** Search CWE weaknesses using source vocabulary and complete local membership. */
export const cweSearchWeaknesses = tool('cwe_search_weaknesses', {
  title: 'Search CWE weaknesses',
  description:
    'Search CWE weaknesses by all text tokens, exact platform or consequence vocabulary, abstraction, status, or view membership. Omit filters to browse; categories are excluded. Results order by all tokens in name, then description, then extended description, then numeric ID. Description previews contain the first sentence; use cwe_get_weakness for complete sections. Follow nextCursor for remaining matches.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({ ...filtersShape, ...pagingShape }),
  output: z.object({
    results: list(
      z
        .object({
          id: text('Canonical CWE ID.'),
          name: text('Source weakness name.'),
          status: text('Source status.'),
          abstraction: text('Source abstraction.').optional(),
          sourceUrl: text('Official definition URL.'),
          descriptionPreview: text('First complete source description sentence.'),
          likelihoodOfExploit: text('Source exploit likelihood.').optional(),
        })
        .describe('Matching weakness preview.'),
      'Matching weakness page.',
    ),
    pagination: paginationSchema,
    provenance: provenanceSchema,
  }),
  enrichment: {
    appliedFilters: z
      .object({
        filter: text('Normalized text filter.').optional(),
        language: text('Canonical language.').optional(),
        technology: text('Canonical technology.').optional(),
        abstraction: text('Canonical abstraction.').optional(),
        consequenceImpact: text('Canonical consequence impact.').optional(),
        status: text('Canonical status.').optional(),
        viewId: text('Canonical view ID.').optional(),
        limit: z.number().int().describe('Effective page limit.'),
      })
      .describe('Applied filters and defaults.'),
    notice: text('Empty-result or page-cap guidance.').optional(),
    totalCount: z.number().int().describe('Complete matching count before paging.'),
    truncated: z.boolean().describe('Whether a page omits remaining matches.').optional(),
    shown: z.number().int().describe('Items shown on this page.').optional(),
    cap: z.number().int().describe('Effective page limit.').optional(),
  },
  enrichmentTrailer: {
    appliedFilters: { render: (filters) => formatCatalog({ appliedFilters: filters })[0].text },
  },
  errors: [
    {
      reason: 'unknown_filter',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Unsupported dynamic vocabulary or unknown or wrong-type view.',
      recovery:
        'Call cwe_list_reference for supported views and filter vocabulary, then repeat cwe_search_weaknesses.',
      thrownBy: 'service',
    },
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Cursor is incompatible with inputs or catalog.',
      recovery: 'Repeat cwe_search_weaknesses without cursor to start a new result set.',
      thrownBy: 'service',
    },
  ],
  handler(input, ctx) {
    const snapshot = getCatalogService().snapshot();
    const filters: WeaknessFilters = {};
    const filter = optionalText(input.filter)?.toLowerCase().split(/\s+/).join(' ');
    if (filter) filters.filter = filter;
    for (const [field, vocabulary] of [
      ['language', 'languages'],
      ['technology', 'technologies'],
      ['abstraction', 'cweAbstractions'],
      ['consequenceImpact', 'consequenceImpacts'],
      ['status', 'cweStatuses'],
    ] as const) {
      const value = optionalText(input[field]);
      if (value) filters[field] = resolveVocabulary(snapshot, vocabulary, value);
    }
    const viewId = optionalText(input.viewId);
    if (viewId) filters.viewId = normalizeId(viewId, 'CWE');
    const matches = searchWeaknesses(snapshot, filters);
    if (!matches.length && !Object.keys(filters).length)
      throw serviceUnavailable('The loaded CWE catalog contains no weaknesses.', {
        retryable: false,
      });
    const page = pageItems(
      matches,
      input,
      ['cwe_search_weaknesses', filters, Math.min(input.limit, 100)],
      snapshot.provenance,
    );
    ctx.enrich.total(matches.length);
    ctx.enrich({ appliedFilters: { ...filters, limit: Math.min(input.limit, 100) } });
    if (page.pagination.hasMore)
      ctx.enrich.truncated({ shown: page.items.length, cap: Math.min(input.limit, 100) });
    const notices = page.notice ? [page.notice] : [];
    if (!matches.length)
      notices.push(
        filters.viewId
          ? 'No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or repeat cwe_search_weaknesses without viewId.'
          : Object.keys(filters).some((key) => key !== 'filter')
            ? `No weaknesses matched the applied filters (${Object.entries(filters)
                .map(([key, value]) => `${key}: ${value}`)
                .join(
                  ', ',
                )}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.`
            : 'No weakness matched every text token. Repeat cwe_search_weaknesses with fewer terms.',
      );
    if (notices.length) ctx.enrich.notice(notices.join(' '));
    return {
      results: page.items.map((entry) => ({
        id: entry.id,
        name: entry.name,
        status: entry.status,
        sourceUrl: entry.sourceUrl,
        descriptionPreview:
          [
            ...new Intl.Segmenter('en', { granularity: 'sentence' }).segment(entry.description),
          ][0]?.segment.trim() ?? entry.description,
        ...(entry.abstraction !== undefined ? { abstraction: entry.abstraction } : {}),
        ...(entry.likelihoodOfExploit !== undefined
          ? { likelihoodOfExploit: entry.likelihoodOfExploit }
          : {}),
      })),
      pagination: page.pagination,
      provenance: snapshot.provenance,
    };
  },
  format: formatCatalog,
});
