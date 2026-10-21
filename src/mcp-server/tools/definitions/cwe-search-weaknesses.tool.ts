/**
 * @fileoverview Search the complete loaded CWE weakness catalog before pagination.
 * @module mcp-server/tools/definitions/cwe-search-weaknesses.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import {
  type CatalogSnapshot,
  compileViewFilter,
  escapeMarkdown,
  getCatalogService,
  resolveVocabulary,
  searchWeaknesses,
  someTokenMatches,
  type WeaknessFilters,
} from '@/services/index.js';
import {
  catalogEnrichmentTrailer,
  filterPhrase,
  filterSchema,
  firstSentence,
  formatCatalog,
  list,
  normalizeFilter,
  normalizeId,
  OPTIONAL_CWE_ID,
  optionalInputEnum,
  optionalText,
  pageResponse,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  termsRepeat,
  text,
  VIEW_ID_FORMS,
} from '../shared.js';

const filtersShape = {
  filter: filterSchema(
    'All whitespace-separated tokens must match the name, a recorded alternate term, the description, or the extended description; blank means unset.',
  ),
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
  mappingUsage: text(
    'Exact MITRE vulnerability mapping usage, such as Allowed or Allowed-with-Review; discover values with cwe_list_reference topic filter_values.',
  ).optional(),
  viewId: z
    .string()
    .regex(OPTIONAL_CWE_ID, VIEW_ID_FORMS)
    .describe(
      'CWE view ID such as CWE-1000 or 1000, from cwe_list_reference topic views; matches the weaknesses its recorded members reach within the view, or that its source filter selects for a filter-defined view. Blank means unset.',
    )
    .optional(),
};

/**
 * Disclose a filter-defined view's filter that cannot be evaluated, then explain a zero-hit search
 * by what emptied it: the view itself, the view beside the other filters, vocabulary filters, or
 * text. A suggested repeat is always one that can return weaknesses, so a zero-hit `viewId` search
 * with other filters runs the view alone, or the other filters alone, when its notice needs that,
 * and a zero-hit text filter of several tokens checks whether one token matches on its own.
 */
function searchNotice(
  snapshot: CatalogSnapshot,
  filters: WeaknessFilters,
  matched: boolean,
): string | undefined {
  const { viewId, ...others } = filters;
  if (viewId !== undefined) {
    /**
     * searchWeaknesses has validated the view. With no other filter the search was the view alone,
     * and without viewId it would return the whole catalog, which always holds a weakness.
     */
    const narrowed = !matched && Object.keys(others).length > 0;
    const widen = () =>
      !narrowed || searchWeaknesses(snapshot, others).length
        ? 'repeat cwe_search_weaknesses without viewId'
        : 'repeat cwe_search_weaknesses with fewer filters';
    const filterDefinition = snapshot.cwe.views.get(viewId)?.filterDefinition;
    if (filterDefinition !== undefined && !compileViewFilter(filterDefinition))
      return `View ${viewId} is defined by a source filter (filterDefinition) with a part this server does not evaluate, so the filter selected no weaknesses here; this does not establish that none belong to the view. Call cwe_get_view to read the filter, or ${widen()}.`;
    if (matched) return undefined;
    if (!narrowed || !searchWeaknesses(snapshot, { viewId }).length)
      return filterDefinition !== undefined
        ? `The source filter of view ${viewId} selects no weaknesses. Call cwe_get_view to read its filterDefinition.`
        : `View ${viewId} records no membership that reaches a weakness; this does not establish that none belong to it. Call cwe_get_view to read the view.`;
    // The view holds weaknesses, so dropping the other filters returns some.
    return filterDefinition !== undefined
      ? `No weakness that the source filter of view ${viewId} selects matches the other filters. Call cwe_get_view to read its filterDefinition, or repeat cwe_search_weaknesses with fewer filters.`
      : `No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or ${widen()}.`;
  }
  if (matched) return undefined;
  const { filter } = filters;
  if (filter === undefined || Object.keys(filters).length > 1)
    return `No weaknesses matched the applied filters (${Object.entries(filters)
      .map(([key, value]) => `${key}: ${escapeMarkdown(value)}`)
      .join(
        ', ',
      )}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.`;
  return `No weakness matched ${filterPhrase(filter)}. Repeat cwe_search_weaknesses with ${termsRepeat(
    filter,
    () => someTokenMatches(snapshot, 'cwe', filter),
  )}.`;
}

/** Search CWE weaknesses using source vocabulary and complete local membership. */
export const cweSearchWeaknesses = tool('cwe_search_weaknesses', {
  title: 'Search CWE weaknesses',
  description:
    'Search CWE weaknesses by all text tokens, exact platform or consequence vocabulary, abstraction, status, mapping usage, or view membership. Omit filters to browse; categories are excluded. Each result carries MITRE’s mapping usage, which says whether the entry may be used to map a vulnerability. Results order by all tokens in the name or in one recorded alternate term such as XSS, then all in the description, then any other match, then numeric ID. Description previews contain the first sentence; use cwe_get_weakness for complete sections. Follow nextCursor for remaining matches.',
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
          mappingUsage: text(
            'Source vulnerability mapping usage, such as Allowed or Prohibited; absent when not recorded.',
          ).optional(),
          sourceUrl: text('Official definition URL.'),
          descriptionPreview: text('First complete sentence of the CommonMark source description.'),
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
        mappingUsage: text('Canonical mapping usage.').optional(),
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
  enrichmentTrailer: catalogEnrichmentTrailer,
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
    const filter = normalizeFilter(input.filter);
    if (filter) filters.filter = filter;
    for (const [field, vocabulary] of [
      ['language', 'languages'],
      ['technology', 'technologies'],
      ['abstraction', 'cweAbstractions'],
      ['consequenceImpact', 'consequenceImpacts'],
      ['status', 'cweStatuses'],
      ['mappingUsage', 'cweMappingUsages'],
    ] as const) {
      const value = optionalText(input[field]);
      if (value) filters[field] = resolveVocabulary(snapshot, vocabulary, field, value);
    }
    const viewId = optionalText(input.viewId);
    if (viewId) filters.viewId = normalizeId(viewId);
    const matches = searchWeaknesses(snapshot, filters);
    if (!matches.length && !Object.keys(filters).length)
      throw serviceUnavailable('The loaded CWE catalog contains no weaknesses.', {
        retryable: false,
      });
    const notice = searchNotice(snapshot, filters, matches.length > 0);
    const previews = matches.map((entry) => ({
      id: entry.id,
      name: entry.name,
      status: entry.status,
      sourceUrl: entry.sourceUrl,
      descriptionPreview: firstSentence(entry.description),
      ...(entry.abstraction !== undefined ? { abstraction: entry.abstraction } : {}),
      ...(entry.mappingNotes?.usage !== undefined
        ? { mappingUsage: entry.mappingNotes.usage }
        : {}),
      ...(entry.likelihoodOfExploit !== undefined
        ? { likelihoodOfExploit: entry.likelihoodOfExploit }
        : {}),
    }));
    const { output, enrichment } = pageResponse(previews, input, {
      binding: ['cwe_search_weaknesses', filters],
      provenance: snapshot.provenance,
      appliedFilters: filters,
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
