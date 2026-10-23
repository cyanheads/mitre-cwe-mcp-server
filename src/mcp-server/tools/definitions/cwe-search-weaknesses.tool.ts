/**
 * @fileoverview Search the complete loaded CWE weakness catalog before pagination.
 * @module mcp-server/tools/definitions/cwe-search-weaknesses.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import {
  type CatalogSnapshot,
  categoryOnlyStatuses,
  compileViewFilter,
  escapeMarkdown,
  evidenceMatchers,
  getCatalogService,
  recordedEntryId,
  resolveVocabulary,
  resolveWeaknessStatus,
  searchWeaknesses,
  someTokenMatches,
  type WeaknessFilters,
} from '@/services/index.js';
import { observedExampleSchema, taxonomyMappingSchema } from '../catalog-schemas.js';
import {
  CVE_ID_FORMS,
  catalogEnrichmentTrailer,
  filterPhrase,
  filterSchema,
  firstSentence,
  formatCatalog,
  list,
  normalizeFilter,
  normalizeId,
  OPTIONAL_CVE_ID,
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
    'All whitespace-separated tokens must match the name, a recorded alternate term, the description, or the extended description, each at a word start or camelCase hump (dos finds ReDoS), never inside a word: search a compound or negated form as written, such as deserialization or untrusted. Blank means unset.',
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
    'Exact weakness status; discover with cwe_list_reference topic filter_values. A status only categories carry matches nothing. Omission includes all statuses, including Deprecated.',
  ).optional(),
  mappingUsage: text(
    'Exact MITRE vulnerability mapping usage, such as Allowed or Allowed-with-Review; discover values with cwe_list_reference topic filter_values.',
  ).optional(),
  taxonomyName: text(
    'Exact taxonomy name a weakness mapping records, such as CERT C Secure Coding or ISA/IEC 62443; discover values with cwe_list_reference topic filter_values. Matches any mapping in that taxonomy, including one without an entry ID.',
  ).optional(),
  taxonomyEntryId: filterSchema(
    'Entry ID a weakness taxonomy mapping records, such as ARR30-C or A1, in any case and with any whitespace runs; matches only the whole recorded ID. With taxonomyName, both must hold on the same mapping. Blank means unset.',
  ),
  observedCveId: z
    .string()
    .regex(OPTIONAL_CVE_ID, CVE_ID_FORMS)
    .describe(
      'CVE ID such as CVE-2021-44228, in any case; matches the weaknesses MITRE cites it on as an observed example, not other CVE-to-CWE assignments such as NVD’s. Blank means unset.',
    )
    .optional(),
  viewId: z
    .string()
    .regex(OPTIONAL_CWE_ID, VIEW_ID_FORMS)
    .describe(
      'CWE view ID such as CWE-1000 or 1000, from cwe_list_reference topic views; matches the weaknesses its recorded members reach within the view, or that its source filter selects for a filter-defined view. Blank means unset.',
    )
    .optional(),
};

/** Filters that match a recorded taxonomy mapping or observed example rather than catalog text. */
const EVIDENCE_FILTERS: ReadonlySet<string> = new Set<keyof WeaknessFilters>([
  'taxonomyName',
  'taxonomyEntryId',
  'observedCveId',
]);

function listFilters(entries: readonly (readonly [string, string])[]): string {
  return entries.map(([key, value]) => `${key}: ${escapeMarkdown(value)}`).join(', ');
}

/**
 * Disclose a filter-defined view's filter that cannot be evaluated, then explain a zero-hit search
 * by what emptied it: a status only categories carry, the view itself, the view beside the other
 * filters, taxonomy mapping and observed example filters that no weakness records together,
 * vocabulary filters, or text. A suggested repeat is always one that can return weaknesses, so a
 * zero-hit `viewId` search with other filters runs the view alone, or the other filters alone, when
 * its notice needs that; a zero-hit evidence search with other filters runs the evidence filters
 * alone, and the others alone when the notice needs that; and a zero-hit text filter of several
 * tokens checks whether one token matches on its own.
 */
function searchNotice(
  snapshot: CatalogSnapshot,
  filters: WeaknessFilters,
  matched: boolean,
): string | undefined {
  const { viewId, ...others } = filters;
  /**
   * searchWeaknesses has validated the view. With no other filter the search was the view alone,
   * and without viewId it would return the whole catalog, which always holds a weakness.
   */
  const narrowed = !matched && Object.keys(others).length > 0;
  const widen = () =>
    !narrowed || searchWeaknesses(snapshot, others).length
      ? 'repeat cwe_search_weaknesses without viewId'
      : 'repeat cwe_search_weaknesses with fewer filters';
  const filterDefinition =
    viewId === undefined ? undefined : snapshot.cwe.views.get(viewId)?.filterDefinition;
  const unevaluated =
    filterDefinition !== undefined && !compileViewFilter(filterDefinition)
      ? `View ${viewId} is defined by a source filter (filterDefinition) with a part this server does not evaluate, so the filter selected no weaknesses here; this does not establish that none belong to the view. Call cwe_get_view to read the filter, or ${widen()}.`
      : undefined;
  if (matched) return unevaluated;
  // No other change returns weaknesses while this status applies, so it is the whole explanation.
  if (filters.status !== undefined && categoryOnlyStatuses(snapshot).includes(filters.status))
    return [
      unevaluated,
      `Status ${escapeMarkdown(filters.status)} occurs only on CWE categories, which cwe_search_weaknesses excludes. Call cwe_list_reference with topic filter_values for the statuses weaknesses carry.`,
    ]
      .filter(Boolean)
      .join(' ');
  if (unevaluated) return unevaluated;
  if (viewId !== undefined) {
    if (!narrowed || !searchWeaknesses(snapshot, { viewId }).length)
      return filterDefinition !== undefined
        ? `The source filter of view ${viewId} selects no weaknesses. Call cwe_get_view to read its filterDefinition.`
        : `View ${viewId} records no membership that reaches a weakness; this does not establish that none belong to it. Call cwe_get_view to read the view.`;
    // The view holds weaknesses, so dropping the other filters returns some.
    return filterDefinition !== undefined
      ? `No weakness that the source filter of view ${viewId} selects matches the other filters. Call cwe_get_view to read its filterDefinition, or repeat cwe_search_weaknesses with fewer filters.`
      : `No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or ${widen()}.`;
  }
  const entries = Object.entries(filters);
  const evidence = entries.filter(([key]) => EVIDENCE_FILTERS.has(key));
  if (evidence.length) {
    const rest = Object.fromEntries(entries.filter(([key]) => !EVIDENCE_FILTERS.has(key)));
    const combined = Object.keys(rest).length > 0;
    // Evidence that some weakness records, emptied only by the other filters, takes the notice below.
    if (!combined || !searchWeaknesses(snapshot, Object.fromEntries(evidence)).length)
      return `No weakness records a taxonomy mapping or observed example matching these filters (${listFilters(evidence)}); this does not establish that no weakness applies. Repeat cwe_search_weaknesses ${combined && !searchWeaknesses(snapshot, rest).length ? 'with fewer filters' : 'without them, or with a text filter'}.`;
  }
  const { filter } = filters;
  if (filter === undefined || entries.length > 1)
    return `No weaknesses matched the applied filters (${listFilters(entries)}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.`;
  return `No weakness matched ${filterPhrase(filter)}. Repeat cwe_search_weaknesses with ${termsRepeat(
    filter,
    () => someTokenMatches(snapshot, 'cwe', filter),
  )}.`;
}

/** Search CWE weaknesses using source vocabulary and complete local membership. */
export const cweSearchWeaknesses = tool('cwe_search_weaknesses', {
  title: 'Search CWE weaknesses',
  description:
    'Search CWE weaknesses by all text tokens, exact platform or consequence vocabulary, abstraction, status, mapping usage, view membership, a recorded taxonomy mapping (taxonomy name or entry ID such as CERT C ARR30-C), or a CVE that MITRE cites as an observed example. A text token matches at a word start, never inside a word, so search a compound or negated form such as deserialization or untrusted as written; text never matches an entry ID or CVE. Omit filters to browse; categories are excluded. Each result carries MITRE’s mapping usage, which says whether the entry may be used to map a vulnerability, and, under a taxonomy or CVE filter, every mapping or observed example that matched. Results order by all tokens in the name or in one recorded alternate term such as XSS, then all in the description, then any other match, then numeric ID. Description previews contain the first sentence; use cwe_get_weakness for complete sections. Follow nextCursor for remaining matches.',
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
          matchedTaxonomyMappings: list(
            taxonomyMappingSchema,
            'Every taxonomy mapping of this weakness that taxonomyName and taxonomyEntryId match, in source order; present only when one of them applies.',
          ).optional(),
          matchedObservedExamples: list(
            observedExampleSchema,
            'Every observed example of this weakness that cites observedCveId, in source order; present only when it applies.',
          ).optional(),
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
        taxonomyName: text('Canonical taxonomy name.').optional(),
        taxonomyEntryId: text(
          'Entry ID as a weakness mapping records it, or the whitespace-collapsed input when none does.',
        ).optional(),
        observedCveId: text('Uppercase CVE ID.').optional(),
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
      ['taxonomyName', 'cweTaxonomyNames'],
    ] as const) {
      const value = optionalText(input[field]);
      if (value)
        filters[field] =
          field === 'status'
            ? resolveWeaknessStatus(snapshot, value)
            : resolveVocabulary(snapshot, vocabulary, field, value);
    }
    const entryId = optionalText(input.taxonomyEntryId);
    if (entryId) filters.taxonomyEntryId = recordedEntryId(snapshot, entryId);
    const cve = optionalText(input.observedCveId);
    if (cve) filters.observedCveId = cve.toUpperCase();
    const viewId = optionalText(input.viewId);
    if (viewId) filters.viewId = normalizeId(viewId);
    const matches = searchWeaknesses(snapshot, filters);
    if (!matches.length && !Object.keys(filters).length)
      throw serviceUnavailable('The loaded CWE catalog contains no weaknesses.', {
        retryable: false,
      });
    const notice = searchNotice(snapshot, filters, matches.length > 0);
    const { mapping, example } = evidenceMatchers(snapshot, filters);
    const previews = matches.map((entry) => {
      // searchWeaknesses kept this weakness only when each applied test matches one of its entries.
      const matchedTaxonomyMappings = mapping && entry.taxonomyMappings?.filter(mapping);
      const matchedObservedExamples = example && entry.observedExamples?.filter(example);
      return {
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
        ...(matchedTaxonomyMappings ? { matchedTaxonomyMappings } : {}),
        ...(matchedObservedExamples ? { matchedObservedExamples } : {}),
      };
    });
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
