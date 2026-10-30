/**
 * @fileoverview Retrieve CWE view metadata and source-ordered direct membership.
 * @module mcp-server/tools/definitions/cwe-get-view.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { compileViewFilter, getCatalogService } from '@/services/index.js';
import { dimensionsSchema, notesSchema } from '../catalog-schemas.js';
import {
  CWE_ID,
  catalogEnrichmentTrailer,
  formatCatalog,
  list,
  normalizeId,
  pageResponse,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
  VIEW_ID_FORMS,
} from '../shared.js';

/** Read one view without expanding its direct membership into descendants. */
export const cweGetView = tool('cwe_get_view', {
  title: 'Get CWE view',
  description:
    'Read a CWE view objective, audience, status, source filter, recorded notes, and direct members in published order. Navigation views list top-level members rather than every descendant; use cwe_get_hierarchy for navigation or cwe_search_weaknesses with viewId for weakness membership closure. A filter-defined (Implicit) view lists no members: its filterDefinition is the source XPath that defines membership, and cwe_search_weaknesses with its viewId returns the weaknesses that filter selects; when the filter has a part this server does not evaluate, the guidance says so and that search returns none with a disclosure. Unknown and non-view IDs return a structured miss. Follow nextCursor for remaining direct members.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    id: z
      .string()
      .regex(CWE_ID, VIEW_ID_FORMS)
      .describe(
        'CWE view ID such as CWE-1000 or 1000; discover with cwe_list_reference topic views.',
      ),
    ...pagingShape,
  }),
  output: z.object({
    found: z.boolean().describe('Whether this ID resolves to a CWE view.'),
    id: text('Canonical requested CWE ID.'),
    reason: z
      .enum(['not_found', 'wrong_type'])
      .describe('Missing record or known non-view.')
      .optional(),
    name: text('Source view name.').optional(),
    type: text('Source view type.').optional(),
    status: text('Source status.').optional(),
    objective: text('Complete source objective in CommonMark.').optional(),
    sourceUrl: text('Official view definition URL.').optional(),
    audience: list(
      z
        .object({
          type: text('Source stakeholder type.').optional(),
          description: text('Source audience description in CommonMark.').optional(),
        })
        .describe('Source stakeholder.'),
      'Source audience.',
    ).optional(),
    filterDefinition: text(
      'Source XPath filter defining a filter-defined view’s membership, exactly as published.',
    ).optional(),
    notes: notesSchema.optional(),
    members: list(
      z
        .object({
          id: text('Direct member CWE ID.'),
          viewId: text('Recorded relationship view ID.'),
          name: text('Resolved member name.').optional(),
          type: z
            .enum(['weakness', 'category', 'grouping', 'view'])
            .describe('Resolved record family.')
            .optional(),
          abstraction: text('Source abstraction.').optional(),
          status: text('Source status.').optional(),
          dimensions: dimensionsSchema.optional(),
        })
        .describe('Direct view member.'),
      'Direct members in source order.',
    ),
    pagination: paginationSchema,
    provenance: provenanceSchema,
    guidance: text('View discovery or empty-members guidance.').optional(),
  }),
  enrichment: {
    appliedFilters: z
      .object({
        id: text('Canonical view ID.'),
        limit: z.number().int().describe('Effective page size.'),
      })
      .describe('Applied inputs and defaults.'),
    notice: text('Page cap disclosure.').optional(),
    totalCount: z.number().int().describe('Direct members before paging.'),
    truncated: z.boolean().describe('Whether more direct members remain.').optional(),
    shown: z.number().int().describe('Page item count.').optional(),
    cap: z.number().int().describe('Effective page limit.').optional(),
  },
  enrichmentTrailer: catalogEnrichmentTrailer,
  errors: [
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Cursor is incompatible with the view or catalog.',
      recovery: 'Repeat cwe_get_view without cursor to retrieve members from the beginning.',
      thrownBy: 'service',
    },
  ],
  handler(input, ctx) {
    const snapshot = getCatalogService().snapshot();
    const id = normalizeId(input.id);
    const view = snapshot.cwe.views.get(id);
    const { output, enrichment } = pageResponse(view?.members ?? [], input, {
      binding: ['cwe_get_view', id],
      provenance: snapshot.provenance,
      appliedFilters: { id },
      output: (page) => {
        const common = {
          id,
          members: page.items.map(({ dimensions, ...member }) => ({
            ...member,
            ...(dimensions
              ? { dimensions: dimensions.map((dimension) => ({ ...dimension })) }
              : {}),
          })),
          pagination: page.pagination,
          provenance: snapshot.provenance,
        };
        if (!view)
          return {
            ...common,
            found: false,
            reason: snapshot.cwe.weaknesses.has(id)
              ? ('wrong_type' as const)
              : ('not_found' as const),
            guidance:
              'Call cwe_list_reference with topic views to find a view ID, then repeat cwe_get_view.',
          };
        const { members: _members, audience, notes, ...metadata } = view;
        return {
          ...metadata,
          ...common,
          found: true,
          ...(audience !== undefined ? { audience: audience.map((item) => ({ ...item })) } : {}),
          ...(notes !== undefined ? { notes: notes.map((note) => ({ ...note })) } : {}),
          ...(view.members.length === 0
            ? {
                guidance:
                  view.filterDefinition === undefined
                    ? 'This view has no recorded direct members; this does not establish that no weaknesses belong to it. Use cwe_get_hierarchy for navigation.'
                    : compileViewFilter(view.filterDefinition)
                      ? `This view has no recorded members: its source filter (filterDefinition) defines its membership. Call cwe_search_weaknesses with viewId ${id} for the weaknesses it selects.`
                      : `This view has no recorded members: its source filter (filterDefinition) defines its membership, but the filter has a part this server does not evaluate, so cwe_search_weaknesses with viewId ${id} returns no weaknesses and says so. Read filterDefinition for the records it selects.`,
              }
            : {}),
        };
      },
    });
    ctx.enrich(enrichment);
    return output;
  },
  format: formatCatalog,
});
