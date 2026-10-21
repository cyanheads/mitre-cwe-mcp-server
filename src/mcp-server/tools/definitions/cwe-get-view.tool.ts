/**
 * @fileoverview Retrieve CWE view metadata and source-ordered direct membership.
 * @module mcp-server/tools/definitions/cwe-get-view.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getCatalogService } from '@/services/index.js';
import {
  formatCatalog,
  list,
  normalizeId,
  pageItems,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
} from '../shared.js';

/** Read one view without expanding its direct membership into descendants. */
export const cweGetView = tool('cwe_get_view', {
  title: 'Get CWE view',
  description:
    'Read a CWE view objective, audience, status, source filter, and direct members in published order. Navigation views list top-level members rather than every descendant; use cwe_get_hierarchy for navigation or cwe_search_weaknesses with viewId for weakness membership closure. Unknown and non-view IDs return a structured miss. Follow nextCursor for remaining direct members.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    id: text('CWE view ID or positive bare integer; discover with cwe_list_reference topic views.'),
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
    objective: text('Complete source objective.').optional(),
    sourceUrl: text('Official view definition URL.').optional(),
    audience: list(
      z
        .object({
          type: text('Source stakeholder type.').optional(),
          description: text('Source audience description.').optional(),
        })
        .describe('Source stakeholder.'),
      'Source audience.',
    ).optional(),
    filterDefinition: text('Complete source member filter definition.').optional(),
    members: list(
      z
        .object({
          id: text('Direct member CWE ID.'),
          viewId: text('Recorded relationship view ID.'),
          name: text('Resolved member name.').optional(),
          type: z
            .enum(['weakness', 'category', 'view'])
            .describe('Resolved record family.')
            .optional(),
          abstraction: text('Source abstraction.').optional(),
          status: text('Source status.').optional(),
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
  enrichmentTrailer: {
    appliedFilters: { render: (filters) => formatCatalog({ appliedFilters: filters })[0].text },
  },
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
    const id = normalizeId(input.id, 'CWE');
    const view = snapshot.cwe.views.get(id);
    const page = pageItems(
      view?.members ?? [],
      input,
      ['cwe_get_view', id, Math.min(input.limit, 100)],
      snapshot.provenance,
    );
    ctx.enrich.total(page.pagination.total);
    ctx.enrich({ appliedFilters: { id, limit: Math.min(input.limit, 100) } });
    if (page.pagination.hasMore)
      ctx.enrich.truncated({ shown: page.items.length, cap: Math.min(input.limit, 100) });
    if (page.notice) ctx.enrich.notice(page.notice);
    const common = {
      id,
      members: page.items.map((member) => ({ ...member })),
      pagination: page.pagination,
      provenance: snapshot.provenance,
    };
    if (!view)
      return {
        ...common,
        found: false,
        reason: snapshot.cwe.weaknesses.has(id) ? ('wrong_type' as const) : ('not_found' as const),
        guidance:
          'Call cwe_list_reference with topic views to find a view ID, then repeat cwe_get_view.',
      };
    const { members: _members, audience, ...metadata } = view;
    return {
      ...metadata,
      ...common,
      found: true,
      ...(audience !== undefined ? { audience: audience.map((item) => ({ ...item })) } : {}),
      ...(view.members.length === 0
        ? {
            guidance:
              'This view has no recorded direct members; this does not establish that no weaknesses belong to it. Review filterDefinition when present, or use cwe_get_hierarchy for navigation.',
          }
        : {}),
    };
  },
  format: formatCatalog,
});
