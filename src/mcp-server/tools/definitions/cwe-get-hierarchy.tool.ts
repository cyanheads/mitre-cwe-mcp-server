/**
 * @fileoverview Retrieve and page live view-scoped CWE topology.
 * @module mcp-server/tools/definitions/cwe-get-hierarchy.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getCatalogService, getHierarchyService, HIERARCHY_RECOVERY } from '@/services/index.js';
import {
  formatCatalog,
  inputEnum,
  list,
  normalizeId,
  pageItems,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
} from '../shared.js';

/** Live edges retain multiple parents and independent view topology. */
export const cweGetHierarchy = tool('cwe_get_hierarchy', {
  title: 'Get CWE hierarchy',
  description:
    'Navigate live CWE parents, children, ancestors, or descendants for a weakness, category, or view. Discover IDs with cwe_search_weaknesses or cwe_list_reference topic views. The default view is 1000; set viewId all for every view. primaryOnly applies only to ancestors. Edges point from parent to child and retain view identity; follow nextCursor for more edges. Continuations re-fetch the traversal and reject changed topology. Empty relations are successful; upstream failures remain errors. Node names come from the loaded catalog and may lag live IDs.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    id: text('CWE ID or positive bare integer.'),
    direction: inputEnum(['parents', 'children', 'ancestors', 'descendants']).describe(
      'Live hierarchy direction.',
    ),
    viewId: z
      .preprocess(
        (value) => (typeof value === 'string' && !value.trim() ? undefined : value),
        z.string().default('1000'),
      )
      .describe('CWE view ID or all; discover with cwe_list_reference topic views.'),
    primaryOnly: z
      .boolean()
      .default(false)
      .describe('Restrict ancestors to primary parents; invalid for other directions when true.'),
    ...pagingShape,
  }),
  output: z.object({
    found: z
      .boolean()
      .describe('Whether the root exists according to the live hierarchy response.'),
    id: text('Canonical queried root ID.'),
    direction: z
      .enum(['parents', 'children', 'ancestors', 'descendants'])
      .describe('Applied traversal direction.'),
    viewId: text('Canonical selected view or all.'),
    primaryOnly: z.boolean().describe('Applied primary ancestor restriction.'),
    nodes: list(
      z
        .object({
          id: text('CWE node ID.'),
          type: text(
            'Upstream type; direct roots use the catalog type or unknown when unavailable.',
          ),
          viewId: text('Topology view ID.'),
          name: text('Loaded catalog name.').optional(),
          abstraction: text('Loaded abstraction.').optional(),
          status: text('Loaded status.').optional(),
          sourceUrl: text('Official catalog URL.').optional(),
        })
        .describe('Node required by this page or the known root.'),
      'Page endpoint nodes and queried root.',
    ),
    edges: list(
      z
        .object({
          parentId: text('Parent CWE ID.'),
          childId: text('Child CWE ID.'),
          viewId: text('Relationship view ID.'),
          primaryParent: z.boolean().describe('Source primary flag when supplied.').optional(),
        })
        .describe('Directed view-scoped relationship.'),
      'Deterministically ordered edge page.',
    ),
    pagination: paginationSchema,
    retrievedAt: text('Live retrieval time in ISO format.'),
    hierarchyFingerprint: text('Full traversal and catalog version fingerprint.'),
    provenance: provenanceSchema,
    guidance: text('Recovery guidance for an unknown root.').optional(),
  }),
  enrichment: {
    appliedFilters: z
      .object({
        id: text('Canonical root ID.'),
        direction: text('Traversal direction.'),
        viewId: text('Selected view or all.'),
        primaryOnly: z.boolean().describe('Primary ancestor restriction.'),
        limit: z.number().int().describe('Effective edge page size.'),
      })
      .describe('Normalized traversal and paging inputs.'),
    totalCount: z.number().int().describe('Full traversal edge count.').optional(),
    notice: text('Paging cap or source drift notice.').optional(),
    truncated: z.boolean().describe('Whether additional edges remain.').optional(),
    shown: z.number().int().describe('Returned edge count.').optional(),
    cap: z.number().int().describe('Effective edge page cap.').optional(),
  },
  enrichmentTrailer: {
    appliedFilters: { render: (filters) => formatCatalog({ appliedFilters: filters })[0].text },
  },
  errors: [
    {
      reason: 'invalid_hierarchy_options',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Unknown view or primaryOnly outside ancestors.',
      recovery:
        'Call cwe_list_reference with topic views, then repeat cwe_get_hierarchy with a supported view and primaryOnly only for ancestors.',
    },
    {
      reason: 'hierarchy_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'The live response is inconsistent or a locally known root returns 404.',
      recovery: HIERARCHY_RECOVERY,
      thrownBy: 'service',
    },
    {
      reason: 'queue_full',
      code: JsonRpcErrorCode.RateLimited,
      when: 'Four requests are active and twenty callers are queued.',
      recovery:
        'Call cwe_get_weakness for recorded relations, then retry cwe_get_hierarchy after the active requests finish.',
      retryable: true,
      thrownBy: 'service',
    },
    {
      reason: 'invalid_cursor',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Traversal, query, or catalog changed since the cursor was created.',
      recovery: 'Repeat cwe_get_hierarchy without cursor to retrieve a consistent new traversal.',
      thrownBy: 'service',
    },
  ],
  async handler(input, ctx) {
    const snapshot = getCatalogService().snapshot();
    const id = normalizeId(input.id, 'CWE');
    const viewId =
      input.viewId.trim().toLowerCase() === 'all' ? 'all' : normalizeId(input.viewId, 'CWE');
    if (
      (input.primaryOnly && input.direction !== 'ancestors') ||
      (viewId !== 'all' && !snapshot.cwe.views.has(viewId))
    )
      throw ctx.fail('invalid_hierarchy_options');
    const query = { id, direction: input.direction, viewId, primaryOnly: input.primaryOnly };
    const result = await getHierarchyService().getHierarchy(query, snapshot, ctx);
    const page = pageItems(
      result.edges,
      input,
      ['cwe_get_hierarchy', query, Math.min(input.limit, 100), result.hierarchyFingerprint],
      snapshot.provenance,
    );
    const endpoints = new Set(
      page.items.flatMap((edge) => [
        `${edge.viewId}:${edge.parentId}`,
        `${edge.viewId}:${edge.childId}`,
      ]),
    );
    const nodes = result.nodes.filter(
      (node) => endpoints.has(`${node.viewId}:${node.id}`) || node.id === id,
    );
    ctx.enrich({ appliedFilters: { ...query, limit: Math.min(input.limit, 100) } });
    ctx.enrich.total(page.pagination.total);
    if (page.pagination.hasMore)
      ctx.enrich.truncated({ shown: page.items.length, cap: Math.min(input.limit, 100) });
    const notice = [page.notice, result.notice].filter(Boolean).join(' ');
    if (notice) ctx.enrich.notice(notice);
    return {
      ...query,
      found: result.found,
      nodes: nodes.map((node) => ({ ...node })),
      edges: page.items.map((edge) => ({ ...edge })),
      pagination: page.pagination,
      retrievedAt: result.retrievedAt,
      hierarchyFingerprint: result.hierarchyFingerprint,
      provenance: snapshot.provenance,
      ...(!result.found
        ? {
            guidance:
              'Call cwe_search_weaknesses to find an existing CWE ID, then repeat cwe_get_hierarchy.',
          }
        : {}),
    };
  },
  format: formatCatalog,
});
