/**
 * @fileoverview Retrieve and page live view-scoped CWE topology.
 * @module mcp-server/tools/definitions/cwe-get-hierarchy.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  getCatalogService,
  getHierarchyService,
  HIERARCHY_RECOVERY,
  nonViewSentence,
} from '@/services/index.js';
import {
  CWE_ID,
  CWE_ID_FORMS,
  catalogEnrichmentTrailer,
  formatCatalog,
  inputEnum,
  list,
  normalizeId,
  pageResponse,
  paginationSchema,
  pagingShape,
  provenanceSchema,
  text,
  VIEW_ID,
} from '../shared.js';

/** Live edges retain multiple parents and independent view topology. */
export const cweGetHierarchy = tool('cwe_get_hierarchy', {
  title: 'Get CWE hierarchy',
  description:
    'Navigate live CWE parents, children, ancestors, or descendants for a weakness, category, or view. Discover IDs with cwe_search_weaknesses or cwe_list_reference topic views. The default view is 1000; set viewId all for every view. primaryOnly applies only to ancestors. Edges point from parent to child and retain view identity; follow nextCursor for more edges. Continuations re-fetch the traversal and reject changed topology. Empty relations are successful; upstream failures remain errors. Node names come from the loaded catalog and may lag live IDs.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    id: z
      .string()
      .regex(CWE_ID, CWE_ID_FORMS)
      .describe('CWE ID such as CWE-79 or 79, for a weakness, category, or view.'),
    direction: inputEnum(['parents', 'children', 'ancestors', 'descendants']).describe(
      'Live hierarchy direction.',
    ),
    viewId: z
      .preprocess(
        (value) => (typeof value === 'string' && !value.trim() ? undefined : value),
        z
          .string()
          .regex(
            VIEW_ID,
            'Use a CWE view ID or all: a positive integer, optionally after CWE and a -, _, or space, such as CWE-1000 or 1000.',
          )
          .default('1000'),
      )
      .describe(
        'CWE view ID such as CWE-1000 or 1000, or all; discover with cwe_list_reference topic views. Blank means the default.',
      ),
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
            'Upstream type. Roots the server adds (parents, single-view children, or an empty single-view result) use the catalog type, or unknown when unavailable.',
          ),
          viewId: text('Topology view ID.'),
          name: text('Loaded catalog name.').optional(),
          abstraction: text('Loaded abstraction.').optional(),
          status: text('Loaded status.').optional(),
          sourceUrl: text('Official catalog URL.').optional(),
        })
        .describe('Endpoint of an edge on this page, or a root without edges on the first page.'),
      "Endpoint nodes of this page's edges; the first page also lists roots without edges.",
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
  enrichmentTrailer: catalogEnrichmentTrailer,
  errors: [
    {
      reason: 'invalid_hierarchy_options',
      code: JsonRpcErrorCode.ValidationError,
      when: 'viewId names no CWE view, or primaryOnly is true outside ancestors; the message names each.',
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
      when: 'The live hierarchy service has no available request slot.',
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
    const id = normalizeId(input.id);
    const viewId = input.viewId.trim().toLowerCase() === 'all' ? 'all' : normalizeId(input.viewId);
    // One sentence per failed condition, so the caller fixes every one in a single retry.
    const problems = [
      viewId !== 'all' && !snapshot.cwe.views.has(viewId) && nonViewSentence(snapshot, viewId),
      input.primaryOnly &&
        input.direction !== 'ancestors' &&
        `primaryOnly applies only to direction ancestors; received direction ${input.direction}.`,
    ].filter(Boolean);
    if (problems.length) throw ctx.fail('invalid_hierarchy_options', problems.join(' '));
    const query = { id, direction: input.direction, viewId, primaryOnly: input.primaryOnly };
    const result = await getHierarchyService().getHierarchy(query, snapshot, ctx);
    const endpoints = (edges: typeof result.edges) =>
      new Set(
        edges.flatMap((edge) => [
          `${edge.viewId}:${edge.parentId}`,
          `${edge.viewId}:${edge.childId}`,
        ]),
      );
    // A root without edges in a view still shows the traversal covers that view; send it once.
    const traversed = endpoints(result.edges);
    const edgeless = new Set(
      result.nodes.filter((node) => !traversed.has(`${node.viewId}:${node.id}`)),
    );
    const { output, enrichment } = pageResponse(result.edges, input, {
      binding: ['cwe_get_hierarchy', query, result.hierarchyFingerprint],
      provenance: snapshot.provenance,
      appliedFilters: query,
      notice: result.notice,
      output: (page) => {
        const needed = endpoints(page.items);
        // Pages are slices of result.edges, so this also holds for an empty traversal.
        const firstPage = page.items[0] === result.edges[0];
        const nodes = result.nodes.filter(
          (node) => needed.has(`${node.viewId}:${node.id}`) || (firstPage && edgeless.has(node)),
        );
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
    });
    ctx.enrich(enrichment);
    return output;
  },
  format: formatCatalog,
});
