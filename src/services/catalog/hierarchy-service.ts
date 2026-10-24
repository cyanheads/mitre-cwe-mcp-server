/**
 * @fileoverview Bounded live CWE topology acquisition and lifecycle ownership.
 * @module services/catalog/hierarchy-service
 */
import { createHash } from 'node:crypto';
import {
  configurationError,
  JsonRpcErrorCode,
  McpError,
  rateLimited,
  requestCancelled,
  serializationError,
  serviceUnavailable,
  timeout,
} from '@cyanheads/mcp-ts-core/errors';
import {
  httpErrorFromResponse,
  type RequestContext,
  withRetry,
} from '@cyanheads/mcp-ts-core/utils';
import {
  BYTE_LIMITS,
  defaultHttpRequest,
  isRefusal,
  isTransientUpstream,
  readBoundedBody,
  refused,
  SOURCE_URLS,
} from './acquisition.js';
import { systemCatalogClock } from './catalog-service.js';
import type {
  CatalogClock,
  CatalogSnapshot,
  HierarchyDirection,
  HierarchyEdge,
  HierarchyNode,
  HttpRequest,
} from './types.js';
import { collapse } from './xml-normalization.js';

/** Recovery also accompanies baseline upstream failures without changing their codes. */
export const HIERARCHY_RECOVERY =
  'Call cwe_get_weakness with sections ["relations"] for source-recorded relations and cwe_list_reference with topic versions. Recorded relations do not replace live children or descendants; retry cwe_get_hierarchy later.';
/** Acquisition accepts canonical IDs and a captured immutable catalog. */
export interface HierarchyInput {
  direction: HierarchyDirection;
  id: string;
  primaryOnly: boolean;
  viewId: string;
}
/** Complete topology precedes edge paging in the tool. */
export interface HierarchyResult {
  edges: HierarchyEdge[];
  found: boolean;
  hierarchyFingerprint: string;
  nodes: HierarchyNode[];
  notice?: string;
  retrievedAt: string;
}
/** Network and deadline clocks are injectable without replacing normalization. */
export interface HierarchyServiceOptions {
  clock?: CatalogClock;
  request?: HttpRequest;
}
type RawNode = { ID: string; Type: string; ViewID: string; Primary_Parent?: boolean };
type QueueEntry = { start(): void; cancel(): void };

const REFUSAL_RECOVERY =
  'Wait a few minutes, then repeat cwe_get_hierarchy; call cwe_get_weakness for recorded relations meanwhile.';
function invalid(): never {
  throw serviceUnavailable('MITRE returned an inconsistent hierarchy.', {
    reason: 'hierarchy_unavailable',
    retryable: false,
    recovery: { hint: HIERARCHY_RECOVERY },
  });
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
/** Flat rows may omit ViewID; only a single-view children request supplies the missing view. */
function rawNode(value: unknown, fallbackView?: string): RawNode {
  const node = object(value);
  const viewId = node.ViewID ?? fallbackView;
  if (
    typeof node.ID !== 'string' ||
    !/^[1-9]\d*$/.test(node.ID) ||
    typeof viewId !== 'string' ||
    !/^[1-9]\d*$/.test(viewId) ||
    typeof node.Type !== 'string' ||
    !node.Type.trim() ||
    (node.Primary_Parent !== undefined && typeof node.Primary_Parent !== 'boolean')
  )
    invalid();
  // The type renders as a plain value, so it is whitespace-collapsed like catalog text.
  return { ...(node as RawNode), Type: collapse(node.Type), ViewID: viewId };
}
function key(node: Pick<HierarchyNode, 'id' | 'viewId'>): string {
  return `${node.viewId}:${node.id}`;
}
function compare(a: string, b: string): number {
  return a.localeCompare(b, 'en', { numeric: true });
}
function rootType(id: string, snapshot: CatalogSnapshot): string {
  if (snapshot.cwe.views.has(id)) return 'view';
  const weakness = snapshot.cwe.weaknesses.get(id);
  if (!weakness) return 'unknown';
  return weakness.abstraction ? `${weakness.abstraction.toLowerCase()}_weakness` : weakness.type;
}
function record(id: string, snapshot: CatalogSnapshot) {
  return snapshot.cwe.weaknesses.get(id) ?? snapshot.cwe.views.get(id);
}
function hydrate(raw: RawNode, snapshot: CatalogSnapshot): HierarchyNode {
  const id = `CWE-${raw.ID}`;
  const known = record(id, snapshot);
  return {
    id,
    type: raw.Type,
    viewId: `CWE-${raw.ViewID}`,
    ...(known ? { name: known.name, status: known.status, sourceUrl: known.sourceUrl } : {}),
    ...(known && 'abstraction' in known && known.abstraction !== undefined
      ? { abstraction: known.abstraction }
      : {}),
  };
}

/**
 * Validate the full flat/tree response iteratively before returning any topology. Parents
 * arrive unscoped and children in every view arrive as an unscoped descendants tree, so both
 * are validated whole, then projected to the requested view or to the first level.
 */
function normalizeHierarchy(
  value: unknown,
  input: HierarchyInput,
  snapshot: CatalogSnapshot,
): { nodes: HierarchyNode[]; edges: HierarchyEdge[]; drift: boolean } {
  if (!Array.isArray(value)) invalid();
  const nodes = new Map<string, HierarchyNode>();
  const edges = new Map<string, HierarchyEdge>();
  let visited = 0;
  const rootNumber = input.id.slice(4);
  const responseView = input.direction === 'parents' ? 'all' : input.viewId;
  const addNode = (raw: RawNode, sourceNode = true): HierarchyNode => {
    if (sourceNode && ++visited > 10000) invalid();
    const node = hydrate(raw, snapshot);
    if (responseView !== 'all' && responseView !== node.viewId) invalid();
    const existing = nodes.get(key(node));
    if (existing && existing.type !== node.type) invalid();
    nodes.set(key(node), node);
    return node;
  };
  const addEdge = (root: HierarchyNode, relative: HierarchyNode, primary: boolean | undefined) => {
    if (root.viewId !== relative.viewId) invalid();
    // A view can list itself among its members; the root is never its own relative.
    if (root.id === relative.id) return;
    const upward = input.direction === 'parents' || input.direction === 'ancestors';
    const edge: HierarchyEdge = {
      parentId: upward ? relative.id : root.id,
      childId: upward ? root.id : relative.id,
      viewId: root.viewId,
      ...(primary !== undefined ? { primaryParent: primary } : {}),
    };
    const edgeKey = `${edge.viewId}:${edge.parentId}:${edge.childId}`;
    const previous = edges.get(edgeKey);
    if (
      previous?.primaryParent !== undefined &&
      primary !== undefined &&
      previous.primaryParent !== primary
    )
      invalid();
    edges.set(edgeKey, previous?.primaryParent !== undefined ? previous : edge);
  };
  const childrenInEveryView = input.direction === 'children' && input.viewId === 'all';
  if (input.direction === 'parents' || (input.direction === 'children' && !childrenInEveryView)) {
    const fallbackView = input.direction === 'children' ? input.viewId.slice(4) : undefined;
    for (const item of value) {
      const raw = rawNode(item, fallbackView);
      // Skipped before node creation: a locally unknown root's catalog type is `unknown`.
      if (raw.ID === rootNumber) continue;
      const relative = addNode(raw);
      const root = addNode(
        { ID: rootNumber, ViewID: raw.ViewID, Type: rootType(input.id, snapshot) },
        false,
      );
      addEdge(root, relative, raw.Primary_Parent);
    }
  } else {
    const branch = input.direction === 'ancestors' ? 'Parents' : 'Children';
    const stack: { value: unknown; previous?: HierarchyNode; depth: number }[] = value.map(
      (item) => ({ value: item, depth: 0 }),
    );
    while (stack.length) {
      const item = stack.pop();
      if (!item || item.depth > 2000) invalid();
      const tree = object(item.value);
      const raw = rawNode(tree.Data);
      if (!item.previous && raw.ID !== rootNumber) invalid();
      const current = addNode(raw);
      if (item.previous) addEdge(item.previous, current, raw.Primary_Parent);
      const relatives = tree[branch];
      if (relatives !== null && !Array.isArray(relatives)) invalid();
      if (Array.isArray(relatives)) {
        if (stack.length + relatives.length > 10000) invalid();
        for (const relative of relatives)
          stack.push({ value: relative, previous: current, depth: item.depth + 1 });
      }
    }
  }
  let nodeList = [...nodes.values()];
  let edgeList = [...edges.values()];
  if (input.direction === 'parents' && input.viewId !== 'all') {
    edgeList = edgeList.filter((edge) => edge.viewId === input.viewId);
    nodeList = nodeList.filter((node) => node.viewId === input.viewId);
  } else if (childrenInEveryView) {
    edgeList = edgeList.filter((edge) => edge.parentId === input.id);
    const children = new Set(edgeList.map((edge) => `${edge.viewId}:${edge.childId}`));
    nodeList = nodeList.filter((node) => node.id === input.id || children.has(key(node)));
  }
  // Empty direct relationships retain a locally known root in the selected view.
  if (!nodeList.length && input.viewId !== 'all' && record(input.id, snapshot))
    nodeList.push(
      hydrate(
        { ID: rootNumber, ViewID: input.viewId.slice(4), Type: rootType(input.id, snapshot) },
        snapshot,
      ),
    );
  return {
    nodes: nodeList.sort((a, b) => compare(a.viewId, b.viewId) || compare(a.id, b.id)),
    edges: edgeList.sort(
      (a, b) =>
        compare(a.viewId, b.viewId) ||
        compare(a.parentId, b.parentId) ||
        compare(a.childId, b.childId),
    ),
    drift: nodeList.some((node) => !record(node.id, snapshot)),
  };
}

/** Four active traversals and twenty queued callers share owned cancellation. */
export class HierarchyService {
  private readonly request: HttpRequest;
  private readonly clock: CatalogClock;
  private readonly owner = new AbortController();
  private readonly flights = new Set<Promise<HierarchyResult>>();
  private readonly queue: QueueEntry[] = [];
  private active = 0;
  constructor(options: HierarchyServiceOptions = {}) {
    this.request = options.request ?? defaultHttpRequest;
    this.clock = options.clock ?? systemCatalogClock;
  }

  private acquire(signal: AbortSignal): Promise<() => void> {
    signal.throwIfAborted();
    if (this.active >= 4 && this.queue.length >= 20)
      throw rateLimited('The hierarchy request queue is full.', {
        reason: 'queue_full',
        retryable: true,
      });
    return new Promise((resolve, reject) => {
      const entry: QueueEntry = {
        start: () => {
          signal.removeEventListener('abort', entry.cancel);
          this.active++;
          resolve(() => {
            this.active--;
            this.queue.shift()?.start();
          });
        },
        cancel: () => {
          const index = this.queue.indexOf(entry);
          if (index !== -1) this.queue.splice(index, 1);
          signal.removeEventListener('abort', entry.cancel);
          reject(signal.reason);
        },
      };
      if (this.active < 4) entry.start();
      else {
        this.queue.push(entry);
        signal.addEventListener('abort', entry.cancel, { once: true });
      }
    });
  }

  /** Request one complete traversal; queue wait consumes the same total deadline. */
  getHierarchy(
    input: HierarchyInput,
    snapshot: CatalogSnapshot,
    context: RequestContext & { signal?: AbortSignal },
  ): Promise<HierarchyResult> {
    const flight = this.run(input, snapshot, context);
    this.flights.add(flight);
    void flight.then(
      () => this.flights.delete(flight),
      () => this.flights.delete(flight),
    );
    return flight;
  }
  private async run(
    input: HierarchyInput,
    snapshot: CatalogSnapshot,
    context: RequestContext & { signal?: AbortSignal },
  ): Promise<HierarchyResult> {
    const started = this.clock.now();
    const deadline = new AbortController();
    const expire = () =>
      deadline.abort(
        timeout('The hierarchy request exceeded its 25-second budget.', {
          reason: 'hierarchy_timeout',
          retryable: true,
          recovery: { hint: HIERARCHY_RECOVERY },
        }),
      );
    const timer = this.clock.schedule(expire, 25000);
    const signal = AbortSignal.any([
      this.owner.signal,
      deadline.signal,
      ...(context.signal ? [context.signal] : []),
    ]);
    let release: (() => void) | undefined;
    try {
      release = await this.acquire(signal);
      const remainingMs = 25000 - (this.clock.now() - started);
      if (remainingMs <= 0) expire();
      signal.throwIfAborted();
      // Unscoped children rows carry no ViewID, and scoped parents omit category and view parents.
      const path =
        input.direction === 'children' && input.viewId === 'all' ? 'descendants' : input.direction;
      const url = new URL(`${SOURCE_URLS.hierarchy}/${input.id.slice(4)}/${path}`);
      if (input.viewId !== 'all' && input.direction !== 'parents')
        url.searchParams.set('view', input.viewId.slice(4));
      if (input.primaryOnly) url.searchParams.set('primary', 'true');
      return await withRetry(
        async (attempt) => {
          let response: Response;
          try {
            response = await this.request(
              url.href,
              { signal: attempt.signal },
              attempt.remainingMs,
              context,
            );
            if (!response.ok) {
              const cause = await httpErrorFromResponse(response, {
                service: 'MITRE',
                captureBody: false,
              });
              await response.body?.cancel();
              throw cause;
            }
          } catch (cause) {
            if (isRefusal(cause)) throw refused('hierarchy request', REFUSAL_RECOVERY);
            if (cause instanceof McpError && cause.code === JsonRpcErrorCode.NotFound) {
              if (snapshot.cwe.weaknesses.has(input.id) || snapshot.cwe.views.has(input.id))
                invalid();
              return this.result(false, [], [], snapshot);
            }
            throw cause;
          }
          const bytes = await readBoundedBody(response, BYTE_LIMITS.hierarchy, attempt.signal);
          const body = new TextDecoder().decode(bytes);
          if (/^\s*<(?:!doctype\s+html|html[\s>])/i.test(body))
            throw serviceUnavailable('MITRE returned HTML instead of hierarchy JSON.', {
              retryable: true,
            });
          let parsed: unknown;
          try {
            parsed = JSON.parse(body);
          } catch (cause) {
            throw serializationError(
              'MITRE returned invalid hierarchy JSON.',
              { retryable: false },
              { cause },
            );
          }
          const normalized = normalizeHierarchy(parsed, input, snapshot);
          attempt.signal.throwIfAborted();
          return {
            ...this.result(true, normalized.nodes, normalized.edges, snapshot),
            ...(normalized.drift
              ? {
                  notice:
                    'The live hierarchy contains IDs absent from the loaded catalog. Call cwe_list_reference with topic versions to inspect source drift.',
                }
              : {}),
          };
        },
        {
          maxRetries: 2,
          baseDelayMs: 1000,
          deadlineMs: remainingMs,
          operation: 'cweHierarchy',
          context,
          signal,
          isTransient: isTransientUpstream,
        },
      );
    } catch (cause) {
      const error = signal.aborted ? signal.reason : cause;
      if (error instanceof McpError && error.data?.reason === 'queue_full') throw error;
      if (error instanceof McpError)
        throw new McpError(
          error.code,
          error.message,
          { ...error.data, recovery: error.data?.recovery ?? { hint: HIERARCHY_RECOVERY } },
          { cause: error },
        );
      if (signal.aborted)
        throw requestCancelled(
          'The hierarchy request was cancelled.',
          { retryable: false, recovery: { hint: HIERARCHY_RECOVERY } },
          { cause: error },
        );
      throw serviceUnavailable(
        'MITRE could not be reached.',
        { retryable: true, recovery: { hint: HIERARCHY_RECOVERY } },
        { cause: error },
      );
    } finally {
      timer.cancel();
      release?.();
    }
  }
  private result(
    found: boolean,
    nodes: HierarchyNode[],
    edges: HierarchyEdge[],
    snapshot: CatalogSnapshot,
  ): HierarchyResult {
    return {
      found,
      nodes,
      edges,
      retrievedAt: new Date(this.clock.now()).toISOString(),
      hierarchyFingerprint: createHash('sha256')
        // Node keys cover roots without edges, which only the first page carries.
        .update(JSON.stringify([snapshot.cwe.version, edges, nodes.map(key)]))
        .digest('hex'),
    };
  }
  /** Abort queued and active calls, then await owned requests. */
  async dispose(): Promise<void> {
    this.owner.abort(
      requestCancelled('The hierarchy service is shutting down.', { retryable: false }),
    );
    await Promise.allSettled(this.flights);
  }
}
let service: HierarchyService | undefined;
/** Initialize the runtime or inject a fixture HTTP adapter for contract tests. */
export function initHierarchyService(options: HierarchyServiceOptions = {}): HierarchyService {
  if (service) throw configurationError('The hierarchy service is already initialized.');
  service = new HierarchyService(options);
  return service;
}
/** Retrieve the initialized live hierarchy boundary. */
export function getHierarchyService(): HierarchyService {
  if (!service) throw configurationError('The hierarchy service is not initialized.');
  return service;
}
/** Release hierarchy ownership during application teardown. */
export async function disposeHierarchyService(): Promise<void> {
  const current = service;
  service = undefined;
  await current?.dispose();
}
