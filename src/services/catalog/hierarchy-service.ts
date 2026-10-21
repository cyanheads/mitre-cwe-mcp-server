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
import { BYTE_LIMITS, defaultHttpRequest, readBoundedBody, SOURCE_URLS } from './acquisition.js';
import { systemCatalogClock } from './catalog-service.js';
import type {
  CatalogClock,
  CatalogSnapshot,
  HierarchyDirection,
  HierarchyEdge,
  HierarchyNode,
  HttpRequest,
} from './types.js';

/** Recovery also accompanies baseline upstream failures without changing their codes. */
export const HIERARCHY_RECOVERY =
  'Call cwe_get_weakness for recorded relations and cwe_list_reference with topic versions; retry cwe_get_hierarchy later.';
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
function rawNode(value: unknown): RawNode {
  const node = object(value);
  if (
    typeof node.ID !== 'string' ||
    !/^[1-9]\d*$/.test(node.ID) ||
    typeof node.ViewID !== 'string' ||
    !/^[1-9]\d*$/.test(node.ViewID) ||
    typeof node.Type !== 'string' ||
    !node.Type.trim() ||
    (node.Primary_Parent !== undefined && typeof node.Primary_Parent !== 'boolean')
  )
    invalid();
  return node as RawNode;
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

/** Validate the full flat/tree response iteratively before returning any topology. */
export function normalizeHierarchy(
  value: unknown,
  input: HierarchyInput,
  snapshot: CatalogSnapshot,
): { nodes: HierarchyNode[]; edges: HierarchyEdge[]; drift: boolean } {
  if (!Array.isArray(value)) invalid();
  const nodes = new Map<string, HierarchyNode>();
  const edges = new Map<string, HierarchyEdge>();
  let visited = 0;
  let drift = false;
  const rootNumber = input.id.slice(4);
  const addNode = (raw: RawNode, sourceNode = true): HierarchyNode => {
    if (sourceNode && ++visited > 10000) invalid();
    const id = `CWE-${raw.ID}`;
    const viewId = `CWE-${raw.ViewID}`;
    if (input.viewId !== 'all' && input.viewId !== viewId) invalid();
    const existing = nodes.get(`${viewId}:${id}`);
    if (existing && existing.type !== raw.Type) invalid();
    const record = snapshot.cwe.weaknesses.get(id) ?? snapshot.cwe.views.get(id);
    if (!record) drift = true;
    const node: HierarchyNode = {
      id,
      type: raw.Type,
      viewId,
      ...(record ? { name: record.name, status: record.status, sourceUrl: record.sourceUrl } : {}),
      ...(record && 'abstraction' in record && record.abstraction !== undefined
        ? { abstraction: record.abstraction }
        : {}),
    };
    nodes.set(key(node), node);
    return node;
  };
  const addEdge = (root: HierarchyNode, relative: HierarchyNode, primary: boolean | undefined) => {
    if (root.viewId !== relative.viewId || root.id === relative.id) invalid();
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
  if (input.direction === 'parents' || input.direction === 'children') {
    for (const item of value) {
      const raw = rawNode(item);
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
  // Empty direct relationships retain a locally known root in the selected view.
  if (!nodes.size && input.viewId !== 'all') {
    const record = snapshot.cwe.weaknesses.get(input.id) ?? snapshot.cwe.views.get(input.id);
    if (record)
      addNode(
        { ID: rootNumber, ViewID: input.viewId.slice(4), Type: rootType(input.id, snapshot) },
        false,
      );
  }
  return {
    nodes: [...nodes.values()].sort((a, b) => compare(a.viewId, b.viewId) || compare(a.id, b.id)),
    edges: [...edges.values()].sort(
      (a, b) =>
        compare(a.viewId, b.viewId) ||
        compare(a.parentId, b.parentId) ||
        compare(a.childId, b.childId),
    ),
    drift,
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
          retryable: false,
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
      const url = new URL(`${SOURCE_URLS.hierarchy}/${input.id.slice(4)}/${input.direction}`);
      if (input.viewId !== 'all') url.searchParams.set('view', input.viewId.slice(4));
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
        },
      );
    } catch (cause) {
      const error = signal.aborted ? signal.reason : cause;
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
        .update(JSON.stringify([snapshot.cwe.version, edges]))
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
