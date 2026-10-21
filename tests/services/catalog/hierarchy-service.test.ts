/**
 * @fileoverview Live hierarchy normalization, bounded acquisition and ownership tests.
 * @module tests/services/catalog/hierarchy-service.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildCatalogSnapshot } from '@/services/catalog/catalog-index.js';
import {
  HIERARCHY_RECOVERY,
  type HierarchyInput,
  HierarchyService,
} from '@/services/catalog/hierarchy-service.js';
import type {
  CatalogClock,
  CatalogHealth,
  HttpRequest,
  Weakness,
} from '@/services/catalog/types.js';

const clock: CatalogClock = {
  now: () => Date.now(),
  schedule: (callback, delay) => {
    const timer = setTimeout(callback, delay);
    return { cancel: () => clearTimeout(timer) };
  },
};
const input: HierarchyInput = {
  id: 'CWE-1',
  direction: 'children',
  viewId: 'CWE-1000',
  primaryOnly: false,
};
const raw = (id: number, view = 1000, primary?: boolean) => ({
  ID: String(id),
  Type: 'base_weakness',
  ViewID: String(view),
  ...(primary !== undefined ? { Primary_Parent: primary } : {}),
});
function snapshot() {
  const health: CatalogHealth = {
    version: 'test',
    date: '2026-10-20',
    counts: {},
    loadedAt: '2026-10-20T00:00:00Z',
    nextCheckAt: '2026-10-21T00:00:00Z',
    sourceUrl: 'https://example.test',
  };
  const entries: Weakness[] = [1, 2, 3, 4].map((id) => ({
    id: `CWE-${id}`,
    name: `Name ${id}`,
    description: '',
    status: 'Stable',
    abstraction: 'Base',
    type: 'weakness',
    sourceUrl: `https://cwe.mitre.org/data/definitions/${id}.html`,
  }));
  return buildCatalogSnapshot(
    {
      version: '4.test',
      date: health.date,
      weaknesses: new Map(entries.map((row) => [row.id, row])),
      views: new Map(),
    },
    { version: '3.test', date: health.date, attackPatterns: new Map() },
    { cwe: health, capec: health },
    health.loadedAt,
  );
}
const services: HierarchyService[] = [];
function service(request: HttpRequest) {
  const result = new HierarchyService({ request, clock });
  services.push(result);
  return result;
}
const run = (body: unknown, query: Partial<HierarchyInput> = {}) =>
  service(async () => Response.json(body)).getHierarchy(
    { ...input, ...query },
    snapshot(),
    createMockContext(),
  );
afterEach(async () => {
  await Promise.all(services.splice(0).map((item) => item.dispose()));
  vi.useRealTimers();
});

describe('live hierarchy topology', () => {
  it('deduplicates flat edges, keeps multiview primary flags and hydrates only known records', async () => {
    const result = await run(
      [raw(2, 1000, false), raw(2, 1000, false), raw(2, 1001, true), raw(99)],
      { viewId: 'all' },
    );
    expect(result.edges).toEqual([
      { parentId: 'CWE-1', childId: 'CWE-2', viewId: 'CWE-1000', primaryParent: false },
      { parentId: 'CWE-1', childId: 'CWE-99', viewId: 'CWE-1000' },
      { parentId: 'CWE-1', childId: 'CWE-2', viewId: 'CWE-1001', primaryParent: true },
    ]);
    expect(result.nodes.find((row) => row.id === 'CWE-2')).toMatchObject({
      name: 'Name 2',
      status: 'Stable',
      abstraction: 'Base',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/2.html',
    });
    expect(result.nodes.find((row) => row.id === 'CWE-99')).toEqual({
      id: 'CWE-99',
      type: 'base_weakness',
      viewId: 'CWE-1000',
    });
    expect(result.notice).toContain('source drift');
  });

  it.each(['ancestors', 'descendants'] as const)(
    'preserves depth and multiple parents for %s without a root self edge',
    async (direction) => {
      const branch = direction === 'ancestors' ? 'Parents' : 'Children';
      const leaf = (id: number) => ({ Data: raw(id), [branch]: null });
      const result = await run(
        [
          {
            Data: raw(1),
            [branch]: [
              { Data: raw(2, 1000, true), [branch]: [leaf(4)] },
              { Data: raw(3, 1000, false), [branch]: [leaf(4)] },
            ],
          },
        ],
        { direction },
      );
      expect(result.nodes.map((row) => row.id)).toEqual(['CWE-1', 'CWE-2', 'CWE-3', 'CWE-4']);
      expect(result.edges).toHaveLength(4);
      expect(result.edges.every((edge) => edge.parentId !== edge.childId)).toBe(true);
      expect(result.edges).toContainEqual(
        direction === 'ancestors'
          ? { parentId: 'CWE-4', childId: 'CWE-2', viewId: 'CWE-1000' }
          : { parentId: 'CWE-2', childId: 'CWE-4', viewId: 'CWE-1000' },
      );
    },
  );

  it('requests only verified query parameters and orients direct parents', async () => {
    const request = vi.fn<HttpRequest>(async () => Response.json([raw(2, 1000, true)]));
    const result = await service(request).getHierarchy(
      { ...input, direction: 'parents' },
      snapshot(),
      createMockContext(),
    );
    expect(request.mock.calls[0]?.[0]).toBe(
      'https://cwe-api.mitre.org/api/v1/cwe/1/parents?view=1000',
    );
    expect(result.edges).toEqual([
      { parentId: 'CWE-2', childId: 'CWE-1', viewId: 'CWE-1000', primaryParent: true },
    ]);
    await service(request)
      .getHierarchy(
        { ...input, direction: 'ancestors', viewId: 'all', primaryOnly: true },
        snapshot(),
        createMockContext(),
      )
      .catch(() => undefined);
    expect(request.mock.calls[1]?.[0]).toBe(
      'https://cwe-api.mitre.org/api/v1/cwe/1/ancestors?primary=true',
    );
  });

  it('distinguishes empty relations from an unknown live root and a known-root 404', async () => {
    expect(await run([])).toMatchObject({ found: true, edges: [], nodes: [{ id: 'CWE-1' }] });
    const missing = service(async () => new Response(null, { status: 404 }));
    expect(
      await missing.getHierarchy({ ...input, id: 'CWE-999' }, snapshot(), createMockContext()),
    ).toMatchObject({ found: false, nodes: [], edges: [] });
    await expect(
      missing.getHierarchy(input, snapshot(), createMockContext()),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: { reason: 'hierarchy_unavailable', recovery: { hint: HIERARCHY_RECOVERY } },
    });
  });

  it('does not invent a base abstraction for a sparse known root', async () => {
    const data = snapshot();
    const root = data.cwe.weaknesses.get('CWE-1')!;
    const { abstraction: _abstraction, ...sparse } = root;
    const modified = { ...data, cwe: { ...data.cwe, weaknesses: new Map([['CWE-1', sparse]]) } };
    const result = await service(async () => Response.json([raw(2)])).getHierarchy(
      input,
      modified,
      createMockContext(),
    );
    expect(result.nodes.find((node) => node.id === 'CWE-1')).toMatchObject({ type: 'weakness' });
    expect(result.nodes.find((node) => node.id === 'CWE-1')).not.toHaveProperty('abstraction');
  });

  it.each([
    null,
    {},
    [null],
    [{ ...raw(2), ID: 2 }],
    [{ ...raw(2), ID: '0' }],
    [{ ...raw(2), ViewID: '0' }],
    [{ ...raw(2), Type: '' }],
    [{ ...raw(2), Primary_Parent: 'true' }],
    [raw(2, 1001)],
    [raw(1)],
    [raw(2, 1000, true), raw(2, 1000, false)],
    [raw(2), { ...raw(2), Type: 'category' }],
  ])('rejects inconsistent flat response %# without partial topology', async (body) => {
    await expect(run(body)).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: { reason: 'hierarchy_unavailable', retryable: false },
    });
  });

  it.each([
    [{ Data: raw(2), Children: null }],
    [{ Data: raw(1) }],
    [{ Data: raw(1), Children: {} }],
    [{ Data: raw(1), Children: [{ Data: raw(2, 1001), Children: null }] }],
  ])('validates the entire recursive response %#', async (body) => {
    await expect(run(body, { direction: 'descendants' })).rejects.toMatchObject({
      data: { reason: 'hierarchy_unavailable' },
    });
  });

  it('accepts 10000 source nodes and rejects the next one', async () => {
    const rows = Array.from({ length: 10000 }, (_, index) => raw(index + 2));
    expect((await run(rows)).edges).toHaveLength(10000);
    await expect(run([...rows, raw(10002)])).rejects.toMatchObject({
      data: { reason: 'hierarchy_unavailable' },
    });
  });

  it('accepts depth 2000 and rejects 2001 without recursive normalization', async () => {
    const chain = (depth: number): string => {
      let body = 'null';
      for (let id = depth + 1; id >= 1; id--)
        body = `[{"Data":${JSON.stringify(raw(id))},"Children":${body}}]`;
      return body;
    };
    const request: HttpRequest = async () => new Response(chain(2000));
    expect(
      (
        await service(request).getHierarchy(
          { ...input, direction: 'descendants' },
          snapshot(),
          createMockContext(),
        )
      ).edges,
    ).toHaveLength(2000);
    await expect(
      service(async () => new Response(chain(2001))).getHierarchy(
        { ...input, direction: 'descendants' },
        snapshot(),
        createMockContext(),
      ),
    ).rejects.toMatchObject({ data: { reason: 'hierarchy_unavailable' } });
  });

  it('bounds streamed and declared bodies at 10 MiB and preserves serialization errors', async () => {
    expect(
      await service(async () => new Response('[]' + ' '.repeat(10 * 1024 * 1024 - 2))).getHierarchy(
        input,
        snapshot(),
        createMockContext(),
      ),
    ).toMatchObject({ found: true, edges: [] });
    for (const response of [
      new Response(' '.repeat(10 * 1024 * 1024 + 1)),
      new Response('[]', { headers: { 'content-length': String(10 * 1024 * 1024 + 1) } }),
    ]) {
      await expect(
        service(async () => response).getHierarchy(input, snapshot(), createMockContext()),
      ).rejects.toMatchObject({ data: { recovery: { hint: HIERARCHY_RECOVERY } } });
    }
    await expect(
      service(async () => new Response('{')).getHierarchy(input, snapshot(), createMockContext()),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.SerializationError,
      data: { recovery: { hint: HIERARCHY_RECOVERY } },
    });
  });
});

describe('hierarchy request ownership', () => {
  it('retries transient responses and preserves exhausted mapped codes with recovery', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const request: HttpRequest = async () =>
      ++calls < 3 ? new Response(null, { status: 503 }) : Response.json([]);
    const success = service(request).getHierarchy(input, snapshot(), createMockContext());
    await vi.runAllTimersAsync();
    expect(await success).toMatchObject({ found: true });
    expect(calls).toBe(3);
    const failure = service(async () => new Response(null, { status: 429 })).getHierarchy(
      input,
      snapshot(),
      createMockContext(),
    );
    const check = expect(failure).rejects.toMatchObject({
      code: JsonRpcErrorCode.RateLimited,
      data: { recovery: { hint: HIERARCHY_RECOVERY } },
    });
    await vi.runAllTimersAsync();
    await check;
  });

  it('retries an HTML gateway response but never retries malformed JSON or schema data', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const html = service(async () =>
      ++calls === 1 ? new Response('<!doctype html><html>Gateway</html>') : Response.json([]),
    );
    const result = html.getHierarchy(input, snapshot(), createMockContext());
    await vi.runAllTimersAsync();
    expect(await result).toMatchObject({ found: true });
    expect(calls).toBe(2);
    for (const body of ['{', '{}']) {
      const request = vi.fn<HttpRequest>(async () => new Response(body));
      const rejected = service(request).getHierarchy(input, snapshot(), createMockContext());
      await expect(rejected).rejects.toMatchObject({
        data: { retryable: false, recovery: { hint: HIERARCHY_RECOVERY } },
      });
      expect(request).toHaveBeenCalledTimes(1);
    }
  });

  it('retains a terminal HTTP authorization error and its recovery without relabeling it', async () => {
    const request = vi.fn<HttpRequest>(async () => new Response(null, { status: 403 }));
    await expect(
      service(request).getHierarchy(input, snapshot(), createMockContext()),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
      data: { recovery: { hint: HIERARCHY_RECOVERY } },
    });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('starts the next queued caller when an active request completes', async () => {
    const resolvers: ((response: Response) => void)[] = [];
    const request = vi.fn<HttpRequest>(
      async (_url, options) =>
        new Promise((resolve, reject) => {
          resolvers.push(resolve);
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          });
        }),
    );
    const live = service(request);
    const results = Array.from({ length: 5 }, () =>
      live.getHierarchy(input, snapshot(), createMockContext()).catch((error) => error),
    );
    await Promise.resolve();
    await Promise.resolve();
    expect(request).toHaveBeenCalledTimes(4);
    resolvers[0]!(Response.json([]));
    expect(await results[0]).toMatchObject({ found: true });
    expect(request).toHaveBeenCalledTimes(5);
    await live.dispose();
    await Promise.all(results);
  });

  it('allows four active and twenty queued calls, rejects overflow and disposes every owner', async () => {
    vi.useFakeTimers();
    let active = 0;
    const request: HttpRequest = async (_url, options) => {
      active++;
      return new Promise((_resolve, reject) =>
        options.signal.addEventListener(
          'abort',
          () => {
            active--;
            reject(options.signal.reason);
          },
          { once: true },
        ),
      );
    };
    const live = service(request);
    const outcomes = Array.from({ length: 24 }, () =>
      live.getHierarchy(input, snapshot(), createMockContext()).catch((error) => error),
    );
    await Promise.resolve();
    await Promise.resolve();
    expect(active).toBe(4);
    await expect(live.getHierarchy(input, snapshot(), createMockContext())).rejects.toMatchObject({
      code: JsonRpcErrorCode.RateLimited,
      data: { reason: 'queue_full' },
    });
    await live.dispose();
    expect(active).toBe(0);
    for (const result of await Promise.all(outcomes))
      expect(result).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
  });

  it('removes an aborted queued caller without sending it upstream and cancels active callers', async () => {
    const request = vi.fn<HttpRequest>(
      async (_url, options) =>
        new Promise((_resolve, reject) =>
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          }),
        ),
    );
    const live = service(request);
    const activeController = new AbortController();
    const running = live
      .getHierarchy(input, snapshot(), createMockContext({ signal: activeController.signal }))
      .catch((error) => error);
    const blockers = Array.from({ length: 3 }, () =>
      live.getHierarchy(input, snapshot(), createMockContext()).catch((error) => error),
    );
    const controller = new AbortController();
    const queued = live
      .getHierarchy(input, snapshot(), createMockContext({ signal: controller.signal }))
      .catch((error) => error);
    await Promise.resolve();
    await Promise.resolve();
    controller.abort();
    expect(await queued).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    expect(request).toHaveBeenCalledTimes(4);
    activeController.abort();
    expect(await running).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    await live.dispose();
    await Promise.all(blockers);
    expect(request).toHaveBeenCalledTimes(4);
  });

  it('counts queue wait toward the same 25-second deadline', async () => {
    vi.useFakeTimers();
    const request = vi.fn<HttpRequest>(
      async (_url, options) =>
        new Promise((_resolve, reject) =>
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          }),
        ),
    );
    const live = service(request);
    const pending = Array.from({ length: 5 }, () =>
      live.getHierarchy(input, snapshot(), createMockContext()).catch((error) => error),
    );
    await vi.advanceTimersByTimeAsync(25000);
    for (const result of await Promise.all(pending))
      expect(result).toMatchObject({
        code: JsonRpcErrorCode.Timeout,
        data: { recovery: { hint: HIERARCHY_RECOVERY } },
      });
    expect(request).toHaveBeenCalledTimes(4);
  });
});
