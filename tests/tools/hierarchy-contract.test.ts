/**
 * @fileoverview Live hierarchy contracts through real catalog acquisition and both output surfaces.
 * @module tests/tools/hierarchy-contract.test
 */
import { readFileSync } from 'node:fs';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cweGetHierarchy } from '@/mcp-server/tools/definitions/cwe-get-hierarchy.tool.js';
import {
  type CatalogClock,
  disposeCatalogService,
  disposeHierarchyService,
  type HttpRequest,
  initCatalogService,
  initHierarchyService,
  SOURCE_URLS,
} from '@/services/index.js';
import { parseMarkdown } from '../helpers/commonmark.js';

const clock: CatalogClock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
const raw = (id: number, view = 1000) => ({
  ID: String(id),
  Type: 'base_weakness',
  ViewID: String(view),
});
let body: unknown;
let status: number;
const urls: string[] = [];
async function load(version = '4.hierarchy') {
  const rows = Array.from(
    { length: 110 },
    (_, index) =>
      `<Weakness ID="${index + 1}" Name="Known ${index + 1}" Status="Stable" Abstraction="Base"><Description>Record.</Description></Weakness>`,
  ).join('');
  const cwe = `<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="${version}" Date="2026-04-30"><Weaknesses>${rows}</Weaknesses><Categories><Category ID="900" Name="Group" Status="Stable"><Summary>Group.</Summary></Category></Categories><Views><View ID="1000" Name="Navigation" Type="Graph" Status="Stable"><Members/></View><View ID="1001" Name="Alternate" Type="Graph" Status="Stable"><Members/></View></Views></Weakness_Catalog>`;
  const capec =
    '<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.hierarchy" Date="2023-01-24"><Attack_Patterns><Attack_Pattern ID="1" Name="Pattern" Status="Stable" Abstraction="Standard"><Description>Record.</Description></Attack_Pattern></Attack_Patterns></Attack_Pattern_Catalog>';
  const request: HttpRequest = async (url) => {
    if (url === SOURCE_URLS.cwe) return new Response(zipSync({ 'cwe.xml': strToU8(cwe) }));
    if (url === SOURCE_URLS.capec) return new Response(capec);
    throw new Error(`Unexpected catalog request ${url}`);
  };
  await initCatalogService({ request, clock, context: createMockContext() });
}
const call = (args: Record<string, unknown> = {}) =>
  runToolContract(cweGetHierarchy, { id: '1', direction: 'children', ...args });
/** Real CWE REST API bodies captured for CWE 4.20. */
const fixture = <T = unknown>(name: string): T =>
  JSON.parse(readFileSync(new URL(`../fixtures/hierarchy/${name}.json`, import.meta.url), 'utf8'));
type Tree = { Data: { ViewID: string }; Parents: Tree[] | null };
type Page = {
  nodes: { id: string; viewId: string }[];
  edges: { parentId: string; childId: string; viewId: string }[];
  pagination: { total: number; nextCursor?: string };
};
type Wire = Awaited<ReturnType<typeof call>>;
/** Every rendered `content[]` line, as a client that forwards the text sees it. */
const lines = (wire: Wire) =>
  wire.content.flatMap((block) => (block.type === 'text' ? block.text.split('\n') : []));
/** An edge as `content[]` renders it: fields no node record carries, so only the edge supplies them. */
const edgeText = (edge: { parentId: string; childId: string; viewId: string }) =>
  `**parentId**\n\n> ${edge.parentId}\n\n**childId**\n\n> ${edge.childId}\n\n**viewId**\n\n> ${edge.viewId}`;
/** Follow every continuation, keeping both surfaces of each page. */
async function walk(args: Record<string, unknown>) {
  const pages: { data: Page; content: string }[] = [];
  let cursor: string | undefined;
  do {
    const wire = await call(cursor ? { ...args, cursor } : args);
    expect(wire.isError).not.toBe(true);
    const data = wire.structuredContent as Page;
    pages.push({ data, content: lines(wire).join('\n') });
    cursor = data.pagination.nextCursor;
  } while (cursor && pages.length < 50);
  return pages;
}
const keys = (page: Page) => page.nodes.map((node) => `${node.viewId}:${node.id}`);
const endpoints = (page: Page) =>
  new Set(
    page.edges.flatMap((edge) => [
      `${edge.viewId}:${edge.parentId}`,
      `${edge.viewId}:${edge.childId}`,
    ]),
  );
beforeEach(async () => {
  body = Array.from({ length: 105 }, (_, index) => raw(index + 2));
  status = 200;
  urls.length = 0;
  await load();
  initHierarchyService({
    clock,
    request: async (url) => {
      urls.push(url);
      return status === 200 ? Response.json(body) : new Response(null, { status });
    },
  });
});
afterEach(async () => {
  vi.unstubAllGlobals();
  await disposeHierarchyService();
  await disposeCatalogService();
});

describe('cwe_get_hierarchy public contracts', () => {
  it('reports owned active and queued deadline expiry as retryable hierarchy_timeout on both surfaces', async () => {
    await disposeHierarchyService();
    const expirations: (() => void)[] = [];
    let requests = 0;
    initHierarchyService({
      clock: {
        now: () => 0,
        schedule: (callback) => {
          expirations.push(callback);
          return { cancel() {} };
        },
      },
      request: async (_url, options) =>
        new Promise((_resolve, reject) => {
          requests++;
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          });
        }),
    });
    const pending = Array.from({ length: 5 }, () => call({ direction: 'descendants' }));
    await Promise.resolve();
    await Promise.resolve();
    expect(requests).toBe(4);
    expect(expirations).toHaveLength(5);
    // Expire the queued caller first: it must never reach the request adapter.
    expirations[4]!();
    for (const expire of expirations.slice(0, 4)) expire();
    for (const wire of await Promise.all(pending)) {
      expect(wire.structuredContent).toMatchObject({
        error: {
          code: JsonRpcErrorCode.Timeout,
          data: {
            reason: 'hierarchy_timeout',
            retryable: true,
            recovery: {
              hint: 'Call cwe_get_weakness with sections ["relations"] for source-recorded relations and cwe_list_reference with topic versions. Recorded relations do not replace live children or descendants; retry cwe_get_hierarchy later.',
            },
          },
        },
      });
      for (const surface of [wire.content, wire.structuredContent]) {
        expect(JSON.stringify(surface)).toContain('hierarchy_timeout');
        expect(JSON.stringify(surface)).toContain(
          'Recorded relations do not replace live children or descendants',
        );
      }
      expect(parseMarkdown(lines(wire).join('\n')).text).toContain(
        'Call cwe_get_weakness with sections ["relations"] for source-recorded relations and cwe_list_reference with topic versions. Recorded relations do not replace live children or descendants; retry cwe_get_hierarchy later.',
      );
    }
    expect(requests).toBe(4);
  });

  it('keeps caller cancellation distinct from owned expiry on both surfaces', async () => {
    await disposeHierarchyService();
    let started!: () => void;
    const ready = new Promise<void>((resolve) => {
      started = resolve;
    });
    initHierarchyService({
      clock,
      request: async (_url, options) => {
        started();
        return new Promise((_resolve, reject) =>
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          }),
        );
      },
    });
    const controller = new AbortController();
    const pending = runToolContract(
      cweGetHierarchy,
      { id: '1', direction: 'descendants' },
      { context: { signal: controller.signal } },
    );
    await ready;
    controller.abort();
    const wire = await pending;
    expect(wire.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.RequestCancelled,
        message: 'The hierarchy request was cancelled.',
        data: { retryable: false },
      },
    });
    for (const surface of [wire.content, wire.structuredContent]) {
      expect(JSON.stringify(surface)).toContain('The hierarchy request was cancelled.');
      expect(JSON.stringify(surface)).not.toContain('hierarchy_timeout');
    }
    expect(lines(wire).join('\n')).toContain('not retryable');
  });
  it('normalizes IDs and case, applies view 1000 defaults and renders complete endpoint records', async () => {
    body = [raw(2)];
    const wire = await call({ id: ' cwe-0001 ', direction: ' CHILDREN ' });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      id: 'CWE-1',
      viewId: 'CWE-1000',
      direction: 'children',
      primaryOnly: false,
      appliedFilters: { limit: 20 },
      nodes: [
        { id: 'CWE-1', name: 'Known 1' },
        { id: 'CWE-2', name: 'Known 2' },
      ],
      edges: [{ parentId: 'CWE-1', childId: 'CWE-2', viewId: 'CWE-1000' }],
      provenance: { cweVersion: '4.hierarchy' },
    });
    const rendered = JSON.stringify(wire.content);
    for (const value of [
      'Known 1',
      'Known 2',
      'parentId',
      'childId',
      'viewId',
      'hierarchyFingerprint',
      'retrievedAt',
      'provenance',
    ])
      expect(rendered).toContain(value);
    expect(rendered).toContain(
      '[https://cwe.mitre.org/data/definitions/2.html](<https://cwe.mitre.org/data/definitions/2.html>)',
    );
    expect(urls).toEqual(['https://cwe-api.mitre.org/api/v1/cwe/1/children?view=1000']);
  });

  it('pages edges within byte and count caps and keeps every page endpoint', async () => {
    const first = await call({ limit: 1000 });
    expect(first.isError).not.toBe(true);
    expect(first.structuredContent).toMatchObject({
      pagination: { total: 105, hasMore: true },
      truncated: true,
      cap: 100,
      notice: expect.stringContaining('capped at 100'),
    });
    expect(JSON.stringify(first.content)).toContain('capped at 100');
    let wire = first;
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const data = wire.structuredContent as {
        nodes: { id: string; viewId: string }[];
        edges: { parentId: string; childId: string; viewId: string }[];
        pagination: { total: number; shown: number; nextCursor?: string };
      };
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(24000);
      expect(data.edges.length).toBeGreaterThan(0);
      expect(data.edges.length).toBeLessThanOrEqual(100);
      expect(data.pagination.total).toBe(105);
      expect(data.pagination.shown).toBe(data.edges.length);
      const ids = new Set(data.nodes.map((node) => `${node.viewId}:${node.id}`));
      for (const edge of data.edges) {
        expect(ids.has(`${edge.viewId}:${edge.parentId}`)).toBe(true);
        expect(ids.has(`${edge.viewId}:${edge.childId}`)).toBe(true);
        expect(lines(wire).join('\n')).toContain(edgeText(edge));
        seen.push(edge.childId);
      }
      cursor = data.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(105);
      if (cursor) wire = await call({ limit: 1000, cursor });
    } while (cursor);
    expect(seen).toEqual(Array.from({ length: 105 }, (_, i) => `CWE-${i + 2}`));
    for (const limit of [0, 1001, 1.5])
      expect((await call({ limit })).structuredContent).toMatchObject({
        error: { code: JsonRpcErrorCode.InvalidParams },
      });
  });

  it('invalidates continuations after query, topology, page size or catalog changes', async () => {
    const first = await call({ limit: 1 });
    const cursor = (first.structuredContent as { pagination: { nextCursor: string } }).pagination
      .nextCursor;
    const rows = body as ReturnType<typeof raw>[];
    // Children in every view come from the first level of the descendants tree.
    const tree = [{ Data: raw(1), Children: rows.map((row) => ({ Data: row, Children: null })) }];
    for (const change of [
      { id: '110' },
      { viewId: 'all' },
      { limit: 2 },
      { cursor: `${cursor}x` },
    ]) {
      body = 'viewId' in change ? tree : rows;
      const wire = await call({ limit: 1, cursor, ...change });
      expect(wire.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_cursor' } },
      });
      for (const surface of [wire.content, wire.structuredContent])
        expect(JSON.stringify(surface)).toContain('without cursor');
    }
    body = [raw(2), raw(3)];
    expect((await call({ limit: 1, cursor })).structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
    body = Array.from({ length: 105 }, (_, index) => raw(index + 2));
    await disposeCatalogService();
    await load('4.next');
    expect((await call({ limit: 1, cursor })).structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
  });

  it('retains recursive multiview topology and sparse drift notices on both surfaces', async () => {
    body = [1000, 1001].map((view) => ({
      Data: raw(1, view),
      Children: [{ Data: raw(2, view), Children: [{ Data: raw(999, view), Children: null }] }],
    }));
    const wire = await call({ direction: 'descendants', viewId: ' ALL ', limit: 1 });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      viewId: 'all',
      notice: expect.stringContaining('source drift'),
      pagination: { total: 4, shown: 1 },
    });
    expect(JSON.stringify(wire.content)).toContain('source drift');
    expect(urls[0]).toBe('https://cwe-api.mitre.org/api/v1/cwe/1/descendants');
  });

  it('requests unscoped parents and returns only the requested view on both surfaces', async () => {
    body = fixture('cwe-79-parents');
    const wire = await call({ id: '79', direction: 'parents' });
    expect(urls).toEqual(['https://cwe-api.mitre.org/api/v1/cwe/79/parents']);
    expect(wire.structuredContent).toMatchObject({
      pagination: { total: 1 },
      nodes: [
        { id: 'CWE-74', viewId: 'CWE-1000', name: 'Known 74' },
        { id: 'CWE-79', viewId: 'CWE-1000', name: 'Known 79' },
      ],
      edges: [{ parentId: 'CWE-74', childId: 'CWE-79', viewId: 'CWE-1000', primaryParent: true }],
    });
    const rendered = lines(wire);
    for (const line of ['> Known 74', '> Known 79']) expect(rendered).toContain(line);
    expect(rendered.join('\n')).toContain(
      `${edgeText({ parentId: 'CWE-74', childId: 'CWE-79', viewId: 'CWE-1000' })}\n\n**primaryParent**\n\ntrue`,
    );
    expect(rendered.join('\n')).not.toContain('CWE-1003');
  });

  it('serves children in every view from the first level of unscoped descendants', async () => {
    body = fixture('cwe-20-descendants');
    const pages = await walk({ id: '20', direction: 'children', viewId: 'all', limit: 100 });
    expect(new Set(urls)).toEqual(new Set(['https://cwe-api.mitre.org/api/v1/cwe/20/descendants']));
    expect(pages[0]?.data.pagination.total).toBe(35);
    const edges = pages.flatMap(({ data, content }) =>
      data.edges.map((edge) => {
        expect(content).toContain(edgeText(edge));
        return `${edge.viewId}:${edge.parentId}>${edge.childId}`;
      }),
    );
    expect(new Set(edges).size).toBe(35);
    expect(edges.every((edge) => edge.includes(':CWE-20>'))).toBe(true);
    expect(pages.flatMap(({ data }) => keys(data))).not.toContain('CWE-1000:CWE-129');
  });

  it('carries only page endpoint nodes and ships edge-less roots once, on the first page', async () => {
    body = fixture('cwe-79-ancestors-primary');
    const pages = await walk({
      id: '79',
      direction: 'ancestors',
      primaryOnly: true,
      viewId: 'all',
    });
    expect(pages.map(({ data }) => data.edges.length)).toEqual([20, 20, 10]);
    expect(urls).toHaveLength(3);
    const nodes = new Set<string>();
    const edges = new Set<string>();
    for (const [index, { data, content }] of pages.entries()) {
      const needed = endpoints(data);
      expect(keys(data).filter((key) => !needed.has(key))).toEqual(
        index === 0 ? ['CWE-711:CWE-79'] : [],
      );
      for (const key of needed) expect(keys(data)).toContain(key);
      expect(content.match(/\*\*type\*\*/g)).toHaveLength(data.nodes.length);
      for (const key of keys(data)) nodes.add(key);
      for (const edge of data.edges) edges.add(`${edge.viewId}:${edge.parentId}>${edge.childId}`);
    }
    expect(nodes.size).toBe(80);
    expect(edges.size).toBe(50);
  });

  it('keeps several edge-less roots on the first page only and returns them for an empty traversal', async () => {
    const trees = fixture<Tree[]>('cwe-20-ancestors-primary');
    body = trees;
    const pages = await walk({
      id: '20',
      direction: 'ancestors',
      primaryOnly: true,
      viewId: 'all',
    });
    expect(pages.map(({ data }) => data.edges.length)).toEqual([20, 13]);
    expect(pages.map(({ data }) => keys(data).filter((key) => !endpoints(data).has(key)))).toEqual([
      ['CWE-734:CWE-20', 'CWE-868:CWE-20'],
      [],
    ]);
    body = trees.filter((tree) => !tree.Parents);
    const empty = (await walk({ id: '20', direction: 'ancestors', viewId: 'all' }))[0]!;
    expect(empty.data.pagination.total).toBe(0);
    expect(keys(empty.data)).toEqual(['CWE-734:CWE-20', 'CWE-868:CWE-20']);
    expect(empty.content.match(/\*\*type\*\*/g)).toHaveLength(2);
  });

  it('rejects a continuation whose re-fetch adds a root without edges', async () => {
    const trees = fixture<Tree[]>('cwe-79-ancestors-primary');
    const args = { id: '79', direction: 'ancestors', primaryOnly: true, viewId: 'all' };
    body = trees.filter((tree) => tree.Parents);
    const cursor = ((await call(args)).structuredContent as Page).pagination.nextCursor;
    body = trees;
    expect((await call({ ...args, cursor })).structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
  });

  it('omits a single-view root from pages whose edges do not reference it', async () => {
    body = fixture<Tree[]>('cwe-79-ancestors-primary').filter(
      (tree) => tree.Data.ViewID === '1000',
    );
    const pages = await walk({ id: '79', direction: 'ancestors', primaryOnly: true, limit: 1 });
    expect(urls[0]).toBe(
      'https://cwe-api.mitre.org/api/v1/cwe/79/ancestors?view=1000&primary=true',
    );
    expect(pages.map(({ data }) => keys(data))).toEqual([
      ['CWE-1000:CWE-74', 'CWE-1000:CWE-79'],
      ['CWE-1000:CWE-74', 'CWE-1000:CWE-707'],
      ['CWE-1000:CWE-707', 'CWE-1000:CWE-1000'],
    ]);
  });

  it('reports a MITRE 403 through the production adapter as a retryable refusal after one request', async () => {
    await disposeHierarchyService();
    const fetch = vi.fn(
      async () => new Response('{"supportID": "8278137309397805653"}', { status: 403 }),
    );
    vi.stubGlobal('fetch', fetch);
    initHierarchyService({ clock });
    const wire = await call();
    expect(wire.isError).toBe(true);
    expect(wire.structuredContent).toMatchObject({
      error: { code: JsonRpcErrorCode.ServiceUnavailable, data: { retryable: true } },
    });
    for (const surface of [wire.content, wire.structuredContent]) {
      expect(JSON.stringify(surface)).toContain('Wait a few minutes');
      expect(JSON.stringify(surface)).not.toContain('8278137309397805653');
    }
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('reports invalid options with declared recovery and rejects malformed required inputs', async () => {
    for (const args of [{ primaryOnly: true }, { viewId: '999' }, { viewId: '1' }]) {
      const wire = await call(args);
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: {
          code: JsonRpcErrorCode.ValidationError,
          data: { reason: 'invalid_hierarchy_options' },
        },
      });
      for (const surface of [wire.content, wire.structuredContent])
        expect(JSON.stringify(surface)).toContain('cwe_list_reference');
    }
    for (const id of ['', ' ', '0', '-1', 'CAPEC-1', '1.2'])
      expect((await call({ id })).isError).toBe(true);
    for (const direction of ['', ' ', 'siblings'])
      expect((await call({ direction })).structuredContent).toMatchObject({
        error: { code: JsonRpcErrorCode.InvalidParams },
      });
    expect(urls).toHaveLength(0);
  });

  it('names each failed option in one message that content[] carries alone', async () => {
    for (const [args, message] of [
      [
        { primaryOnly: true },
        'primaryOnly applies only to direction ancestors; received direction children.',
      ],
      [{ viewId: '999' }, 'viewId CWE-999 is not a CWE view in the loaded catalog.'],
      [{ viewId: 'cwe1' }, 'viewId CWE-1 is a weakness, not a CWE view.'],
      [{ viewId: '900' }, 'viewId CWE-900 is a category, not a CWE view.'],
      [
        { viewId: '1', direction: 'parents', primaryOnly: true },
        'viewId CWE-1 is a weakness, not a CWE view. primaryOnly applies only to direction ancestors; received direction parents.',
      ],
    ] as const) {
      const wire = await call(args);
      expect(wire.structuredContent).toMatchObject({
        error: { message, data: { reason: 'invalid_hierarchy_options' } },
      });
      expect(lines(wire)).toContain(`Error: ${message}`);
    }
    expect(urls).toHaveLength(0);
  });

  it('accepts every advertised ID form and rejects others as invalid arguments naming the forms', async () => {
    body = [];
    for (const [args, id, viewId] of [
      [{ id: 'CWE1', viewId: 'cwe_1001' }, 'CWE-1', 'CWE-1001'],
      [{ id: 'cwe 001', viewId: ' CWE 1000 ' }, 'CWE-1', 'CWE-1000'],
      [{ id: 'CWE\t2', viewId: '\tALL\n' }, 'CWE-2', 'all'],
    ] as const) {
      const wire = await call(args);
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({ id, viewId });
    }
    for (const [args, field] of [
      [{ id: 'CWE–1' }, 'id'],
      [{ id: 'CWE:1' }, 'id'],
      [{ id: 'T1059.1' }, 'id'],
      [{ viewId: 'every' }, 'viewId'],
      [{ viewId: '+1000' }, 'viewId'],
    ] as const) {
      const wire = await call(args);
      expect(wire.structuredContent).toMatchObject({
        error: { code: JsonRpcErrorCode.InvalidParams },
      });
      expect(JSON.stringify(wire.content)).toContain(`${field}: Use a CWE`);
    }
  });

  it('treats optional blank view as the default and blank cursor as unset', async () => {
    body = [];
    const baseline = await call();
    const blank = await call({ viewId: ' ', cursor: ' ' });
    expect(blank.isError).not.toBe(true);
    expect(blank.structuredContent).toEqual(baseline.structuredContent);
    expect(blank.content).toEqual(baseline.content);
  });

  it('supports primary ancestors and distinguishes actual empty, unknown root and source inconsistency', async () => {
    body = [{ Data: raw(1), Parents: null }];
    const primary = await call({ direction: 'ancestors', primaryOnly: true });
    expect(primary.isError).not.toBe(true);
    expect(urls[0]).toBe('https://cwe-api.mitre.org/api/v1/cwe/1/ancestors?view=1000&primary=true');
    body = [];
    expect((await call()).structuredContent).toMatchObject({
      found: true,
      edges: [],
      pagination: { total: 0, shown: 0, hasMore: false },
    });
    status = 404;
    const miss = await call({ id: '9999' });
    expect(miss.isError).not.toBe(true);
    expect(miss.structuredContent).toMatchObject({
      found: false,
      nodes: [],
      edges: [],
      guidance: expect.stringContaining('cwe_search_weaknesses'),
    });
    expect(lines(miss)).toContain(`> ${(miss.structuredContent as { guidance: string }).guidance}`);
    const failure = await call();
    expect(failure.isError).toBe(true);
    expect(failure.structuredContent).toMatchObject({
      error: { data: { reason: 'hierarchy_unavailable' } },
    });
    for (const surface of [failure.content, failure.structuredContent])
      expect(JSON.stringify(surface)).toContain('cwe_get_weakness');
  });

  it('exposes queue overflow recovery on both surfaces and cancels outstanding contracts', async () => {
    await disposeHierarchyService();
    let requests = 0;
    initHierarchyService({
      clock,
      request: async (_url, options) =>
        new Promise((_resolve, reject) => {
          requests++;
          options.signal.addEventListener('abort', () => reject(options.signal.reason), {
            once: true,
          });
        }),
    });
    const pending = Array.from({ length: 24 }, () => call());
    await Promise.resolve();
    await Promise.resolve();
    expect(requests).toBe(4);
    const overflow = await call();
    expect(overflow.isError).toBe(true);
    expect(overflow.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.RateLimited,
        data: { reason: 'queue_full', retryable: true },
      },
    });
    for (const surface of [overflow.content, overflow.structuredContent])
      expect(JSON.stringify(surface)).toContain('after the active requests finish');
    await disposeHierarchyService();
    for (const result of await Promise.all(pending))
      expect(result.structuredContent).toMatchObject({
        error: { code: JsonRpcErrorCode.RequestCancelled },
      });
  });
});
