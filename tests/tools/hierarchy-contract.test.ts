/**
 * @fileoverview Live hierarchy contracts through real catalog acquisition and both output surfaces.
 * @module tests/tools/hierarchy-contract.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
  await disposeHierarchyService();
  await disposeCatalogService();
});

describe('cwe_get_hierarchy public contracts', () => {
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
        expect(JSON.stringify(wire.content).replace(/\\/g, '')).toContain(edge.childId);
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
    for (const change of [
      { id: '110' },
      { viewId: 'all' },
      { limit: 2 },
      { cursor: `${cursor}x` },
    ]) {
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
    expect(JSON.stringify(miss.content).replace(/\\/g, '')).toContain('cwe_search_weaknesses');
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
