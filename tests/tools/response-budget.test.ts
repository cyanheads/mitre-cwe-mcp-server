/**
 * @fileoverview Delivered UTF-8 response budgets and lossless continuation through real catalog services.
 * @module tests/tools/response-budget.test
 */
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, describe, expect, it } from 'vitest';
import { cweGetAttackPattern } from '@/mcp-server/tools/definitions/cwe-get-attack-pattern.tool.js';
import { cweGetHierarchy } from '@/mcp-server/tools/definitions/cwe-get-hierarchy.tool.js';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import { cweListReference } from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchAttackPatterns } from '@/mcp-server/tools/definitions/cwe-search-attack-patterns.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import {
  disposeCatalogService,
  disposeHierarchyService,
  initCatalogService,
  initHierarchyService,
  SOURCE_URLS,
} from '@/services/index.js';

const budget = 24_000;
const clock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
type Wire = Awaited<ReturnType<typeof runToolContract>>;
type Page = {
  items?: { id?: string; key: string }[];
  results?: { id: string }[];
  pagination: { total: number; shown: number; hasMore: boolean; nextCursor?: string };
};
type Batch = {
  entries: { id: string; kind: string; description?: string; notice?: string }[];
  notFound: { id: string }[];
  deferredIds: string[];
};
const bytes = (wire: Wire) => Buffer.byteLength(JSON.stringify(wire), 'utf8');
function bounded(wire: Wire) {
  expect(wire.isError).not.toBe(true);
  expect(bytes(wire)).toBeLessThanOrEqual(budget);
}
function disclosed(wire: Wire) {
  for (const surface of [wire.content, wire.structuredContent])
    expect(JSON.stringify(surface)).toMatch(/(?:byte|response|size) budget|24[ ,]?000|oversiz/i);
}
async function load(
  description = 'é'.repeat(1500),
  count = 35,
  name = 'Known',
  withMembers = false,
) {
  const members = withMembers
    ? Array.from(
        { length: count },
        (_, i) => `<Has_Member CWE_ID="${count - i}" View_ID="1000"/>`,
      ).join('')
    : '';
  const weaknesses = Array.from(
    { length: count },
    (_, i) =>
      `<Weakness ID="${i + 1}" Name="${name} ${i + 1}" Status="Stable" Abstraction="Base"><Description>${description}</Description></Weakness>`,
  ).join('');
  const views = Array.from(
    { length: count },
    (_, i) =>
      `<View ID="${1000 + i}" Name="View ${i}" Type="Graph" Status="Stable"><Objective>${description}</Objective><Members>${i === 0 ? members : ''}</Members></View>`,
  ).join('');
  const patterns = Array.from(
    { length: count },
    (_, i) =>
      `<Attack_Pattern ID="${i + 1}" Name="Pattern ${i + 1}" Status="Stable" Abstraction="Standard"><Description>${description}</Description></Attack_Pattern>`,
  ).join('');
  const cwe = `<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="4.budget" Date="2026-04-30"><Weaknesses>${weaknesses}</Weaknesses><Categories><Category ID="900" Name="Group" Status="Stable"><Summary>Group.</Summary></Category></Categories><Views>${views}</Views></Weakness_Catalog>`;
  const capec = `<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.budget" Date="2023-01-24"><Attack_Patterns>${patterns}</Attack_Patterns></Attack_Pattern_Catalog>`;
  await initCatalogService({
    clock,
    context: createMockContext(),
    request: async (url) => {
      if (url === SOURCE_URLS.cwe) return new Response(zipSync({ 'cwe.xml': strToU8(cwe) }));
      if (url === SOURCE_URLS.capec) return new Response(capec);
      throw new Error(`Unexpected catalog URL ${url}`);
    },
  });
}
afterEach(async () => {
  await disposeHierarchyService();
  await disposeCatalogService();
});

describe('complete delivered response budget', () => {
  it.each(['reference', 'search', 'weaknesses'] as const)(
    'bounds %s pages and exhausts all ordered items exactly once',
    async (kind) => {
      await load();
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const wire =
          kind === 'reference'
            ? await runToolContract(cweListReference, { topic: 'views', limit: 1000, cursor })
            : kind === 'weaknesses'
              ? await runToolContract(cweSearchWeaknesses, { limit: 1000, cursor })
              : await runToolContract(cweSearchAttackPatterns, { limit: 1000, cursor });
        bounded(wire);
        const data = wire.structuredContent as Page;
        const items = data.items ?? data.results ?? [];
        expect(data.pagination.total).toBe(35);
        expect(data.pagination.shown).toBe(items.length);
        expect(items.length).toBeGreaterThan(0);
        for (const item of items)
          expect(JSON.stringify(wire.content).replace(/\\/g, '')).toContain(item.id);
        if (data.pagination.hasMore) disclosed(wire);
        seen.push(...items.map((item) => item.id ?? ('key' in item ? item.key : '')));
        cursor = data.pagination.nextCursor;
        expect(seen.length).toBeLessThanOrEqual(35);
      } while (cursor);
      expect(seen).toEqual(
        Array.from({ length: 35 }, (_, i) =>
          kind === 'reference'
            ? `CWE-${1000 + i}`
            : `${kind === 'weaknesses' ? 'CWE' : 'CAPEC'}-${i + 1}`,
        ),
      );
    },
  );

  it('pages direct view members by bytes while retaining source order and complete names', async () => {
    const name = '界'.repeat(150);
    await load('Small objective.', 35, name, true);
    const seen: string[] = [];
    let cursor: string | undefined;
    let calls = 0;
    do {
      const wire = await runToolContract(cweGetView, { id: '1000', limit: 1000, cursor });
      bounded(wire);
      const data = wire.structuredContent as {
        objective: string;
        members: { id: string; name: string }[];
        pagination: Page['pagination'];
      };
      expect(data.objective).toBe('Small objective.');
      expect(data.pagination.total).toBe(35);
      expect(data.members.length).toBeGreaterThan(0);
      for (const member of data.members) {
        expect(member.name).toBe(`${name} ${member.id.slice(4)}`);
        expect(JSON.stringify(wire.content)).toContain(member.name);
        expect(JSON.stringify(wire.content).replace(/\\/g, '')).toContain(member.id);
        seen.push(member.id);
      }
      cursor = data.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(35);
      calls++;
    } while (cursor);
    expect(calls).toBeGreaterThan(1);
    expect(seen).toEqual(Array.from({ length: 35 }, (_, i) => `CWE-${35 - i}`));
  });

  it.each(['cwe', 'capec'] as const)(
    'outlines an individually oversized rendered %s default',
    async (kind) => {
      await load('é'.repeat(6500), 1);
      const wire =
        kind === 'cwe'
          ? await runToolContract(cweGetWeakness, { ids: ['1'] })
          : await runToolContract(cweGetAttackPattern, { ids: ['1'] });
      bounded(wire);
      expect((wire.structuredContent as Batch).entries[0]?.kind).toBe('outline');
      expect(JSON.stringify(wire.content)).toContain('outline');
    },
  );

  it.each(['cwe', 'capec'] as const)(
    'defers whole %s IDs under aggregate pressure, including missing IDs',
    async (kind) => {
      await load();
      let ids = ['1', '9999', '2', '3', '4', '5', '6', '7', '8'];
      const processed: string[] = [];
      let calls = 0;
      do {
        const wire =
          kind === 'cwe'
            ? await runToolContract(cweGetWeakness, { ids })
            : await runToolContract(cweGetAttackPattern, { ids });
        bounded(wire);
        const data = wire.structuredContent as Batch;
        expect(
          data.entries.every(
            (entry) => entry.kind === 'full' && entry.description === 'é'.repeat(1500),
          ),
        ).toBe(true);
        const returned = [
          ...data.entries.map((entry) => entry.id),
          ...data.notFound.map((entry) => entry.id),
        ];
        expect(returned.length).toBeGreaterThan(0);
        expect(returned.every((id) => !data.deferredIds.includes(id))).toBe(true);
        processed.push(...returned);
        ids = data.deferredIds;
        expect(++calls).toBeLessThan(10);
      } while (ids.length);
      const prefix = kind === 'cwe' ? 'CWE' : 'CAPEC';
      expect(processed.sort()).toEqual(
        ['1', '9999', '2', '3', '4', '5', '6', '7', '8'].map((id) => `${prefix}-${id}`).sort(),
      );
      expect(new Set(processed).size).toBe(processed.length);
      expect(calls).toBeGreaterThan(1);
    },
  );

  it('preserves explicit oversized detail content and discloses its cost on both surfaces', async () => {
    const description = '界'.repeat(9000);
    await load(description, 1);
    const wire = await runToolContract(cweGetWeakness, { ids: ['1'], sections: ['summary'] });
    expect(wire.isError).not.toBe(true);
    expect(bytes(wire)).toBeGreaterThan(budget);
    expect((wire.structuredContent as Batch).entries[0]).toMatchObject({
      kind: 'full',
      description,
    });
    expect(JSON.stringify(wire.content)).toContain(description);
    disclosed(wire);
  });

  it('returns one oversized list item intact and advances to the next item', async () => {
    const description = '界'.repeat(9000);
    await load(description, 2);
    const first = await runToolContract(cweListReference, { topic: 'views', limit: 1000 });
    expect(first.isError).not.toBe(true);
    expect((first.structuredContent as Page).items).toHaveLength(1);
    expect(first.structuredContent).toMatchObject({ pagination: { shown: 1, hasMore: true } });
    expect(JSON.stringify(first.content)).toContain(description);
    disclosed(first);
    const cursor = (first.structuredContent as Page).pagination.nextCursor;
    const second = await runToolContract(cweListReference, { topic: 'views', limit: 1000, cursor });
    expect(second.structuredContent).toMatchObject({
      items: [{ id: 'CWE-1001', description }],
      pagination: { shown: 1, hasMore: false },
    });
    disclosed(second);
  });

  it('retains a full default immediately below the delivered-byte boundary and outlines above it', async () => {
    await load('x', 1);
    const baseline = await runToolContract(cweGetWeakness, { ids: ['1'] });
    const padding = Math.floor((budget - bytes(baseline)) / 2);
    await disposeCatalogService();
    await load('x'.repeat(1 + padding), 1);
    const at = await runToolContract(cweGetWeakness, { ids: ['1'] });
    bounded(at);
    expect(bytes(at)).toBeGreaterThanOrEqual(budget - 1);
    expect((at.structuredContent as Batch).entries[0]?.kind).toBe('full');
    await disposeCatalogService();
    await load('x'.repeat(2 + padding), 1);
    const over = await runToolContract(cweGetWeakness, { ids: ['1'] });
    bounded(over);
    expect((over.structuredContent as Batch).entries[0]?.kind).toBe('outline');
  });

  it('accounts for deferred-ID metadata when the first record fits only on its own', async () => {
    await load('x', 1);
    const baseline = await runToolContract(cweGetWeakness, { ids: ['1'] });
    const description = 'x'.repeat(1 + Math.floor((budget - bytes(baseline)) / 2));
    await disposeCatalogService();
    await load(description, 1);
    const alone = await runToolContract(cweGetWeakness, { ids: ['1'] });
    bounded(alone);
    expect((alone.structuredContent as Batch).entries[0]?.kind).toBe('full');
    const remaining = Array.from({ length: 199 }, (_, i) => `CWE-${10000 + i}`);
    const ids = ['1', ...remaining];
    const ordinary = await runToolContract(cweGetWeakness, { ids });
    bounded(ordinary);
    expect((ordinary.structuredContent as Batch).entries).toEqual([
      expect.objectContaining({ id: 'CWE-1', kind: 'outline' }),
    ]);
    expect((ordinary.structuredContent as Batch).notFound).toEqual([]);
    expect((ordinary.structuredContent as Batch).deferredIds).toEqual(remaining);
    const explicit = await runToolContract(cweGetWeakness, {
      ids,
      sections: ['summary', 'consequences', 'mitigations', 'relations'],
    });
    expect(explicit.isError).not.toBe(true);
    expect((explicit.structuredContent as Batch).entries).toEqual([
      expect.objectContaining({ id: 'CWE-1', kind: 'full', description }),
    ]);
    expect((explicit.structuredContent as Batch).deferredIds).toEqual(remaining);
    expect(bytes(explicit)).toBeGreaterThan(budget);
    expect(JSON.stringify(explicit.content)).toContain(description);
    disclosed(explicit);
  });

  it('budgets hierarchy edges with all endpoint nodes and exhaustive continuation', async () => {
    await load('Record.', 35, '界'.repeat(150));
    initHierarchyService({
      clock,
      request: async () =>
        Response.json(
          Array.from({ length: 34 }, (_, i) => ({
            ID: String(i + 2),
            Type: 'base_weakness',
            ViewID: '1000',
          })),
        ),
    });
    const edges: string[] = [];
    let cursor: string | undefined;
    do {
      const wire = await runToolContract(cweGetHierarchy, {
        id: '1',
        direction: 'children',
        limit: 1000,
        cursor,
      });
      bounded(wire);
      const data = wire.structuredContent as {
        nodes: { id: string }[];
        edges: { parentId: string; childId: string }[];
        pagination: Page['pagination'];
      };
      const nodes = new Set(data.nodes.map((node) => node.id));
      expect(data.edges.length).toBeGreaterThan(0);
      for (const edge of data.edges) {
        expect(nodes.has(edge.parentId)).toBe(true);
        expect(nodes.has(edge.childId)).toBe(true);
        edges.push(edge.childId);
      }
      cursor = data.pagination.nextCursor;
      expect(edges.length).toBeLessThanOrEqual(34);
    } while (cursor);
    expect(edges).toEqual(Array.from({ length: 34 }, (_, i) => `CWE-${i + 2}`));
  });

  it('keeps empty pages bounded and terminal', async () => {
    await load();
    const wire = await runToolContract(cweListReference, { topic: 'views', filter: 'absent' });
    bounded(wire);
    expect(wire.structuredContent).toMatchObject({
      items: [],
      pagination: { total: 0, shown: 0, hasMore: false },
    });
    expect((wire.structuredContent as Page).pagination.nextCursor).toBeUndefined();
  });
});
