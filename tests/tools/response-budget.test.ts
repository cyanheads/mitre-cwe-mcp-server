/**
 * @fileoverview Delivered UTF-8 response budgets and lossless continuation through real catalog services.
 * @module tests/tools/response-budget.test
 */
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cweGetAttackPattern } from '@/mcp-server/tools/definitions/cwe-get-attack-pattern.tool.js';
import { cweGetHierarchy } from '@/mcp-server/tools/definitions/cwe-get-hierarchy.tool.js';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import { cweListReference } from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchAttackPatterns } from '@/mcp-server/tools/definitions/cwe-search-attack-patterns.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import { RESPONSE_BUDGET, selectWithinBudget } from '@/mcp-server/tools/shared.js';
import {
  disposeCatalogService,
  disposeHierarchyService,
  initCatalogService,
  initHierarchyService,
  SOURCE_URLS,
} from '@/services/index.js';

/** Batch builds of the detail tools, counted through the real fitting function they call. */
const fitting = vi.hoisted(() => ({ builds: 0, maxima: [] as number[] }));
vi.mock('@/mcp-server/tools/shared.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/mcp-server/tools/shared.js')>();
  return {
    ...actual,
    selectWithinBudget: <T>(
      maximum: number,
      build: (count: number, oversized: boolean) => T,
      measure: ((result: T) => number) | undefined,
    ) => {
      fitting.maxima.push(maximum);
      return actual.selectWithinBudget(
        maximum,
        (count, oversized) => {
          fitting.builds++;
          return build(count, oversized);
        },
        measure,
      );
    },
  };
});
beforeEach(() => {
  fitting.builds = 0;
  fitting.maxima.length = 0;
});
/** Each detail call fits its batch with at most `ceil(log2 n) + 2` builds, n its processed IDs. */
function boundedBuilds() {
  expect(fitting.maxima).toHaveLength(1);
  const maximum = fitting.maxima[0] as number;
  expect(fitting.builds, `${maximum} processed IDs`).toBeLessThanOrEqual(
    Math.ceil(Math.log2(maximum)) + 2,
  );
  fitting.builds = 0;
  fitting.maxima.length = 0;
}

const budget = 24_000;
/** The oversize disclosure when the first result fits on its own and the deferred IDs do not. */
const deferredOverflow =
  'The identifiers echoed in deferredIds exceed the 24,000-byte response budget beside the first result, which fits on its own; all are returned so none is lost.';
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
/** Every rendered `content[]` line, as a client that forwards the text sees it. */
const lines = (wire: Wire) =>
  wire.content.flatMap((block) => (block.type === 'text' ? block.text.split('\n') : []));
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
  firstViewNotes = '',
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
      `<View ID="${1000 + i}" Name="View ${i}" Type="Graph" Status="Stable"><Objective>${description}</Objective><Members>${i === 0 ? members : ''}</Members>${i === 0 ? firstViewNotes : ''}</View>`,
  ).join('');
  const patterns = Array.from(
    { length: count },
    (_, i) =>
      `<Attack_Pattern ID="${i + 1}" Name="Pattern ${i + 1}" Status="Stable" Abstraction="Standard"><Description>${description}</Description></Attack_Pattern>`,
  ).join('');
  await serve(weaknesses, views, patterns);
}
async function serve(weaknesses: string, views: string, patterns: string) {
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
/**
 * Weaknesses whose default sections are a summary, one consequence, and one mitigation of the given
 * character counts, and patterns whose summary, prerequisites, and mitigations follow the same counts.
 */
async function loadSections(
  count: number,
  sizes: { summary: number; consequence: number; mitigation: number },
) {
  const weaknesses = Array.from(
    { length: count },
    (_, i) =>
      `<Weakness ID="${i + 1}" Name="Known ${i + 1}" Status="Stable" Abstraction="Base"><Description>${'d'.repeat(sizes.summary)}</Description><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact><Note>${'c'.repeat(sizes.consequence)}</Note></Consequence></Common_Consequences><Potential_Mitigations><Mitigation><Phase>Implementation</Phase><Description>${'m'.repeat(sizes.mitigation)}</Description></Mitigation></Potential_Mitigations></Weakness>`,
  ).join('');
  const patterns = Array.from(
    { length: count },
    (_, i) =>
      `<Attack_Pattern ID="${i + 1}" Name="Pattern ${i + 1}" Status="Stable" Abstraction="Standard"><Description>${'d'.repeat(sizes.summary)}</Description><Prerequisites><Prerequisite>${'c'.repeat(sizes.consequence)}</Prerequisite></Prerequisites><Mitigations><Mitigation>${'m'.repeat(sizes.mitigation)}</Mitigation></Mitigations></Attack_Pattern>`,
  ).join('');
  await serve(
    weaknesses,
    '<View ID="1000" Name="View" Type="Graph" Status="Stable"><Objective>View.</Objective><Members/></View>',
    patterns,
  );
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
        for (const item of items) expect(lines(wire)).toContain(`> ${item.id}`);
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

  it('counts matched taxonomy mappings and observed examples toward the page budget and lists each weakness once', async () => {
    // Six repeated-ID mappings and two citations of one CVE per weakness, as on CWE-1391.
    const mappings = Array.from(
      { length: 6 },
      (_, j) =>
        `<Taxonomy_Mapping Taxonomy_Name="ISA/IEC 62443"><Entry_ID>Part 4-2</Entry_ID><Entry_Name>Req CR ${j}.1 ${'requirement '.repeat(8)}</Entry_Name></Taxonomy_Mapping>`,
    ).join('');
    const examples = Array.from(
      { length: 2 },
      (_, j) =>
        `<Observed_Example><Reference>CVE-2021-44228</Reference><Description>Citation ${j}: ${'evaluates lookups '.repeat(25)}</Description><Link>https://www.cve.org/CVERecord?id=CVE-2021-44228</Link></Observed_Example>`,
    ).join('');
    await serve(
      Array.from(
        { length: 40 },
        (_, i) =>
          `<Weakness ID="${i + 1}" Name="Known ${i + 1}" Status="Stable" Abstraction="Base"><Description>Short.</Description><Observed_Examples>${examples}</Observed_Examples><Taxonomy_Mappings>${mappings}</Taxonomy_Mappings></Weakness>`,
      ).join(''),
      '<View ID="1000" Name="View" Type="Graph" Status="Stable"><Objective>View.</Objective><Members/></View>',
      '<Attack_Pattern ID="1" Name="Pattern 1" Status="Stable" Abstraction="Standard"><Description>Short.</Description></Attack_Pattern>',
    );
    // Without the filters a default page holds all 20 rows, cut by count alone.
    const plain = await runToolContract(cweSearchWeaknesses, {});
    bounded(plain);
    expect(plain.structuredContent).toMatchObject({ pagination: { shown: 20 }, truncated: true });
    expect(plain.structuredContent).not.toHaveProperty('notice');
    // Each matched entry renders one line opening with its own text: `> Req CR` or `> Citation`.
    for (const [args, field, perRow, opening] of [
      [
        { taxonomyName: 'isa/iec 62443', taxonomyEntryId: 'PART 4-2' },
        'matchedTaxonomyMappings',
        6,
        '> Req CR ',
      ],
      [{ observedCveId: 'cve-2021-44228' }, 'matchedObservedExamples', 2, '> Citation '],
    ] as const) {
      const seen: string[] = [];
      let cursor: string | undefined;
      let pages = 0;
      do {
        const wire = await runToolContract(cweSearchWeaknesses, { ...args, cursor });
        bounded(wire);
        const data = wire.structuredContent as Page & {
          results: Record<string, unknown[]>[];
          notice?: string;
        };
        const rows = data.results;
        expect(data.pagination.total).toBe(40);
        expect(rows.length).toBeGreaterThan(0);
        // The matched entries, not the count limit, cut every page short of the 20-row default.
        if (data.pagination.hasMore) {
          expect(rows.length).toBeLessThan(20);
          expect(data.notice).toBe(
            'The 24,000-byte response budget reduced this page; follow nextCursor for the remainder.',
          );
          disclosed(wire);
        }
        for (const row of rows) expect(row[field]).toHaveLength(perRow);
        expect(lines(wire).filter((line) => line === `**${field}**`)).toHaveLength(rows.length);
        expect(lines(wire).filter((line) => line.startsWith(opening))).toHaveLength(
          rows.length * perRow,
        );
        seen.push(...rows.map((row) => String(row.id)));
        cursor = data.pagination.nextCursor;
        pages++;
      } while (cursor);
      expect(pages, field).toBeGreaterThan(2);
      expect(seen).toEqual(Array.from({ length: 40 }, (_, i) => `CWE-${i + 1}`));
    }
  });

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
        expect(lines(wire)).toContain(`> ${member.name}`);
        expect(lines(wire)).toContain(`> ${member.id}`);
        seen.push(member.id);
      }
      cursor = data.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(35);
      calls++;
    } while (cursor);
    expect(calls).toBeGreaterThan(1);
    expect(seen).toEqual(Array.from({ length: 35 }, (_, i) => `CWE-${35 - i}`));
  });

  it('repeats complete view notes on every byte-bounded member page', async () => {
    const note = '界'.repeat(2000);
    const name = '界'.repeat(150);
    await load(
      'Small objective.',
      35,
      name,
      true,
      `<Notes><Note Type="Maintenance">${note}</Note></Notes>`,
    );
    const seen: string[] = [];
    let cursor: string | undefined;
    let calls = 0;
    do {
      const wire = await runToolContract(cweGetView, { id: '1000', limit: 1000, cursor });
      bounded(wire);
      const data = wire.structuredContent as {
        notes: { type: string; text: string }[];
        members: { id: string; name: string }[];
        pagination: Page['pagination'];
      };
      expect(data.notes).toEqual([{ type: 'Maintenance', text: note }]);
      expect(lines(wire)).toContain(`> ${note}`);
      expect(data.members.length).toBeGreaterThan(0);
      for (const member of data.members) expect(lines(wire)).toContain(`> ${member.name}`);
      seen.push(...data.members.map((member) => member.id));
      if (data.pagination.hasMore) disclosed(wire);
      cursor = data.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(35);
      calls++;
    } while (cursor);
    expect(calls).toBeGreaterThan(2);
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
      boundedBuilds();
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
        boundedBuilds();
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

  it('measures the example-parameter guidance of an explicit selection beside deferred IDs', async () => {
    // Three summaries fit with fewer bytes to spare than the sentence costs on both surfaces.
    await load('é'.repeat(1680));
    const ids = Array.from({ length: 20 }, (_, i) => String(i + 1));
    const plain = await runToolContract(cweGetWeakness, { ids, sections: ['summary'] });
    boundedBuilds();
    bounded(plain);
    const sentence =
      'The example parameters (exampleOffset 2) apply only to section examples, which the selected sections exclude. Repeat cwe_get_weakness with sections ["summary","examples"] to apply them.';
    expect(budget - bytes(plain)).toBeLessThan(2 * Buffer.byteLength(sentence));
    expect((plain.structuredContent as Batch).entries).toHaveLength(3);
    const wire = await runToolContract(cweGetWeakness, {
      ids,
      sections: ['summary'],
      exampleOffset: 2,
    });
    boundedBuilds();
    bounded(wire);
    disclosed(wire);
    const data = wire.structuredContent as Batch & { guidance: string };
    expect(data.guidance).toBe(
      `The 24,000-byte response budget deferred whole identifiers. Repeat cwe_get_weakness with deferredIds to retrieve the remaining entries. ${sentence}`,
    );
    expect(lines(wire)).toContain(`> ${data.guidance}`);
    // The sentence is measured with the batch, so it costs a whole deferred ID.
    expect(data.entries.map((entry) => entry.id)).toEqual(['CWE-1', 'CWE-2']);
    expect(data.deferredIds).toEqual(ids.slice(2).map((id) => `CWE-${id}`));
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
    fitting.builds = 0;
    fitting.maxima.length = 0;
    const ordinary = await runToolContract(cweGetWeakness, { ids });
    bounded(ordinary);
    // Its only section cannot fit beside the deferred IDs, so the oversized build outlines it.
    boundedBuilds();
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

  it.each(['cwe', 'capec'] as const)(
    'returns the longest prefix of partial %s defaults and defers the rest whole to the end',
    async (kind) => {
      await loadSections(6, { summary: 1500, consequence: 1500, mitigation: 9000 });
      const prefix = kind === 'cwe' ? 'CWE' : 'CAPEC';
      const omittedNotice = `Omitted to fit the 24,000-byte response budget: mitigations. Repeat ${kind === 'cwe' ? 'cwe_get_weakness' : 'cwe_get_attack_pattern'} with this ID and sections ["mitigations"].`;
      let ids = ['1', '2', '3', '4', '5', '6'];
      const processed: string[] = [];
      const firstCall: string[] = [];
      let calls = 0;
      do {
        const wire =
          kind === 'cwe'
            ? await runToolContract(cweGetWeakness, { ids })
            : await runToolContract(cweGetAttackPattern, { ids });
        bounded(wire);
        boundedBuilds();
        const data = wire.structuredContent as Batch;
        expect(data.entries.length).toBeGreaterThan(0);
        for (const entry of data.entries) {
          expect(entry).toMatchObject({
            kind: 'partial',
            description: 'd'.repeat(1500),
            notice: expect.stringContaining(omittedNotice),
          });
          expect(entry).not.toHaveProperty('mitigations');
        }
        // The summaries are identical, so content[] must render one per entry, not one in all.
        expect(lines(wire).filter((line) => line === `> ${'d'.repeat(1500)}`)).toHaveLength(
          data.entries.length,
        );
        if (data.deferredIds.length) disclosed(wire);
        if (calls === 0) firstCall.push(...data.entries.map((entry) => entry.id));
        processed.push(...data.entries.map((entry) => entry.id));
        ids = data.deferredIds;
        expect(++calls).toBeLessThan(7);
      } while (ids.length);
      // Two partial entries share a response, so the first call defers four whole IDs.
      expect(firstCall).toEqual([`${prefix}-1`, `${prefix}-2`]);
      expect(processed).toEqual([1, 2, 3, 4, 5, 6].map((id) => `${prefix}-${id}`));
    },
  );

  it('refills the first default record against its deferred-ID metadata instead of outlining it', async () => {
    await loadSections(1, { summary: 1500, consequence: 1500, mitigation: 7000 });
    const alone = await runToolContract(cweGetWeakness, { ids: ['1'] });
    bounded(alone);
    expect((alone.structuredContent as Batch).entries[0]?.kind).toBe('full');
    boundedBuilds();
    const remaining = Array.from({ length: 199 }, (_, i) => `CWE-${10000 + i}`);
    const wire = await runToolContract(cweGetWeakness, { ids: ['1', ...remaining] });
    bounded(wire);
    boundedBuilds();
    const data = wire.structuredContent as Batch;
    expect(data.entries).toEqual([
      expect.objectContaining({
        id: 'CWE-1',
        kind: 'partial',
        description: 'd'.repeat(1500),
        outline: [{ section: 'mitigations', sizeInBytes: expect.any(Number) }],
        notice:
          'The source entry has no content for these selected sections: relations. Omitted to fit the 24,000-byte response budget: mitigations. Repeat cwe_get_weakness with this ID and sections ["mitigations"].',
      }),
    ]);
    expect(data.notFound).toEqual([]);
    expect(data.deferredIds).toEqual(remaining);
    disclosed(wire);
    expect(JSON.stringify(wire)).not.toMatch(/oversiz|exceed the 24,000/);
    // An explicit selection stays complete and discloses its size, within the same build bound.
    const explicit = await runToolContract(cweGetWeakness, {
      ids: ['1', ...remaining],
      sections: ['summary', 'consequences', 'mitigations', 'relations'],
    });
    boundedBuilds();
    expect(bytes(explicit)).toBeGreaterThan(budget);
    expect((explicit.structuredContent as Batch).entries).toEqual([
      expect.objectContaining({ id: 'CWE-1', kind: 'full' }),
    ]);
    expect(JSON.stringify(explicit.content)).toContain('m'.repeat(7000));
    disclosed(explicit);
  });

  it('builds the oversized fallback once when not even an outline fits beside the deferred IDs', async () => {
    await loadSections(1, { summary: 1500, consequence: 1500, mitigation: 7000 });
    const remaining = Array.from({ length: 199 }, (_, i) => `CWE-${i + 1}${'0'.repeat(40)}`);
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['1', ...remaining.map((id) => id.slice(4))],
    });
    expect(wire.isError).not.toBe(true);
    boundedBuilds();
    const data = wire.structuredContent as Batch;
    expect(data.entries).toEqual([expect.objectContaining({ id: 'CWE-1', kind: 'outline' })]);
    expect(data.deferredIds).toEqual(remaining);
    expect(bytes(wire)).toBeGreaterThan(budget);
    // The outline fits on its own; the deferred-ID echo is what overflows.
    for (const surface of [wire.content, wire.structuredContent]) {
      expect(JSON.stringify(surface)).toContain(deferredOverflow);
      expect(JSON.stringify(surface)).not.toContain('One complete selected record');
    }
  });

  it.each(['cwe', 'capec'] as const)(
    'names what overflows a %s detail response: the record, or the deferred-ID echo',
    async (kind) => {
      const description = '界'.repeat(9000);
      await load(description, 1);
      const call = (args: { ids: string[]; sections?: string[] }) =>
        kind === 'cwe'
          ? runToolContract(cweGetWeakness, args)
          : runToolContract(cweGetAttackPattern, args);
      const toolName = kind === 'cwe' ? 'cwe_get_weakness' : 'cwe_get_attack_pattern';
      /** The batch guidance, as structuredContent carries it and `content[]` renders it. */
      const guidance = (wire: Wire) => {
        const { guidance } = wire.structuredContent as { guidance?: string };
        expect(lines(wire)).toContain(`> ${guidance}`);
        return guidance;
      };

      const record = await call({ ids: ['1'], sections: ['summary'] });
      expect(record.isError).not.toBe(true);
      boundedBuilds();
      expect(bytes(record)).toBeGreaterThan(budget);
      expect((record.structuredContent as Batch).entries).toEqual([
        expect.objectContaining({ kind: 'full', description }),
      ]);
      expect(guidance(record)).toBe(
        'One complete selected record and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.',
      );

      // 200 long items that are no ID: the first is processed and every other one is echoed.
      const items = Array.from(
        { length: 200 },
        (_, i) => `item ${String(i).padStart(3, '0')} ${'x'.repeat(141)}`,
      );
      const echo = await call({ ids: items });
      expect(echo.isError).not.toBe(true);
      boundedBuilds();
      expect(bytes(echo)).toBeGreaterThan(budget);
      const data = echo.structuredContent as Batch;
      expect(data.entries).toEqual([]);
      expect(data.notFound).toEqual([expect.objectContaining({ id: items[0] })]);
      expect(data.deferredIds).toEqual(items.slice(1));
      expect(guidance(echo)).toBe(
        `The 24,000-byte response budget deferred whole identifiers. ${deferredOverflow} Repeat ${toolName} with deferredIds to retrieve the remaining entries.`,
      );
      // The enrichment notice repeats the same disclosure.
      expect((echo.structuredContent as { notice?: string }).notice).toBe(guidance(echo));
    },
  );

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

  it('fits a page with a logarithmic number of builds and selects what the linear walk selects', () => {
    /** The walk the search replaces: the largest fitting count from the top down, else oversized. */
    function linear(maximum: number, size: (count: number) => number): number {
      for (let count = maximum; count >= Math.min(1, maximum); count--)
        if (size(count) <= RESPONSE_BUDGET) return count;
      return -1;
    }
    for (const maximum of [1, 2, 3, 7, 8, 9, 20, 99, 100, 1000]) {
      const fits =
        maximum <= 100
          ? Array.from({ length: maximum + 1 }, (_, fit) => fit)
          : [0, 1, 2, 3, 499, 500, 998, 999, 1000];
      for (const fit of fits) {
        /**
         * Size grows with the count past `fit`. The complete page carries no budget notice, so it
         * can measure smaller than the page one item shorter.
         */
        const shapes = [
          (count: number) => RESPONSE_BUDGET - fit + count,
          (count: number) => RESPONSE_BUDGET - fit + count + (count < maximum ? 50 : 0),
        ];
        for (const size of shapes) {
          // The oversized fallback is a build too, and it counts toward the bound.
          let builds = 0;
          const oversizedCounts: number[] = [];
          const selected = selectWithinBudget(
            maximum,
            (count, oversized) => {
              builds++;
              if (!oversized) return count;
              oversizedCounts.push(count);
              return -1;
            },
            size,
          );
          expect(selected, `maximum ${maximum}, fit ${fit}`).toBe(linear(maximum, size));
          expect(oversizedCounts, `maximum ${maximum}, fit ${fit}`).toEqual(
            selected === -1 ? [1] : [],
          );
          expect(builds, `maximum ${maximum}, fit ${fit}`).toBeLessThanOrEqual(
            Math.ceil(Math.log2(maximum)) + 2,
          );
        }
      }
    }
    let builds = 0;
    const count = (value: number, oversized: boolean) => {
      builds++;
      return oversized ? -1 : value;
    };
    expect(selectWithinBudget(5, count, undefined)).toBe(5);
    expect(selectWithinBudget(0, count, () => RESPONSE_BUDGET + 1)).toBe(-1);
    expect(selectWithinBudget(0, count, () => RESPONSE_BUDGET)).toBe(0);
    expect(builds).toBe(4);
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
