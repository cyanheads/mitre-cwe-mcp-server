/**
 * @fileoverview Count-limited pages and complete large detail batches on both client surfaces.
 * @module tests/tools/count-pagination.test
 */
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, describe, expect, it } from 'vitest';
import { cweGetAttackPattern } from '@/mcp-server/tools/definitions/cwe-get-attack-pattern.tool.js';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import { cweListReference } from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchAttackPatterns } from '@/mcp-server/tools/definitions/cwe-search-attack-patterns.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import { disposeCatalogService, initCatalogService, SOURCE_URLS } from '@/services/index.js';

const clock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
type Wire = Awaited<ReturnType<typeof runToolContract>>;
type Page = {
  items?: { id: string }[];
  results?: { id: string }[];
  pagination: { total: number; shown: number; hasMore: boolean; nextCursor?: string };
};
const lines = (wire: Wire) =>
  wire.content.flatMap((block) => (block.type === 'text' ? block.text.split('\n') : []));

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
  const cwe = `<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="4.paging" Date="2026-04-30"><Weaknesses>${weaknesses}</Weaknesses><Categories><Category ID="900" Name="Group" Status="Stable"><Summary>Group.</Summary></Category></Categories><Views>${views}</Views></Weakness_Catalog>`;
  const capec = `<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.paging" Date="2023-01-24"><Attack_Patterns>${patterns}</Attack_Patterns></Attack_Pattern_Catalog>`;
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
  await disposeCatalogService();
});

describe('complete count-limited responses', () => {
  it.each(['reference', 'weaknesses', 'patterns'] as const)(
    'delivers large %s pages at the requested count and exhausts them in order',
    async (kind) => {
      await load('é'.repeat(1500), 105);
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const args = { limit: 101, cursor };
        const wire =
          kind === 'reference'
            ? await runToolContract(cweListReference, { ...args, topic: 'views' })
            : kind === 'weaknesses'
              ? await runToolContract(cweSearchWeaknesses, args)
              : await runToolContract(cweSearchAttackPatterns, args);
        expect(wire.isError).not.toBe(true);
        const data = wire.structuredContent as Page;
        const items = data.items ?? data.results ?? [];
        const shown = seen.length === 0 ? 100 : 5;
        expect(data.pagination).toMatchObject({ total: 105, shown, hasMore: shown === 100 });
        expect(items).toHaveLength(shown);
        const notice =
          shown === 100
            ? 'The requested limit was capped at 100 items; follow nextCursor for the remainder.'
            : 'The requested limit was capped at 100 items.';
        expect(data).toHaveProperty('notice', notice);
        expect(lines(wire)).toContain(`> ${notice}`);
        for (const item of items) expect(lines(wire)).toContain(`> ${item.id}`);
        expect(lines(wire)).toContain('> 4.paging');
        expect(lines(wire)).toContain('> 3.paging');
        seen.push(...items.map((item) => item.id));
        cursor = data.pagination.nextCursor;
      } while (cursor);
      expect(seen).toEqual(
        Array.from({ length: 105 }, (_, i) =>
          kind === 'reference'
            ? `CWE-${1000 + i}`
            : `${kind === 'weaknesses' ? 'CWE' : 'CAPEC'}-${i + 1}`,
        ),
      );
    },
  );

  it('keeps complete matched taxonomy mappings and observed examples on each count-limited page', async () => {
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
    const plain = await runToolContract(cweSearchWeaknesses, {});
    expect(plain.isError).not.toBe(true);
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
        expect(wire.isError).not.toBe(true);
        const data = wire.structuredContent as Page & {
          results: Record<string, unknown[]>[];
          notice?: string;
        };
        const rows = data.results;
        expect(data.pagination.total).toBe(40);
        expect(rows).toHaveLength(20);
        expect(data).not.toHaveProperty('notice');
        for (const row of rows) expect(row[field]).toHaveLength(perRow);
        expect(lines(wire).filter((line) => line === `**${field}**`)).toHaveLength(rows.length);
        expect(lines(wire).filter((line) => line.startsWith(opening))).toHaveLength(
          rows.length * perRow,
        );
        seen.push(...rows.map((row) => String(row.id)));
        cursor = data.pagination.nextCursor;
        pages++;
      } while (cursor);
      expect(pages, field).toBe(2);
      expect(seen).toEqual(Array.from({ length: 40 }, (_, i) => `CWE-${i + 1}`));
    }
  });

  it('repeats complete view notes on every count-limited member page', async () => {
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
      const wire = await runToolContract(cweGetView, { id: '1000', limit: 20, cursor });
      expect(wire.isError).not.toBe(true);
      const data = wire.structuredContent as {
        notes: { type: string; text: string }[];
        members: { id: string; name: string }[];
        pagination: Page['pagination'];
      };
      expect(data.notes).toEqual([{ type: 'Maintenance', text: note }]);
      expect(lines(wire)).toContain(`> ${note}`);
      expect(data.members).toHaveLength(calls === 0 ? 20 : 15);
      for (const member of data.members) expect(lines(wire)).toContain(`> ${member.name}`);
      seen.push(...data.members.map((member) => member.id));
      cursor = data.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(35);
      calls++;
    } while (cursor);
    expect(calls).toBe(2);
    expect(seen).toEqual(Array.from({ length: 35 }, (_, i) => `CWE-${35 - i}`));
  });

  it.each([
    ['CWE', cweGetWeakness],
    ['CAPEC', cweGetAttackPattern],
  ] as const)('returns multiple large %s records intact in one batch', async (family, tool) => {
    const description = '界'.repeat(9000);
    await load(description, 3);
    const ids = ['2', '9999', '1'];
    for (const sections of [undefined, ['summary']]) {
      const wire = await runToolContract(tool, { ids, sections });
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        entries: [
          { id: `${family}-2`, kind: 'full', description },
          { id: `${family}-1`, kind: 'full', description },
        ],
        notFound: [{ id: `${family}-9999`, reason: 'not_found' }],
        deferredIds: [],
        totalCount: 3,
      });
      expect(wire.structuredContent).not.toHaveProperty('guidance');
      expect(lines(wire).filter((line) => line === `> ${description}`)).toHaveLength(2);
      expect(lines(wire)).toContain('> not_found');
      expect(lines(wire)).toContain('> 4.paging');
      expect(lines(wire)).toContain('> 3.paging');
    }
  });
});
