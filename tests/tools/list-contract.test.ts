/**
 * @fileoverview Search and view contracts through acquired catalog fixtures and both client surfaces.
 * @module tests/tools/list-contract.test
 */
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweSearchAttackPatterns } from '@/mcp-server/tools/definitions/cwe-search-attack-patterns.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import {
  type CatalogClock,
  disposeCatalogService,
  type HttpRequest,
  initCatalogService,
  SOURCE_URLS,
} from '@/services/index.js';

const clock: CatalogClock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
const preview = `First ${'complete '.repeat(60)}sentence.`;
const weakness = (
  id: number,
  name: string,
  description: string,
  extra = '',
  status = 'Stable',
  abstraction = 'Base',
) =>
  `<Weakness ID="${id}" Name="${name}" Status="${status}" Abstraction="${abstraction}"><Description>${description}</Description>${extra}</Weakness>`;
const child = (id: number, view = 1000) =>
  `<Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="${id}" View_ID="${view}"/></Related_Weaknesses>`;
const member = (id: number, view = 1000) => `<Has_Member CWE_ID="${id}" View_ID="${view}"/>`;
const platform =
  '<Applicable_Platforms><Language Name="C" Class="Compiled"/><Technology Name="Web Server" Class="Server"/></Applicable_Platforms><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact></Consequence></Common_Consequences><Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>';
const pattern = (
  id: number,
  name: string,
  description: string,
  extra = '',
  status = 'Stable',
  abstraction = 'Detailed',
) =>
  `<Attack_Pattern ID="${id}" Name="${name}" Status="${status}" Abstraction="${abstraction}"><Description>${description}</Description>${extra}</Attack_Pattern>`;
const mapping = (cwe: number, attack: string) =>
  `<Related_Weaknesses><Related_Weakness CWE_ID="${cwe}"/></Related_Weaknesses><Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>${attack}</Entry_ID></Taxonomy_Mapping></Taxonomy_Mappings>`;
function catalogs(version = '4.list') {
  const rows = [
    weakness(
      30,
      'Ordinary',
      'Ordinary description.',
      '<Extended_Description>needle alpha extended.</Extended_Description>',
    ),
    weakness(20, 'Ordinary', 'needle alpha description.'),
    weakness(10, 'needle alpha', `${preview} Second sentence.`, platform + child(900)),
    weakness(11, 'needle alpha', 'Other sentence.', child(10)),
    weakness(12, 'needle', 'alpha split across fields.', child(11)),
    weakness(13, 'Off view', 'Outside.', child(10, 1001), 'Deprecated', 'Class'),
    ...Array.from({ length: 105 }, (_, index) =>
      weakness(200 + index, `Bulk ${index}`, 'Bulk description.'),
    ),
  ].join('');
  const direct = [
    member(900),
    member(30),
    member(10),
    ...Array.from({ length: 105 }, (_, index) => member(304 - index)),
  ].join('');
  const cwe = `<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="${version}" Date="2026-04-30"><Weaknesses>${rows}</Weaknesses><Categories><Category ID="900" Name="Category" Status="Stable"><Summary>Grouping.</Summary><Relationships>${member(10)}${member(901)}</Relationships></Category><Category ID="901" Name="Nested" Status="Stable"><Summary>Nested grouping.</Summary><Relationships>${member(900)}${member(20)}</Relationships></Category></Categories><Views><View ID="1000" Name="Navigation" Type="Graph" Status="Stable"><Objective>First objective line.\nSecond objective line.</Objective><Audience><Stakeholder><Type>Developer</Type><Description>Build software.</Description></Stakeholder></Audience><Members>${direct}</Members></View><View ID="1001" Name="Filtered" Type="Implicit" Status="Draft"><Members><Filter>status = 'Draft'</Filter></Members></View></Views></Weakness_Catalog>`;
  const capec = `<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.list" Date="2023-01-24"><Attack_Patterns>${[
    pattern(30, 'Ordinary', 'needle alpha description.', mapping(11, '1059')),
    pattern(
      10,
      'needle alpha',
      `${preview} Next sentence.`,
      `${mapping(10, '1059.001')}<Typical_Severity>High</Typical_Severity><Likelihood_Of_Attack>Medium</Likelihood_Of_Attack>`,
    ),
    pattern(11, 'needle', 'alpha elsewhere.', mapping(10, '1050.001')),
    pattern(2, 'Sparse pattern', '', '', 'Draft', 'Meta'),
    pattern(3, 'Inactive', 'Deprecated description.', '', 'Deprecated', 'Standard'),
    pattern(4, 'Inactive', 'Obsolete description.', '', 'Obsolete'),
    ...Array.from({ length: 105 }, (_, index) =>
      pattern(200 + index, `Bulk ${index}`, 'Bulk description.'),
    ),
  ].join('')}</Attack_Patterns></Attack_Pattern_Catalog>`;
  return { cwe, capec };
}
async function load(version?: string) {
  const xml = catalogs(version);
  const request: HttpRequest = async (url) => {
    if (url === SOURCE_URLS.cwe) return new Response(zipSync({ 'cwe.xml': strToU8(xml.cwe) }));
    if (url === SOURCE_URLS.capec) return new Response(xml.capec);
    throw new Error(`Unexpected network request: ${url}`);
  };
  await initCatalogService({ request, clock, context: createMockContext() });
}
const search = (args: Record<string, unknown>) =>
  cweSearchWeaknesses.handler(
    cweSearchWeaknesses.input.parse(args),
    createMockContext({ errors: cweSearchWeaknesses.errors }),
  );
const attacks = (args: Record<string, unknown>) =>
  cweSearchAttackPatterns.handler(
    cweSearchAttackPatterns.input.parse(args),
    createMockContext({ errors: cweSearchAttackPatterns.errors }),
  );
const view = (args: Record<string, unknown>) =>
  cweGetView.handler(
    cweGetView.input.parse(args),
    createMockContext({ errors: cweGetView.errors }),
  );
beforeEach(async () => {
  await load();
});
afterEach(async () => {
  await disposeCatalogService();
});

describe('complete local search and view contracts', () => {
  it('filters the full corpus before paging, ranks complete token matches and excludes categories', async () => {
    const first = await search({ filter: ' NEEDLE   ALPHA ', limit: 2 });
    expect(cweSearchWeaknesses.output.safeParse(first).success).toBe(true);
    expect(first.results.map((row) => row.id)).toEqual(['CWE-10', 'CWE-11']);
    const rest = await search({
      filter: 'needle alpha',
      limit: 2,
      cursor: first.pagination.nextCursor,
    });
    expect(rest.results.map((row) => row.id)).toEqual(['CWE-20', 'CWE-12']);
    const last = await search({
      filter: 'needle alpha',
      limit: 2,
      cursor: rest.pagination.nextCursor,
    });
    expect(last.results.map((row) => row.id)).toEqual(['CWE-30']);
    expect(last.pagination).toEqual({ total: 5, shown: 1, hasMore: false });
    expect((await search({ filter: 'Category' })).results).toEqual([]);
    expect((await attacks({ filter: 'needle alpha' })).results.map((row) => row.id)).toEqual([
      'CAPEC-10',
      'CAPEC-30',
      'CAPEC-11',
    ]);
  });

  it('canonicalizes every weakness filter and echoes effective defaults on both surfaces', async () => {
    const wire = await runToolContract(cweSearchWeaknesses, {
      filter: ' NEEDLE  ALPHA ',
      language: ' compiled ',
      technology: ' web server ',
      abstraction: ' base ',
      consequenceImpact: ' modify data ',
      status: ' stable ',
      viewId: ' cwe-01000 ',
    });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      results: [
        {
          id: 'CWE-10',
          likelihoodOfExploit: 'High',
          descriptionPreview: preview,
          sourceUrl: 'https://cwe.mitre.org/data/definitions/10.html',
        },
      ],
      appliedFilters: {
        filter: 'needle alpha',
        language: 'Compiled',
        technology: 'Web Server',
        abstraction: 'Base',
        consequenceImpact: 'Modify Data',
        status: 'Stable',
        viewId: 'CWE-1000',
        limit: 20,
      },
      totalCount: 1,
    });
    const text = JSON.stringify(wire.content);
    expect(text).toContain(preview);
    expect(text).toContain(
      '[https://cwe.mitre.org/data/definitions/10.html](<https://cwe.mitre.org/data/definitions/10.html>)',
    );
    for (const value of ['Compiled', 'Web Server', 'Modify Data', 'appliedFilters', '1 total'])
      expect(text).toContain(value);
    expect(
      (await search({ language: 'c', technology: 'server' })).results.map((row) => row.id),
    ).toEqual(['CWE-10']);
    expect(
      (await search({ status: 'deprecated', abstraction: 'CLASS' })).results.map((row) => row.id),
    ).toEqual(['CWE-13']);
  });

  it('follows nested cyclic same-view membership but keeps direct members in source order', async () => {
    const scoped = await search({ viewId: '1000', filter: 'needle alpha' });
    expect(scoped.results.map((row) => row.id)).toEqual([
      'CWE-10',
      'CWE-11',
      'CWE-20',
      'CWE-12',
      'CWE-30',
    ]);
    expect((await search({ viewId: '1000', status: 'Deprecated' })).results).toEqual([]);
    const first = await view({ id: 'cwe-01000', limit: 2 });
    expect(cweGetView.output.safeParse(first).success).toBe(true);
    expect(first.members.map((row) => row.id)).toEqual(['CWE-900', 'CWE-30']);
    expect(first.members[0]).toMatchObject({
      type: 'category',
      name: 'Category',
      viewId: 'CWE-1000',
    });
    const second = await view({ id: '1000', limit: 2, cursor: first.pagination.nextCursor });
    expect(second.members.map((row) => row.id)).toEqual(['CWE-10', 'CWE-304']);
    const wire = await runToolContract(cweGetView, { id: '1000', limit: 2 });
    expect(wire.structuredContent).toMatchObject({
      objective: 'First objective line. Second objective line.',
      audience: [{ type: 'Developer', description: 'Build software.' }],
      totalCount: 108,
      truncated: true,
      shown: 2,
      cap: 2,
      appliedFilters: { id: 'CWE-1000', limit: 2 },
    });
    expect(JSON.stringify(wire.content)).toContain('Second objective line.');
    expect(JSON.stringify(wire.content)).toContain('sourceUrl');
  });

  it('keeps exact CWE crosswalks, ATT&CK parent boundaries, sparse fields and inactive defaults', async () => {
    const wire = await runToolContract(cweSearchAttackPatterns, {
      cweId: 'cwe-0010',
      attackTechniqueId: 't1059',
      abstraction: ' detailed ',
      severity: ' high ',
      likelihood: ' medium ',
    });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      results: [
        {
          id: 'CAPEC-10',
          descriptionPreview: preview,
          severity: 'High',
          likelihood: 'Medium',
          relatedWeaknesses: [{ id: 'CWE-10', name: 'needle alpha' }],
          attackTechniqueIds: ['T1059.001'],
        },
      ],
      appliedFilters: {
        cweId: 'CWE-10',
        attackTechniqueId: 'T1059',
        abstraction: 'Detailed',
        severity: 'High',
        likelihood: 'Medium',
        includeInactive: false,
        limit: 20,
      },
    });
    expect(JSON.stringify(wire.content)).toContain(preview);
    expect(JSON.stringify(wire.content)).toContain(
      '[https://capec.mitre.org/data/definitions/10.html](<https://capec.mitre.org/data/definitions/10.html>)',
    );
    expect((await attacks({ cweId: '10' })).results.map((row) => row.id)).toEqual([
      'CAPEC-10',
      'CAPEC-11',
    ]);
    expect((await attacks({ attackTechniqueId: '1059' })).results.map((row) => row.id)).toEqual([
      'CAPEC-10',
      'CAPEC-30',
    ]);
    expect((await attacks({ attackTechniqueId: '1059.001' })).results.map((row) => row.id)).toEqual(
      ['CAPEC-10'],
    );
    const sparse = await attacks({ abstraction: ' meta ' });
    expect(cweSearchAttackPatterns.output.safeParse(sparse).success).toBe(true);
    expect(sparse.results).toEqual([
      {
        id: 'CAPEC-2',
        name: 'Sparse pattern',
        status: 'Draft',
        abstraction: 'Meta',
        sourceUrl: 'https://capec.mitre.org/data/definitions/2.html',
        descriptionPreview: '',
      },
    ]);
    expect((await attacks({ filter: 'inactive' })).results).toEqual([]);
    expect(
      (await attacks({ filter: 'inactive', includeInactive: true })).results.map((row) => row.id),
    ).toEqual(['CAPEC-3', 'CAPEC-4']);
  });

  it.each(['10', '900', '999999'])(
    'returns a recoverable resolver miss for view %s',
    async (id) => {
      const wire = await runToolContract(cweGetView, { id });
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        found: false,
        id: `CWE-${id}`,
        reason: id === '999999' ? 'not_found' : 'wrong_type',
        members: [],
        pagination: { total: 0, shown: 0, hasMore: false },
        guidance: expect.stringContaining('cwe_list_reference'),
      });
      expect(JSON.stringify(wire.content)).toMatch(/cwe.*list.*reference/);
      expect(JSON.stringify(wire.content)).toMatch(id === '999999' ? /not.*found/ : /wrong.*type/);
    },
  );

  it('preserves filter-defined empty views without claiming no weaknesses exist', async () => {
    const wire = await runToolContract(cweGetView, { id: '1001' });
    expect(wire.structuredContent).toMatchObject({
      found: true,
      filterDefinition: "status = 'Draft'",
      members: [],
      guidance: expect.stringContaining('does not establish'),
    });
    expect(JSON.stringify(wire.content)).toContain("status = 'Draft'");
    expect(JSON.stringify(wire.content)).toContain('does not establish');
    const empty = await runToolContract(cweSearchWeaknesses, { viewId: '1001' });
    expect(empty.structuredContent).toMatchObject({
      results: [],
      notice: expect.stringContaining('cwe_get_view'),
    });
    expect(JSON.stringify(empty.content)).toContain('cwe_get_view');
  });

  it('distinguishes dynamic unknown filters from successful misses and reports recovery on both paths', async () => {
    for (const args of [
      { language: 'Imaginary' },
      { technology: 'Imaginary' },
      { consequenceImpact: 'Imaginary' },
      { status: 'Imaginary' },
      { viewId: '10' },
      { viewId: '999999' },
    ]) {
      const wire = await runToolContract(cweSearchWeaknesses, args);
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { data: { reason: 'unknown_filter' } },
      });
      expect(JSON.stringify(wire.structuredContent)).toContain('cwe_list_reference');
      expect(JSON.stringify(wire.content)).toContain('cwe_list_reference');
    }
    for (const args of [{ severity: 'Imaginary' }, { likelihood: 'Imaginary' }]) {
      const wire = await runToolContract(cweSearchAttackPatterns, args);
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { data: { reason: 'unknown_filter' } },
      });
      expect(JSON.stringify(wire.content)).toContain('cwe_list_reference');
      expect(JSON.stringify(wire.structuredContent)).toContain('cwe_list_reference');
    }
    for (const id of ['0', '-1', 'CAPEC-1', '1.2'])
      expect((await runToolContract(cweGetView, { id })).isError).toBe(true);
  });

  it('discloses empty matches and incomplete mappings on both consumption paths', async () => {
    const textMiss = await runToolContract(cweSearchWeaknesses, { filter: 'no nonexistent' });
    const filterMiss = await runToolContract(cweSearchWeaknesses, {
      status: 'Deprecated',
      language: 'C',
    });
    const mappingMiss = await runToolContract(cweSearchAttackPatterns, { cweId: '999999' });
    for (const wire of [textMiss, filterMiss, mappingMiss]) {
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        results: [],
        totalCount: 0,
        pagination: { total: 0, shown: 0, hasMore: false },
        notice: expect.any(String),
      });
    }
    for (const surface of [
      JSON.stringify(mappingMiss.content),
      JSON.stringify(mappingMiss.structuredContent),
    ]) {
      expect(surface).toContain('does not establish');
      expect(surface).toContain('includeInactive true');
    }
    expect(JSON.stringify(textMiss.content)).toContain('fewer terms');
    expect(JSON.stringify(filterMiss.content)).toContain('Deprecated');
  });

  it('caps pages at 100, accepts a submitted ceiling of 1000 and continues the remaining source order', async () => {
    const w = await runToolContract(cweSearchWeaknesses, { filter: 'Bulk', limit: 1000 });
    const a = await runToolContract(cweSearchAttackPatterns, { filter: 'Bulk', limit: 101 });
    const v = await runToolContract(cweGetView, { id: '1000', limit: 101 });
    for (const wire of [w, a, v]) {
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        pagination: { shown: 100, hasMore: true },
        truncated: true,
        shown: 100,
        cap: 100,
        notice: expect.stringContaining('capped at 100'),
      });
      expect(JSON.stringify(wire.content)).toContain('capped at 100');
    }
    const first = await search({ filter: 'Bulk', limit: 1000 });
    const last = await search({ filter: 'Bulk', limit: 1000, cursor: first.pagination.nextCursor });
    expect(last.results.map((row) => row.id)).toEqual([
      'CWE-300',
      'CWE-301',
      'CWE-302',
      'CWE-303',
      'CWE-304',
    ]);
    expect(last.pagination.hasMore).toBe(false);
    const direct = await view({ id: '1000', limit: 100 });
    expect(
      (await view({ id: '1000', limit: 100, cursor: direct.pagination.nextCursor })).members.map(
        (row) => row.id,
      ),
    ).toEqual(Array.from({ length: 8 }, (_, index) => `CWE-${207 - index}`));
    for (const [definition, args] of [
      [cweSearchWeaknesses, {}],
      [cweSearchAttackPatterns, {}],
      [cweGetView, { id: '1000' }],
    ] as const) {
      expect(definition.input.safeParse({ ...args, limit: 1000 }).success).toBe(true);
      for (const limit of [0, 1001, 1.5])
        expect(definition.input.safeParse({ ...args, limit }).success).toBe(false);
    }
  });

  it('rejects tampered, changed-query and stale-version cursors with recovery', async () => {
    const w = (await search({ limit: 1 })).pagination.nextCursor!;
    const a = (await attacks({ limit: 1 })).pagination.nextCursor!;
    const v = (await view({ id: '1000', limit: 1 })).pagination.nextCursor!;
    const cases = [
      () => runToolContract(cweSearchWeaknesses, { limit: 1, cursor: `${w}.suffix` }),
      () => runToolContract(cweSearchWeaknesses, { limit: 1, cursor: w, filter: 'Bulk' }),
      () => runToolContract(cweSearchWeaknesses, { limit: 2, cursor: w }),
      () => runToolContract(cweSearchAttackPatterns, { limit: 1, cursor: `${a}x` }),
      () =>
        runToolContract(cweSearchAttackPatterns, { limit: 1, cursor: a, includeInactive: true }),
      () => runToolContract(cweSearchAttackPatterns, { limit: 2, cursor: a }),
      () => runToolContract(cweGetView, { id: '1000', limit: 1, cursor: `${v}.suffix` }),
      () => runToolContract(cweGetView, { id: '1001', limit: 1, cursor: v }),
      () => runToolContract(cweGetView, { id: '1000', limit: 2, cursor: v }),
    ];
    for (const call of cases) {
      const wire = await call();
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_cursor' } },
      });
      expect(JSON.stringify(wire.structuredContent)).toContain('without cursor');
      expect(JSON.stringify(wire.content)).toContain('without cursor');
    }
    await disposeCatalogService();
    await load('4.next');
    for (const wire of [
      await runToolContract(cweSearchWeaknesses, { limit: 1, cursor: w }),
      await runToolContract(cweSearchAttackPatterns, { limit: 1, cursor: a }),
      await runToolContract(cweGetView, { id: '1000', limit: 1, cursor: v }),
    ]) {
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_cursor' } },
      });
    }
  });

  it('treats every blank weakness input as unset on both surfaces', async () => {
    const baseW = await runToolContract(cweSearchWeaknesses, {});
    const blankW = await runToolContract(cweSearchWeaknesses, {
      filter: ' ',
      language: ' ',
      technology: ' ',
      abstraction: '',
      consequenceImpact: ' ',
      status: ' ',
      viewId: ' ',
      cursor: ' ',
    });
    expect(blankW.isError).not.toBe(true);
    expect(blankW.structuredContent).toEqual(baseW.structuredContent);
    expect(blankW.content).toEqual(baseW.content);
  });

  it('treats every blank CAPEC input as unset on both surfaces', async () => {
    const baseA = await runToolContract(cweSearchAttackPatterns, {});
    const blankA = await runToolContract(cweSearchAttackPatterns, {
      filter: ' ',
      cweId: ' ',
      attackTechniqueId: ' ',
      abstraction: '',
      severity: ' ',
      likelihood: ' ',
      cursor: ' ',
    });
    expect(blankA.isError).not.toBe(true);
    expect(blankA.structuredContent).toEqual(baseA.structuredContent);
    expect(blankA.content).toEqual(baseA.content);
  });

  it('treats blank view continuation as unset on both surfaces', async () => {
    const baseV = await runToolContract(cweGetView, { id: '1000' });
    const blankV = await runToolContract(cweGetView, { id: '1000', cursor: ' ' });
    expect(blankV.structuredContent).toEqual(baseV.structuredContent);
    expect(blankV.content).toEqual(baseV.content);
  });
});
