/**
 * @fileoverview Search and view contracts through acquired catalog fixtures and both client surfaces.
 * @module tests/tools/list-contract.test
 */
import { readFileSync } from 'node:fs';
import { z } from '@cyanheads/mcp-ts-core';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import fc from 'fast-check';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cweGetHierarchy } from '@/mcp-server/tools/definitions/cwe-get-hierarchy.tool.js';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweListReference } from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchAttackPatterns } from '@/mcp-server/tools/definitions/cwe-search-attack-patterns.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import {
  ATTACK_ID_FORMS,
  batchIds,
  CAPEC_ID,
  CVE_ID_FORMS,
  CWE_ID,
  CWE_ID_FORMS,
  filterSchema,
  firstSentence,
  normalizeAttackId,
  OPTIONAL_ATTACK_ID,
  OPTIONAL_CVE_ID,
  OPTIONAL_CWE_ID,
  parseId,
  VIEW_ID,
  VIEW_ID_FORMS,
} from '@/mcp-server/tools/shared.js';
import { parseCweCatalog } from '@/services/catalog/xml-normalization.js';
import {
  type CatalogClock,
  disposeCatalogService,
  type HttpRequest,
  initCatalogService,
  SOURCE_URLS,
} from '@/services/index.js';
import { parseMarkdown, referenceDefinitions, visibleText } from '../helpers/commonmark.js';
import { expectLinearTime } from '../helpers/cpu-timing.js';

const clock: CatalogClock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
const preview = `First ${'complete '.repeat(60)}sentence.`;
const dotnet =
  "An ASP .NET application must enable custom error pages in order to prevent attackers from mining information from the framework's built-in responses.";
const verb =
  'An attacker modifies the HTTP Verb (e.g. GET, PUT, TRACE, etc.) in order to bypass access restrictions.';
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
const usage = (value: string) => `<Mapping_Notes><Usage>${value}</Usage></Mapping_Notes>`;
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
/** Recorded alternate terms, each with an optional explanation. */
const terms = (...entries: [term: string, description?: string][]) =>
  `<Alternate_Terms>${entries
    .map(
      ([term, description]) =>
        `<Alternate_Term><Term>${term}</Term>${description ? `<Description>${description}</Description>` : ''}</Alternate_Term>`,
    )
    .join('')}</Alternate_Terms>`;
/** One recorded taxonomy mapping; absent parts stay absent, as in the source. */
const taxonomy = (name: string, parts: { id?: string; entry?: string; fit?: string } = {}) =>
  `<Taxonomy_Mapping Taxonomy_Name="${name}">${parts.id ? `<Entry_ID>${parts.id}</Entry_ID>` : ''}${parts.entry ? `<Entry_Name>${parts.entry}</Entry_Name>` : ''}${parts.fit ? `<Mapping_Fit>${parts.fit}</Mapping_Fit>` : ''}</Taxonomy_Mapping>`;
const observed = (reference: string, description: string) =>
  `<Observed_Example><Reference>${reference}</Reference><Description>${description}</Description><Link>https://www.cve.org/CVERecord?id=${reference}</Link></Observed_Example>`;
/**
 * Taxonomy mappings and observed examples on CWE-10, 11, and 12 and on category 900: an Entry_ID in
 * two taxonomies (A1), one repeated within a weakness (Part 4-2), a mapping without an Entry_ID, a
 * CVE cited twice on one weakness, and a non-CVE reference.
 */
const withEvidence = (xml: string) =>
  xml
    .replace(
      '<Usage>Allowed</Usage></Mapping_Notes>',
      `<Usage>Allowed</Usage></Mapping_Notes><Observed_Examples>${observed('CVE-2021-44228', 'Logging library evaluates *lookups* in messages.')}${observed('[REF-1374]', 'Not a CVE.')}</Observed_Examples><Taxonomy_Mappings>${taxonomy('CERT C Secure Coding', { id: 'ARR30-C', entry: 'Do not form or use out-of-bounds pointers or array subscripts', fit: 'CWE More Abstract' })}${taxonomy('OWASP Top Ten 2004', { id: 'A1', entry: 'Unvalidated Input', fit: 'CWE More Specific' })}${taxonomy('7 Pernicious Kingdoms', { entry: 'Buffer Overflow' })}</Taxonomy_Mappings>`,
    )
    .replace(
      '<Usage>Allowed-with-Review</Usage></Mapping_Notes>',
      `<Usage>Allowed-with-Review</Usage></Mapping_Notes><Observed_Examples>${observed('CVE-2014-1266', 'Duplicate goto skips a check.')}${observed('CVE-2021-44228', 'First citation.')}${observed('CVE-2021-44228', 'Second citation.')}</Observed_Examples><Taxonomy_Mappings>${taxonomy('OWASP Top Ten 2007', { id: 'A1', entry: 'Cross Site Scripting (XSS)', fit: 'CWE More Specific' })}${taxonomy('ISA/IEC 62443', { id: 'Part 4-2', entry: 'Req CR 1.1' })}${taxonomy('ISA/IEC 62443', { id: 'Part 3-3', entry: 'Req SR 1.1' })}${taxonomy('ISA/IEC 62443', { id: 'Part 4-2', entry: 'Req CR 2.1' })}</Taxonomy_Mappings>`,
    )
    .replace(
      '<Usage>Discouraged</Usage></Mapping_Notes>',
      `<Usage>Discouraged</Usage></Mapping_Notes><Taxonomy_Mappings>${taxonomy('CERT C Secure Coding', { id: 'ARR30-C', fit: 'Imprecise' })}</Taxonomy_Mappings>`,
    )
    .replace(
      '<Summary>Grouping.</Summary>',
      `<Summary>Grouping.</Summary><Taxonomy_Mappings>${taxonomy('Category Taxonomy', { id: 'ARR00-C' })}${taxonomy('CERT C Secure Coding', { id: 'ARR00-C' })}</Taxonomy_Mappings>`,
    );
function catalogs(version = '4.list') {
  const rows = [
    weakness(
      30,
      'Ordinary',
      'Ordinary description.',
      '<Extended_Description>needle alpha extended.</Extended_Description>',
    ),
    weakness(20, 'Ordinary', 'needle alpha description.'),
    weakness(
      10,
      'needle alpha',
      `${preview} Second sentence.`,
      platform + child(900) + usage('Allowed'),
    ),
    weakness(11, 'needle alpha', 'Other sentence.', child(10) + usage('Allowed-with-Review')),
    weakness(12, 'needle', 'alpha split across fields.', child(11) + usage('Discouraged')),
    weakness(
      13,
      'Off view',
      'Outside.',
      child(10, 1001) + usage('Prohibited'),
      'Deprecated',
      'Class',
    ),
    weakness(14, 'Token break', `${dotnet} Second sentence.`),
    weakness(15, 'Basic XSS', 'Basic.'),
    weakness(16, 'Encoding', 'Missing xss encoding.'),
    weakness(
      50,
      'Cross-site Scripting',
      'Scripting.',
      terms(['XSS', 'Common acronym.'], ['Reflected XSS / Type 1']),
    ),
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
  const cwe = `<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="${version}" Date="2026-04-30"><Weaknesses>${rows}</Weaknesses><Categories><Category ID="900" Name="Category" Status="Stable"><Summary>Grouping.</Summary><Relationships>${member(10)}${member(901)}</Relationships></Category><Category ID="901" Name="Nested" Status="Stable"><Summary>Nested grouping.</Summary><Relationships>${member(900)}${member(20)}</Relationships></Category></Categories><Views><View ID="1000" Name="Navigation" Type="Graph" Status="Stable"><Objective>First objective line.\nSecond objective line.</Objective><Audience><Stakeholder><Type>Developer</Type><Description>Build software.</Description></Stakeholder></Audience><Members>${direct}</Members></View><View ID="1001" Name="Filtered" Type="Implicit" Status="Draft"><Filter>/Weakness_Catalog/*/*[@Status='Deprecated']</Filter></View><View ID="1002" Name="Unevaluated" Type="Implicit" Status="Draft"><Filter>/Weakness_Catalog/Weaknesses/Weakness[@Likelihood='High']</Filter></View><View ID="1003" Name="Retired" Type="Implicit" Status="Deprecated"><Filter>/Weakness_Catalog[false()]</Filter></View></Views></Weakness_Catalog>`;
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
    pattern(5, 'Open bracket', `${verb} Some environments differ.`),
    pattern(
      94,
      'Adversary in the Middle',
      'Intercepts traffic.',
      terms(['Man-in-the-Middle / MITM']),
    ),
    pattern(20, 'Interception', 'Uses a mitm proxy.'),
    pattern(60, 'MITM proxy', 'Relays traffic.', terms(['MITM'])),
    ...Array.from({ length: 105 }, (_, index) =>
      pattern(200 + index, `Bulk ${index}`, 'Bulk description.'),
    ),
  ].join('')}</Attack_Patterns></Attack_Pattern_Catalog>`;
  return { cwe, capec };
}
async function load(
  version?: string,
  editCwe: (xml: string) => string = (xml) => xml,
  editCapec: (xml: string) => string = (xml) => xml,
) {
  const xml = catalogs(version);
  const request: HttpRequest = async (url) => {
    if (url === SOURCE_URLS.cwe)
      return new Response(zipSync({ 'cwe.xml': strToU8(editCwe(xml.cwe)) }));
    if (url === SOURCE_URLS.capec) return new Response(editCapec(xml.capec));
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
type Wire = Awaited<ReturnType<typeof runToolContract>>;
/** Every rendered `content[]` line, as a client that forwards the text sees it. */
const lines = (wire: Wire) =>
  wire.content.flatMap((block) => (block.type === 'text' ? block.text.split('\n') : []));
/** Each value rendered under `**key**`, copied out of `content[]` without its quote marker. */
const copied = (wire: Wire, key: string) =>
  lines(wire).flatMap((line, index, all) =>
    line === `**${key}**` ? [all[index + 2]?.replace(/^> /, '') ?? ''] : [],
  );
/** The continuation as an agent copies it out of `content[]`, backticks removed. */
function copiedCursor(wire: Wire): string | undefined {
  const rendered = lines(wire);
  const label = rendered.indexOf('**nextCursor**');
  return label === -1 ? undefined : rendered[label + 2]?.replace(/^> /, '').replace(/`/g, '');
}
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

  it('previews the complete first sentence through both search tools', async () => {
    for (const [wire, sentence] of [
      [await runToolContract(cweSearchWeaknesses, { filter: 'token break' }), dotnet],
      [await runToolContract(cweSearchAttackPatterns, { filter: 'open bracket' }), verb],
    ] as const) {
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        results: [{ descriptionPreview: sentence }],
        totalCount: 1,
      });
      expect(lines(wire)).toContain(`> ${sentence}`);
    }
  });

  it('ranks a recorded alternate term with name matches through both search tools and surfaces', async () => {
    const copiedIds = (wire: Wire) =>
      lines(wire).flatMap((line, index, all) =>
        line === '**id**' ? [all[index + 2]?.replace(/^> /, '')] : [],
      );
    for (const [definition, filter, expected] of [
      [cweSearchWeaknesses, 'XSS', ['CWE-15', 'CWE-50', 'CWE-16']],
      [cweSearchWeaknesses, 'type 1 reflected', ['CWE-50']],
      [cweSearchAttackPatterns, 'mitm', ['CAPEC-60', 'CAPEC-94', 'CAPEC-20']],
    ] as const) {
      const wire = await runToolContract(definition, { filter });
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({ totalCount: expected.length });
      const { results } = wire.structuredContent as { results: { id: string }[] };
      expect(results.map((row) => row.id)).toEqual(expected);
      expect(copiedIds(wire)).toEqual(expected);
    }
    // A term's explanation is returned by cwe_get_weakness but never searched.
    const explanation = await runToolContract(cweSearchWeaknesses, { filter: 'acronym' });
    expect(explanation.structuredContent).toMatchObject({ results: [], totalCount: 0 });
    expect(lines(explanation)).toContain(
      '> No weakness matched the text filter "acronym". Repeat cwe_search_weaknesses with a different term.',
    );
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
      const { guidance, reason } = wire.structuredContent as { guidance: string; reason: string };
      expect(lines(wire)).toContain(`> ${guidance}`);
      expect(lines(wire)).toContain(`> ${reason}`);
      expect(lines(wire)).toContain(`> CWE-${id}`);
    },
  );

  it('searches a filter-defined view through its source filter and routes the view there', async () => {
    const filter = "/Weakness_Catalog/*/*[@Status='Deprecated']";
    const wire = await runToolContract(cweGetView, { id: '1001' });
    expect(wire.structuredContent).toMatchObject({
      found: true,
      filterDefinition: filter,
      members: [],
      guidance:
        'This view has no recorded members: its source filter (filterDefinition) defines its membership. Call cwe_search_weaknesses with viewId CWE-1001 for the weaknesses it selects.',
    });
    // content[] carries the XPath as literal text: a CommonMark parse yields it back exactly.
    const rendered = lines(wire);
    expect(parseMarkdown(rendered[rendered.indexOf('**filterDefinition**') + 2] ?? '').text).toBe(
      filter,
    );
    const { guidance } = wire.structuredContent as { guidance: string };
    expect(rendered).toContain(`> ${guidance}`);

    const selected = await runToolContract(cweSearchWeaknesses, { viewId: '1001' });
    expect(selected.structuredContent).toMatchObject({
      results: [{ id: 'CWE-13', status: 'Deprecated' }],
      totalCount: 1,
      appliedFilters: { viewId: 'CWE-1001' },
    });
    expect(selected.structuredContent).not.toHaveProperty('notice');

    // Zero hits name the view as filter-defined; an unevaluated filter is disclosed.
    const unevaluated =
      'View CWE-1002 is defined by a source filter (filterDefinition) with a part this server does not evaluate, so the filter selected no weaknesses here; this does not establish that none belong to the view. Call cwe_get_view to read the filter, or repeat cwe_search_weaknesses';
    const members =
      'No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or repeat cwe_search_weaknesses';
    for (const [args, expected] of [
      [
        { viewId: '1001', status: 'stable' },
        'No weakness that the source filter of view CWE-1001 selects matches the other filters. Call cwe_get_view to read its filterDefinition, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      [
        { viewId: '1003' },
        'The source filter of view CWE-1003 selects no weaknesses. Call cwe_get_view to read its filterDefinition.',
      ],
      // A filter that selects nothing explains the miss whatever the other filters.
      [
        { viewId: '1003', status: 'stable' },
        'The source filter of view CWE-1003 selects no weaknesses. Call cwe_get_view to read its filterDefinition.',
      ],
      [{ viewId: '1002' }, `${unevaluated} without viewId.`],
      [{ viewId: '1002', status: 'deprecated' }, `${unevaluated} without viewId.`],
      // Without viewId the text still matches nothing, so the repeat drops filters instead.
      [{ viewId: '1002', filter: 'zzzz' }, `${unevaluated} with fewer filters.`],
      // A view with recorded members keeps its zero-hit notice.
      [{ viewId: '1000', status: 'Deprecated' }, `${members} without viewId.`],
      [{ viewId: '1000', filter: 'zzzz' }, `${members} with fewer filters.`],
    ] as const) {
      const empty = await runToolContract(cweSearchWeaknesses, args);
      expect(empty.isError).not.toBe(true);
      expect(empty.structuredContent).toMatchObject({
        results: [],
        totalCount: 0,
        notice: expected,
      });
      expect(copied(empty, 'notice').map((line) => parseMarkdown(line).text)).toEqual([expected]);
      expect(lines(empty)).toContain(`> ${expected}`);
      // A suggested repeat without viewId returns weaknesses.
      if (expected.endsWith('without viewId.')) {
        const { viewId: _viewId, ...others } = args;
        expect((await search(others)).pagination.total).toBeGreaterThan(0);
      }
    }
  });

  it('says when a view’s recorded membership reaches no weakness', async () => {
    await disposeCatalogService();
    await load(undefined, (xml) =>
      xml.replace(
        '</Views>',
        '<View ID="1004" Name="Retired" Type="Explicit" Status="Deprecated"><Objective>Retired.</Objective></View><View ID="1005" Name="Groups" Type="Graph" Status="Draft"><Objective>Groups only.</Objective><Members><Has_Member CWE_ID="1004" View_ID="1005"/></Members></View></Views>',
      ),
    );
    for (const viewId of ['1004', '1005'])
      for (const args of [{ viewId }, { viewId, status: 'stable' }]) {
        const expected = `View CWE-${viewId} records no membership that reaches a weakness; this does not establish that none belong to it. Call cwe_get_view to read the view.`;
        const wire = await runToolContract(cweSearchWeaknesses, args);
        expect(wire.isError).not.toBe(true);
        expect(wire.structuredContent).toMatchObject({
          results: [],
          totalCount: 0,
          notice: expected,
        });
        expect(copied(wire, 'notice').map((line) => parseMarkdown(line).text)).toEqual([expected]);
        expect(lines(wire)).toContain(`> ${expected}`);
      }
  });

  it('routes a filter the server does not evaluate to its source text', async () => {
    const wire = await runToolContract(cweGetView, { id: '1002' });
    const guidance =
      'This view has no recorded members: its source filter (filterDefinition) defines its membership, but the filter has a part this server does not evaluate, so cwe_search_weaknesses with viewId CWE-1002 returns no weaknesses and says so. Read filterDefinition for the records it selects.';
    expect(wire.structuredContent).toMatchObject({
      found: true,
      filterDefinition: "/Weakness_Catalog/Weaknesses/Weakness[@Likelihood='High']",
      members: [],
      guidance,
    });
    expect(copied(wire, 'guidance').map((line) => parseMarkdown(line).text)).toEqual([guidance]);
    expect(lines(wire)).toContain(`> ${guidance}`);
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

  it('names the failing field and value, and lists a short vocabulary, in content[] alone', async () => {
    const cases = [
      [
        cweSearchWeaknesses,
        { language: 'Imaginary' },
        'language',
        'Unknown language "Imaginary"; supported values: C, Compiled.',
        ['C', 'Compiled'],
      ],
      [
        cweSearchWeaknesses,
        { technology: ' imaginary ' },
        'technology',
        'Unknown technology "imaginary"; supported values: Server, Web Server.',
        ['Server', 'Web Server'],
      ],
      [
        cweSearchWeaknesses,
        { consequenceImpact: 'Imaginary' },
        'consequenceImpact',
        'Unknown consequenceImpact "Imaginary"; supported values: Modify Data.',
        ['Modify Data'],
      ],
      [
        cweSearchWeaknesses,
        { status: 'Imaginary' },
        'status',
        'Unknown status "Imaginary"; supported values: Deprecated, Stable.',
        ['Deprecated', 'Stable'],
      ],
      [
        cweSearchAttackPatterns,
        { severity: 'critical' },
        'severity',
        'Unknown severity "critical"; supported values: High.',
        ['High'],
      ],
      [
        cweSearchAttackPatterns,
        { likelihood: 'Imaginary' },
        'likelihood',
        'Unknown likelihood "Imaginary"; supported values: Medium.',
        ['Medium'],
      ],
      // Caller text is quoted as literal text: its parse is the value, never emphasis or a link.
      [
        cweSearchAttackPatterns,
        { severity: '*crit* [x](y)' },
        'severity',
        'Unknown severity "*crit* [x](y)"; supported values: High.',
        ['High'],
      ],
    ] as const;
    for (const [definition, args, field, visible, supported] of cases) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError).toBe(true);
      const { error } = wire.structuredContent as {
        error: { message: string; data: Record<string, unknown> };
      };
      expect(parseMarkdown(error.message).text).toBe(visible);
      expect(parseMarkdown(error.message).nodes).not.toContain('link');
      expect(error.data).toMatchObject({ reason: 'unknown_filter', field, supported });
      expect(error.data.value).toBe(Object.values(args)[0]?.trim());
      expect(error.data).not.toHaveProperty('vocabulary');
      expect(lines(wire)).toContain(`Error: ${error.message}`);
    }
    for (const [viewId, visible] of [
      ['10', 'viewId CWE-10 is a weakness, not a CWE view.'],
      ['cwe 900', 'viewId CWE-900 is a category, not a CWE view.'],
      ['999999', 'viewId CWE-999999 is not a CWE view in the loaded catalog.'],
    ] as const) {
      const wire = await runToolContract(cweSearchWeaknesses, { viewId });
      expect(wire.structuredContent).toMatchObject({
        error: {
          message: visible,
          data: { reason: 'unknown_filter', field: 'viewId', value: visible.split(' ')[1] },
        },
      });
      expect(lines(wire)).toContain(`Error: ${visible}`);
    }
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
    // Neither token matches on its own here, so fewer terms could not return a weakness.
    expect(JSON.stringify(textMiss.content)).toContain('different terms');
    expect(JSON.stringify(filterMiss.content)).toContain('Deprecated');
  });

  it('quotes caller and catalog text in zero-hit notices as literal text on both surfaces', async () => {
    const cases = [
      [
        cweSearchWeaknesses,
        { filter: '*x*', status: 'stable' },
        'No weaknesses matched the applied filters (filter: *x*, status: Stable). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: '_x_ [y](z)', severity: 'high' },
        'No CAPEC patterns matched the applied filters (includeInactive: false, filter: _x_ [y](z), severity: High). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_attack_patterns with fewer filters. Repeat cwe_search_attack_patterns with includeInactive true to include Deprecated and Obsolete patterns.',
      ],
      // Rendered at a paragraph start, this filter could define a link that the notice then uses.
      [
        cweSearchWeaknesses,
        { filter: '[a](b]: javascript:alert(1)', status: 'stable' },
        'No weaknesses matched the applied filters (filter: [a](b]: javascript:alert(1), status: Stable). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: '[a](b]: javascript:alert(1)' },
        'No CAPEC pattern matched every token of the text filter "[a](b]: javascript:alert(1)". Repeat cwe_search_attack_patterns with different terms.',
      ],
    ] as const;
    for (const [definition, args, visible] of cases) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError).not.toBe(true);
      // The whole document defines no link reference and links nowhere.
      const document = wire.content
        .map((block) => (block.type === 'text' ? block.text : ''))
        .join('');
      expect(referenceDefinitions(document)).toEqual([]);
      expect(parseMarkdown(document).nodes).not.toContain('link');
      const { notice, appliedFilters } = wire.structuredContent as {
        notice: string;
        appliedFilters: { filter: string };
      };
      /** The notice is CommonMark prose whose parse is the literal text; content[] embeds it. */
      const parsed = parseMarkdown(notice);
      expect(parsed.text).toBe(visible);
      expect(parsed.nodes.every((node) => ['document', 'paragraph', 'text'].includes(node))).toBe(
        true,
      );
      expect(lines(wire)).toContain(`> ${notice}`);
      // The plain filter echo keeps the caller's text and renders it as literal text.
      expect(appliedFilters.filter).toBe(args.filter);
      const rendered = lines(wire);
      expect(parseMarkdown(rendered[rendered.indexOf('**filter**') + 2] ?? '').text).toBe(
        args.filter,
      );
    }
  });

  it('echoes a zero-hit text filter and suggests only a repeat that can change the result, on every filter tool', async () => {
    const cases = [
      // One token: fewer terms would drop the filter and browse.
      [
        cweSearchWeaknesses,
        { filter: 'Acronym' },
        'No weakness matched the text filter "acronym". Repeat cwe_search_weaknesses with a different term.',
      ],
      // A token that matches on its own makes fewer terms a repeat that returns weaknesses.
      [
        cweSearchWeaknesses,
        { filter: ' needle\tNONEXISTENT ' },
        'No weakness matched every token of the text filter "needle nonexistent". Repeat cwe_search_weaknesses with fewer terms.',
      ],
      // No token matches on its own, so no subset of them can match.
      [
        cweSearchWeaknesses,
        { filter: '*x* [a](b]: javascript:alert(1)' },
        'No weakness matched every token of the text filter "*x* [a](b]: javascript:alert(1)". Repeat cwe_search_weaknesses with different terms.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: '_x_' },
        'No CAPEC pattern matched the text filter "_x_". Repeat cwe_search_attack_patterns with a different term.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: 'needle zzqx' },
        'No CAPEC pattern matched every token of the text filter "needle zzqx". Repeat cwe_search_attack_patterns with fewer terms.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: 'zzqx qqzz', includeInactive: true },
        'No CAPEC pattern matched every token of the text filter "zzqx qqzz". Repeat cwe_search_attack_patterns with different terms.',
      ],
      // Only excluded patterns match, so includeInactive is the repeat that returns them.
      [
        cweSearchAttackPatterns,
        { filter: 'obsolete' },
        'Only Deprecated or Obsolete patterns, which are excluded by default, matched the text filter "obsolete". Repeat cwe_search_attack_patterns with includeInactive true to include Deprecated and Obsolete patterns.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: 'inactive description' },
        'Only Deprecated or Obsolete patterns, which are excluded by default, matched every token of the text filter "inactive description". Repeat cwe_search_attack_patterns with includeInactive true to include Deprecated and Obsolete patterns.',
      ],
      [
        cweListReference,
        { topic: 'workflow', filter: 'zzqx' },
        'No reference item matched the filter "zzqx". Repeat cwe_list_reference without filter to list every item in topic workflow.',
      ],
      [
        cweListReference,
        { topic: 'workflow', filter: 'ROOT nonexistent' },
        'No reference item matched every token of the filter "root nonexistent". Repeat cwe_list_reference with fewer terms, or without filter to list every item in topic workflow.',
      ],
      [
        cweListReference,
        { topic: 'workflow', filter: '[x]: y zzqx' },
        'No reference item matched every token of the filter "[x]: y zzqx". Repeat cwe_list_reference without filter to list every item in topic workflow.',
      ],
      // An empty topic has nothing a repeat could return, with or without a filter.
      [
        cweListReference,
        { topic: 'mitigation_phases' },
        'Topic mitigation_phases lists no items in the loaded catalogs.',
      ],
      [
        cweListReference,
        { topic: 'mitigation_phases', filter: 'design' },
        'Topic mitigation_phases lists no items in the loaded catalogs.',
      ],
    ] as const;
    for (const [definition, args, visible] of cases) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError, JSON.stringify(args)).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({ totalCount: 0 });
      const { notice } = wire.structuredContent as { notice: string };
      // The notice is prose whose parse is the literal text; the filter forms no link or emphasis.
      const parsed = parseMarkdown(notice);
      expect(parsed.text, JSON.stringify(args)).toBe(visible);
      expect(parsed.nodes.every((node) => ['document', 'paragraph', 'text'].includes(node))).toBe(
        true,
      );
      const document = wire.content
        .map((block) => (block.type === 'text' ? block.text : ''))
        .join('');
      expect(referenceDefinitions(document)).toEqual([]);
      expect(lines(wire)).toContain(`> ${notice}`);
    }
  });

  it('matches text tokens at word starts only, on every filter tool and every zero-hit re-search', async () => {
    const zeroHits = [
      // CWE-14 holds "information" and CAPEC-20 "Interception": the tokens occur only inside words.
      [
        cweSearchWeaknesses,
        { filter: 'format' },
        'No weakness matched the text filter "format". Repeat cwe_search_weaknesses with a different term.',
      ],
      [
        cweSearchWeaknesses,
        { filter: 'zzqx format' },
        'No weakness matched every token of the text filter "zzqx format". Repeat cwe_search_weaknesses with different terms.',
      ],
      // The view's re-search of the other filters alone applies the same rule.
      [
        cweSearchWeaknesses,
        { filter: 'format', viewId: '1000' },
        'No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: 'cept' },
        'No CAPEC pattern matched the text filter "cept". Repeat cwe_search_attack_patterns with a different term.',
      ],
      [
        cweSearchAttackPatterns,
        { filter: 'zzqx cept' },
        'No CAPEC pattern matched every token of the text filter "zzqx cept". Repeat cwe_search_attack_patterns with different terms.',
      ],
      // So does the re-search that includes inactive patterns.
      [
        cweSearchAttackPatterns,
        { filter: 'solete' },
        'No CAPEC pattern matched the text filter "solete". Repeat cwe_search_attack_patterns with a different term.',
      ],
      [
        cweListReference,
        { topic: 'views', filter: 'tered' },
        'No reference item matched the filter "tered". Repeat cwe_list_reference without filter to list every item in topic views.',
      ],
      [
        cweListReference,
        { topic: 'views', filter: 'zzqx tered' },
        'No reference item matched every token of the filter "zzqx tered". Repeat cwe_list_reference without filter to list every item in topic views.',
      ],
    ] as const;
    for (const [definition, args, visible] of zeroHits) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError, JSON.stringify(args)).not.toBe(true);
      expect(wire.structuredContent, JSON.stringify(args)).toMatchObject({ totalCount: 0 });
      const { notice } = wire.structuredContent as { notice: string };
      expect(parseMarkdown(notice).text, JSON.stringify(args)).toBe(visible);
      expect(lines(wire)).toContain(`> ${notice}`);
    }
    // The whole word still matches, on both surfaces.
    for (const [definition, args, key, expected] of [
      [cweSearchWeaknesses, { filter: 'information' }, 'id', ['CWE-14']],
      [cweSearchAttackPatterns, { filter: 'interception' }, 'id', ['CAPEC-20']],
      [cweListReference, { topic: 'views', filter: 'filtered' }, 'label', ['Filtered']],
    ] as const) {
      const wire = await runToolContract(definition, args);
      expect(wire.structuredContent).toMatchObject({ totalCount: expected.length });
      expect(copied(wire, key)).toEqual(expected);
    }
    // A camelCase hump is a word start in a label too; a lowercase run is not.
    await disposeCatalogService();
    await load(undefined, (xml) =>
      xml.replace(
        '<Language Name="C" Class="Compiled"/>',
        '<Language Name="C" Class="Compiled"/><Language Name="JavaScript"/><Language Name="Typescript"/>',
      ),
    );
    const platforms = async (filter: string) => {
      const wire = await runToolContract(cweListReference, { topic: 'platforms', filter });
      expect(wire.isError, filter).not.toBe(true);
      return copied(wire, 'label');
    };
    expect(await platforms('script')).toEqual(['JavaScript']);
    expect(await platforms('javascript')).toEqual(['JavaScript']);
    expect(await platforms('avascript')).toEqual([]);
  });

  it('uses the bounded prefix rule in search tiers, reference labels and fewer-term notices on both surfaces', async () => {
    await disposeCatalogService();
    await load(
      undefined,
      (xml) =>
        xml
          .replace('Name="Navigation"', 'Name="Untrusted Navigation"')
          .replace(
            '</Weaknesses>',
            `${weakness(2, 'Untrusted', 'Other.')}${weakness(1, 'Ordinary', 'Untrusted description.')}${weakness(3, 'Other', 'Other.', terms(['Misconfigured']))}</Weaknesses>`,
          ),
      (xml) =>
        xml.replace(
          '</Attack_Patterns>',
          `${pattern(1, 'Untrusted', 'Other.')}${pattern(6, 'Other', 'Untrusted description.')}${pattern(7, 'Other', 'Other.', terms(['Misconfigured']))}</Attack_Patterns>`,
        ),
    );
    for (const [definition, args, expected] of [
      [cweSearchWeaknesses, { filter: 'trusted' }, ['CWE-2', 'CWE-1']],
      [cweSearchWeaknesses, { filter: 'config' }, ['CWE-3']],
      [cweSearchAttackPatterns, { filter: 'trusted' }, ['CAPEC-1', 'CAPEC-6']],
      [cweSearchAttackPatterns, { filter: 'config' }, ['CAPEC-7']],
      [cweListReference, { topic: 'views', filter: 'trusted' }, ['CWE-1000']],
    ] as const) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError).not.toBe(true);
      expect(copied(wire, 'id')).toEqual(expected);
      expect(wire.structuredContent).toMatchObject({ totalCount: expected.length });
      const empty = await runToolContract(definition, { ...args, filter: `${args.filter} zzqx` });
      expect(empty.structuredContent).toMatchObject({
        totalCount: 0,
        notice: expect.stringContaining('fewer terms'),
      });
      for (const surface of [empty.content, empty.structuredContent])
        expect(JSON.stringify(surface)).toContain('fewer terms');
    }
  });

  it('accepts a status only categories carry, returns no rows, and says why on both surfaces', async () => {
    await disposeCatalogService();
    await load(undefined, (xml) =>
      xml.replace(
        '<Category ID="901" Name="Nested" Status="Stable">',
        '<Category ID="901" Name="Nested" Status="Obsolete">',
      ),
    );
    const categoryOnly =
      'Status Obsolete occurs only on CWE categories, which cwe_search_weaknesses excludes. Call cwe_list_reference with topic filter_values for the statuses weaknesses carry.';
    for (const [args, visible] of [
      [{ status: 'obsolete' }, categoryOnly],
      [{ status: 'Obsolete', filter: 'needle', viewId: '1000' }, categoryOnly],
      [{ status: ' OBSOLETE ', language: 'c', mappingUsage: 'allowed' }, categoryOnly],
      // An unevaluated view filter is still disclosed first.
      [
        { status: 'obsolete', viewId: '1002' },
        `View CWE-1002 is defined by a source filter (filterDefinition) with a part this server does not evaluate, so the filter selected no weaknesses here; this does not establish that none belong to the view. Call cwe_get_view to read the filter, or repeat cwe_search_weaknesses with fewer filters. ${categoryOnly}`,
      ],
    ] as const) {
      const wire = await runToolContract(cweSearchWeaknesses, args);
      expect(wire.isError, JSON.stringify(args)).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        results: [],
        totalCount: 0,
        appliedFilters: { status: 'Obsolete' },
      });
      const { notice } = wire.structuredContent as { notice: string };
      expect(parseMarkdown(notice).text, JSON.stringify(args)).toBe(visible);
      expect(lines(wire)).toContain(`> ${notice}`);
      expect(copied(wire, 'status')).toEqual(['Obsolete']);
    }
    // An unknown status lists the statuses weaknesses carry, never the category-only one.
    const unknown = await runToolContract(cweSearchWeaknesses, { status: 'Foo' });
    const message = 'Unknown status "Foo"; supported values: Deprecated, Stable.';
    expect(unknown.structuredContent).toMatchObject({
      error: {
        message,
        data: { reason: 'unknown_filter', field: 'status', supported: ['Deprecated', 'Stable'] },
      },
    });
    expect(lines(unknown)).toContain(`Error: ${message}`);
    // A weakness status filters as before.
    expect((await search({ status: 'deprecated' })).results.map((row) => row.id)).toEqual([
      'CWE-13',
    ]);
  });

  it('rejects a filter holding a control character that catalog text cannot contain, on every filter tool', async () => {
    // XML 1.0 text holds no C0 control other than whitespace, so such a filter could never match.
    const schema = filterSchema('Filter.');
    for (let code = 0; code < 0x20; code++)
      expect(
        schema.safeParse(`a${String.fromCharCode(code)}b`).success,
        `U+${code.toString(16).padStart(4, '0')}`,
      ).toBe(code >= 0x09 && code <= 0x0d);
    for (const value of ['a\u007fb', 'a\u0085b', 'a\u009fb', 'a b', 'a�b', '[a](b]: c'])
      expect(schema.safeParse(value).success, JSON.stringify(value)).toBe(true);
    // Each tool rejects before its handler runs and names the field and the rule on both surfaces.
    for (const [definition, args] of [
      [cweSearchWeaknesses, { filter: 'needle\u0000alpha', status: 'stable' }],
      [cweSearchAttackPatterns, { filter: 'needle\u001f' }],
      [cweListReference, { topic: 'workflow', filter: '\u0008root' }],
    ] as const) {
      const wire = await runToolContract(definition, args);
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { code: -32602, data: { reason: 'invalid_arguments' } },
      });
      for (const surface of [wire.content, wire.structuredContent])
        expect(JSON.stringify(surface)).toContain(
          'filter: Remove control characters U+0000–U+0008 and U+000E–U+001F',
        );
    }
  });

  it('keeps reading whitespace controls as token separators and other code points as filter text', async () => {
    for (const definition of [cweSearchWeaknesses, cweSearchAttackPatterns]) {
      const wire = await runToolContract(definition, { filter: '\u000bneedle\u000calpha' });
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({ appliedFilters: { filter: 'needle alpha' } });
    }
    for (const filter of ['needle\u007f', 'needle\u0085', 'needle\u009f', 'needle�'])
      expect(await runToolContract(cweSearchWeaknesses, { filter })).toMatchObject({
        structuredContent: { appliedFilters: { filter }, totalCount: 0 },
      });
  });

  it('caps pages at 100, accepts a submitted ceiling of 1000 and continues the remaining source order', async () => {
    const w = await runToolContract(cweSearchWeaknesses, { filter: 'Bulk', limit: 1000 });
    const a = await runToolContract(cweSearchAttackPatterns, { filter: 'Bulk', limit: 101 });
    const v = await runToolContract(cweGetView, { id: '1000', limit: 101 });
    for (const wire of [w, a, v]) {
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        pagination: { hasMore: true },
        truncated: true,
        cap: 100,
        notice: expect.stringContaining('capped at 100'),
      });
      expect(JSON.stringify(wire.content)).toContain('capped at 100');
    }
    for (const kind of ['weakness', 'attack', 'view'] as const) {
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const args = { filter: 'Bulk', limit: 101, cursor };
        const wire =
          kind === 'weakness'
            ? await runToolContract(cweSearchWeaknesses, args)
            : kind === 'attack'
              ? await runToolContract(cweSearchAttackPatterns, args)
              : await runToolContract(cweGetView, { id: '1000', limit: 101, cursor });
        expect(wire.isError).not.toBe(true);
        expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(24000);
        const data = wire.structuredContent as {
          results?: { id: string }[];
          members?: { id: string }[];
          totalCount: number;
          pagination: { total: number; shown: number; nextCursor?: string };
        };
        const rows = data.results ?? data.members ?? [];
        const total = kind === 'view' ? 108 : 105;
        expect(data.pagination.total).toBe(total);
        expect(data.totalCount).toBe(total);
        expect(data.pagination.shown).toBe(rows.length);
        expect(rows.length).toBeGreaterThan(0);
        expect(rows.length).toBeLessThanOrEqual(100);
        for (const row of rows) expect(lines(wire)).toContain(`> ${row.id}`);
        seen.push(...rows.map((row) => row.id));
        // Continue with the cursor exactly as a content[]-only agent copies it.
        cursor = copiedCursor(wire);
        expect(cursor).toBe(data.pagination.nextCursor);
        expect(seen.length).toBeLessThanOrEqual(total);
      } while (cursor);
      expect(seen).toEqual(
        kind === 'view'
          ? [
              'CWE-900',
              'CWE-30',
              'CWE-10',
              ...Array.from({ length: 105 }, (_, i) => `CWE-${304 - i}`),
            ]
          : Array.from(
              { length: 105 },
              (_, i) => `${kind === 'weakness' ? 'CWE' : 'CAPEC'}-${200 + i}`,
            ),
      );
    }
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
      mappingUsage: ' ',
      taxonomyName: ' ',
      taxonomyEntryId: ' ',
      observedCveId: ' ',
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

  it('shows each weakness mapping usage and filters by it as it does by status, on both surfaces', async () => {
    const base = await runToolContract(cweSearchWeaknesses, { filter: 'needle alpha' });
    expect(base.isError).not.toBe(true);
    const rows = (base.structuredContent as { results: Record<string, unknown>[] }).results;
    expect(rows.map((row) => [row.id, row.mappingUsage])).toEqual([
      ['CWE-10', 'Allowed'],
      ['CWE-11', 'Allowed-with-Review'],
      ['CWE-20', undefined],
      ['CWE-12', 'Discouraged'],
      ['CWE-30', undefined],
    ]);
    expect(rows[2]).not.toHaveProperty('mappingUsage');
    const rendered = lines(base).filter(Boolean);
    const first = rendered.indexOf('**abstraction**');
    expect(rendered.slice(first, first + 5)).toEqual([
      '**abstraction**',
      '> Base',
      '**mappingUsage**',
      '> Allowed',
      '**sourceUrl**',
    ]);
    const shown = rendered.flatMap((line, index) =>
      line === '**mappingUsage**' ? [parseMarkdown(rendered[index + 1] ?? '').text] : [],
    );
    expect(shown).toEqual(['Allowed', 'Allowed-with-Review', 'Discouraged']);

    const filtered = await runToolContract(cweSearchWeaknesses, {
      mappingUsage: ' ALLOWED-with-review ',
    });
    expect(filtered.isError).not.toBe(true);
    expect(filtered.structuredContent).toMatchObject({
      results: [{ id: 'CWE-11', mappingUsage: 'Allowed-with-Review' }],
      appliedFilters: { mappingUsage: 'Allowed-with-Review', limit: 20 },
      totalCount: 1,
    });
    // The row and the applied-filter echo both copy back as the canonical value.
    const echoes = lines(filtered).flatMap((line, index, all) =>
      line === '**mappingUsage**' ? [all[index + 2]?.replace(/^> /, '') ?? ''] : [],
    );
    expect(echoes).toEqual(['Allowed-with-Review', 'Allowed-with-Review']);
    expect(
      (await search({ mappingUsage: 'prohibited', status: 'DEPRECATED' })).results.map(
        (row) => row.id,
      ),
    ).toEqual(['CWE-13']);

    // Blank is unset: the response is the unfiltered one.
    const unfiltered = await runToolContract(cweSearchWeaknesses, {});
    const blank = await runToolContract(cweSearchWeaknesses, { mappingUsage: ' \n ' });
    expect(blank.isError).not.toBe(true);
    expect(blank.structuredContent).toEqual(unfiltered.structuredContent);
    expect(blank.content).toEqual(unfiltered.content);

    // No fuzzy matching: spaces for hyphens, other casing of a different word, or a prefix fail.
    for (const mappingUsage of ['Allowed with Review', 'Allowed-With-Reviews', 'allow']) {
      const wire = await runToolContract(cweSearchWeaknesses, { mappingUsage });
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: {
          message: `Unknown mappingUsage "${mappingUsage}"; supported values: Allowed, Allowed-with-Review, Discouraged, Prohibited.`,
          data: {
            reason: 'unknown_filter',
            field: 'mappingUsage',
            value: mappingUsage,
            supported: ['Allowed', 'Allowed-with-Review', 'Discouraged', 'Prohibited'],
          },
        },
      });
      for (const surface of [wire.structuredContent, wire.content])
        expect(JSON.stringify(surface)).toContain('cwe_list_reference');
    }

    // A zero-hit notice names the applied usage; a cursor binds it.
    const none = await runToolContract(cweSearchWeaknesses, {
      mappingUsage: 'prohibited',
      status: 'stable',
    });
    const { notice } = none.structuredContent as { notice: string };
    expect(parseMarkdown(notice).text).toBe(
      'No weaknesses matched the applied filters (status: Stable, mappingUsage: Prohibited). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.',
    );
    expect(lines(none)).toContain(`> ${notice}`);
    const cursor = (await search({ limit: 1 })).pagination.nextCursor;
    const rebound = await runToolContract(cweSearchWeaknesses, {
      limit: 1,
      cursor,
      mappingUsage: 'Allowed',
    });
    expect(rebound.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
  });

  it('never matches a taxonomy entry ID or a CVE as text, and adds no matched fields without their filters', async () => {
    const before = await runToolContract(cweSearchWeaknesses, { filter: 'needle alpha' });
    await disposeCatalogService();
    await load(undefined, withEvidence);
    for (const filter of ['ARR30-C', 'arr30', 'CVE-2021-44228', 'Part 4-2', 'Pernicious'])
      expect((await search({ filter })).results, filter).toEqual([]);
    // Recorded mappings and examples change no response that does not filter by them.
    const after = await runToolContract(cweSearchWeaknesses, { filter: 'needle alpha' });
    expect(after.structuredContent).toEqual(before.structuredContent);
    expect(after.content).toEqual(before.content);
  });

  it('finds weaknesses by taxonomy mapping and observed-example CVE and lists the matches on both surfaces', async () => {
    await disposeCatalogService();
    await load(undefined, withEvidence);
    const byEntry = await runToolContract(cweSearchWeaknesses, { taxonomyEntryId: ' arr30-c ' });
    expect(byEntry.isError).not.toBe(true);
    expect(cweSearchWeaknesses.output.parse(byEntry.structuredContent)).toBeTruthy();
    expect(byEntry.structuredContent).toMatchObject({
      results: [
        {
          id: 'CWE-10',
          matchedTaxonomyMappings: [
            {
              taxonomy: 'CERT C Secure Coding',
              id: 'ARR30-C',
              name: 'Do not form or use out-of-bounds pointers or array subscripts',
              fit: 'CWE More Abstract',
            },
          ],
        },
        {
          id: 'CWE-12',
          matchedTaxonomyMappings: [
            { taxonomy: 'CERT C Secure Coding', id: 'ARR30-C', fit: 'Imprecise' },
          ],
        },
      ],
      appliedFilters: { taxonomyEntryId: 'ARR30-C', limit: 20 },
      totalCount: 2,
    });
    const rows = (byEntry.structuredContent as { results: Record<string, unknown>[] }).results;
    for (const row of rows) expect(row).not.toHaveProperty('matchedObservedExamples');
    // content[] carries each matched mapping field by field, in schema order, after the row.
    const rendered = lines(byEntry).filter(Boolean);
    const start = rendered.indexOf('**matchedTaxonomyMappings**');
    expect(rendered.slice(start, start + 10)).toEqual([
      '**matchedTaxonomyMappings**',
      '**1**',
      '**taxonomy**',
      '> CERT C Secure Coding',
      '**id**',
      '> ARR30-C',
      '**name**',
      '> Do not form or use out-of-bounds pointers or array subscripts',
      '**fit**',
      '> CWE More Abstract',
    ]);
    expect(rendered.filter((line) => line === '**matchedTaxonomyMappings**')).toHaveLength(2);
    expect(copied(byEntry, 'taxonomyEntryId')).toEqual(['ARR30-C']);

    // A CVE cited twice on one weakness appears twice, in source order, beside its description.
    const byCve = await runToolContract(cweSearchWeaknesses, { observedCveId: ' cve-2021-44228 ' });
    expect(byCve.isError).not.toBe(true);
    expect(cweSearchWeaknesses.output.parse(byCve.structuredContent)).toBeTruthy();
    const link = 'https://www.cve.org/CVERecord?id=CVE-2021-44228';
    expect(byCve.structuredContent).toMatchObject({
      results: [
        {
          id: 'CWE-10',
          matchedObservedExamples: [
            {
              reference: 'CVE-2021-44228',
              description: 'Logging library evaluates \\*lookups\\* in messages.',
              link,
            },
          ],
        },
        {
          id: 'CWE-11',
          matchedObservedExamples: [
            { reference: 'CVE-2021-44228', description: 'First citation.', link },
            { reference: 'CVE-2021-44228', description: 'Second citation.', link },
          ],
        },
      ],
      appliedFilters: { observedCveId: 'CVE-2021-44228' },
      totalCount: 2,
    });
    for (const row of (byCve.structuredContent as { results: Record<string, unknown>[] }).results)
      expect(row).not.toHaveProperty('matchedTaxonomyMappings');
    expect(copied(byCve, 'description').map((line) => parseMarkdown(line).text)).toEqual([
      'Logging library evaluates *lookups* in messages.',
      'First citation.',
      'Second citation.',
    ]);
    expect(copied(byCve, 'reference')).toEqual(Array(3).fill('CVE-2021-44228'));
    expect(lines(byCve).filter((line) => line === `[${link}](<${link}>)`)).toHaveLength(3);
    expect(copied(byCve, 'observedCveId')).toEqual(['CVE-2021-44228']);

    // An Entry_ID alone matches every taxonomy; with a name, both hold on one mapping.
    const ids = async (args: Record<string, unknown>) =>
      cweSearchWeaknesses.output
        .parse((await runToolContract(cweSearchWeaknesses, args)).structuredContent)
        .results.map((row) => [
          row.id,
          row.matchedTaxonomyMappings?.map((item) => `${item.taxonomy} ${item.id ?? '-'}`),
        ]);
    expect(await ids({ taxonomyEntryId: 'A1' })).toEqual([
      ['CWE-10', ['OWASP Top Ten 2004 A1']],
      ['CWE-11', ['OWASP Top Ten 2007 A1']],
    ]);
    expect(await ids({ taxonomyEntryId: 'a1', taxonomyName: 'owasp top ten 2007' })).toEqual([
      ['CWE-11', ['OWASP Top Ten 2007 A1']],
    ]);
    expect(await ids({ taxonomyName: 'isa/iec 62443', taxonomyEntryId: 'part  4-2' })).toEqual([
      ['CWE-11', ['ISA/IEC 62443 Part 4-2', 'ISA/IEC 62443 Part 4-2']],
    ]);
    expect(await ids({ taxonomyName: 'ISA/IEC 62443' })).toEqual([
      ['CWE-11', ['ISA/IEC 62443 Part 4-2', 'ISA/IEC 62443 Part 3-3', 'ISA/IEC 62443 Part 4-2']],
    ]);
    // A name alone matches a mapping without an Entry_ID, which renders no id.
    const kingdoms = await runToolContract(cweSearchWeaknesses, {
      taxonomyName: '7 pernicious kingdoms',
    });
    expect(kingdoms.structuredContent).toMatchObject({
      results: [
        {
          id: 'CWE-10',
          matchedTaxonomyMappings: [{ taxonomy: '7 Pernicious Kingdoms', name: 'Buffer Overflow' }],
        },
      ],
      appliedFilters: { taxonomyName: '7 Pernicious Kingdoms' },
    });
    expect(
      (kingdoms.structuredContent as { results: { matchedTaxonomyMappings: object[] }[] })
        .results[0]?.matchedTaxonomyMappings[0],
    ).not.toHaveProperty('id');
    const kingdomLines = lines(kingdoms).filter(Boolean);
    const block = kingdomLines.indexOf('**matchedTaxonomyMappings**');
    expect(kingdomLines.slice(block, block + 7)).toEqual([
      '**matchedTaxonomyMappings**',
      '**1**',
      '**taxonomy**',
      '> 7 Pernicious Kingdoms',
      '**name**',
      '> Buffer Overflow',
      '**pagination**',
    ]);
    // Combined with each other and the existing filters by AND.
    expect(
      await ids({ observedCveId: 'CVE-2021-44228', taxonomyEntryId: 'A1', language: 'c' }),
    ).toEqual([['CWE-10', ['OWASP Top Ten 2004 A1']]]);
    // A category's mapping never matches: search covers weaknesses only.
    expect(await ids({ taxonomyEntryId: 'ARR00-C' })).toEqual([]);
  });

  it('rejects an unknown taxonomy name and a taxonomy entry ID holding a control character', async () => {
    await disposeCatalogService();
    await load(undefined, withEvidence);
    const unknown = await runToolContract(cweSearchWeaknesses, { taxonomyName: 'CERT C' });
    const message =
      'Unknown taxonomyName "CERT C"; supported values: 7 Pernicious Kingdoms, CERT C Secure Coding, ISA/IEC 62443, OWASP Top Ten 2004, OWASP Top Ten 2007.';
    const hint =
      'Call cwe_list_reference for supported views and filter vocabulary, then repeat cwe_search_weaknesses.';
    expect(unknown.structuredContent).toMatchObject({
      error: {
        message,
        data: {
          reason: 'unknown_filter',
          field: 'taxonomyName',
          value: 'CERT C',
          recovery: { hint },
        },
      },
    });
    expect(lines(unknown)).toEqual(
      expect.arrayContaining([`Error: ${message}`, `Recovery: ${hint}`]),
    );
    // An Entry_ID holding a control character could never match.
    const control = await runToolContract(cweSearchWeaknesses, { taxonomyEntryId: 'A\u00001' });
    expect(control.structuredContent).toMatchObject({
      error: { code: -32602, data: { reason: 'invalid_arguments' } },
    });
    for (const surface of [control.content, control.structuredContent])
      expect(JSON.stringify(surface)).toContain(
        'taxonomyEntryId: Remove control characters U+0000–U+0008 and U+000E–U+001F',
      );
  });

  it('explains a zero-hit taxonomy or CVE search by what emptied it, and binds the filters into cursors', async () => {
    await disposeCatalogService();
    await load(undefined, (xml) =>
      withEvidence(xml).replace(
        '<Category ID="901" Name="Nested" Status="Stable">',
        '<Category ID="901" Name="Nested" Status="Obsolete">',
      ),
    );
    const unrecorded = (filters: string, repeat: string) =>
      `No weakness records a taxonomy mapping or observed example matching these filters (${filters}); this does not establish that no weakness applies. Repeat cwe_search_weaknesses ${repeat}.`;
    const generic = (filters: string) =>
      `No weaknesses matched the applied filters (${filters}). Call cwe_list_reference for supported vocabulary, or repeat cwe_search_weaknesses with fewer filters.`;
    for (const [args, visible] of [
      [
        { observedCveId: 'CVE-2021-4422' },
        unrecorded('observedCveId: CVE-2021-4422', 'without them, or with a text filter'),
      ],
      // Each holds somewhere, never on one mapping.
      [
        { taxonomyName: 'CERT C Secure Coding', taxonomyEntryId: 'a1' },
        unrecorded(
          'taxonomyName: CERT C Secure Coding, taxonomyEntryId: A1',
          'without them, or with a text filter',
        ),
      ],
      // The other filters match a weakness alone, so dropping the evidence filters returns some.
      [
        { abstraction: 'class', taxonomyEntryId: 'ZZZ-1' },
        unrecorded('taxonomyEntryId: ZZZ-1', 'without them, or with a text filter'),
      ],
      // The other filters match nothing alone, so only fewer filters can return a weakness.
      [
        { language: 'c', status: 'deprecated', observedCveId: 'cve-2021-4422' },
        unrecorded('observedCveId: CVE-2021-4422', 'with fewer filters'),
      ],
      // Some weakness records this CVE, and only the other filters exclude it.
      [
        { status: 'deprecated', observedCveId: 'CVE-2021-44228' },
        generic('status: Deprecated, observedCveId: CVE-2021-44228'),
      ],
      // With a view, the view notices apply and these count as other filters.
      [
        { observedCveId: 'CVE-2021-4422', viewId: '1000' },
        'No weaknesses matched this view and the other filters. Call cwe_get_view for its direct members, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      [
        { observedCveId: 'CVE-2014-1266', viewId: '1001' },
        'No weakness that the source filter of view CWE-1001 selects matches the other filters. Call cwe_get_view to read its filterDefinition, or repeat cwe_search_weaknesses with fewer filters.',
      ],
      // A status only categories carry explains the whole result first.
      [
        { observedCveId: 'CVE-2021-4422', status: 'obsolete' },
        'Status Obsolete occurs only on CWE categories, which cwe_search_weaknesses excludes. Call cwe_list_reference with topic filter_values for the statuses weaknesses carry.',
      ],
    ] as const) {
      const wire = await runToolContract(cweSearchWeaknesses, args);
      expect(wire.isError, JSON.stringify(args)).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({ results: [], totalCount: 0 });
      const { notice } = wire.structuredContent as { notice: string };
      expect(parseMarkdown(notice).text, JSON.stringify(args)).toBe(visible);
      expect(lines(wire)).toContain(`> ${notice}`);
    }
    // Caller text in the notice is literal text.
    const quoted = await runToolContract(cweSearchWeaknesses, { taxonomyEntryId: '*x* [a](b)' });
    const { notice } = quoted.structuredContent as { notice: string };
    expect(parseMarkdown(notice).text).toBe(
      unrecorded('taxonomyEntryId: *x* [a](b)', 'without them, or with a text filter'),
    );
    expect(parseMarkdown(notice).nodes).not.toContain('link');

    // Cursors bind the canonical filters: a respelling continues, another value is rejected.
    const first = await search({ taxonomyEntryId: 'A1', limit: 1 });
    expect(first.results.map((row) => row.id)).toEqual(['CWE-10']);
    const cursor = first.pagination.nextCursor;
    expect(
      (await search({ taxonomyEntryId: ' a1 ', limit: 1, cursor })).results.map((row) => row.id),
    ).toEqual(['CWE-11']);
    const unfilteredCursor = (await search({ limit: 1 })).pagination.nextCursor;
    for (const args of [
      { taxonomyEntryId: 'ARR30-C', limit: 1, cursor },
      { taxonomyEntryId: 'A1', taxonomyName: 'OWASP Top Ten 2004', limit: 1, cursor },
      { taxonomyEntryId: 'A1', observedCveId: 'CVE-2021-44228', limit: 1, cursor },
      { observedCveId: 'CVE-2021-44228', limit: 1, cursor: unfilteredCursor },
      { taxonomyName: '7 Pernicious Kingdoms', limit: 1, cursor: unfilteredCursor },
    ]) {
      const wire = await runToolContract(cweSearchWeaknesses, args);
      expect(wire.structuredContent, JSON.stringify(args)).toMatchObject({
        error: { data: { reason: 'invalid_cursor' } },
      });
    }
  });

  it('returns recorded view notes on every member page and on both surfaces', async () => {
    await disposeCatalogService();
    await load(undefined, (xml) =>
      xml.replace(
        '<Members>',
        '<Notes><Note Type="Relationship">Members follow *CWE-1000* [REF-1].</Note><Note Type="Other">Second_note.</Note></Notes><Members>',
      ),
    );
    const notes = [
      { type: 'Relationship', text: 'Members follow \\*CWE-1000\\* [REF-1].' },
      { type: 'Other', text: 'Second_note.' },
    ];
    const first = await runToolContract(cweGetView, { id: '1000', limit: 2 });
    const second = await runToolContract(cweGetView, {
      id: '1000',
      limit: 2,
      cursor: (first.structuredContent as { pagination: { nextCursor: string } }).pagination
        .nextCursor,
    });
    for (const [wire, ids] of [
      [first, ['CWE-900', 'CWE-30']],
      [second, ['CWE-10', 'CWE-304']],
    ] as const) {
      expect(wire.isError).not.toBe(true);
      const data = wire.structuredContent as { notes: unknown; members: { id: string }[] };
      expect(data.notes).toEqual(notes);
      expect(data.members.map((row) => row.id)).toEqual(ids);
      // Each note copied out of content[] reads as the source text: no emphasis, no link.
      expect(copied(wire, 'text').map((line) => parseMarkdown(line).text)).toEqual([
        'Members follow *CWE-1000* [REF-1].',
        'Second_note.',
      ]);
      const rendered = lines(wire).filter(Boolean);
      const start = rendered.indexOf('**notes**');
      expect(rendered.slice(start, rendered.indexOf('**members**'))).toEqual([
        '**notes**',
        '**1**',
        '**type**',
        '> Relationship',
        '**text**',
        '> Members follow \\*CWE-1000\\* [REF-1].',
        '**2**',
        '**type**',
        '> Other',
        '**text**',
        '> Second_note.',
      ]);
    }
    expect(cweGetView.output.safeParse(await view({ id: '1000' })).success).toBe(true);
    // A view without notes carries neither the field nor its label.
    const plain = await runToolContract(cweGetView, { id: '1001' });
    expect(plain.structuredContent).not.toHaveProperty('notes');
    expect(lines(plain)).not.toContain('**notes**');
  });
});

describe('descriptionPreview first sentence', () => {
  const capec113 =
    'An adversary manipulates the use or processing of an interface (e.g. Application Programming Interface (API) or System-on-Chip (SoC)) resulting in an adverse impact upon the security of the system implementing the interface.';
  const cwe391 =
    '[PLANNED FOR DEPRECATION. SEE MAINTENANCE NOTES AND CONSIDER CWE-252, CWE-248, OR CWE-1069.]';
  // [description, preview]
  const joined: [string, string][] = [
    // The segment break fell inside a token.
    [`${dotnet} Second sentence.`, dotnet],
    [
      'Allowing a .NET application to run at escalated levels can be dangerous. Next.',
      'Allowing a .NET application to run at escalated levels can be dangerous.',
    ],
    [
      'The product does not handle a Windows shortcut (.LNK) whose target is outside of the intended control sphere. This could allow access.',
      'The product does not handle a Windows shortcut (.LNK) whose target is outside of the intended control sphere.',
    ],
    // A parenthesis or bracket opened in the preview is still unclosed, nested and escaped ones too.
    [`${verb} Some web environments differ.`, verb],
    [`${capec113} Next sentence.`, capec113],
    [`${cwe391} Ignoring exceptions may allow an attacker to act unnoticed.`, cwe391],
    ['\\[Draft. Details\\] follow here. Next.', '\\[Draft. Details\\] follow here.'],
    // A bracket that never closes yields the whole description, never a fragment.
    ['Opens (a note. Second sentence. Third', 'Opens (a note. Second sentence. Third'],
    // A code span, backtick fence, or emphasis is still open.
    ['Foo ` a. B ` bar. Next.', 'Foo ` a. B ` bar.'],
    ['\\``a. B` c. Next.', '\\``a. B` c.'],
    ['Foo *a. B* bar. Next.', 'Foo *a. B* bar.'],
    ['Foo **a. B** bar. Next.', 'Foo **a. B** bar.'],
    ['Foo _a. B_ bar. Next.', 'Foo _a. B_ bar.'],
    ['```\ncode. More\n```\n\nText. More.', '```\ncode. More\n```'],
    // The break falls inside a pipe-table row.
    ['| Name. | Value |\n| --- | --- |\n| a. B | c |\n\nAfter. More.', '| Name. | Value |'],
    // The preview holds no letter yet: a list marker or an escaped ordinal.
    ['1. First item. More.\n2. Second.', '1. First item.'],
    ['1\\. Not a list. More.', '1\\. Not a list.'],
  ];
  // Previews whose first segment already ends in whitespace with nothing open stay as they were.
  const unchanged: [string, string][] = [
    ['Short. Another.', 'Short.'],
    ['Balanced (note) and [ref] here. Next.', 'Balanced (note) and [ref] here.'],
    ['Item 1) first. Second.', 'Item 1) first.'],
    ['First paragraph\n\nSecond paragraph.', 'First paragraph'],
    [`${preview} Second sentence.`, preview],
    ['', ''],
    // A delimiter that cannot close later, or is escaped, or flanks nothing, is literal text.
    ['Foo *a. B bar. Next.', 'Foo *a.'],
    ['Foo `a. B bar. Next.', 'Foo `a.'],
    ['Foo \\*a. B\\* bar. Next.', 'Foo \\*a.'],
    ['a * b. C * d. Next.', 'a * b.'],
    ['Use snake_case. Next.', 'Use snake_case.'],
  ];

  it.each(joined)('joins segments until the sentence is complete: %j', (description, expected) => {
    expect(firstSentence(description)).toBe(expected);
  });

  it.each(unchanged)('keeps a complete first segment: %j', (description, expected) => {
    expect(firstSentence(description)).toBe(expected);
  });

  it('reads code as inert, so a parenthesis inside a code span holds nothing open', () => {
    expect(firstSentence('Use `(` here. Next.')).toBe('Use `(` here.');
  });

  it('never previews a fragment of a normalized description', () => {
    const fixture = readFileSync(
      new URL('../fixtures/catalog/cwe-normalization.xml', import.meta.url),
      'utf8',
    );
    const normalized = (xhtml: string) =>
      parseCweCatalog(
        fixture.replace(
          '<Description>Sparse description.</Description>',
          `<Description>${xhtml}</Description>`,
        ),
      ).weaknesses.get('CWE-20')?.description ?? '';
    const words = fc
      .array(fc.constantFrom('Foo', 'bar', 'a.', 'B.', 'e.g.', '.NET', '1.', '(', ')', '[', ']'), {
        minLength: 1,
        maxLength: 6,
      })
      .map((parts) => parts.join(' '));
    const inline = fc.oneof(
      { weight: 3, arbitrary: words },
      {
        weight: 2,
        arbitrary: fc
          .tuple(fc.constantFrom('b', 'i', 'code'), words, words)
          .map(([tag, inner, after]) => `<xhtml:${tag}>${inner}</xhtml:${tag}> ${after}`),
      },
    );
    const block = fc.oneof(
      inline.map((content) => `<xhtml:p>${content}</xhtml:p>`),
      fc
        .tuple(fc.constantFrom('ol', 'ul'), fc.array(inline, { minLength: 1, maxLength: 3 }))
        .map(
          ([tag, items]) =>
            `<xhtml:${tag}>${items.map((item) => `<xhtml:li>${item}</xhtml:li>`).join('')}</xhtml:${tag}>`,
        ),
      words.map((code) => `<xhtml:pre>${code}\n${code}</xhtml:pre>`),
      fc
        .array(fc.tuple(words, words), { minLength: 1, maxLength: 3 })
        .map(
          (rows) =>
            `<xhtml:table>${rows.map((cells) => `<xhtml:tr>${cells.map((cell) => `<xhtml:td>${cell}</xhtml:td>`).join('')}</xhtml:tr>`).join('')}</xhtml:table>`,
        ),
    );
    /**
     * Never a fragment: what the preview shows is the start of what the description shows, so no
     * delimiter it cut from its partner shows as text, and it shows a letter whenever the
     * description does.
     */
    fc.assert(
      fc.property(fc.array(block, { minLength: 1, maxLength: 4 }), (blocks) => {
        const description = normalized(blocks.join(''));
        const shown = visibleText(firstSentence(description));
        expect(visibleText(description).startsWith(shown)).toBe(true);
        expect(/\p{L}/u.test(shown)).toBe(/\p{L}/u.test(description));
      }),
      { seed: 20261021, numRuns: 1000 },
    );
  });

  it('scans each character once, however many segments it joins', { timeout: 60_000 }, () => {
    /**
     * Backtick runs of growing length, so no run ever finds a closing run of its own length. Like
     * the other shapes that would otherwise end at their first sentence, it opens with `(`, which
     * holds the preview open so the scan reaches every character.
     */
    const backtickLadder = (length: number) => {
      let text = '(';
      for (let run = 1; text.length < length; run++) text += `${'`'.repeat(run)}a. B `;
      return text.slice(0, length);
    };
    const shapes: [string, (length: number) => string][] = [
      ['digit run', (length) => '7'.repeat(length)],
      ['unclosed parentheses', (length) => '('.repeat(length)],
      ['repeated abbreviation in an open parenthesis', (length) => '(e.g. x. '.repeat(length / 9)],
      ['one long line, then a break', (length) => `${'§1 x'.repeat(length / 4)}\ny`],
      ['breaks throughout', (length) => '  \r\n'.repeat(length / 4)],
      ['backtick runs that never close', backtickLadder],
      ['escaped backticks', (length) => `(${'\\`a. B '.repeat(length / 7)}`],
      ['emphasis openers closed only at the end', (length) => `${'*a. B '.repeat(length / 6)}x*`],
      ['one pipe-table row of sentences', (length) => `| ${'a. B '.repeat(length / 5)}|`],
      [
        'pipe-table rows on lone carriage returns',
        (length) => `(${'| a. B |\r'.repeat(length / 9)}`,
      ],
      ['letterless ordinals', (length) => '1. '.repeat(length / 3)],
    ];
    for (const [label, build] of shapes) expectLinearTime(label, build, firstSentence);
  });
});

describe('identifier grammar', () => {
  /** The forms the input grammar is decided on, valid and invalid, including the issue's list. */
  const forms = [
    '79',
    ' 79 ',
    '079',
    'CWE-79',
    'cwe-079',
    'CWE79',
    'cwe 079',
    'CWE_79',
    'CWE\t79',
    'CWE  79',
    ' CWE 79 ',
    '﻿79',
    '1059',
    '0',
    '00',
    'CWE-0',
    '-1',
    '+79',
    '1.2',
    '79.0',
    '1e2',
    '0x4F',
    'CWE–79',
    'CWE:79',
    'CWE--79',
    'CWE- 79',
    'CWE -79',
    'CWE-CWE-79',
    'CAPEC-79',
    'https://cwe.mitre.org/data/definitions/79.html',
    '79,89',
    '79 89',
    '٧٩',
    '９９',
    '79\u0085',
    'NVD-CWE-noinfo',
    'T1059',
    'T1059.1',
    'T1059.001',
    't1059',
    'T 1059',
    'all',
    ' ALL ',
    'al l',
    'CVE-2021-44228',
    ' cve-2021-44228 ',
    'Cve-2017-1000095',
    'CVE-2002-216',
    'CVE-21-44228',
    'CVE 2021-44228',
    'CVE_2021_44228',
    'CVE-2021-44228x',
    'CVE-2021-44228 CVE-2021-44229',
    '2021-44228',
    'CVE-٢٠٢١-44228',
    '',
    ' ',
    '\t',
  ];
  /** Expected verdicts, written out rather than derived from the patterns under test. */
  const cwe = new Map(
    [
      '79',
      ' 79 ',
      '079',
      'CWE-79',
      'cwe-079',
      'CWE79',
      'cwe 079',
      'CWE_79',
      'CWE\t79',
      'CWE  79',
      ' CWE 79 ',
      '﻿79',
    ].map((form) => [form, 'CWE-79']),
  ).set('1059', 'CWE-1059');
  const blank = new Set(['', ' ', '\t']);
  const attack = new Map([
    ['T1059', 'T1059'],
    ['T1059.001', 'T1059.001'],
    ['t1059', 'T1059'],
    ['1059', 'T1059'],
  ]);
  const cve = new Map([
    ['CVE-2021-44228', 'CVE-2021-44228'],
    [' cve-2021-44228 ', 'CVE-2021-44228'],
    ['Cve-2017-1000095', 'CVE-2017-1000095'],
  ]);
  const inputs = [
    [cweGetView, 'id', (form: string) => cwe.has(form)],
    [cweGetHierarchy, 'id', (form: string) => cwe.has(form)],
    [
      cweGetHierarchy,
      'viewId',
      (form: string) => cwe.has(form) || blank.has(form) || form.trim().toLowerCase() === 'all',
    ],
    [cweSearchWeaknesses, 'viewId', (form: string) => cwe.has(form) || blank.has(form)],
    [cweSearchWeaknesses, 'observedCveId', (form: string) => cve.has(form) || blank.has(form)],
    [cweSearchAttackPatterns, 'cweId', (form: string) => cwe.has(form) || blank.has(form)],
    [
      cweSearchAttackPatterns,
      'attackTechniqueId',
      (form: string) => attack.has(form) || blank.has(form),
    ],
  ] as const;

  it('advertises flag-free patterns that accept exactly the forms the handlers parse', () => {
    for (const [definition, field, accepts] of inputs) {
      const schema = z.toJSONSchema(definition.input, { io: 'input' }) as {
        properties: Record<string, { pattern?: string }>;
      };
      const pattern = schema.properties[field]?.pattern;
      expect(pattern, `${definition.name} ${field}`).toBeTypeOf('string');
      // JSON Schema validators compile the pattern as written, some in Unicode mode.
      for (const compiled of [new RegExp(pattern as string), new RegExp(pattern as string, 'u')])
        for (const form of forms)
          expect(compiled.test(form), `${definition.name} ${field} ${JSON.stringify(form)}`).toBe(
            accepts(form),
          );
    }
    for (const form of forms) {
      expect(parseId(form, 'CWE'), JSON.stringify(form)).toBe(cwe.get(form));
      if (attack.has(form)) expect(normalizeAttackId(form)).toBe(attack.get(form));
      else if (!blank.has(form)) expect(() => normalizeAttackId(form)).toThrow(ATTACK_ID_FORMS);
      // An ids item classifies by the same grammar.
      const [position] = batchIds([form], 'CWE').ids;
      expect(position?.family === 'CWE' ? position.id : undefined).toBe(cwe.get(form));
    }
  });

  it('rejects a malformed single ID as an invalid argument that names the accepted forms', async () => {
    for (const form of forms) {
      const label = JSON.stringify(form);
      const view = await runToolContract(cweGetView, { id: form });
      if (cwe.has(form)) expect(view.isError, label).not.toBe(true);
      else {
        expect(view.structuredContent, label).toMatchObject({ error: { code: -32602 } });
        for (const surface of [view.content, view.structuredContent])
          expect(JSON.stringify(surface), label).toContain(`id: ${VIEW_ID_FORMS}`);
      }
      const mapping = await runToolContract(cweSearchAttackPatterns, { cweId: form });
      expect(mapping.isError === true, label).toBe(!cwe.has(form) && !blank.has(form));
      if (mapping.isError)
        expect(JSON.stringify(mapping.content)).toContain(`cweId: ${CWE_ID_FORMS}`);
      const technique = await runToolContract(cweSearchAttackPatterns, { attackTechniqueId: form });
      expect(technique.isError === true, label).toBe(!attack.has(form) && !blank.has(form));
      if (technique.isError)
        expect(JSON.stringify(technique.content)).toContain(
          `attackTechniqueId: ${ATTACK_ID_FORMS}`,
        );
      // A well-formed ID that names no view fails as unknown_filter, never as a malformed argument.
      const scoped = await runToolContract(cweSearchWeaknesses, { viewId: form });
      const code = (scoped.structuredContent as { error?: { code: number } }).error?.code;
      expect(code === -32602, label).toBe(!cwe.has(form) && !blank.has(form));
      // A well-formed CVE no weakness cites is a zero-hit answer, echoed uppercase.
      const cited = await runToolContract(cweSearchWeaknesses, { observedCveId: form });
      if (cve.has(form))
        expect(cited.structuredContent, label).toMatchObject({
          totalCount: 0,
          appliedFilters: { observedCveId: cve.get(form) },
        });
      else if (blank.has(form)) expect(cited.isError, label).not.toBe(true);
      else {
        expect(cited.structuredContent, label).toMatchObject({ error: { code: -32602 } });
        for (const surface of [cited.content, cited.structuredContent])
          expect(JSON.stringify(surface), label).toContain(`observedCveId: ${CVE_ID_FORMS}`);
      }
    }
    // Integer transport values, as JSON delivers them, are still repaired before the pattern applies.
    const integerView = await runToolContract(
      cweGetView,
      JSON.parse('{"id":1000}') as { id: string },
    );
    expect(integerView.structuredContent).toMatchObject({ id: 'CWE-1000', found: true });
    const integerMapping = await runToolContract(
      cweSearchAttackPatterns,
      JSON.parse('{"cweId":10}') as { cweId: string },
    );
    expect(integerMapping.structuredContent).toMatchObject({
      appliedFilters: { cweId: 'CWE-10' },
    });
  });

  it('parses caller-sized text in linear time', { timeout: 60_000 }, () => {
    const parse = (value: string) => {
      for (const pattern of [
        CWE_ID,
        OPTIONAL_CWE_ID,
        VIEW_ID,
        CAPEC_ID,
        OPTIONAL_ATTACK_ID,
        OPTIONAL_CVE_ID,
      ])
        pattern.test(value);
      return batchIds([value], 'CWE');
    };
    const shapes: [string, (length: number) => string][] = [
      ['digit run', (length) => '7'.repeat(length)],
      ['CVE sequence digits before text', (length) => `CVE-2021-${'7'.repeat(length)}x`],
      ['CVE then whitespace before text', (length) => `CVE-2021-44228${' '.repeat(length)}x`],
      ['whitespace before a CVE that fails', (length) => `${' '.repeat(length)}CVE-2021-44228x`],
      ['repeated CVE prefixes', (length) => 'CVE-2021-'.repeat(length / 9)],
      ['zeros with no digit after them', (length) => `${'0'.repeat(length)}x`],
      ['whitespace before text', (length) => `${' '.repeat(length)}x`],
      ['prefix and whitespace before text', (length) => `CWE${' '.repeat(length)}x`],
      ['digits and whitespace before text', (length) => `7${'\t'.repeat(length)}x`],
      ['repeated prefixes', (length) => 'CWE-'.repeat(length / 4)],
      ['one long line, then a break', (length) => `${'§1 x'.repeat(length / 4)}\ny`],
      ['breaks throughout', (length) => '  \r\n'.repeat(length / 4)],
    ];
    for (const [label, build] of shapes) expectLinearTime(label, build, parse);
  });
});
