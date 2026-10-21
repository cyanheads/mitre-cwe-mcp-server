/**
 * @fileoverview Detail projection, reference paging, and both client consumption paths.
 * @module tests/tools/detail-contract.test
 */
import { readFileSync } from 'node:fs';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cweGetAttackPattern } from '@/mcp-server/tools/definitions/cwe-get-attack-pattern.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import {
  cweListReference,
  referenceTopics,
} from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { attackPatternSections, weaknessSections } from '@/mcp-server/tools/detail-projection.js';
import { formatCatalog, pageItems } from '@/mcp-server/tools/shared.js';
import {
  type CatalogClock,
  disposeCatalogService,
  getCatalogService,
  type HttpRequest,
  initCatalogService,
  SOURCE_URLS,
} from '@/services/index.js';

const originalCwe = readFileSync(
  new URL('../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const originalCapec = readFileSync(
  new URL('../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);
const cwe = originalCwe.replace(
  '<Related_Weaknesses>',
  `<Extended_Description>Extended narrative.</Extended_Description><Likelihood_Of_Exploit>High</Likelihood_Of_Exploit><Modes_Of_Introduction><Introduction><Phase>Implementation</Phase><Note>Introduced here.</Note></Introduction></Modes_Of_Introduction><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact><Note>Conditional.</Note></Consequence></Common_Consequences><Potential_Mitigations><Mitigation><Phase>Architecture and Design</Phase><Description>Validate all fields.</Description><Effectiveness>High</Effectiveness></Mitigation></Potential_Mitigations><Detection_Methods><Detection_Method><Method>Static Analysis</Method><Description>Trace data.</Description></Detection_Method></Detection_Methods><Observed_Examples><Observed_Example><Reference>CVE-2026-0001</Reference><Description>Observed case.</Description><Link>https://example.test/cve</Link></Observed_Example></Observed_Examples><Applicable_Platforms><Language Name="C" Class="Compiled"/><Technology Name="Web Server"/><Operating_System Class="Unix"/><Architecture Name="x86"/></Applicable_Platforms><Mapping_Notes><Usage>ALLOWED</Usage><Rationale>Root cause.</Rationale><Comments>Check context.</Comments><Reasons><Reason>Acceptable</Reason></Reasons></Mapping_Notes><Related_Weaknesses>`,
);
const capec = originalCapec.replace(
  '<Prerequisites>',
  '<Typical_Severity>High</Typical_Severity><Likelihood_Of_Attack>Medium</Likelihood_Of_Attack><Extended_Description>Extended attack.</Extended_Description><Resources_Required><Resource>One browser.</Resource></Resources_Required><Example_Instances><Example>First instance.</Example><Example>Second instance.</Example></Example_Instances><Indicators><Indicator>Outer signal.</Indicator></Indicators><Prerequisites>',
);
const clock: CatalogClock = {
  now: () => Date.parse('2026-10-20T00:00:00Z'),
  schedule: () => ({ cancel() {} }),
};
async function load(cweXml = cwe, capecXml = capec) {
  const request: HttpRequest = async (url) => {
    if (url === SOURCE_URLS.cwe)
      return new Response(
        zipSync({
          'cwe.xml': strToU8(
            cweXml.replace('<Reason>Acceptable</Reason>', '<Reason Type="Acceptable"/>'),
          ),
        }),
      );
    if (url === SOURCE_URLS.capec)
      return new Response(capecXml, { headers: { etag: 'fixture-etag' } });
    throw new Error(`Unexpected network request: ${url}`);
  };
  return initCatalogService({ request, clock, context: createMockContext() });
}
function weakness(args: Record<string, unknown>) {
  return cweGetWeakness.handler(
    cweGetWeakness.input.parse(args),
    createMockContext({ errors: cweGetWeakness.errors }),
  );
}
function pattern(args: Record<string, unknown>) {
  return cweGetAttackPattern.handler(cweGetAttackPattern.input.parse(args), createMockContext());
}
function reference(args: Record<string, unknown>) {
  return cweListReference.handler(
    cweListReference.input.parse(args),
    createMockContext({ errors: cweListReference.errors }),
  );
}
beforeEach(async () => {
  await load();
});
afterEach(async () => {
  await disposeCatalogService();
});

describe('complete detail contracts', () => {
  it('preserves every CWE section and ordered nested mixed-code examples', async () => {
    const result = await weakness({ ids: ['79'], sections: weaknessSections, exampleLimit: 100 });
    expect(cweGetWeakness.output.safeParse(result).success).toBe(true);
    const entry = result.entries[0]!;
    expect(entry.availableSections).toEqual(weaknessSections);
    expect(entry).toMatchObject({
      kind: 'full',
      extendedDescription: 'Extended narrative.',
      likelihoodOfExploit: 'High',
      consequences: [{ scopes: ['Integrity'], impacts: ['Modify Data'] }],
      mitigations: [{ phases: ['Architecture and Design'], description: 'Validate all fields.' }],
      detectionMethods: [{ method: 'Static Analysis' }],
      observedExamples: [{ reference: 'CVE-2026-0001', link: 'https://example.test/cve' }],
      mappingNotes: { usage: 'ALLOWED' },
      references: [{ authors: ['Alice', 'Bob'], url: 'https://example.test/ref', section: '2' }],
    });
    expect(entry.examples?.[0]?.blocks.map((block) => block.kind)).toEqual([
      'prose',
      'code',
      'prose',
      'code',
      'prose',
    ]);
    expect(entry.examples?.[0]?.blocks[1]).toMatchObject({
      text: 'if (a < b) {\n  call("x");\n}\nnext();',
      language: 'C',
      nature: 'Bad',
    });
    expect(entry.examples?.[0]?.blocks[3]).toMatchObject({
      text: '  literal <tag> &amp;\n    next();',
    });
    const rendered = cweGetWeakness.format!(result)
      .flatMap((block) => (block.type === 'text' ? [block.text] : []))
      .join('\n');
    expect(rendered).toContain('if (a < b) {\n  call("x");\n}\nnext();');
    expect(rendered).toContain('[https://example.test/ref](<https://example.test/ref>)');
    expect(rendered).toContain('Before code.');
    expect(rendered).toContain('After code.');
  });

  it('returns every CAPEC section including nested execution and partial taxonomy mappings', async () => {
    const result = await pattern({ ids: ['CAPEC-001'], sections: attackPatternSections });
    expect(cweGetAttackPattern.output.safeParse(result).success).toBe(true);
    const entry = result.entries[0]!;
    expect(entry.availableSections).toEqual(attackPatternSections);
    expect(entry).toMatchObject({
      typicalSeverity: 'High',
      likelihoodOfAttack: 'Medium',
      prerequisites: ['First prerequisite.', 'Second prerequisite.'],
      executionFlow: [
        {
          step: '1',
          techniques: ['Probe one.', 'Probe two.'],
          indicators: ['Signal one.', 'Signal two.'],
        },
        { step: '2', phase: 'Exploit' },
      ],
      skills: [{ level: 'Low', description: 'Read source.' }, { description: 'Write payload.' }],
      resourcesRequired: ['One browser.'],
      exampleInstances: ['First instance.', 'Second instance.'],
      attackTechniqueIds: ['T1059.001'],
    });
    expect(entry.taxonomyMappings).toContainEqual({ taxonomy: 'Other' });
    const rendered = JSON.stringify(cweGetAttackPattern.format!(result));
    expect(rendered).toContain('Signal two.');
    expect(rendered).toContain('Second instance.');
    expect(rendered).toContain('T1059');
  });

  it('keeps sparse and inactive records honest, category order intact, and outlines selectable', async () => {
    const result = await weakness({ ids: ['20', '900', '1000', '999999'], sections: [] });
    expect(result.entries.map((entry) => entry.kind)).toEqual(['outline', 'outline']);
    expect(result.entries[0]).not.toHaveProperty('description');
    expect(result.notFound).toMatchObject([
      { id: 'CWE-1000', reason: 'wrong_type', guidance: expect.stringContaining('cwe_get_view') },
      { id: 'CWE-999999', reason: 'not_found' },
    ]);
    const category = await weakness({ ids: ['900'], sections: ['relations'] });
    expect(category.entries[0]?.members?.map((member) => member.id)).toEqual(['CWE-79', 'CWE-20']);
    const sparse = await pattern({ ids: ['2', '999999'], sections: attackPatternSections });
    expect(sparse.entries[0]).toMatchObject({
      status: 'Deprecated',
      kind: 'full',
      description: 'Only identity and description.',
    });
    expect(sparse.entries[0]).not.toHaveProperty('typicalSeverity');
    expect(sparse.entries[0]?.notice).toContain('no content');
    expect(sparse.notFound[0]?.guidance).toContain('cwe_search_attack_patterns');
    const empty = await weakness({ ids: ['999999'] });
    expect(empty.entries).toEqual([]);
    expect(cweGetWeakness.output.safeParse(empty).success).toBe(true);
  });

  it('deduplicates normalized IDs before deferring and validates submitted ceilings and syntax', async () => {
    const ids = ['79', 'CWE-079', ...Array.from({ length: 21 }, (_, index) => String(index + 100))];
    const result = await weakness({ ids });
    expect(result.entries.map((entry) => entry.id)).toEqual(['CWE-79']);
    expect(result.notFound).toHaveLength(19);
    expect(result.deferredIds).toEqual(['CWE-119', 'CWE-120']);
    const wire = await runToolContract(cweGetWeakness, { ids });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      totalCount: 22,
      truncated: true,
      shown: 20,
      cap: 20,
    });
    expect(JSON.stringify(wire.content)).toContain('22');
    expect(cweGetWeakness.input.safeParse({ ids: Array(200).fill('79') }).success).toBe(true);
    expect(cweGetWeakness.input.safeParse({ ids: Array(201).fill('79') }).success).toBe(false);
    for (const id of ['0', 'CAPEC-1', '-1', '1.2', 'CWE-']) {
      const invalid = await runToolContract(cweGetWeakness, { ids: [id] });
      expect(invalid.isError).toBe(true);
    }
    const batch = await pattern({
      ids: Array.from({ length: 21 }, (_, index) => String(index + 1)),
    });
    expect(batch.deferredIds).toEqual(['CAPEC-21']);
  });

  it('validates effective output and enrichment for ordinary detail successes', async () => {
    const weaknessResult = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: ['examples', 'mappings'],
    });
    expect(weaknessResult.isError).not.toBe(true);
    expect(weaknessResult.structuredContent).toMatchObject({
      totalCount: 1,
      entries: [
        {
          examples: [{ index: 0 }, { index: 1 }],
          examplePage: { total: 2, shown: 2, offset: 0, hasMore: false },
          references: [{ url: 'https://example.test/ref' }],
        },
      ],
    });
    expect(JSON.stringify(weaknessResult.content)).toContain('https://example.test/ref');
    const patternResult = await runToolContract(cweGetAttackPattern, {
      ids: ['1'],
      sections: ['execution', 'mappings'],
    });
    expect(patternResult.isError).not.toBe(true);
    expect(patternResult.structuredContent).toMatchObject({
      totalCount: 1,
      entries: [
        { executionFlow: [{ step: '1' }, { step: '2' }], attackTechniqueIds: ['T1059.001'] },
      ],
    });
    expect(JSON.stringify(patternResult.content)).toContain('Signal two.');
  });

  it('pages complete source examples after language filtering and handles exhausted offsets', async () => {
    const first = await weakness({ ids: ['79'], sections: ['examples'], exampleLimit: 1 });
    expect(first.entries[0]?.examplePage).toEqual({
      total: 2,
      shown: 1,
      offset: 0,
      hasMore: true,
      nextOffset: 1,
    });
    const second = await weakness({
      ids: ['79'],
      sections: ['examples'],
      exampleOffset: 1,
      exampleLimit: 1,
    });
    expect(second.entries[0]?.examples).toEqual([
      { index: 1, blocks: [{ kind: 'prose', text: 'Second example.' }] },
    ]);
    const filtered = await weakness({
      ids: ['79'],
      sections: ['examples'],
      exampleLanguage: ' c ',
    });
    expect(filtered.entries[0]?.examplePage).toEqual({
      total: 1,
      shown: 1,
      offset: 0,
      hasMore: false,
    });
    const past = await weakness({ ids: ['79'], sections: ['examples'], exampleOffset: 200 });
    expect(past.entries[0]?.examples).toEqual([]);
    expect(past.entries[0]?.examplePage).toEqual({
      total: 2,
      shown: 0,
      offset: 200,
      hasMore: false,
    });
    const invalid = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      exampleLanguage: 'Imaginary',
    });
    expect(invalid.isError).toBe(true);
    expect(invalid.structuredContent).toMatchObject({
      error: { data: { reason: 'unknown_filter' } },
    });
    expect(JSON.stringify(invalid.content)).toContain('cwe_list_reference');
  });

  it('switches defaults at exactly 24,000 UTF-8 bytes but never truncates explicit selections', async () => {
    const base = await weakness({ ids: ['20'] });
    const { notice: _notice, ...fullBeforeNotice } = base.entries[0]!;
    const size = Buffer.byteLength(JSON.stringify(fullBeforeNotice));
    const description = 'Sparse description.';
    const at = description + 'x'.repeat(24000 - size);
    await disposeCatalogService();
    await load(cwe.replace(description, at));
    expect((await weakness({ ids: ['20'] })).entries[0]?.kind).toBe('full');
    await disposeCatalogService();
    await load(cwe.replace(description, `${at}x`));
    expect((await weakness({ ids: ['20'] })).entries[0]?.kind).toBe('outline');
    const explicit = await weakness({ ids: ['20'], sections: ['summary'] });
    expect(explicit.entries[0]).toMatchObject({ kind: 'full', description: `${at}x` });
    expect(JSON.stringify(cweGetWeakness.format!(explicit))).toContain(`${at}x`);
  });

  it('outlines oversized CAPEC defaults and honors explicit complete and empty sections', async () => {
    await disposeCatalogService();
    const long = 'é'.repeat(13000);
    await load(cwe, capec.replace('Attack description.', long));
    const outline = await pattern({ ids: ['1'] });
    expect(outline.entries[0]?.kind).toBe('outline');
    expect(outline.entries[0]?.outline).toContainEqual(
      expect.objectContaining({ section: 'summary', sizeInBytes: expect.any(Number) }),
    );
    const explicit = await pattern({ ids: ['1'], sections: ['summary'] });
    expect(explicit.entries[0]).toMatchObject({ kind: 'full', description: long });
    expect(JSON.stringify(cweGetAttackPattern.format!(explicit))).toContain(long);
    expect((await pattern({ ids: ['1'], sections: [] })).entries[0]?.kind).toBe('outline');
  });
});

describe('reference and shared contracts', () => {
  it.each(referenceTopics)('validates and formats topic %s from loaded catalogs', async (topic) => {
    const result = await reference({ topic });
    expect(cweListReference.output.safeParse(result).success).toBe(true);
    expect(result.items.length).toBeGreaterThan(0);
    const rendered = JSON.stringify(cweListReference.format!(result));
    expect(rendered).toContain('**provenance**');
    if (topic === 'versions') {
      expect(result.catalogs).toMatchObject([
        { catalog: 'CWE', version: '4.test', counts: { weaknesses: 2, categories: 1, views: 2 } },
        { catalog: 'CAPEC', version: '3.test', etag: 'fixture-etag' },
      ]);
      expect(rendered).toContain('**nextCheckAt**');
    }
    if (topic === 'platforms')
      expect(result.items).toContainEqual(
        expect.objectContaining({ valueKind: 'exampleLanguages', label: 'C' }),
      );
    if (topic === 'views')
      expect(result.items.map((item) => item.id)).toEqual(['CWE-1000', 'CWE-1001']);
  });

  it('supplies abstraction explanations, not only the source labels', async () => {
    const result = await reference({ topic: 'abstraction_levels' });
    expect(
      result.items.every(
        (item) => typeof item.description === 'string' && item.description.length > 0,
      ),
    ).toBe(true);
  });

  it('normalizes static topic and section vocabulary case and whitespace', async () => {
    expect(cweListReference.input.safeParse({ topic: ' VERSIONS ' }).success).toBe(true);
    expect(cweGetWeakness.input.safeParse({ ids: ['79'], sections: [' SUMMARY '] }).success).toBe(
      true,
    );
  });

  it('continues reference pages and rejects tampering, changed queries and stale catalog versions', async () => {
    const first = await reference({ topic: 'views', limit: 1 });
    const cursor = first.pagination.nextCursor!;
    expect((await reference({ topic: 'views', limit: 1, cursor })).items[0]?.id).toBe('CWE-1001');
    for (const args of [
      { topic: 'views', limit: 1, cursor: `${cursor}x` },
      { topic: 'workflow', limit: 1, cursor },
      { topic: 'views', limit: 2, cursor },
      { topic: 'views', limit: 1, filter: 'navigation', cursor },
    ] as const) {
      const invalid = await runToolContract(cweListReference, args);
      expect(invalid.isError).toBe(true);
      expect(invalid.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_cursor' } },
      });
      expect(JSON.stringify(invalid.content)).toContain('without cursor');
    }
    await disposeCatalogService();
    await load(cwe.replace('4.test', '4.next'));
    const stale = await runToolContract(cweListReference, { topic: 'views', limit: 1, cursor });
    expect(stale.isError).toBe(true);
    expect(stale.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cursor' } },
    });
  });

  it('preserves empty reference pages, all-token matching, whitespace input and explicit limit caps', async () => {
    expect((await reference({ topic: 'workflow', filter: 'ROOT cause' })).items).toHaveLength(1);
    const none = await reference({ topic: 'workflow', filter: 'root nonexistent' });
    expect(none.items).toEqual([]);
    expect(none.pagination).toEqual({ total: 0, shown: 0, hasMore: false });
    const emptyWire = await runToolContract(cweListReference, {
      topic: 'workflow',
      filter: 'root nonexistent',
    });
    expect(JSON.stringify(emptyWire)).toContain('No reference item matched every filter token.');
    expect((await reference({ topic: 'workflow', filter: '  ' })).items).toHaveLength(5);
    const provenance = getCatalogService().snapshot().provenance;
    const rows = Array.from({ length: 101 }, (_, index) => index);
    expect(pageItems(rows, { limit: 100 }, ['test'], provenance).pagination).toMatchObject({
      shown: 100,
      hasMore: true,
    });
    const capped = pageItems(rows, { limit: 101 }, ['test'], provenance);
    expect(capped.items).toHaveLength(100);
    expect(capped.notice).toContain('capped at 100');
    expect(
      pageItems(rows, { limit: 101, cursor: capped.pagination.nextCursor! }, ['test'], provenance)
        .items,
    ).toEqual([100]);
    expect(cweListReference.input.safeParse({ topic: 'views', limit: 1000 }).success).toBe(true);
    expect(cweListReference.input.safeParse({ topic: 'views', limit: 1001 }).success).toBe(false);
  });

  it('does not accept suffixes after a valid signed cursor', async () => {
    const first = await reference({ topic: 'views', limit: 1 });
    const result = await runToolContract(cweListReference, {
      topic: 'views',
      limit: 1,
      cursor: `${first.pagination.nextCursor}.ignored`,
    });
    expect(result.isError).toBe(true);
  });

  it('treats whitespace-only optional cursor as unset', async () => {
    const omitted = await runToolContract(cweListReference, { topic: 'workflow' });
    const blank = await runToolContract(cweListReference, { topic: 'workflow', cursor: '   ' });
    expect(blank.isError).not.toBe(true);
    expect(blank.structuredContent).toEqual(omitted.structuredContent);
    expect(blank.content).toEqual(omitted.content);
  });

  it('discloses actual reference cap overflow on both client surfaces', async () => {
    await disposeCatalogService();
    const views = Array.from(
      { length: 101 },
      (_, index) =>
        `<View ID="${2000 + index}" Name="View ${index}" Type="Graph" Status="Stable"><Objective>Browse.</Objective></View>`,
    ).join('');
    await load(cwe.replace('</Views>', `${views}</Views>`));
    const result = await runToolContract(cweListReference, { topic: 'views', limit: 101 });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      items: expect.any(Array),
      pagination: { total: 103, shown: 100, hasMore: true },
      totalCount: 103,
      truncated: true,
      shown: 100,
      cap: 100,
    });
    expect(JSON.stringify(result.content)).toContain('capped at 100');
    expect(JSON.stringify(result.structuredContent)).toContain('capped at 100');
  });

  it('renders code fences safely and preserves prose line breaks and links', () => {
    const value = {
      description: 'First\nSecond\n\n[link](https://example.test/a)',
      examples: [{ blocks: [{ kind: 'code', language: 'C', text: '```\n  <script>\n```' }] }],
      sourceUrl: 'https://example.test/a_(b)?x=1&y=2',
    };
    const text = formatCatalog(value)[0]!.text;
    expect(text).toContain('> First\n> Second\n> \n> [link](https://example.test/a)');
    expect(text).toContain('````\n```\n  <script>\n```\n````');
    expect(text).toContain(
      '[https://example.test/a_(b)?x=1&amp;y=2](<https://example.test/a_(b)?x=1&amp;y=2>)',
    );
  });

  it('preserves XML literal entities and escaped HTML as text through detail formatting', async () => {
    await disposeCatalogService();
    await load(
      cwe.replace(
        'Sparse description.',
        'Literal &amp;lt;tag&amp;gt; and &lt;script&gt;alert(1)&lt;/script&gt;.',
      ),
    );
    const result = await weakness({ ids: ['20'], sections: ['summary'] });
    const description = result.entries[0]!.description!;
    const text = cweGetWeakness.format!(result)
      .flatMap((block) => (block.type === 'text' ? [block.text] : []))
      .join('\n');
    expect(text).not.toMatch(/(?<!\\)<\/?script>/);
    expect(description).toContain('&amp;lt;tag&amp;gt;');
    expect(text).toContain('&amp;lt;tag&amp;gt;');
  });
});
