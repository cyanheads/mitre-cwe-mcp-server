/**
 * @fileoverview Schema-8 additions survive section selection, indexing, and both MCP surfaces.
 * @module tests/tools/schema8-contract.test
 */
import { readFileSync } from 'node:fs';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cweGetView } from '@/mcp-server/tools/definitions/cwe-get-view.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import { cweListReference } from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
import { weaknessSections } from '@/mcp-server/tools/detail-projection.js';
import { formatCatalog } from '@/mcp-server/tools/shared.js';
import { HierarchyService } from '@/services/catalog/hierarchy-service.js';
import { compileViewFilter } from '@/services/catalog/view-filter.js';
import {
  disposeCatalogService,
  getCatalogService,
  initCatalogService,
  SOURCE_URLS,
} from '@/services/index.js';
import { parseMarkdown, renderHtml } from '../helpers/commonmark.js';

const xml = readFileSync(new URL('../fixtures/catalog/cwe-schema8.xml', import.meta.url), 'utf8');
const capec = readFileSync(
  new URL('../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);
async function load(source = xml) {
  await initCatalogService({
    request: async (url) => {
      if (url === SOURCE_URLS.cwe) return new Response(zipSync({ 'cwe.xml': strToU8(source) }));
      if (url === SOURCE_URLS.capec) return new Response(capec);
      throw new Error(`Unexpected URL ${url}`);
    },
    clock: { now: () => 0, schedule: () => ({ cancel() {} }) },
    context: createMockContext(),
  });
}
beforeEach(() => load());
afterEach(disposeCatalogService);
const markdown = (wire: Awaited<ReturnType<typeof runToolContract>>) =>
  wire.content.flatMap((block) => (block.type === 'text' ? [block.text] : [])).join('\n');
const entry = (wire: Awaited<ReturnType<typeof runToolContract>>) =>
  (wire.structuredContent as { entries: Record<string, unknown>[] }).entries[0];

describe('schema-8 delivery', () => {
  it('characterizes existing defaults, empty lookup and invalid ID recovery', async () => {
    const result = await runToolContract(cweGetWeakness, { ids: ['1461'] });
    expect(entry(result)).toMatchObject({
      id: 'CWE-1461',
      type: 'weakness',
      requestedSections: ['summary', 'consequences', 'mitigations', 'relations'],
      description: 'Hardware.',
    });
    const missing = await runToolContract(cweGetWeakness, { ids: ['999999', 'not an ID'] });
    expect(missing.structuredContent).toMatchObject({
      entries: [],
      notFound: [{ reason: 'not_found' }, { reason: 'invalid_id' }],
    });
    expect(parseMarkdown(markdown(missing)).text).toContain('Use one CWE ID per item');
  });

  it('preserves every additive field in its existing selected section and CommonMark rendering', async () => {
    const result = await runToolContract(cweGetWeakness, {
      ids: ['1209'],
      sections: [...weaknessSections],
    });
    expect(result.isError).not.toBe(true);
    expect(entry(result)).toMatchObject({
      technicalNuance: 'Precise **nuance**.\n\nSecond paragraph.',
      dimensions: [
        { type: 'Behavior-Type', value: 'Comparison' },
        { type: 'Code-Property', value: 'Incompatible' },
      ],
      alternateTerms: [{ term: 'Alt_name', roles: ['Common-Name', 'Attack-Focused'] }],
      modesOfIntroduction: [
        { phase: 'Architecture and Design' },
        { phase: 'Implementation' },
        { phase: 'Training', domain: 'AI' },
        { phase: 'Testing' },
        { phase: 'Hardware Manufacturing', domain: 'Hardware' },
      ],
      relatedWeaknesses: [
        {
          nature: 'Overlaps',
          id: 'CWE-1461',
          dimensions: [{ type: 'Resource-Type', value: 'Memory' }],
        },
      ],
      mitigations: [
        {
          phases: ['Training', 'Implementation', 'Output Processing'],
          phaseDetails: [
            { phase: 'Training', domain: 'AI' },
            { phase: 'Implementation' },
            { phase: 'Output Processing', domain: 'AI' },
          ],
        },
        { phases: ['Testing'] },
      ],
      detectionMethods: [
        {
          phases: ['Testing', 'Prompting'],
          phaseDetails: [{ phase: 'Testing' }, { phase: 'Prompting', domain: 'AI' }],
        },
        { method: 'Other' },
      ],
      platforms: [{ note: 'Platform *caveat*.' }, { name: 'Other' }],
      observedExamples: [{ rationales: ['Chain', 'Early-Publication'] }],
      notes: [{ version: '5.0', releaseDate: '2026-10-28' }],
      references: [
        {
          altUrl: 'https://example.test/alt_a?q=1&b=2',
          altUrlDate: '2026-10-23',
          mediaTypes: ['Video', 'Text'],
          accessRestrictions: 'Minimal-Registration',
          rationales: ['Early-Publication', 'Other'],
        },
      ],
    });
    const rendered = markdown(result);
    expect(renderHtml(rendered)).toContain('Precise <strong>nuance</strong>.');
    expect(renderHtml(rendered)).toContain('Platform <em>caveat</em>.');
    expect(renderHtml(rendered)).toContain('href="https://example.test/alt_a?q=1&amp;b=2"');
    for (const literal of [
      'Behavior-Type',
      'Attack-Focused',
      'Hardware Manufacturing',
      'Output Processing',
      'Prompting',
      'Early-Publication',
      'Minimal-Registration',
      '2026-10-23',
    ])
      expect(parseMarkdown(rendered).text).toContain(literal);
  });

  it('resolves nested grouping members and weakness-only view closure', async () => {
    const result = await runToolContract(cweGetWeakness, {
      ids: ['900', '901'],
      sections: ['summary', 'relations', 'mappings', 'notes'],
    });
    expect(result.isError).not.toBe(true);
    expect(entry(result)).toMatchObject({
      type: 'grouping',
      mappingNotes: { usage: 'Prohibited', reasons: ['Grouping'] },
      members: [
        {
          id: 'CWE-901',
          name: 'Nested grouping',
          type: 'grouping',
          dimensions: [{ type: 'Technology', value: 'Hardware' }],
        },
      ],
    });
    expect(parseMarkdown(markdown(result)).text).toContain('Nested grouping');
    const view = await runToolContract(cweGetView, { id: '1000' });
    expect(view.structuredContent).toMatchObject({
      members: [
        {
          id: 'CWE-900',
          type: 'grouping',
          dimensions: [{ type: 'Resource-Type', value: 'Device' }],
        },
      ],
      notes: [{ version: '5.0', releaseDate: '2026-10-28' }],
    });
    expect(parseMarkdown(markdown(view)).text).toContain('Device');
    const search = await runToolContract(cweSearchWeaknesses, { viewId: '1000' });
    expect(search.structuredContent).toMatchObject({ results: [{ id: 'CWE-1209' }] });
  });

  it('preserves shared observed rationales and separate family health counts', async () => {
    const result = await runToolContract(cweSearchWeaknesses, { observedCveId: 'CVE-2026-1234' });
    expect(result.structuredContent).toMatchObject({
      results: [{ matchedObservedExamples: [{ rationales: ['Chain', 'Early-Publication'] }] }],
    });
    expect(parseMarkdown(markdown(result)).text).toContain('Early-Publication');
    const health = await runToolContract(cweListReference, { topic: 'versions' });
    expect(health.structuredContent).toMatchObject({
      catalogs: [{ counts: { weaknesses: 2, categories: 0, groupings: 2, views: 1 } }, {}],
    });
    expect(parseMarkdown(markdown(health)).text).toContain('groupings');
  });

  it('excludes custom phases from source Phase XPath even when their labels equal standard phases', () => {
    const filter = compileViewFilter(
      "/Weakness_Catalog/Weaknesses/Weakness[Modes_Of_Introduction/Introduction/Phase='Implementation']",
    );
    const base = {
      id: 'CWE-1',
      name: 'one',
      type: 'weakness' as const,
      status: 'Draft',
      sourceUrl: 'https://example.test',
      description: 'One.',
    };
    expect(
      filter?.({ ...base, modesOfIntroduction: [{ phase: 'Implementation', domain: 'Hardware' }] }),
    ).toBe(false);
    expect(
      filter?.({
        ...base,
        modesOfIntroduction: [{ phase: 'Testing' }, { phase: 'Implementation' }],
      }),
    ).toBe(true);
  });

  it('names grouping-only statuses and preserves unknown-filter recovery on both surfaces', async () => {
    const result = await runToolContract(cweSearchWeaknesses, { status: 'Stable' });
    expect(result.structuredContent).toMatchObject({
      results: [],
      notice:
        'Status Stable occurs only on CWE groupings, which cwe_search_weaknesses excludes. Call cwe_list_reference with topic filter_values for the statuses weaknesses carry.',
    });
    expect(parseMarkdown(markdown(result)).text).toContain('only on CWE groupings');
    const invalid = await runToolContract(cweSearchWeaknesses, { status: 'invented' });
    expect(invalid.structuredContent).toMatchObject({
      error: { data: { reason: 'unknown_filter' } },
    });
    expect(parseMarkdown(markdown(invalid)).text).toContain('Draft');
  });

  it('preserves unphased prose and treats rationale, role, dimension and domain labels literally', async () => {
    await disposeCatalogService();
    await load(
      xml.replace(
        '<Modes_Of_Introduction>',
        '<Modes_Of_Introduction><Introduction><Note>Unphased <xhtml:b>note</xhtml:b>.</Note></Introduction>',
      ),
    );
    const result = await runToolContract(cweGetWeakness, { ids: ['1209'], sections: ['summary'] });
    expect(entry(result)).toMatchObject({ unphasedIntroductionNotes: ['Unphased **note**.'] });
    expect(renderHtml(markdown(result))).toContain('Unphased <strong>note</strong>.');
    const labels = formatCatalog({
      rationales: ['*Chain*'],
      roles: ['_Role_'],
      dimensions: [{ type: '*Type*', value: '*Value*' }],
      phaseDetails: [{ phase: '*Testing*', domain: '*Hardware*' }],
    })[0].text;
    expect(parseMarkdown(labels).nodes).not.toContain('emph');
    for (const value of ['*Chain*', '_Role_', '*Type*', '*Value*', '*Testing*', '*Hardware*'])
      expect(parseMarkdown(labels).text).toContain(value);
  });

  it('accounts for new summary bytes in default omissions and returns explicit metadata intact', async () => {
    await disposeCatalogService();
    await load(
      xml.replace('Precise <xhtml:b>nuance</xhtml:b>.', `Precise ${'nuance '.repeat(4000)}`),
    );
    const defaults = await runToolContract(cweGetWeakness, { ids: ['1209'] });
    expect(entry(defaults)).toMatchObject({ kind: 'partial', outline: [{ section: 'summary' }] });
    expect(parseMarkdown(markdown(defaults)).text).toContain('summary');
    const selected = await runToolContract(cweGetWeakness, {
      ids: ['1209'],
      sections: ['summary'],
    });
    expect(entry(selected)?.technicalNuance).toBe(
      `Precise ${'nuance '.repeat(4000).trim()}\n\nSecond paragraph.`,
    );
    expect(parseMarkdown(markdown(selected)).text).toContain(
      `Precise ${'nuance '.repeat(4000).trim()}`,
    );
    expect(selected.structuredContent).toMatchObject({
      guidance:
        'One complete selected record and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.',
    });
  });

  it('keeps schema-8 fields across page re-slices and excludes Overlaps from hierarchy closure', async () => {
    const first = await runToolContract(cweSearchWeaknesses, { limit: 1 });
    expect(first.structuredContent).toMatchObject({
      results: [{ id: 'CWE-1209' }],
      pagination: { total: 2, shown: 1, hasMore: true },
    });
    const cursor = (first.structuredContent as { pagination: { nextCursor: string } }).pagination
      .nextCursor;
    const next = await runToolContract(cweSearchWeaknesses, { limit: 1, cursor });
    expect(next.structuredContent).toMatchObject({
      results: [{ id: 'CWE-1461' }],
      pagination: { total: 2, shown: 1, hasMore: false },
    });
    const filtered = await runToolContract(cweSearchWeaknesses, { viewId: '1000' });
    expect(filtered.structuredContent).toMatchObject({
      results: [{ id: 'CWE-1209' }],
      pagination: { total: 1 },
    });
    const invalid = await runToolContract(cweSearchWeaknesses, { viewId: '900' });
    expect(invalid.structuredContent).toMatchObject({
      error: { data: { reason: 'unknown_filter' } },
    });
    expect(parseMarkdown(markdown(invalid)).text).toContain('CWE-900 is a grouping');
    const phases = await runToolContract(cweListReference, { topic: 'mitigation_phases' });
    for (const value of ['Training', 'Implementation', 'Output Processing', 'Testing'])
      expect(parseMarkdown(markdown(phases)).text).toContain(value);
    const empty = await runToolContract(cweGetWeakness, {
      ids: ['1209'],
      sections: ['examples'],
      exampleOffset: 100,
    });
    expect(entry(empty)?.examples).toBeUndefined();
    expect(parseMarkdown(markdown(empty)).text).toContain('no content');
  });

  it.each(['grouping', 'category'])(
    'hydrates grouping roots and nested live topology when the API reports %s',
    async (type) => {
      const service = new HierarchyService({
        request: async () =>
          Response.json([
            {
              Data: { ID: '900', Type: type, ViewID: '1000' },
              Children: [
                {
                  Data: { ID: '901', Type: type, ViewID: '1000' },
                  Children: [
                    { Data: { ID: '1209', Type: 'base_weakness', ViewID: '1000' }, Children: null },
                  ],
                },
              ],
            },
          ]),
      });
      try {
        const result = await service.getHierarchy(
          { id: 'CWE-900', direction: 'descendants', viewId: 'CWE-1000', primaryOnly: false },
          getCatalogService().snapshot(),
          createMockContext(),
        );
        expect(result.edges).toEqual([
          { parentId: 'CWE-900', childId: 'CWE-901', viewId: 'CWE-1000' },
          { parentId: 'CWE-901', childId: 'CWE-1209', viewId: 'CWE-1000' },
        ]);
        expect(
          result.nodes.filter((node) => node.type === 'grouping').map((node) => node.name),
        ).toEqual(['Grouping', 'Nested grouping']);
      } finally {
        await service.dispose();
      }
    },
  );
});
