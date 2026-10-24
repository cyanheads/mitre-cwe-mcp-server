/**
 * @fileoverview Detail projection, reference paging, and both client consumption paths.
 * @module tests/tools/detail-contract.test
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import fc from 'fast-check';
import { strToU8, zipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cweGetAttackPattern } from '@/mcp-server/tools/definitions/cwe-get-attack-pattern.tool.js';
import { cweGetWeakness } from '@/mcp-server/tools/definitions/cwe-get-weakness.tool.js';
import {
  cweListReference,
  referenceTopics,
} from '@/mcp-server/tools/definitions/cwe-list-reference.tool.js';
import { cweSearchWeaknesses } from '@/mcp-server/tools/definitions/cwe-search-weaknesses.tool.js';
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
import { parseMarkdown, referenceDefinitions, renderHtml } from '../helpers/commonmark.js';

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
  `<Extended_Description>Extended narrative.</Extended_Description><Likelihood_Of_Exploit>High</Likelihood_Of_Exploit><Modes_Of_Introduction><Introduction><Phase>Implementation</Phase><Note>Introduced here.</Note></Introduction></Modes_Of_Introduction><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact><Note>Conditional.</Note></Consequence></Common_Consequences><Potential_Mitigations><Mitigation><Phase>Architecture and Design</Phase><Description>Validate all fields.</Description><Effectiveness>High</Effectiveness></Mitigation></Potential_Mitigations><Detection_Methods><Detection_Method><Method>Static Analysis</Method><Description>Trace data.</Description></Detection_Method></Detection_Methods><Observed_Examples><Observed_Example><Reference>CVE-2026-0001</Reference><Description>Observed case.</Description><Link>https://example.test/cve</Link></Observed_Example></Observed_Examples><Applicable_Platforms><Language Name="C" Class="Compiled"/><Technology Name="Web Server"/><Operating_System Class="Unix"/><Architecture Name="x86"/></Applicable_Platforms><Mapping_Notes><Usage>ALLOWED</Usage><Rationale>Root cause.</Rationale><Comments>Check context.</Comments><Reasons><Reason>Acceptable</Reason></Reasons></Mapping_Notes><Weakness_Ordinalities><Weakness_Ordinality><Ordinality>Primary</Ordinality></Weakness_Ordinality><Weakness_Ordinality><Ordinality>Resultant</Ordinality><Description>Follows <xhtml:b>input</xhtml:b> gaps.</Description></Weakness_Ordinality></Weakness_Ordinalities><Background_Details><Background_Detail><xhtml:p>Browsers keep *state*.</xhtml:p><xhtml:ul><xhtml:li>one</xhtml:li><xhtml:li>two</xhtml:li></xhtml:ul></Background_Detail></Background_Details><Functional_Areas><Functional_Area>File_Processing *raw*</Functional_Area></Functional_Areas><Affected_Resources><Affected_Resource>File or Directory</Affected_Resource></Affected_Resources><Notes><Note Type="Relationship">Related to <xhtml:b>CWE-20</xhtml:b>.</Note><Note Type="Research Gap"><xhtml:p>First paragraph.</xhtml:p><xhtml:p># Not a heading.</xhtml:p></Note></Notes><Related_Weaknesses>`,
);
const capec = originalCapec.replace(
  '<Prerequisites>',
  '<Typical_Severity>High</Typical_Severity><Likelihood_Of_Attack>Medium</Likelihood_Of_Attack><Extended_Description>Extended attack.</Extended_Description><Resources_Required><Resource>One browser.</Resource></Resources_Required><Example_Instances><Example>First instance.</Example><Example>Second instance.</Example></Example_Instances><Indicators><Indicator>Outer signal.</Indicator></Indicators><Notes><Note Type="Terminology">Also called <xhtml:i>splitting</xhtml:i>.</Note></Notes><Prerequisites>',
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
type Wire = Awaited<ReturnType<typeof runToolContract>>;
/** Every rendered `content[]` line, as a client that forwards the text sees it. */
const lines = (wire: Wire) =>
  wire.content.flatMap((block) => (block.type === 'text' ? block.text.split('\n') : []));
/** Each value rendered under `**key**`, copied out of `content[]` without its quote marker. */
const copied = (wire: Wire, key: string) =>
  lines(wire).flatMap((line, index, all) =>
    line === `**${key}**` ? [all[index + 2]?.replace(/^> /, '') ?? ''] : [],
  );
/** The items of a string list rendered under `**key**`, copied out of `content[]` in order. */
function copiedList(wire: Wire, key: string): string[] {
  const all = lines(wire);
  const values: string[] = [];
  for (
    let index = all.indexOf(`**${key}**`) + 2;
    /^\*\*\d+\*\*$/.test(all[index] ?? '');
    index += 4
  )
    values.push(all[index + 2]?.replace(/^> /, '') ?? '');
  return values;
}
/** Serialized bytes of both surfaces, enrichment included: what the response budget measures. */
const delivered = (wire: Wire) => Buffer.byteLength(JSON.stringify(wire), 'utf8');
const entriesOf = (wire: Wire) =>
  (wire.structuredContent as { entries: Record<string, unknown>[] }).entries;
/** The sections a notice or guidance re-call says to request, as a caller reads them from the text. */
const recalled = (notice: string) =>
  JSON.parse(/sections (\[[^\]]*\])/.exec(notice)?.[1] ?? 'null') as string[];
/** Every argument a partial entry's notice re-call names: its sections, then each example parameter. */
function recallArgs(notice: string): Record<string, unknown> {
  const tail = notice.slice(notice.indexOf(']', notice.indexOf('sections [')) + 1);
  const args: Record<string, unknown> = { sections: recalled(notice) };
  for (const [, key, value] of tail.matchAll(/(example\w+) ("[^"]*"|\d+)/g))
    args[key as string] = JSON.parse(value as string);
  return args;
}
/** Delivered size of one section: its structured JSON plus its rendered `content[]` text. */
const sectionBytes = (fields: Record<string, unknown>) =>
  Buffer.byteLength(JSON.stringify(fields)) +
  Buffer.byteLength(JSON.stringify(formatCatalog(fields)[0].text));
/** A one-section outline as `content[]` renders it; requestedSections never renders these labels. */
const outlineText = (entry: Record<string, unknown>) => {
  const [{ section, sizeInBytes }] = entry.outline as [{ section: string; sizeInBytes: number }];
  return `**outline**\n\n**1**\n\n**section**\n\n> ${section}\n\n**sizeInBytes**\n\n${sizeInBytes}`;
};
beforeEach(async () => {
  await load();
});
afterEach(async () => {
  await disposeCatalogService();
});

describe('complete detail contracts', () => {
  it('splits omitted recalls by their complete response and keeps example arguments on their group', async () => {
    await disposeCatalogService();
    const mitigation = 'm'.repeat(6000);
    const example = 'e'.repeat(6000);
    await load(
      cwe
        .replace('Conditional.', 'c'.repeat(7800))
        .replace('Validate all fields.', mitigation)
        .replace(
          '<Body_Text>Second example.</Body_Text>',
          `<Body_Text>${example}</Body_Text><Example_Code Language="C">second();</Example_Code>`,
        ),
    );
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      exampleLanguage: ' c ',
      exampleOffset: 1,
      exampleLimit: 1,
    });
    const notice = entriesOf(wire)[0]?.notice as string;
    const recipes = [
      ...notice.matchAll(/Repeat cwe_get_weakness with this ID and sections .*?(?=\. |\.$)/g),
    ].map(([recipe]) => recallArgs(recipe));
    expect(recipes).toEqual([
      { sections: ['mitigations'] },
      { sections: ['examples'], exampleLanguage: 'C', exampleOffset: 1, exampleLimit: 1 },
    ]);
    expect(lines(wire)).toContain(`> ${notice}`);
    for (const args of recipes) {
      const recall = await runToolContract(cweGetWeakness, { ids: ['79'], ...args });
      expect(delivered(recall)).toBeLessThanOrEqual(24_000);
      expect(entriesOf(recall)[0]?.kind).toBe('full');
      expect(lines(recall)).toContain(
        `> ${(args.sections as string[]).includes('examples') ? example : mitigation}`,
      );
    }
  });
  it('keeps a small combined omitted-section recall together', async () => {
    await disposeCatalogService();
    await load(
      cwe
        .replace('Conditional.', 'c'.repeat(10000))
        .replace('Validate all fields.', 'm'.repeat(2000))
        .replace('Before code.', 'unselected'.repeat(4000))
        .replace('Second example.', 'e'.repeat(2000)),
    );
    const wire = await runToolContract(cweGetWeakness, { ids: ['79'], exampleOffset: 1 });
    expect(entriesOf(wire)[0]?.notice).toContain(
      'sections ["mitigations","relations","examples"], exampleOffset 1.',
    );
    const recall = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: ['mitigations', 'relations', 'examples'],
      exampleOffset: 1,
    });
    expect(delivered(recall)).toBeLessThanOrEqual(24_000);
    expect(lines(recall)).toContain(`> ${'m'.repeat(2000)}`);
    expect(JSON.stringify(recall)).not.toContain('unselected');
  });

  it('splits CAPEC recalls in declared order and preserves an oversized section intact', async () => {
    await disposeCatalogService();
    const prerequisite = 'p'.repeat(6000);
    const execution = 'e'.repeat(13000);
    const mitigation = 'm'.repeat(6000);
    await load(
      cwe,
      capec
        .replace('Attack description.', 's'.repeat(7800))
        .replace('First prerequisite.', prerequisite)
        .replace('Use input.', execution)
        .replace('Validate.', mitigation),
    );
    const wire = await runToolContract(cweGetAttackPattern, { ids: ['1'] });
    const entry = entriesOf(wire)[0]!;
    const notice = entry.notice as string;
    const recipes = [
      ...notice.matchAll(/Repeat cwe_get_attack_pattern with this ID and sections .*?(?=\. |\.$)/g),
    ].map(([recipe]) => recalled(recipe));
    expect(recipes).toEqual([['prerequisites'], ['execution'], ['mitigations']]);
    expect((entry.outline as { section: string }[]).map(({ section }) => section)).toEqual(
      recipes.flat(),
    );
    expect(lines(wire)).toContain(`> ${notice}`);
    for (const sections of recipes) {
      const recall = await runToolContract(cweGetAttackPattern, { ids: ['1'], sections });
      expect(entriesOf(recall)[0]).toMatchObject({ kind: 'full', requestedSections: sections });
      if (sections.includes('execution')) {
        expect(delivered(recall)).toBeGreaterThan(24_000);
        for (const surface of [recall.content, recall.structuredContent])
          expect(JSON.stringify(surface)).toContain('returned intact');
        expect(lines(recall)).toContain(`> ${execution}`);
      } else expect(delivered(recall)).toBeLessThanOrEqual(24_000);
    }
  });
  it('delivers nested prose quotes and empty lists intact on both surfaces', async () => {
    await disposeCatalogService();
    const prose =
      '<xhtml:div style="margin-left:1em;"><xhtml:p>Quoted <xhtml:b>payload</xhtml:b>.</xhtml:p><xhtml:ul><xhtml:li><xhtml:ul><xhtml:li/><xhtml:li/></xhtml:ul></xhtml:li></xhtml:ul><xhtml:div style="margin-left:1em;">nested</xhtml:div></xhtml:div>';
    await load(cwe.replace('Sparse description.', prose), capec.replace('First instance.', prose));
    for (const [definition, input, field] of [
      [cweGetWeakness, { ids: ['20'], sections: ['summary'] }, 'description'],
      [cweGetAttackPattern, { ids: ['1'], sections: ['examples'] }, 'exampleInstances'],
    ] as const) {
      const wire = await runToolContract(definition, {
        ids: [...input.ids],
        sections: [...input.sections],
      });
      expect(wire.isError).not.toBe(true);
      const stored = entriesOf(wire)[0]![field];
      const markdown = Array.isArray(stored) ? (stored[0] as string) : (stored as string);
      expect(parseMarkdown(markdown).text.trim()).toBe('Quoted payload.\nnested');
      expect(parseMarkdown(markdown).nodes.filter((node) => node === 'block_quote')).toHaveLength(
        2,
      );
      expect(parseMarkdown(markdown).nodes.filter((node) => node === 'list')).toHaveLength(2);
      expect(parseMarkdown(markdown).nodes).not.toContain('thematic_break');
      const document = wire.content
        .flatMap((block) => (block.type === 'text' ? [block.text] : []))
        .join('\n');
      expect(document).toContain(
        markdown
          .split('\n')
          .map((line) => `> ${line}`)
          .join('\n'),
      );
    }
  });

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
      text: 'if (a < b) {\n    call("x");\n}\nnext();',
      language: 'C',
      nature: 'Bad',
    });
    expect(entry.examples?.[0]?.blocks[3]).toMatchObject({
      text: '  literal <tag> &amp;\n    next();',
    });
    const rendered = cweGetWeakness.format!(result)
      .flatMap((block) => (block.type === 'text' ? [block.text] : []))
      .join('\n');
    expect(rendered).toContain('```\nif (a < b) {\n    call("x");\n}\nnext();\n```');
    expect(rendered).toContain('[https://example.test/ref](<https://example.test/ref>)');
    expect(rendered).toContain('Before code.');
    expect(rendered).toContain('After code.');
  });

  it('returns an example’s references beside its blocks on both surfaces', async () => {
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: ['examples'],
      exampleLimit: 1,
    });
    expect(wire.isError).not.toBe(true);
    const [example] =
      cweGetWeakness.output.parse(wire.structuredContent).entries[0]?.examples ?? [];
    expect(example?.references).toEqual([
      {
        id: 'REF-2',
        authors: ['Carol'],
        title: 'Example source',
        url: 'https://example.test/example-source',
        section: 'Figure 3',
      },
    ]);
    expect(example?.blocks.map(({ kind }) => kind)).toEqual([
      'prose',
      'code',
      'prose',
      'code',
      'prose',
    ]);
    expect(copied(wire, 'text')).not.toContain('');
    expect(copied(wire, 'id')).toContain('REF-2');
    expect(copied(wire, 'title')).toEqual(['Example source']);
    expect(copiedList(wire, 'authors')).toEqual(['Carol']);
    expect(copied(wire, 'section')).toEqual(['Figure 3']);
    expect(lines(wire)).toContain(
      '[https://example.test/example-source](<https://example.test/example-source>)',
    );
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
    // A malformed item is its own result; the rest of the batch still resolves.
    const malformed = await runToolContract(cweGetWeakness, {
      ids: ['0', 'CAPEC-1', '-1', '1.2', 'CWE-', '79'],
      sections: [],
    });
    expect(malformed.isError).not.toBe(true);
    const { entries, notFound } = malformed.structuredContent as {
      entries: { id: string }[];
      notFound: { id: string; reason: string; guidance: string }[];
    };
    expect(entries.map((entry) => entry.id)).toEqual(['CWE-79']);
    expect(notFound.map(({ id, reason }) => [id, reason])).toEqual([
      ['0', 'invalid_id'],
      ['CAPEC-1', 'wrong_type'],
      ['-1', 'invalid_id'],
      ['1.2', 'invalid_id'],
      ['CWE-', 'invalid_id'],
    ]);
    expect(copied(malformed, 'id').map((line) => parseMarkdown(line).text)).toEqual([
      'CWE-79',
      '0',
      'CAPEC-1',
      '-1',
      '1.2',
      'CWE-',
    ]);
    const batch = await pattern({
      ids: Array.from({ length: 21 }, (_, index) => String(index + 1)),
    });
    expect(batch.deferredIds).toEqual(['CAPEC-21']);
  });

  it('resolves a mixed batch per item, with recovery for each miss on both surfaces', async () => {
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['79', 'CWE79', '20', 'CWE-', 'NVD-CWE-noinfo', 'CAPEC-1', 'nvd-cwe-other'],
      sections: [],
    });
    expect(wire.isError).not.toBe(true);
    expect(cweGetWeakness.output.safeParse(wire.structuredContent).success).toBe(true);
    const generic =
      'Use one CWE ID per item, such as CWE-79, CWE79, or 79. Call cwe_search_weaknesses to find a CWE ID, then repeat cwe_get_weakness.';
    const nvd =
      'NVD-CWE-noinfo and NVD-CWE-Other are NVD placeholders that name no CWE entry. Call cwe_search_weaknesses with terms from the vulnerability description to find the weakness.';
    expect(wire.structuredContent).toMatchObject({
      entries: [{ id: 'CWE-79' }, { id: 'CWE-20' }],
      notFound: [
        { id: 'CWE-', reason: 'invalid_id', guidance: generic },
        { id: 'NVD-CWE-noinfo', reason: 'invalid_id', guidance: nvd },
        {
          id: 'CAPEC-1',
          reason: 'wrong_type',
          guidance: 'This is a CAPEC ID. Call cwe_get_attack_pattern with it.',
        },
        { id: 'nvd-cwe-other', reason: 'invalid_id', guidance: nvd },
      ],
      deferredIds: [],
      totalCount: 6,
    });
    // content[] alone carries every item, reason, and recovery, each parsing back to its value.
    const parsed = (key: string) => copied(wire, key).map((line) => parseMarkdown(line).text);
    expect(parsed('id')).toEqual([
      'CWE-79',
      'CWE-20',
      'CWE-',
      'NVD-CWE-noinfo',
      'CAPEC-1',
      'nvd-cwe-other',
    ]);
    expect(parsed('reason')).toEqual(['invalid_id', 'invalid_id', 'wrong_type', 'invalid_id']);
    expect(parsed('guidance')).toEqual([
      generic,
      nvd,
      'This is a CAPEC ID. Call cwe_get_attack_pattern with it.',
      nvd,
    ]);
  });

  it('answers a CWE ID in the CAPEC tool as wrong_type and other text as invalid_id', async () => {
    const wire = await runToolContract(cweGetAttackPattern, {
      ids: ['1', 'CWE-79', 'cwe 020', 'NVD-CWE-noinfo', 'CAPEC-', 'capec_002'],
      sections: [],
    });
    expect(wire.isError).not.toBe(true);
    const toWeakness =
      'This is a CWE ID. Call cwe_get_weakness with it, or cwe_get_view for a CWE view.';
    const generic =
      'Use one CAPEC ID per item, such as CAPEC-66, CAPEC66, or 66. Call cwe_search_attack_patterns to find a CAPEC ID, then repeat cwe_get_attack_pattern.';
    expect(wire.structuredContent).toMatchObject({
      entries: [{ id: 'CAPEC-1' }, { id: 'CAPEC-2' }],
      notFound: [
        { id: 'CWE-79', reason: 'wrong_type', guidance: toWeakness },
        { id: 'CWE-20', reason: 'wrong_type', guidance: toWeakness },
        { id: 'NVD-CWE-noinfo', reason: 'invalid_id', guidance: generic },
        { id: 'CAPEC-', reason: 'invalid_id', guidance: generic },
      ],
    });
    expect(copied(wire, 'guidance').map((line) => parseMarkdown(line).text)).toEqual([
      toWeakness,
      toWeakness,
      generic,
      generic,
    ]);
  });

  it('defers an invalid item past position 20 and answers it as invalid_id when resubmitted', async () => {
    const valid = Array.from({ length: 20 }, (_, index) => String(index + 100));
    const first = await runToolContract(cweGetWeakness, {
      ids: [...valid, 'CWE-', 'x\n\ty'],
      sections: [],
    });
    expect(first.isError).not.toBe(true);
    // The collapsed spelling is one line, so a client copies it out of content[] whole.
    expect(first.structuredContent).toMatchObject({ deferredIds: ['CWE-', 'x y'], shown: 20 });
    expect(copiedList(first, 'deferredIds')).toEqual(['CWE-', 'x y']);
    const second = await runToolContract(cweGetWeakness, {
      ids: copiedList(first, 'deferredIds'),
      sections: [],
    });
    expect(second.structuredContent).toMatchObject({
      entries: [],
      notFound: [
        { id: 'CWE-', reason: 'invalid_id' },
        { id: 'x y', reason: 'invalid_id' },
      ],
      deferredIds: [],
    });
  });

  it('reads one ID per item, accepting whitespace separators and never splitting joined text', async () => {
    const result = await weakness({
      ids: ['79,20', '79 20', '79\n20', 'CWE\t20', 'cwe 079', ' CWE  0020 '],
      sections: [],
    });
    expect(result.entries.map((entry) => entry.id)).toEqual(['CWE-20', 'CWE-79']);
    expect(result.notFound.map(({ id, reason }) => [id, reason])).toEqual([
      ['79,20', 'invalid_id'],
      ['79 20', 'invalid_id'],
    ]);
  });

  it('rejects a control character in an item and bounds echoed text that is no ID', async () => {
    for (const ids of [['79\u0000'], ['20', '\u001f79']]) {
      const wire = await runToolContract(cweGetWeakness, { ids });
      expect(wire.isError).toBe(true);
      expect(wire.structuredContent).toMatchObject({
        error: { code: -32602, data: { reason: 'invalid_arguments' } },
      });
      for (const surface of [wire.content, wire.structuredContent])
        expect(JSON.stringify(surface)).toContain(
          'Remove control characters U+0000–U+0008 and U+000E–U+001F: no catalog ID contains them.',
        );
    }
    const longest = await weakness({ ids: ['x'.repeat(150), `${'0'.repeat(300)}79`] });
    expect(longest.entries.map((entry) => entry.id)).toEqual(['CWE-79']);
    expect(longest.notFound).toMatchObject([{ id: 'x'.repeat(150), reason: 'invalid_id' }]);
    const longer = await runToolContract(cweGetWeakness, { ids: ['79', 'x'.repeat(151)] });
    expect(longer.isError).toBe(true);
    expect(JSON.stringify(longer.content)).toContain(
      'An item that is not a catalog ID can be at most 150 characters.',
    );
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

  it('outlines oversized delivered defaults but preserves explicit selections', async () => {
    const description = 'Sparse description.';
    const at = description + 'x'.repeat(24000);
    await disposeCatalogService();
    await load(cwe.replace(description, at));
    expect((await weakness({ ids: ['20'] })).entries[0]?.kind).toBe('outline');
    const explicit = await weakness({ ids: ['20'], sections: ['summary'] });
    expect(explicit.entries[0]).toMatchObject({ kind: 'full', description: at });
    expect(JSON.stringify(cweGetWeakness.format!(explicit))).toContain(at);
  });

  it('omits an oversized CAPEC default section, keeps the rest and honors explicit complete and empty sections', async () => {
    await disposeCatalogService();
    const long = 'é'.repeat(13000);
    await load(cwe, capec.replace('Attack description.', long));
    const wire = await runToolContract(cweGetAttackPattern, { ids: ['1'] });
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const entry = entriesOf(wire)[0]!;
    const notice =
      'Omitted to fit the 24,000-byte response budget: summary. Repeat cwe_get_attack_pattern with this ID and sections ["summary"].';
    expect(entry).toMatchObject({
      kind: 'partial',
      requestedSections: ['summary', 'prerequisites', 'execution', 'mitigations', 'mappings'],
      prerequisites: ['First prerequisite.', 'Second prerequisite.'],
      attackTechniqueIds: ['T1059.001'],
      outline: [{ section: 'summary', sizeInBytes: expect.any(Number) }],
      notice,
    });
    expect(entry).not.toHaveProperty('description');
    expect(entry).toHaveProperty('executionFlow');
    expect(lines(wire)).toContain(`> ${notice}`);
    expect(lines(wire).join('\n')).toContain(outlineText(entry));
    // The notice's re-call returns exactly the omitted section, complete.
    const explicit = await runToolContract(cweGetAttackPattern, {
      ids: ['1'],
      sections: recalled(notice),
    });
    expect(entriesOf(explicit)[0]).toMatchObject({ kind: 'full', description: long });
    expect(lines(explicit)).toContain(`> ${long}`);
    expect((await pattern({ ids: ['1'], sections: [] })).entries[0]?.kind).toBe('outline');
  });

  it('keeps default sections in declared order, omitting one that overflows even when it is smaller', async () => {
    // Consequences come first and are larger; mitigations alone would fit but not after them.
    const note = 'c'.repeat(7800);
    const mitigation = 'm'.repeat(4500);
    await disposeCatalogService();
    await load(cwe.replace('Conditional.', note).replace('Validate all fields.', mitigation));
    const wire = await runToolContract(cweGetWeakness, { ids: ['79'] });
    expect(wire.isError).not.toBe(true);
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const entry = entriesOf(wire)[0]!;
    const notice =
      'Omitted to fit the 24,000-byte response budget: mitigations. Repeat cwe_get_weakness with this ID and sections ["mitigations"].';
    expect(entry).toMatchObject({
      kind: 'partial',
      requestedSections: ['summary', 'consequences', 'mitigations', 'relations'],
      consequences: [{ note }],
      relatedWeaknesses: [{ id: 'CWE-20' }],
      outline: [{ section: 'mitigations', sizeInBytes: expect.any(Number) }],
      notice,
    });
    expect(entry).not.toHaveProperty('mitigations');
    expect(entry).toHaveProperty('description');
    for (const line of [`> ${notice}`, `> ${note}`, '> partial'])
      expect(lines(wire)).toContain(line);
    expect(lines(wire).join('\n')).toContain(outlineText(entry));
    expect(lines(wire)).not.toContain(`> ${mitigation}`);
    // The omitted section's size is what adding it costs a response, on both surfaces.
    const marginal =
      delivered(
        await runToolContract(cweGetWeakness, {
          ids: ['79'],
          sections: ['summary', 'mitigations'],
        }),
      ) - delivered(await runToolContract(cweGetWeakness, { ids: ['79'], sections: ['summary'] }));
    const size = (entry.outline as { sizeInBytes: number }[])[0]!.sizeInBytes;
    expect(Math.abs(size - marginal) / marginal).toBeLessThan(0.02);
    const recall = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: recalled(notice),
    });
    expect(entriesOf(recall)[0]).toMatchObject({
      kind: 'full',
      requestedSections: ['mitigations'],
      mitigations: [{ description: mitigation }],
    });
  });

  it('joins the absent-section and omitted-section notices for a category', async () => {
    const summary = 'é'.repeat(13000);
    await disposeCatalogService();
    await load(cwe.replace('Organizational summary.', summary));
    const wire = await runToolContract(cweGetWeakness, { ids: ['900'] });
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const notice =
      'The source entry has no content for these selected sections: consequences, mitigations. Omitted to fit the 24,000-byte response budget: summary. Repeat cwe_get_weakness with this ID and sections ["summary"].';
    expect(entriesOf(wire)[0]).toMatchObject({
      kind: 'partial',
      type: 'category',
      members: [{ id: 'CWE-79' }, { id: 'CWE-20' }],
      outline: [{ section: 'summary', sizeInBytes: expect.any(Number) }],
      notice,
    });
    expect(entriesOf(wire)[0]).not.toHaveProperty('description');
    // The notice copied out of content[] reads back as the value, and embeds verbatim.
    expect(copied(wire, 'notice').map((line) => parseMarkdown(line).text)).toEqual([notice]);
    expect(lines(wire)).toContain(`> ${notice}`);
  });

  it('outlines a default record when each of its sections overflows alone', async () => {
    const huge = 'q'.repeat(24000);
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Description>Sparse description.</Description>',
        `<Description>${huge}</Description><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact><Note>${huge}</Note></Consequence></Common_Consequences><Potential_Mitigations><Mitigation><Description>${huge}</Description></Mitigation></Potential_Mitigations>`,
      ),
    );
    const wire = await runToolContract(cweGetWeakness, { ids: ['20'] });
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const entry = entriesOf(wire)[0]!;
    expect(entry).toMatchObject({
      kind: 'outline',
      outline: [
        { section: 'summary', sizeInBytes: expect.any(Number) },
        { section: 'consequences', sizeInBytes: expect.any(Number) },
        { section: 'mitigations', sizeInBytes: expect.any(Number) },
      ],
    });
    for (const field of ['description', 'consequences', 'mitigations'])
      expect(entry).not.toHaveProperty(field);
  });

  it('adds an example page to the default sections when an example parameter is in effect, on both surfaces', async () => {
    // CWE-20 carries a Java example, so Java is loaded vocabulary that CWE-79 never matches.
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Description>Sparse description.</Description>',
        '<Description>Sparse description.</Description><Demonstrative_Examples><Demonstrative_Example><Example_Code Language="Java">run();</Example_Code></Demonstrative_Example></Demonstrative_Examples>',
      ),
    );
    const requested = ['summary', 'consequences', 'mitigations', 'relations', 'examples'];
    // Each parameter alone puts examples in effect, and a page walk follows nextOffset. An offset
    // past the end and a language no example of the record uses return an empty page.
    for (const [args, indexes, page] of [
      [{ exampleLanguage: 'c' }, [0], { total: 1, shown: 1, offset: 0, hasMore: false }],
      [{ exampleLimit: 1 }, [0], { total: 2, shown: 1, offset: 0, hasMore: true, nextOffset: 1 }],
      [
        { exampleOffset: 1, exampleLimit: 1 },
        [1],
        { total: 2, shown: 1, offset: 1, hasMore: false },
      ],
      [{ exampleOffset: 200 }, [], { total: 2, shown: 0, offset: 200, hasMore: false }],
      [{ exampleLanguage: 'java' }, [], { total: 0, shown: 0, offset: 0, hasMore: false }],
    ] as const) {
      const label = JSON.stringify(args);
      const wire = await runToolContract(cweGetWeakness, { ids: ['79'], ...args });
      expect(wire.isError, label).not.toBe(true);
      const entry = cweGetWeakness.output.parse(wire.structuredContent).entries[0]!;
      expect(entry, label).toMatchObject({
        kind: 'full',
        requestedSections: requested,
        consequences: [{ note: 'Conditional.' }],
        mitigations: [{ description: 'Validate all fields.' }],
        relatedWeaknesses: [{ id: 'CWE-20' }],
      });
      expect(entry, label).toHaveProperty('description');
      expect(entry, label).not.toHaveProperty('notice');
      expect(
        entry.examples?.map(({ index }) => index),
        label,
      ).toEqual(indexes);
      expect(entry.examplePage, label).toEqual(page);
      expect(copiedList(wire, 'requestedSections'), label).toEqual(requested);
      expect(copied(wire, 'examples')[0] === '[]', label).toBe(indexes.length === 0);
      for (const [index, line] of [
        [0, '> Before code.'],
        [1, '> Second example.'],
      ] as const)
        expect(lines(wire).includes(line), `${label} ${line}`).toBe(
          (indexes as readonly number[]).includes(index),
        );
      expect(
        Object.keys(page).flatMap((key) => copied(wire, key)),
        label,
      ).toEqual(Object.values(page).map(String));
    }
  });

  it('keeps calls whose example parameters hold their defaults byte-identical to calls without them', async () => {
    for (const args of [{ ids: ['79', '900', '20'] }, { ids: ['79'], sections: ['summary'] }]) {
      const plain = await runToolContract(cweGetWeakness, args);
      for (const defaults of [
        { exampleLimit: 3 },
        { exampleOffset: 0 },
        { exampleLanguage: '  ' },
        { exampleOffset: 0, exampleLimit: 3 },
      ])
        expect(await runToolContract(cweGetWeakness, { ...args, ...defaults })).toEqual(plain);
    }
  });

  it('omits an example page that does not fit beside the defaults and sizes it as the page its re-call returns', async () => {
    // Defaults fit; the page selected by exampleOffset 1, the second example, does not fit beside them.
    const note = 'c'.repeat(7800);
    const second = 'e'.repeat(4500);
    await disposeCatalogService();
    await load(cwe.replace('Conditional.', note).replace('Second example.', second));
    const wire = await runToolContract(cweGetWeakness, { ids: ['79'], exampleOffset: 1 });
    expect(wire.isError).not.toBe(true);
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const entry = entriesOf(wire)[0]!;
    const notice =
      'Omitted to fit the 24,000-byte response budget: examples. Repeat cwe_get_weakness with this ID and sections ["examples"], exampleOffset 1.';
    expect(entry).toMatchObject({
      kind: 'partial',
      requestedSections: ['summary', 'consequences', 'mitigations', 'relations', 'examples'],
      consequences: [{ note }],
      mitigations: [{ description: 'Validate all fields.' }],
      outline: [{ section: 'examples', sizeInBytes: expect.any(Number) }],
      notice,
    });
    expect(entry).not.toHaveProperty('examples');
    expect(entry).not.toHaveProperty('examplePage');
    expect(lines(wire)).toContain(`> ${notice}`);
    expect(lines(wire).join('\n')).toContain(outlineText(entry));
    expect(lines(wire)).not.toContain(`> ${second}`);
    // The notice's re-call, executed verbatim, returns the advertised page within the budget.
    const args = recallArgs(notice);
    expect(args).toEqual({ sections: ['examples'], exampleOffset: 1 });
    const recall = await runToolContract(cweGetWeakness, { ids: ['79'], ...args });
    expect(recall.isError).not.toBe(true);
    expect(delivered(recall)).toBeLessThanOrEqual(24_000);
    const page = entriesOf(recall)[0]!;
    expect(page).toMatchObject({
      kind: 'full',
      examples: [{ index: 1, blocks: [{ kind: 'prose', text: second }] }],
      examplePage: { total: 2, shown: 1, offset: 1, hasMore: false },
    });
    expect(lines(recall)).toContain(`> ${second}`);
    const size = (entry.outline as { sizeInBytes: number }[])[0]!.sizeInBytes;
    expect(size).toBe(sectionBytes({ examples: page.examples, examplePage: page.examplePage }));
  });

  it('names example parameters in the re-call of a default record that outlines whole', async () => {
    const huge = 'q'.repeat(24000);
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Description>Sparse description.</Description>',
        `<Description>${huge}</Description><Common_Consequences><Consequence><Scope>Integrity</Scope><Impact>Modify Data</Impact><Note>${huge}</Note></Consequence></Common_Consequences><Potential_Mitigations><Mitigation><Description>${huge}</Description></Mitigation></Potential_Mitigations><Demonstrative_Examples><Demonstrative_Example><Body_Text>Prose only.</Body_Text></Demonstrative_Example><Demonstrative_Example><Example_Code Language="Java">${huge}</Example_Code></Demonstrative_Example></Demonstrative_Examples>`,
      ),
    );
    const wire = await runToolContract(cweGetWeakness, { ids: ['20'], exampleLanguage: 'java' });
    expect(delivered(wire)).toBeLessThanOrEqual(24_000);
    const entry = entriesOf(wire)[0]!;
    const notice =
      'Repeat cwe_get_weakness with this ID and explicit sections, one section at a time for large records; add exampleLanguage "Java" when selecting examples.';
    expect(entry).toMatchObject({ kind: 'outline', notice });
    expect(lines(wire)).toContain(`> ${notice}`);
    const outline = entry.outline as { section: string; sizeInBytes: number }[];
    expect(outline.map(({ section }) => section)).toEqual([
      'summary',
      'consequences',
      'mitigations',
      'examples',
    ]);
    const page = entriesOf(
      await runToolContract(cweGetWeakness, {
        ids: ['20'],
        sections: ['examples'],
        exampleLanguage: 'Java',
      }),
    )[0]!;
    expect(page.examples).toMatchObject([{ index: 1 }]);
    expect(outline[3]!.sizeInBytes).toBe(
      sectionBytes({ examples: page.examples, examplePage: page.examplePage }),
    );
  });

  it('returns explicit sections without examples unchanged and gives the re-call that applies example parameters', async () => {
    const summary = await runToolContract(cweGetWeakness, {
      ids: ['79', '20'],
      sections: ['summary'],
    });
    expect(summary.structuredContent).not.toHaveProperty('guidance');
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['79', '20'],
      sections: ['summary'],
      exampleOffset: 1,
    });
    expect(wire.isError).not.toBe(true);
    expect(entriesOf(wire)).toEqual(entriesOf(summary));
    const guidance =
      'The example parameters (exampleOffset 1) apply only to section examples, which the selected sections exclude. Repeat cwe_get_weakness with sections ["summary","examples"] to apply them.';
    expect(wire.structuredContent).toMatchObject({ guidance });
    // One call-level sentence, copied out of content[] as the value it renders.
    expect(copied(wire, 'guidance').map((line) => parseMarkdown(line).text)).toEqual([guidance]);
    // The guidance re-call, executed verbatim with the caller's other arguments, applies the offset.
    const recall = await runToolContract(cweGetWeakness, {
      ids: ['79', '20'],
      sections: recalled(guidance),
      exampleOffset: 1,
    });
    expect(recall.structuredContent).not.toHaveProperty('guidance');
    expect(entriesOf(recall)[0]).toMatchObject({
      kind: 'full',
      requestedSections: ['summary', 'examples'],
      examples: [{ index: 1 }],
      examplePage: { total: 2, shown: 1, offset: 1, hasMore: false },
    });
    // An empty selection keeps its outline and names every parameter in effect.
    const outline = await runToolContract(cweGetWeakness, { ids: ['79'], sections: [] });
    const named = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: [],
      exampleLanguage: ' c ',
      exampleOffset: 2,
      exampleLimit: 1,
    });
    expect(entriesOf(named)).toEqual(entriesOf(outline));
    const namedGuidance =
      'The example parameters (exampleLanguage "C", exampleOffset 2, exampleLimit 1) apply only to section examples, which the selected sections exclude. Repeat cwe_get_weakness with sections ["examples"] to apply them.';
    expect(named.structuredContent).toMatchObject({ guidance: namedGuidance });
    expect(copied(named, 'guidance').map((line) => parseMarkdown(line).text)).toEqual([
      namedGuidance,
    ]);
  });

  it('sizes an outlined examples section as the page its plain re-call returns', async () => {
    await disposeCatalogService();
    await load(
      cwe.replace(
        '</Demonstrative_Examples>',
        '<Demonstrative_Example><Body_Text>Third example.</Body_Text></Demonstrative_Example><Demonstrative_Example><Body_Text>Fourth example, past the default page of three.</Body_Text></Demonstrative_Example></Demonstrative_Examples>',
      ),
    );
    const page = entriesOf(
      await runToolContract(cweGetWeakness, { ids: ['79'], sections: ['examples'] }),
    )[0]!;
    expect(page.examplePage).toMatchObject({ total: 4, shown: 3, hasMore: true });
    const expected = sectionBytes({ examples: page.examples, examplePage: page.examplePage });
    // The outline's plain re-call (no example parameters) returns the default page, whatever the
    // parameters of the outlining call.
    for (const extra of [{}, { exampleOffset: 1 }]) {
      const label = JSON.stringify(extra);
      const wire = await runToolContract(cweGetWeakness, { ids: ['79'], sections: [], ...extra });
      const outline = entriesOf(wire)[0]!.outline as { section: string; sizeInBytes: number }[];
      const at = outline.findIndex(({ section }) => section === 'examples');
      expect(outline[at]?.sizeInBytes, label).toBe(expected);
      expect(copied(wire, 'sizeInBytes')[at], label).toBe(String(expected));
    }
  });

  it('rejects an unknown example language whatever the sections select', async () => {
    for (const sections of [undefined, ['summary'], ['examples'], []]) {
      const wire = await runToolContract(cweGetWeakness, {
        ids: ['79'],
        exampleLanguage: 'Imaginary',
        ...(sections ? { sections } : {}),
      });
      const label = JSON.stringify(sections);
      const message = 'Unknown exampleLanguage "Imaginary"; supported values: C.';
      expect(wire.isError, label).toBe(true);
      expect(wire.structuredContent, label).toMatchObject({
        error: { message, data: { reason: 'unknown_filter', field: 'exampleLanguage' } },
      });
      expect(lines(wire), label).toEqual(
        expect.arrayContaining([`Error: ${message}`, '(reason unknown_filter · not retryable)']),
      );
    }
  });

  it('returns alternate terms in the summary section in source order on both surfaces', async () => {
    const cweTerms: { term: string; description?: string }[] = [
      { term: 'XSS', description: 'Common **acronym** for a_b \\<script>.' },
      { term: 'Reflected XSS / Type 1 XSS' },
      { term: 'HTML_Injection [legacy]' },
    ];
    const capecTerms: { term: string; description?: string }[] = [
      { term: 'Man-in-the-Middle / MITM' },
      { term: 'On-path Attacker', description: 'Neutral term.' },
    ];
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Related_Weaknesses>',
        '<Alternate_Terms><Alternate_Term><Term>XSS</Term><Description>Common <xhtml:b>acronym</xhtml:b> for a_b &lt;script&gt;.</Description></Alternate_Term><Alternate_Term><Term>Reflected XSS / Type 1 XSS</Term></Alternate_Term><Alternate_Term><Term>HTML_Injection [legacy]</Term></Alternate_Term></Alternate_Terms><Related_Weaknesses>',
      ),
      capec.replace(
        '<Prerequisites>',
        '<Alternate_Terms><Alternate_Term><Term>Man-in-the-Middle / MITM</Term></Alternate_Term><Alternate_Term><Term>On-path Attacker</Term><Description>Neutral term.</Description></Alternate_Term></Alternate_Terms><Prerequisites>',
      ),
    );
    for (const [wire, expected] of [
      [await runToolContract(cweGetWeakness, { ids: ['79'], sections: ['summary'] }), cweTerms],
      [
        await runToolContract(cweGetAttackPattern, { ids: ['1'], sections: ['summary'] }),
        capecTerms,
      ],
    ] as const) {
      expect(wire.isError).not.toBe(true);
      expect(wire.structuredContent).toMatchObject({
        entries: [{ kind: 'full', alternateTerms: expected }],
      });
      // Each term parses back to its value; each explanation is embedded verbatim.
      expect(copied(wire, 'term').map((line) => parseMarkdown(line).text)).toEqual(
        expected.map(({ term }) => term),
      );
      for (const { description } of expected)
        if (description) expect(lines(wire)).toContain(`> ${description}`);
    }
    const summary = await weakness({ ids: ['79'], sections: ['summary'] });
    expect(cweGetWeakness.output.safeParse(summary).success).toBe(true);
    // The default selection includes summary; other sections and records without terms omit it.
    expect((await weakness({ ids: ['79'] })).entries[0]).toMatchObject({
      kind: 'full',
      alternateTerms: cweTerms,
    });
    expect((await weakness({ ids: ['79'], sections: ['mappings'] })).entries[0]).not.toHaveProperty(
      'alternateTerms',
    );
    const sparse = await runToolContract(cweGetWeakness, { ids: ['20'], sections: ['summary'] });
    expect((sparse.structuredContent as { entries: object[] }).entries[0]).not.toHaveProperty(
      'alternateTerms',
    );
    expect(lines(sparse)).not.toContain('**alternateTerms**');
    expect((await pattern({ ids: ['2'], sections: ['summary'] })).entries[0]).not.toHaveProperty(
      'alternateTerms',
    );
  });

  it('outlines a default that its alternate terms push past the budget, never cutting a term', async () => {
    expect((await weakness({ ids: ['20'] })).entries[0]?.kind).toBe('full');
    const long = 'y'.repeat(24000);
    const terms = [{ term: 'Short' }, { term: 'Long', description: long }];
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Description>Sparse description.</Description>',
        `<Description>Sparse description.</Description><Alternate_Terms><Alternate_Term><Term>Short</Term></Alternate_Term><Alternate_Term><Term>Long</Term><Description>${long}</Description></Alternate_Term></Alternate_Terms>`,
      ),
    );
    const outline = await weakness({ ids: ['20'] });
    // The size counts both surfaces, so it exceeds twice the 24,000-character term.
    const sizeInBytes = sectionBytes({ description: 'Sparse description.', alternateTerms: terms });
    expect(sizeInBytes).toBeGreaterThan(48_000);
    expect(outline.entries[0]).toMatchObject({
      kind: 'outline',
      outline: [{ section: 'summary', sizeInBytes }],
    });
    expect(outline.entries[0]).not.toHaveProperty('alternateTerms');
    const explicit = await runToolContract(cweGetWeakness, { ids: ['20'], sections: ['summary'] });
    expect(explicit.structuredContent).toMatchObject({
      entries: [{ kind: 'full', alternateTerms: terms }],
    });
    expect(lines(explicit)).toContain(`> ${long}`);
  });

  it('returns records without the added elements exactly as before on both surfaces', async () => {
    const provenance = {
      cweVersion: '4.test',
      cweDate: '2026-04-30',
      capecVersion: '3.test',
      capecDate: '2023-01-24',
      loadedAt: '2026-10-20T00:00:00.000Z',
    };
    const listed = (key: string, values: readonly string[]) => [
      `**${key}**`,
      ...values.flatMap((value, index) => [`**${index + 1}**`, `> ${value}`]),
    ];
    const tail = [
      '**notFound**',
      '[]',
      '**deferredIds**',
      '[]',
      '**provenance**',
      ...Object.entries(provenance).flatMap(([key, value]) => [`**${key}**`, `> ${value}`]),
    ];
    const cweSections = [
      'summary',
      'consequences',
      'mitigations',
      'relations',
      'examples',
      'detection',
      'observed',
      'platforms',
      'mappings',
    ];
    const cweNotice =
      'The source entry has no content for these selected sections: consequences, mitigations, relations, examples, detection, observed, platforms, mappings.';
    const cweWire = await runToolContract(cweGetWeakness, { ids: ['20'], sections: cweSections });
    expect(cweWire.structuredContent).toEqual({
      entries: [
        {
          id: 'CWE-20',
          name: 'Sparse',
          status: 'Incomplete',
          sourceUrl: 'https://cwe.mitre.org/data/definitions/20.html',
          kind: 'full',
          requestedSections: cweSections,
          availableSections: ['summary'],
          notice: cweNotice,
          type: 'weakness',
          description: 'Sparse description.',
        },
      ],
      notFound: [],
      deferredIds: [],
      provenance,
      totalCount: 1,
    });
    expect(cweWire.content).toEqual([
      {
        type: 'text',
        text: [
          '**entries**',
          '**1**',
          '**id**',
          '> CWE-20',
          '**name**',
          '> Sparse',
          '**status**',
          '> Incomplete',
          '**sourceUrl**',
          '[https://cwe.mitre.org/data/definitions/20.html](<https://cwe.mitre.org/data/definitions/20.html>)',
          '**kind**',
          '> full',
          ...listed('requestedSections', cweSections),
          ...listed('availableSections', ['summary']),
          '**notice**',
          `> ${cweNotice}`,
          '**type**',
          '> weakness',
          '**description**',
          '> Sparse description.',
          ...tail,
        ].join('\n\n'),
      },
      { type: 'text', text: '\n\n**1 total**\n\n' },
    ]);
    const capecSections = [
      'summary',
      'prerequisites',
      'execution',
      'skills',
      'consequences',
      'mitigations',
      'examples',
      'relations',
      'mappings',
    ];
    const capecNotice =
      'The source entry has no content for these selected sections: prerequisites, execution, skills, consequences, mitigations, examples, relations, mappings.';
    const capecWire = await runToolContract(cweGetAttackPattern, {
      ids: ['2'],
      sections: capecSections,
    });
    expect(capecWire.structuredContent).toEqual({
      entries: [
        {
          id: 'CAPEC-2',
          name: 'Sparse pattern',
          status: 'Deprecated',
          abstraction: 'Meta',
          sourceUrl: 'https://capec.mitre.org/data/definitions/2.html',
          kind: 'full',
          requestedSections: capecSections,
          availableSections: ['summary'],
          notice: capecNotice,
          type: 'attack_pattern',
          description: 'Only identity and description.',
        },
      ],
      notFound: [],
      deferredIds: [],
      provenance,
      totalCount: 1,
    });
    expect(capecWire.content).toEqual([
      {
        type: 'text',
        text: [
          '**entries**',
          '**1**',
          '**id**',
          '> CAPEC-2',
          '**name**',
          '> Sparse pattern',
          '**status**',
          '> Deprecated',
          '**abstraction**',
          '> Meta',
          '**sourceUrl**',
          '[https://capec.mitre.org/data/definitions/2.html](<https://capec.mitre.org/data/definitions/2.html>)',
          '**kind**',
          '> full',
          ...listed('requestedSections', capecSections),
          ...listed('availableSections', ['summary']),
          '**notice**',
          `> ${capecNotice}`,
          '**type**',
          '> attack_pattern',
          '**description**',
          '> Only identity and description.',
          ...tail,
        ].join('\n\n'),
      },
      { type: 'text', text: '\n\n**1 total**\n\n' },
    ]);
  });

  it('names related weaknesses from the loaded catalog on both surfaces and omits unresolved names', async () => {
    await disposeCatalogService();
    await load(
      cwe.replace(
        '<Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000" Ordinal="Primary"/>',
        '<Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000" Ordinal="Primary"/><Related_Weakness Nature="CanPrecede" CWE_ID="404" View_ID="1000"/>',
      ),
    );
    const wire = await runToolContract(cweGetWeakness, { ids: ['79'], sections: ['relations'] });
    expect(wire.isError).not.toBe(true);
    const [entry] = (wire.structuredContent as { entries: Record<string, unknown>[] }).entries;
    expect(entry?.relatedWeaknesses).toEqual([
      { nature: 'ChildOf', id: 'CWE-20', name: 'Sparse', viewId: 'CWE-1000', ordinal: 'Primary' },
      { nature: 'CanPrecede', id: 'CWE-404', viewId: 'CWE-1000' },
    ]);
    const rendered = lines(wire).filter(Boolean);
    const start = rendered.indexOf('**relatedWeaknesses**');
    expect(rendered.slice(start, rendered.indexOf('**relatedAttackPatterns**'))).toEqual([
      '**relatedWeaknesses**',
      '**1**',
      '**nature**',
      '> ChildOf',
      '**id**',
      '> CWE-20',
      '**name**',
      '> Sparse',
      '**viewId**',
      '> CWE-1000',
      '**ordinal**',
      '> Primary',
      '**2**',
      '**nature**',
      '> CanPrecede',
      '**id**',
      '> CWE-404',
      '**viewId**',
      '> CWE-1000',
    ]);
    // Other sections and the related record itself are unchanged.
    expect(entry).not.toHaveProperty('notes');
    expect(
      (await weakness({ ids: ['20'], sections: ['relations'] })).entries[0],
    ).not.toHaveProperty('relatedWeaknesses');
  });

  it('returns ordinalities and background details in summary and functional areas in platforms on both surfaces', async () => {
    const summary = await runToolContract(cweGetWeakness, { ids: ['79'], sections: ['summary'] });
    expect(summary.isError).not.toBe(true);
    const [entry] = (summary.structuredContent as { entries: Record<string, unknown>[] }).entries;
    const background = 'Browsers keep \\*state\\*.\n\n- one\n- two';
    expect(entry?.ordinalities).toEqual([
      { ordinality: 'Primary' },
      { ordinality: 'Resultant', description: 'Follows **input** gaps.' },
    ]);
    expect(entry?.backgroundDetails).toEqual([background]);
    expect(entry).not.toHaveProperty('functionalAreas');
    // Prose embeds verbatim, one quoted line per stored line; source values copy back exactly.
    const rendered = lines(summary);
    const item = rendered.indexOf('**backgroundDetails**') + 4;
    expect(rendered[item - 2]).toBe('**1**');
    // The quoted detail reads as the source text: no emphasis forms, and the list stays a list.
    expect(parseMarkdown(rendered.slice(item, item + 4).join('\n')).text).toBe(
      'Browsers keep *state*.\none\ntwo',
    );
    const block = rendered.indexOf('> Browsers keep \\*state\\*.');
    expect(rendered.slice(block, block + 4)).toEqual([
      '> Browsers keep \\*state\\*.',
      '> ',
      '> - one',
      '> - two',
    ]);
    expect(rendered).toContain('> Follows **input** gaps.');
    expect(copied(summary, 'ordinality')).toEqual(['Primary', 'Resultant']);
    // Ordinalities and background details are part of the default summary.
    expect((await weakness({ ids: ['79'] })).entries[0]).toMatchObject({
      kind: 'full',
      ordinalities: [{ ordinality: 'Primary' }, { ordinality: 'Resultant' }],
      backgroundDetails: [background],
    });
    const platforms = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: ['platforms'],
    });
    expect(platforms.structuredContent).toMatchObject({
      entries: [
        {
          kind: 'full',
          functionalAreas: ['File_Processing *raw*'],
          affectedResources: ['File or Directory'],
        },
      ],
    });
    const platformLines = lines(platforms).filter(Boolean);
    for (const [key, value] of [
      ['functionalAreas', 'File_Processing *raw*'],
      ['affectedResources', 'File or Directory'],
    ] as const) {
      const index = platformLines.indexOf(`**${key}**`);
      expect(platformLines[index + 1]).toBe('**1**');
      const quoted = platformLines[index + 2]?.replace(/^> /, '') ?? '';
      expect(parseMarkdown(quoted).text).toBe(value);
    }
    expect(platformLines).toContain('> File_Processing \\*raw\\*');
  });

  it('returns notes only when selected, for weaknesses, categories and CAPEC patterns on both surfaces', async () => {
    await disposeCatalogService();
    await load(
      cwe.replace(
        '</Relationships></Category>',
        '</Relationships><Notes><Note Type="Maintenance">Category <xhtml:i>note</xhtml:i>.</Note></Notes></Category>',
      ),
    );
    for (const result of [await weakness({ ids: ['79', '900'] }), await pattern({ ids: ['1'] })])
      for (const entry of result.entries) {
        expect(entry.kind).toBe('full');
        expect(entry.availableSections).toContain('notes');
        expect(entry.requestedSections).not.toContain('notes');
        expect(entry).not.toHaveProperty('notes');
      }
    const wire = await runToolContract(cweGetWeakness, {
      ids: ['79', '900', '20'],
      sections: ['notes'],
    });
    expect(wire.isError).not.toBe(true);
    const entries = (wire.structuredContent as { entries: Record<string, unknown>[] }).entries;
    expect(entries.map((entry) => entry.notes)).toEqual([
      [
        { type: 'Relationship', text: 'Related to **CWE-20**.' },
        { type: 'Research Gap', text: 'First paragraph.\n\n\\# Not a heading.' },
      ],
      [{ type: 'Maintenance', text: 'Category *note*.' }],
      undefined,
    ]);
    expect(entries[2]).toMatchObject({
      kind: 'full',
      availableSections: ['summary'],
      notice: 'The source entry has no content for these selected sections: notes.',
    });
    // Note types copy back as plain text after each record type; note text embeds verbatim.
    expect(copied(wire, 'type')).toEqual([
      'weakness',
      'Relationship',
      'Research Gap',
      'category',
      'Maintenance',
      'weakness',
    ]);
    const rendered = lines(wire);
    const paragraphs = rendered.indexOf('> First paragraph.');
    expect(rendered.slice(paragraphs, paragraphs + 3)).toEqual([
      '> First paragraph.',
      '> ',
      '> \\# Not a heading.',
    ]);
    expect(
      parseMarkdown(rendered.slice(paragraphs, paragraphs + 3).join('\n')).nodes,
    ).not.toContain('heading');
    for (const text of ['> Related to **CWE-20**.', '> Category *note*.'])
      expect(rendered).toContain(text);
    const capecWire = await runToolContract(cweGetAttackPattern, {
      ids: ['1', '2'],
      sections: ['notes'],
    });
    expect(capecWire.isError).not.toBe(true);
    expect(capecWire.structuredContent).toMatchObject({
      entries: [
        {
          id: 'CAPEC-1',
          kind: 'full',
          notes: [{ type: 'Terminology', text: 'Also called *splitting*.' }],
        },
        {
          id: 'CAPEC-2',
          availableSections: ['summary'],
          notice: 'The source entry has no content for these selected sections: notes.',
        },
      ],
    });
    expect((capecWire.structuredContent as { entries: object[] }).entries[1]).not.toHaveProperty(
      'notes',
    );
    expect(copied(capecWire, 'type')).toEqual(['attack_pattern', 'Terminology', 'attack_pattern']);
    expect(lines(capecWire)).toContain('> Also called *splitting*.');
    expect(
      cweGetWeakness.output.safeParse(await weakness({ ids: ['79'], sections: ['notes'] })).success,
    ).toBe(true);
  });

  it('returns CAPEC categories and views as typed entries with members, filters and their own defaults', async () => {
    type Entry = Record<string, unknown> & { members?: Record<string, unknown>[] };
    const entriesOf = (wire: Wire) =>
      (wire.structuredContent as { entries: Entry[]; notFound: unknown[] }).entries;
    // A view, a category, and a pattern in one call all resolve.
    const mixed = await runToolContract(cweGetAttackPattern, {
      ids: ['CAPEC-1000', '118', '1'],
      sections: ['summary'],
    });
    expect(mixed.isError).not.toBe(true);
    expect((mixed.structuredContent as { notFound: unknown[] }).notFound).toEqual([]);
    expect(entriesOf(mixed).map(({ id, type, kind }) => [id, type, kind])).toEqual([
      ['CAPEC-1000', 'view', 'full'],
      ['CAPEC-118', 'category', 'full'],
      ['CAPEC-1', 'attack_pattern', 'full'],
    ]);
    expect(entriesOf(mixed)[0]).toMatchObject({
      description: 'Organizes patterns by the mechanism they employ.',
    });
    expect(entriesOf(mixed)[1]).toMatchObject({
      description: 'Patterns that focus on **gathering** information.',
    });
    for (const entry of entriesOf(mixed).slice(0, 2))
      expect(entry).not.toHaveProperty('abstraction');
    expect(entriesOf(mixed)[2]).toMatchObject({ abstraction: 'Detailed' });
    expect(copied(mixed, 'type')).toEqual(['view', 'category', 'attack_pattern']);

    // Omitted sections: categories and views default to summary and relations; patterns keep theirs.
    const filter = "/Attack_Pattern_Catalog/Attack_Patterns/Attack_Pattern[@Abstraction='Meta']";
    const defaults = await runToolContract(cweGetAttackPattern, {
      ids: ['1000', '118', '282', '1'],
    });
    expect(defaults.isError).not.toBe(true);
    const [view, category, implicit, attack] = entriesOf(defaults);
    expect([view, category, implicit, attack].map((entry) => entry?.requestedSections)).toEqual([
      ['summary', 'relations'],
      ['summary', 'relations'],
      ['summary', 'relations'],
      ['summary', 'prerequisites', 'execution', 'mitigations', 'mappings'],
    ]);
    // Members in source order, resolved from the loaded catalog, with no view ID.
    expect(view?.members).toEqual([
      {
        id: 'CAPEC-118',
        name: 'Collect and Analyze Information',
        type: 'category',
        status: 'Stable',
      },
      {
        id: 'CAPEC-119',
        name: 'DEPRECATED: Deplete Resources',
        type: 'category',
        status: 'Deprecated',
      },
      { id: 'CAPEC-404' },
    ]);
    expect(category?.members).toEqual([
      {
        id: 'CAPEC-2',
        name: 'Sparse pattern',
        type: 'attack_pattern',
        status: 'Deprecated',
        abstraction: 'Meta',
      },
      {
        id: 'CAPEC-1',
        name: 'Synthetic attack',
        type: 'attack_pattern',
        status: 'Stable',
        abstraction: 'Detailed',
      },
    ]);
    expect(implicit).toMatchObject({
      kind: 'full',
      filterDefinition: filter,
      availableSections: ['summary', 'relations', 'mappings', 'notes'],
    });
    expect(implicit).not.toHaveProperty('members');
    expect(attack).toMatchObject({ type: 'attack_pattern', abstraction: 'Detailed' });
    expect(attack).not.toHaveProperty('members');
    // content[] carries the same members and the XPath as literal text.
    expect(copied(defaults, 'name').slice(0, 4)).toEqual([
      'Mechanisms of Attack',
      'Collect and Analyze Information',
      'DEPRECATED: Deplete Resources',
      'Collect and Analyze Information',
    ]);
    const rendered = lines(defaults);
    expect(parseMarkdown(rendered[rendered.indexOf('**filterDefinition**') + 2] ?? '').text).toBe(
      filter,
    );

    // Mappings and notes have the pattern shape.
    const grouped = await runToolContract(cweGetAttackPattern, {
      ids: ['118', '282'],
      sections: ['mappings', 'notes'],
    });
    expect(entriesOf(grouped)).toMatchObject([
      {
        taxonomyMappings: [{ taxonomy: 'WASC', id: '13', name: 'Information Leakage' }],
        references: [{ id: 'CAP-REF', title: 'Attack reference', section: '2' }],
        notes: [{ type: 'Maintenance', text: 'Category *note*.' }],
      },
      {
        references: [{ id: 'CAP-REF', title: 'Attack reference' }],
        notes: [{ type: 'Other', text: 'View note.' }],
      },
    ]);
    expect(lines(grouped)).toContain('> Category *note*.');

    // Outlines name this tool for every CAPEC record type, never cwe_get_weakness.
    const outlined = entriesOf(
      await runToolContract(cweGetAttackPattern, { ids: ['1000', '118', '1'], sections: [] }),
    );
    for (const entry of outlined)
      expect(entry).toMatchObject({
        kind: 'outline',
        notice:
          'Repeat cwe_get_attack_pattern with this ID and explicit sections, one section at a time for large records.',
      });
    expect((await weakness({ ids: ['79'], sections: [] })).entries[0]?.notice).toBe(
      'Repeat cwe_get_weakness with this ID and explicit sections, one section at a time for large records.',
    );

    // An unknown ID still returns the search guidance.
    expect((await pattern({ ids: ['999999', '119'] })).notFound).toEqual([
      {
        id: 'CAPEC-999999',
        reason: 'not_found',
        guidance:
          'Call cwe_search_attack_patterns to find an existing CAPEC ID, then repeat cwe_get_attack_pattern.',
      },
    ]);
    for (const result of [
      await pattern({ ids: ['1000', '118', '282'] }),
      await pattern({ ids: ['119'], sections: attackPatternSections }),
    ])
      expect(cweGetAttackPattern.output.safeParse(result).success).toBe(true);
  });

  it('counts background details toward a default outline but never notes', async () => {
    const long = 'z'.repeat(24000);
    const withSparse = (xml: string) =>
      cwe.replace(
        '<Description>Sparse description.</Description>',
        `<Description>Sparse description.</Description>${xml}`,
      );
    await disposeCatalogService();
    await load(
      withSparse(
        `<Background_Details><Background_Detail>${long}</Background_Detail></Background_Details>`,
      ),
    );
    const outline = await weakness({ ids: ['20'] });
    expect(outline.entries[0]).toMatchObject({
      kind: 'outline',
      outline: [
        {
          section: 'summary',
          sizeInBytes: sectionBytes({
            description: 'Sparse description.',
            backgroundDetails: [long],
          }),
        },
      ],
    });
    expect(outline.entries[0]).not.toHaveProperty('backgroundDetails');
    await disposeCatalogService();
    await load(withSparse(`<Notes><Note Type="Maintenance">${long}</Note></Notes>`));
    const defaults = await runToolContract(cweGetWeakness, { ids: ['20'] });
    expect(defaults.structuredContent).toMatchObject({
      entries: [{ kind: 'full', availableSections: ['summary', 'notes'] }],
    });
    expect(JSON.stringify(defaults)).not.toContain(long);
    const explicit = await runToolContract(cweGetWeakness, { ids: ['20'], sections: ['notes'] });
    expect(explicit.structuredContent).toMatchObject({
      entries: [{ kind: 'full', notes: [{ type: 'Maintenance', text: long }] }],
    });
    expect(lines(explicit)).toContain(`> ${long}`);
    // An outline lists the notes section and its size so it can be requested.
    expect((await weakness({ ids: ['20'], sections: [] })).entries[0]?.outline).toEqual([
      { section: 'summary', sizeInBytes: expect.any(Number) },
      {
        section: 'notes',
        sizeInBytes: sectionBytes({ notes: [{ type: 'Maintenance', text: long }] }),
      },
    ]);
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
        {
          catalog: 'CAPEC',
          version: '3.test',
          etag: 'fixture-etag',
          counts: { attackPatterns: 2, categories: 2, views: 2 },
        },
      ]);
      expect(rendered).toContain('**nextCheckAt**');
    }
    if (topic === 'platforms')
      expect(result.items).toContainEqual(
        expect.objectContaining({ valueKind: 'exampleLanguages', label: 'C' }),
      );
    // CAPEC views stay out: CAPEC-1000 would read as CWE-1000 in a mixed list.
    if (topic === 'views')
      expect(result.items.map((item) => item.id)).toEqual(['CWE-1000', 'CWE-1001']);
    if (topic === 'workflow') {
      const mechanics = result.items.find((item) => item.key === 'mechanics')?.description;
      expect(mechanics).toContain('CAPEC-1000');
      expect(mechanics).toContain('CAPEC-3000');
      expect(rendered).toContain('CAPEC-3000');
    }
  });

  it('lists the source filter of a filter-defined view beside its zero member count', async () => {
    const filter = "/Weakness_Catalog/*/*[@Status='Draft']";
    const wire = await runToolContract(cweListReference, { topic: 'views' });
    expect(wire.isError).not.toBe(true);
    expect(wire.structuredContent).toMatchObject({
      items: [
        { id: 'CWE-1000', directMemberCount: 2 },
        { id: 'CWE-1001', directMemberCount: 0, filterDefinition: filter },
      ],
    });
    expect((wire.structuredContent as { items: object[] }).items[0]).not.toHaveProperty(
      'filterDefinition',
    );
    // The XPath renders as literal text: unescaped, `*/*` would parse as emphasis.
    const rendered = lines(wire);
    expect(parseMarkdown(rendered[rendered.indexOf('**filterDefinition**') + 2] ?? '').text).toBe(
      filter,
    );
  });

  it('supplies abstraction explanations, not only the source labels', async () => {
    const result = await reference({ topic: 'abstraction_levels' });
    expect(
      result.items.every(
        (item) => typeof item.description === 'string' && item.description.length > 0,
      ),
    ).toBe(true);
  });

  it('lists CWE mapping usage values recorded on weaknesses under filter_values', async () => {
    await disposeCatalogService();
    // A category's usage stays out: the filter searches weaknesses only.
    await load(
      cwe.replace(
        '<Summary>Organizational summary.</Summary>',
        '<Summary>Organizational summary.</Summary><Mapping_Notes><Usage>Prohibited</Usage></Mapping_Notes>',
      ),
    );
    const wire = await runToolContract(cweListReference, { topic: 'filter_values', limit: 100 });
    expect(wire.isError).not.toBe(true);
    const { items } = wire.structuredContent as {
      items: { key: string; label: string; valueKind?: string; catalog?: string }[];
    };
    expect(items.filter((item) => item.valueKind === 'cweMappingUsages')).toEqual([
      {
        key: 'cweMappingUsages:ALLOWED',
        label: 'ALLOWED',
        valueKind: 'cweMappingUsages',
        catalog: 'CWE',
      },
    ]);
    expect([...new Set(items.map((item) => item.valueKind))]).toEqual([
      'consequenceImpacts',
      'cweStatuses',
      'cweMappingUsages',
      'cweTaxonomyNames',
      'capecStatuses',
      'capecSeverities',
      'capecLikelihoods',
    ]);
    // The label an agent copies out of content[] is a working mappingUsage value.
    const label = copied(wire, 'label').find((value) => value === 'ALLOWED');
    const search = await runToolContract(cweSearchWeaknesses, { mappingUsage: label });
    expect(search.structuredContent).toMatchObject({
      results: [{ id: 'CWE-79', mappingUsage: 'ALLOWED' }],
      appliedFilters: { mappingUsage: 'ALLOWED' },
      totalCount: 1,
    });
    expect(cweListReference.input.shape.topic.description).toContain('CWE mapping usage');
  });

  it('lists the taxonomy names weakness mappings record under filter_values', async () => {
    await disposeCatalogService();
    // A taxonomy only a category records stays out: the filter searches weaknesses only.
    await load(
      cwe
        .replace(
          '<Summary>Organizational summary.</Summary>',
          '<Summary>Organizational summary.</Summary><Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="Category Taxonomy"><Entry_ID>X1</Entry_ID></Taxonomy_Mapping></Taxonomy_Mappings>',
        )
        .replace(
          '<Taxonomy_Mapping Taxonomy_Name="OWASP">',
          '<Taxonomy_Mapping Taxonomy_Name="ISA/IEC 62443"><Entry_ID>Part 4-2</Entry_ID></Taxonomy_Mapping><Taxonomy_Mapping Taxonomy_Name="OWASP">',
        ),
    );
    const wire = await runToolContract(cweListReference, { topic: 'filter_values', limit: 100 });
    expect(wire.isError).not.toBe(true);
    const { items } = wire.structuredContent as {
      items: { key: string; label: string; valueKind?: string; catalog?: string }[];
    };
    expect(items.filter((item) => item.valueKind === 'cweTaxonomyNames')).toEqual([
      {
        key: 'cweTaxonomyNames:ISA/IEC 62443',
        label: 'ISA/IEC 62443',
        valueKind: 'cweTaxonomyNames',
        catalog: 'CWE',
      },
      {
        key: 'cweTaxonomyNames:OWASP',
        label: 'OWASP',
        valueKind: 'cweTaxonomyNames',
        catalog: 'CWE',
      },
    ]);
    const labels = copied(wire, 'label');
    expect(labels).not.toContain('Category Taxonomy');
    // The label an agent copies out of content[] is a working taxonomyName value.
    const search = await runToolContract(cweSearchWeaknesses, {
      taxonomyName: labels.find((value) => value === 'ISA/IEC 62443'),
    });
    expect(search.structuredContent).toMatchObject({
      results: [
        {
          id: 'CWE-79',
          matchedTaxonomyMappings: [{ taxonomy: 'ISA/IEC 62443', id: 'Part 4-2' }],
        },
      ],
      appliedFilters: { taxonomyName: 'ISA/IEC 62443' },
      totalCount: 1,
    });
    // A category-only taxonomy is unknown to the weakness search.
    const unknown = await runToolContract(cweSearchWeaknesses, {
      taxonomyName: 'Category Taxonomy',
    });
    expect(unknown.structuredContent).toMatchObject({
      error: {
        message:
          'Unknown taxonomyName "Category Taxonomy"; supported values: ISA/IEC 62443, OWASP.',
        data: {
          reason: 'unknown_filter',
          field: 'taxonomyName',
          supported: ['ISA/IEC 62443', 'OWASP'],
        },
      },
    });
    expect(cweListReference.input.shape.topic.description).toContain('CWE taxonomy names');
  });

  it('lists under filter_values only the CWE statuses weaknesses carry', async () => {
    await disposeCatalogService();
    // Category 900 is the only Obsolete record; the weaknesses are Draft and Incomplete.
    await load(cwe.replace('Name="Category" Status="Stable"', 'Name="Category" Status="Obsolete"'));
    const wire = await runToolContract(cweListReference, { topic: 'filter_values', limit: 100 });
    const { items } = wire.structuredContent as {
      items: { label: string; valueKind?: string }[];
    };
    const statuses = (kind: string) =>
      items.filter((item) => item.valueKind === kind).map((item) => item.label);
    expect(statuses('cweStatuses')).toEqual(['Draft', 'Incomplete']);
    expect(statuses('capecStatuses')).toEqual(['Deprecated', 'Stable']);
    const rendered = copied(wire, 'label');
    expect(rendered).not.toContain('Obsolete');
    expect(rendered).toEqual(expect.arrayContaining(['Draft', 'Incomplete']));
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
    expect(emptyWire.structuredContent).toMatchObject({
      notice:
        'No reference item matched every token of the filter "root nonexistent". Repeat cwe_list_reference with fewer terms, or without filter to list every item in topic workflow.',
    });
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

  it('collapses reference filter whitespace so its echo parses back and continuations bind it', async () => {
    const first = await runToolContract(cweListReference, {
      topic: 'workflow',
      filter: ' →  \r\n\tCWE ',
      limit: 1,
    });
    expect(first.isError).not.toBe(true);
    const { appliedFilters, items, pagination } = first.structuredContent as {
      appliedFilters: { filter: string };
      items: { key: string }[];
      pagination: { nextCursor: string };
    };
    expect(appliedFilters.filter).toBe('→ cwe');
    expect(copied(first, 'filter').map((line) => parseMarkdown(line).text)).toEqual(['→ cwe']);
    expect(items.map((item) => item.key)).toEqual(['root-cause']);
    // The continuation belongs to the normalized query, however its whitespace was written.
    const next = await runToolContract(cweListReference, {
      topic: 'workflow',
      filter: '→ cwe',
      limit: 1,
      cursor: pagination.nextCursor,
    });
    expect(next.isError).not.toBe(true);
    expect(next.structuredContent).toMatchObject({ items: [{ key: 'mechanics' }] });
    // Text that would read as a link reference definition is a literal search, echoed literally.
    const literal = await runToolContract(cweListReference, {
      topic: 'workflow',
      filter: '[a](b]: javascript:alert(1)',
    });
    expect(literal.structuredContent).toMatchObject({
      items: [],
      appliedFilters: { filter: '[a](b]: javascript:alert(1)' },
    });
    expect(copied(literal, 'filter').map((line) => parseMarkdown(line).text)).toEqual([
      '[a](b]: javascript:alert(1)',
    ]);
    const document = literal.content.map((block) => (block.type === 'text' ? block.text : ''));
    expect(referenceDefinitions(document.join(''))).toEqual([]);
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
    let result = await runToolContract(cweListReference, { topic: 'views', limit: 101 });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      items: expect.any(Array),
      pagination: { total: 103, hasMore: true },
      totalCount: 103,
      truncated: true,
      cap: 100,
    });
    expect(JSON.stringify(result.content)).toContain('capped at 100');
    expect(JSON.stringify(result.structuredContent)).toContain('capped at 100');
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = result.structuredContent as {
        items: { id: string }[];
        pagination: { shown: number; total: number; nextCursor?: string };
        shown?: number;
      };
      expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThanOrEqual(24000);
      expect(page.items.length).toBeGreaterThan(0);
      expect(page.items.length).toBeLessThanOrEqual(100);
      expect(page.pagination.shown).toBe(page.items.length);
      expect(page.pagination.total).toBe(103);
      seen.push(...page.items.map((item) => item.id));
      cursor = page.pagination.nextCursor;
      expect(seen.length).toBeLessThanOrEqual(103);
      if (cursor)
        result = await runToolContract(cweListReference, { topic: 'views', limit: 101, cursor });
    } while (cursor);
    expect(seen).toEqual([
      'CWE-1000',
      'CWE-1001',
      ...Array.from({ length: 101 }, (_, i) => `CWE-${2000 + i}`),
    ]);
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
      '[https://example.test/a\\_(b)?x=1&amp;y=2](<https://example.test/a_(b)?x=1&amp;y=2>)',
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
    expect(description).toBe('Literal \\&lt;tag\\&gt; and \\<script>alert(1)\\</script>.');
    expect(text).toContain(`> ${description}`);
  });

  it('embeds stored prose verbatim and serializes no search projection', async () => {
    await disposeCatalogService();
    await load(
      cwe.replace(
        'Sparse description.',
        '<xhtml:p>Use <xhtml:b>$varname_size</xhtml:b> with <xhtml:code>inet_addr()</xhtml:code>.</xhtml:p><xhtml:p>Then "&lt;script&gt;" [REF-1400].</xhtml:p>',
      ),
    );
    const projection = getCatalogService().snapshot().cwe.searchText.get('CWE-20')?.description;
    expect(projection).toBe('Use $varname_size with inet_addr(). Then "<script>" [REF-1400].');
    const detail = await runToolContract(cweGetWeakness, { ids: ['20'], sections: ['summary'] });
    const search = await runToolContract(cweSearchWeaknesses, { filter: 'varname_size' });
    expect(search.structuredContent).toMatchObject({ results: [{ id: 'CWE-20' }] });
    for (const result of [detail, search]) {
      expect(result.isError).not.toBe(true);
      const surfaces = JSON.stringify([result.structuredContent, result.content]);
      expect(surfaces).not.toContain('searchText');
      expect(surfaces).not.toContain(JSON.stringify(projection).slice(1, -1));
    }
    const stored = 'Use $**varname_size** with ` inet_addr() `.\n\nThen "\\<script>" [REF-1400].';
    expect(detail.structuredContent).toMatchObject({ entries: [{ description: stored }] });
    const text = detail.content.flatMap((block) => (block.type === 'text' ? [block.text] : []));
    expect(text.join('\n')).toContain(
      stored
        .split('\n')
        .map((line) => `> ${line}`)
        .join('\n'),
    );
  });

  it('renders plain strings as literal text that parses back to the value', () => {
    // IDs, vocabulary, and enums need no escape and render exactly as stored.
    for (const value of [
      'CWE-80',
      'CAPEC-66',
      'T1059.001',
      'C++',
      'C#',
      'ASP.NET',
      'DoS: Resource Consumption (CPU)',
      'filter_values',
      'not_found',
      'Synthetic & weakness',
      // The value ends its paragraph, so a closing bracket or an unterminated `&` stays literal.
      '[REF-1100]',
      'v4 [DRAFT]',
      'CAPEC → ATT&CK',
    ])
      expect(formatCatalog({ name: value })[0].text).toBe(`**name**\n\n> ${value}`);
    // A backslash only where the character would otherwise parse as syntax.
    for (const [value, rendered] of [
      ['01. Preprocessor (PRE)', '01\\. Preprocessor (PRE)'],
      ["Path Traversal: '\\..\\filename'", "Path Traversal: '\\\\..\\filename'"],
      ['target="_blank"', 'target="\\_blank"'],
      ['<img>', '\\<img>'],
      ['*p', '\\*p'],
      ['x](y)', 'x\\](y)'],
      ['&lt;', '\\&lt;'],
    ]) {
      const text = formatCatalog({ name: value })[0].text;
      expect(text).toBe(`**name**\n\n> ${rendered}`);
      expect(parseMarkdown(text).text).toBe(`name\n${value}`);
    }
  });

  it('round-trips every trimmed single-line plain string exactly through a CommonMark parse', () => {
    const alphabet = [...'ab1 \t\\`*_[]()<>&#;!-+=~|:./?"\'x9@', 'é', ' ', '　'];
    /**
     * A single-line plain value is trimmed where it enters (catalog values and search filters are
     * also whitespace-collapsed), and CommonMark trims the same whitespace at a paragraph's ends, so
     * such a value parses back exactly, whatever it holds inside.
     */
    const value = fc
      .string({ unit: fc.constantFrom(...alphabet), minLength: 1, maxLength: 48 })
      .map((candidate) => candidate.trim());
    fc.assert(
      fc.property(value, (candidate) => {
        const rendered = formatCatalog({ name: candidate })[0].text;
        const parsed = parseMarkdown(rendered);
        expect(parsed.text).toBe(candidate ? `name\n${candidate}` : 'name');
        expect(referenceDefinitions(rendered)).toEqual([]);
        expect(
          parsed.nodes.every((node) =>
            ['document', 'paragraph', 'strong', 'text', 'block_quote'].includes(node),
          ),
        ).toBe(true);
      }),
      { seed: 20261021, numRuns: 3000 },
    );
  });

  it('keeps catalog text from defining a link across fields on detail and search surfaces', async () => {
    await disposeCatalogService();
    await load(
      cwe
        .replace('Name="Synthetic &amp; weakness"', 'Name="[x](y]"')
        .replace('<Title>Reference</Title>', '<Title>[x](y]: evil.html</Title>')
        .replace(
          /<Description><xhtml:p>First[\s\S]*?<\/Description>/,
          '<Description><xhtml:p>[x](y]: evil.html</xhtml:p><xhtml:p>Body.</xhtml:p></Description>',
        ),
      capec.replace('Name="Synthetic attack"', 'Name="[x](y]"'),
    );
    const documentOf = (wire: Wire) =>
      wire.content.map((block) => (block.type === 'text' ? block.text : '')).join('');
    const detail = await runToolContract(cweGetWeakness, {
      ids: ['79'],
      sections: ['summary', 'relations', 'mappings'],
    });
    for (const wire of [
      detail,
      await runToolContract(cweGetAttackPattern, { ids: ['1'], sections: ['summary'] }),
      await runToolContract(cweSearchWeaknesses, { limit: 5 }),
    ]) {
      expect(wire.isError).not.toBe(true);
      const document = documentOf(wire);
      expect(referenceDefinitions(document)).toEqual([]);
      for (const [, destination] of renderHtml(document).matchAll(/href="([^"]*)"/g))
        expect(destination).toMatch(/^https:\/\//);
    }
    expect(parseMarkdown(documentOf(detail)).text.split('\n')).toEqual(
      expect.arrayContaining(['[x](y]', '[x](y]: evil.html', 'Body.']),
    );
  });

  it('renders a continuation as a code span whose literal is the exact cursor', () => {
    // base64url can place `_` beside `.` or `-`, which plain-text escaping would have to escape.
    for (const cursor of ['eyJxIjoxfQ._WFu-_x9.sig', 'a-_b_-c._d', 'abc.def']) {
      const text = formatCatalog({ pagination: { nextCursor: cursor } })[0].text;
      expect(text).toBe(`**pagination**\n\n**nextCursor**\n\n> \`${cursor}\``);
      const parsed = parseMarkdown(text);
      expect(parsed.text).toBe(`pagination\nnextCursor\n${cursor}`);
      expect(parsed.nodes).toContain('code');
    }
  });

  it('renders identifiers and vocabulary that an agent can copy back as inputs', async () => {
    await disposeCatalogService();
    await load(
      cwe
        .replace(
          '<Language Name="C" Class="Compiled"/>',
          '<Language Name="C" Class="Compiled"/><Language Name="C++"/><Language Name="C#"/><Technology Name="ASP.NET"/>',
        )
        .replace(
          '<Impact>Modify Data</Impact>',
          '<Impact>Modify Data</Impact><Impact>DoS: Resource Consumption (CPU)</Impact>',
        ),
    );
    const platforms = await runToolContract(cweListReference, { topic: 'platforms', limit: 100 });
    const impacts = await runToolContract(cweListReference, { topic: 'filter_values', limit: 100 });
    const labels = [...copied(platforms, 'label'), ...copied(impacts, 'label')];
    expect(labels).toEqual(
      expect.arrayContaining(['C++', 'C#', 'ASP.NET', 'DoS: Resource Consumption (CPU)']),
    );
    // The output topic and its applied-filter echo.
    expect(copied(impacts, 'topic')).toEqual(['filter_values', 'filter_values']);
    for (const topic of copied(impacts, 'topic'))
      expect((await runToolContract(cweListReference, { topic })).isError).not.toBe(true);
    for (const [field, label] of [
      ['language', 'C++'],
      ['language', 'C#'],
      ['technology', 'ASP.NET'],
      ['consequenceImpact', 'DoS: Resource Consumption (CPU)'],
    ] as const) {
      const value = labels.find((candidate) => candidate === label);
      const wire = await runToolContract(cweSearchWeaknesses, { [field]: value });
      expect(wire.isError).not.toBe(true);
      expect(copied(wire, 'id')).toEqual(['CWE-79']);
      const detail = await runToolContract(cweGetWeakness, {
        ids: [...copied(wire, 'id'), 'CWE-404'],
        sections: [],
      });
      expect(detail.isError).not.toBe(true);
      expect(copied(detail, 'id')).toEqual(['CWE-79', 'CWE-404']);
      expect(copied(detail, 'reason')).toEqual(['not_found']);
    }
  });

  it('quotes the catalog date in the versions description as literal text', async () => {
    await disposeCatalogService();
    await load(cwe.replace('Date="2026-04-30"', 'Date="*2026-04-30*"'));
    const wire = await runToolContract(cweListReference, { topic: 'versions' });
    expect(wire.isError).not.toBe(true);
    const { items, catalogs } = wire.structuredContent as {
      items: { key: string; description: string }[];
      catalogs: { date: string }[];
    };
    const description = items.find((item) => item.key === 'cwe')?.description ?? '';
    const parsed = parseMarkdown(description);
    expect(parsed.text).toBe('Published *2026-04-30*; loaded 2026-10-20T00:00:00.000Z.');
    expect(parsed.nodes.every((node) => ['document', 'paragraph', 'text'].includes(node))).toBe(
      true,
    );
    expect(lines(wire)).toContain(`> ${description}`);
    expect(catalogs[0]?.date).toBe('*2026-04-30*');
    expect(copied(wire, 'date').map((line) => parseMarkdown(line).text)).toEqual([
      '*2026-04-30*',
      '2023-01-24',
    ]);
  });

  it('discloses where each served catalog came from and when it was fetched, on both surfaces', async () => {
    const downloaded = await runToolContract(cweListReference, { topic: 'versions' });
    expect(downloaded.structuredContent).toMatchObject({
      catalogs: [
        { catalog: 'CWE', source: 'upstream', fetchedAt: '2026-10-20T00:00:00.000Z' },
        { catalog: 'CAPEC', source: 'upstream', fetchedAt: '2026-10-20T00:00:00.000Z' },
      ],
    });
    expect(copied(downloaded, 'source')).toEqual(['upstream', 'upstream']);
    expect(copied(downloaded, 'fetchedAt')).toEqual([
      '2026-10-20T00:00:00.000Z',
      '2026-10-20T00:00:00.000Z',
    ]);
    // A seeded cache: CWE carries a matching download record, CAPEC was dropped in by hand.
    await disposeCatalogService();
    const dir = await mkdtemp(join(tmpdir(), 'mitre-cwe-versions-test-'));
    try {
      const cweSource = cwe.replace('<Reason>Acceptable</Reason>', '<Reason Type="Acceptable"/>');
      const cweArchive = zipSync({ 'cwe.xml': strToU8(cweSource) });
      await writeFile(join(dir, 'cwec_latest.xml.zip'), cweArchive);
      await writeFile(
        join(dir, 'cwec_latest.xml.zip.json'),
        JSON.stringify({
          version: '4.test',
          date: '2026-04-30',
          sha256: createHash('sha256').update(cweArchive).digest('hex'),
          fetchedAt: '2026-10-19T08:00:00Z',
        }),
      );
      await writeFile(join(dir, 'capec_latest.xml'), capec);
      await initCatalogService({
        request: async (url) => {
          throw new Error(`Unexpected network request: ${url}`);
        },
        clock,
        cacheDir: dir,
        context: createMockContext(),
      });
      const fromCache = await runToolContract(cweListReference, { topic: 'versions' });
      expect(fromCache.isError).not.toBe(true);
      const { catalogs } = fromCache.structuredContent as { catalogs: Record<string, unknown>[] };
      expect(catalogs).toMatchObject([
        { catalog: 'CWE', source: 'cache', fetchedAt: '2026-10-19T08:00:00Z' },
        { catalog: 'CAPEC', source: 'cache' },
      ]);
      expect(catalogs[1]).not.toHaveProperty('fetchedAt');
      expect(copied(fromCache, 'source')).toEqual(['cache', 'cache']);
      expect(copied(fromCache, 'fetchedAt')).toEqual(['2026-10-19T08:00:00Z']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
