/**
 * @fileoverview Pure catalog parsing tests using synthetic MITRE-shaped XML.
 * @module tests/services/catalog/xml-normalization.test
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  orderedContentToMarkdown,
  parseCapecCatalog,
  parseCweCatalog,
} from '@/services/catalog/xml-normalization.js';

const cweXml = readFileSync(
  new URL('../../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const capecXml = readFileSync(
  new URL('../../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);

describe('parseCweCatalog', () => {
  it('retains an unresolved external reference identity and recorded section', () => {
    const xml = cweXml.replace('External_Reference_ID="REF-1"', 'External_Reference_ID="missing"');
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.references).toEqual([
      { id: 'missing', section: '2' },
    ]);
  });

  it('preserves scalar external-reference URLs without Markdown escaping', () => {
    const url = 'https://example.test/a_b/[record](revision)?q=%5Bvalue%5D&next=a_b';
    const xml = cweXml.replace(
      '<URL>https://example.test/ref</URL>',
      `<URL>${url.replaceAll('&', '&amp;')}</URL>`,
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.references?.[0]?.url).toBe(url);
  });

  it('preserves scalar observed-example links without Markdown escaping', () => {
    const url = 'https://example.test/a_b/[record](revision)?q=%28value%29&next=a_b';
    const xml = cweXml.replace(
      '</Demonstrative_Examples>',
      `</Demonstrative_Examples><Observed_Examples><Observed_Example><Link>${url.replaceAll('&', '&amp;')}</Link></Observed_Example></Observed_Examples>`,
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.observedExamples?.[0]?.link).toBe(url);
  });

  it('preserves prose order, markup, line breaks and exactly-once entities', () => {
    const catalog = parseCweCatalog(cweXml);
    expect(catalog.version).toBe('4.test');
    expect(catalog.date).toBe('2026-04-30');
    expect(catalog.weaknesses.get('CWE-79')).toMatchObject({
      name: 'Synthetic & weakness',
      description:
        'First &amp; A &amp;lt; sentence.  \nSecond **bold** and *emphasis*.\n\n- one\n- two\n\nRead [source](<https://example.test/?a=1&amp;b=2>).',
      relatedWeaknesses: [
        { nature: 'ChildOf', id: 'CWE-20', viewId: 'CWE-1000', ordinal: 'Primary' },
      ],
      relatedAttackPatterns: [{ id: 'CAPEC-1' }],
      taxonomyMappings: [{ taxonomy: 'OWASP', id: 'A03', name: 'Injection', fit: 'Exact' }],
      references: [
        {
          id: 'REF-1',
          authors: ['Alice', 'Bob'],
          title: 'Reference',
          publicationYear: '2026',
          url: 'https://example.test/ref',
          section: '2',
        },
      ],
    });
  });

  it('keeps alternating prose and code, source indices, indentation and CDATA literal', () => {
    expect(parseCweCatalog(cweXml).weaknesses.get('CWE-79')?.examples).toEqual([
      {
        index: 0,
        blocks: [
          { kind: 'prose', text: 'Before code.' },
          {
            kind: 'code',
            language: 'C',
            nature: 'Bad',
            text: 'if (a < b) {\n  call("x");\n}\nnext();',
          },
          { kind: 'prose', text: 'Between code.' },
          { kind: 'code', text: '  literal <tag> &amp;\n    next();' },
          { kind: 'prose', text: 'After code.' },
        ],
      },
      { index: 1, blocks: [{ kind: 'prose', text: 'Second example.' }] },
    ]);
  });

  it('does not invent absent optional fields', () => {
    expect(parseCweCatalog(cweXml).weaknesses.get('CWE-20')).toEqual({
      id: 'CWE-20',
      type: 'weakness',
      name: 'Sparse',
      status: 'Incomplete',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/20.html',
      description: 'Sparse description.',
    });
  });

  it('distinguishes category summaries, ordered membership and filter-only views', () => {
    const catalog = parseCweCatalog(cweXml);
    expect(catalog.weaknesses.get('CWE-900')).toEqual({
      id: 'CWE-900',
      type: 'category',
      name: 'Category',
      status: 'Stable',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/900.html',
      description: 'Organizational summary.',
      members: [
        { id: 'CWE-79', viewId: 'CWE-1000' },
        { id: 'CWE-20', viewId: 'CWE-1000' },
      ],
    });
    expect(catalog.views.get('CWE-1000')).toMatchObject({
      audience: [{ type: 'Developer', description: 'Build software.' }],
      members: [
        { id: 'CWE-900', viewId: 'CWE-1000' },
        { id: 'CWE-79', viewId: 'CWE-1000' },
      ],
    });
    expect(catalog.views.get('CWE-1001')).toMatchObject({
      members: [],
      filterDefinition: "status = 'Draft'",
    });
  });
});

describe('parseCapecCatalog', () => {
  it('retains a present but empty description on a draft attack pattern', () => {
    const xml = capecXml
      .replace('Name="Sparse pattern" Status="Deprecated"', 'Name="Sparse pattern" Status="Draft"')
      .replace(
        '<Description>Only identity and description.</Description>',
        '<Description></Description>',
      );
    expect(parseCapecCatalog(xml).attackPatterns.get('CAPEC-2')).toMatchObject({
      id: 'CAPEC-2',
      status: 'Draft',
      description: '',
    });
  });

  it('retains unresolved references with and without recorded sections', () => {
    const xml = capecXml.replace(
      '<Reference External_Reference_ID="CAP-REF"/>',
      '<Reference External_Reference_ID="missing" Section="Appendix A"/><Reference External_Reference_ID="other-missing"/>',
    );
    expect(parseCapecCatalog(xml).attackPatterns.get('CAPEC-1')?.references).toEqual([
      { id: 'missing', section: 'Appendix A' },
      { id: 'other-missing' },
    ]);
  });

  it('preserves nested execution steps and recorded crosswalks without deriving absent mappings', () => {
    const catalog = parseCapecCatalog(capecXml);
    expect(catalog.attackPatterns.get('CAPEC-1')).toMatchObject({
      prerequisites: ['First prerequisite.', 'Second prerequisite.'],
      executionFlow: [
        {
          step: '1',
          phase: 'Explore',
          description: 'Find **input**.\n\n1. inspect\n2. trace',
          techniques: ['Probe one.', 'Probe two.'],
          indicators: ['Signal one.', 'Signal two.'],
        },
        { step: '2', phase: 'Exploit', description: 'Use input.' },
      ],
      skills: [{ level: 'Low', description: 'Read source.' }, { description: 'Write payload.' }],
      consequences: [
        {
          scopes: ['Confidentiality', 'Integrity'],
          impacts: ['Read Data', 'Modify Data'],
          note: 'Conditional.',
        },
      ],
      mitigations: ['Validate.', 'Encode.'],
      relatedWeaknesses: [{ id: 'CWE-79' }],
      relatedAttackPatterns: [{ nature: 'ChildOf', id: 'CAPEC-2' }],
      attackTechniqueIds: ['T1059.001'],
      taxonomyMappings: [
        { taxonomy: 'ATTACK', id: '1059.001', name: 'PowerShell' },
        { taxonomy: 'ATTACK', id: 'T1059.001' },
        { taxonomy: 'Other' },
      ],
      references: [{ id: 'CAP-REF', title: 'Attack reference' }],
    });
    expect(catalog.attackPatterns.get('CAPEC-2')).toEqual({
      id: 'CAPEC-2',
      name: 'Sparse pattern',
      status: 'Deprecated',
      abstraction: 'Meta',
      sourceUrl: 'https://capec.mitre.org/data/definitions/2.html',
      description: 'Only identity and description.',
    });
  });
});

describe('catalog validation boundaries', () => {
  const invalidCwe = [
    ['malformed XML', cweXml.replace('</Weaknesses>', '</Wrong>')],
    ['wrong root', cweXml.replaceAll('Weakness_Catalog', 'Other_Catalog')],
    ['wrong namespace', cweXml.replace('http://cwe.mitre.org/cwe-7', 'http://example.test/schema')],
    ['missing root version', cweXml.replace(' Version="4.test"', '')],
    ['missing name', cweXml.replace(' Name="Sparse"', '')],
    ['blank status', cweXml.replace('Status="Incomplete"', 'Status=" "')],
    ['zero identifier', cweXml.replace('ID="0079"', 'ID="000"')],
    ['nonnumeric identifier', cweXml.replace('ID="0079"', 'ID="79x"')],
    [
      'duplicate normalized identifier',
      cweXml.replace('ID="20" Name="Sparse"', 'ID="79" Name="Sparse"'),
    ],
    ['cross-family duplicate', cweXml.replace('ID="1001"', 'ID="79"')],
    ['missing family', cweXml.replace(/<Categories>[\s\S]*?<\/Categories>/, '')],
    ['missing description', cweXml.replace('<Description>Sparse description.</Description>', '')],
    [
      'duplicate reference',
      cweXml.replace(
        '</External_References>',
        '<External_Reference Reference_ID="REF-1"/></External_References>',
      ),
    ],
    [
      'external entity declaration',
      `<!DOCTYPE Weakness_Catalog [<!ENTITY x SYSTEM "file:///etc/passwd">]>${cweXml}`,
    ],
    [
      'internal expansion declaration',
      `<!DOCTYPE Weakness_Catalog [<!ENTITY x "payload">]>${cweXml}`,
    ],
    ['multiple roots', `${cweXml}<other/>`],
  ];
  it.each(invalidCwe)('rejects %s as nonretryable invalid_catalog', (_name, xml) => {
    expect(() => parseCweCatalog(xml)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it.each([
    [
      'empty patterns',
      capecXml.replace(/<Attack_Patterns>[\s\S]*?<\/Attack_Patterns>/, '<Attack_Patterns/>'),
    ],
    ['missing abstraction', capecXml.replace(' Abstraction="Detailed"', '')],
    [
      'absent description',
      capecXml.replace('<Description>Only identity and description.</Description>', ''),
    ],
    [
      'duplicate patterns',
      capecXml.replace('ID="2" Name="Sparse pattern"', 'ID="1" Name="Sparse pattern"'),
    ],
    ['invalid ATTACK mapping', capecXml.replace('1059.001', '1059.0001')],
    ['missing execution phase', capecXml.replace('<Phase>Explore</Phase>', '')],
  ])('rejects CAPEC %s', (_name, xml) => {
    expect(() => parseCapecCatalog(xml)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it.each([parseCweCatalog, parseCapecCatalog])(
    'classifies an HTML outage as retryable',
    (parse) => {
      expect(() => parse('<!DOCTYPE html><html><body>Unavailable</body></html>')).toThrow(
        expect.objectContaining({
          data: expect.objectContaining({ reason: 'upstream_html', retryable: true }),
        }),
      );
    },
  );
});

describe('orderedContentToMarkdown', () => {
  it('sizes code fences beyond source delimiters and retains blank lines inside code', () => {
    expect(orderedContentToMarkdown([{ pre: [{ '#text': '  start\n\n\n    ```\n  end' }] }])).toBe(
      '````\n  start\n\n\n    ```\n  end\n````',
    );
  });

  it('escapes data syntax and keeps nested lists in source order', () => {
    expect(orderedContentToMarkdown([{ '#text': '<script>*data*</script>' }])).toBe(
      '\\<script\\>\\*data\\*\\</script\\>',
    );
    expect(
      orderedContentToMarkdown([
        {
          ol: [
            { li: [{ '#text': 'outer' }, { ul: [{ li: [{ '#text': 'inner' }] }] }] },
            { li: [{ '#text': 'second' }] },
          ],
        },
      ]),
    ).toBe('1. outer\n\n  - inner\n2. second');
  });
});
