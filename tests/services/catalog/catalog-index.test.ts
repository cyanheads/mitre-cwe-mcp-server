/**
 * @fileoverview Full-corpus index, membership, vocabulary and recorded mapping tests.
 * @module tests/services/catalog/catalog-index.test
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  buildCatalogSnapshot,
  resolveVocabulary,
  searchAttackPatterns,
  searchWeaknesses,
  someTokenMatches,
  weaknessesInView,
} from '@/services/catalog/catalog-index.js';
import type {
  AttackPattern,
  CapecCatalog,
  CatalogHealth,
  CatalogView,
  CweCatalog,
  SearchText,
  Weakness,
} from '@/services/catalog/types.js';
import { parseCapecCatalog, parseCweCatalog } from '@/services/catalog/xml-normalization.js';

const weakness = (id: number, fields: Partial<Weakness> = {}): Weakness => ({
  id: `CWE-${id}`,
  name: 'Other',
  description: 'Other',
  status: 'Draft',
  type: 'weakness',
  sourceUrl: `https://cwe.mitre.org/data/definitions/${id}.html`,
  ...fields,
});
const pattern = (id: number, fields: Partial<AttackPattern> = {}): AttackPattern => ({
  id: `CAPEC-${id}`,
  type: 'attack_pattern',
  name: 'Other',
  description: 'Other',
  status: 'Stable',
  abstraction: 'Standard',
  sourceUrl: `https://capec.mitre.org/data/definitions/${id}.html`,
  ...fields,
});
/** Hand-built records hold plain prose, so their projection is the stored text and terms. */
const searchText = (entry: Weakness | AttackPattern): SearchText => ({
  ...(entry.alternateTerms ? { alternateTerms: entry.alternateTerms.map(({ term }) => term) } : {}),
  description: entry.description,
  ...(entry.extendedDescription ? { extendedDescription: entry.extendedDescription } : {}),
});
const health: CatalogHealth = {
  version: 'test',
  date: '2026-10-20',
  counts: {},
  loadedAt: '2026-10-20T00:00:00Z',
  nextCheckAt: '2026-10-21T00:00:00Z',
  sourceUrl: 'https://example.test',
};
/** A view with no recorded members unless given; `filterDefinition` makes it filter-defined. */
const view = (id: number, fields: Partial<CatalogView> = {}): CatalogView => ({
  id: `CWE-${id}`,
  name: 'View',
  type: 'Implicit',
  status: 'Draft',
  sourceUrl: `https://cwe.mitre.org/data/definitions/${id}.html`,
  members: [],
  ...fields,
});
function snapshot(entries: Weakness[], patterns: AttackPattern[] = [], views: CatalogView[] = []) {
  return buildCatalogSnapshot(
    {
      version: '4.test',
      date: '2026-10-20',
      weaknesses: new Map(entries.map((entry) => [entry.id, entry])),
      searchText: new Map(entries.map((entry) => [entry.id, searchText(entry)])),
      views: new Map(
        [
          view(1000, {
            name: 'Navigation',
            type: 'Graph',
            status: 'Stable',
            members: [{ id: 'CWE-900', viewId: 'CWE-1000' }],
          }),
          ...views,
        ].map((entry) => [entry.id, entry]),
      ),
    },
    {
      version: '3.test',
      date: '2023-01-24',
      attackPatterns: new Map(patterns.map((entry) => [entry.id, entry])),
      categories: new Map(),
      views: new Map(),
      searchText: new Map(patterns.map((entry) => [entry.id, searchText(entry)])),
    },
    { cwe: health, capec: health },
    health.loadedAt,
  );
}

describe('catalog indexes', () => {
  it('orders every matching weakness by name, description, then extended text and numeric ID', () => {
    const data = snapshot([
      ...Array.from({ length: 35 }, (_, index) => weakness(index + 100, { name: 'Noise' })),
      weakness(80, { extendedDescription: 'needle thread' }),
      weakness(20, { description: 'needle thread' }),
      weakness(10, { name: 'thread needle' }),
      weakness(2, { name: 'needle thread' }),
      weakness(1, { name: 'needle only' }),
      weakness(900, { name: 'needle thread', type: 'category' }),
    ]);
    expect(searchWeaknesses(data, { filter: '  NEEDLE thread ' }).map((entry) => entry.id)).toEqual(
      ['CWE-2', 'CWE-10', 'CWE-20', 'CWE-80'],
    );
    expect(searchWeaknesses(data, { filter: 'absent' })).toEqual([]);
    expect(searchWeaknesses(data, {})).toHaveLength(40);
  });

  it('ranks a record with name matches only when one alternate term holds every token', () => {
    const data = snapshot(
      [
        weakness(5, { description: 'Stored xss here.' }),
        weakness(6, { description: 'Html with xss.' }),
        weakness(80, { name: 'Basic XSS' }),
        weakness(81, {
          name: 'Cross-site Scripting',
          alternateTerms: [
            { term: 'XSS', description: 'A common acronym.' },
            { term: 'HTML Injection' },
            { term: 'Reflected XSS / Type 1 XSS' },
          ],
        }),
        weakness(82, { name: 'XSS filter', alternateTerms: [{ term: 'XSS' }] }),
        weakness(94, { name: 'Code Injection' }),
        weakness(470, {
          name: 'Select Classes or Code',
          alternateTerms: [{ term: 'Reflection Injection' }],
        }),
        weakness(940, { description: 'Allows code injection.' }),
      ],
      [
        pattern(94, {
          name: 'Adversary in the Middle',
          alternateTerms: [{ term: 'Man-in-the-Middle / MITM' }],
        }),
        pattern(20, { description: 'Uses a mitm proxy.' }),
        pattern(95, { name: 'Inactive', status: 'Deprecated', alternateTerms: [{ term: 'MITM' }] }),
      ],
    );
    const ids = (filter: string) => searchWeaknesses(data, { filter }).map((entry) => entry.id);
    // A term match ties with name matches ahead of the description tier, and a record matching
    // through both its name and a term appears once.
    expect(ids('XSS')).toEqual(['CWE-80', 'CWE-81', 'CWE-82', 'CWE-5', 'CWE-6']);
    expect(ids('type 1 reflected')).toEqual(['CWE-81']);
    // Tokens from the name and an unrelated term, or from two terms, are a spread match.
    expect(ids('code injection')).toEqual(['CWE-94', 'CWE-940', 'CWE-470']);
    expect(ids('xss html')).toEqual(['CWE-6', 'CWE-81']);
    // Term explanations are returned by the detail tools but never searched.
    expect(ids('acronym')).toEqual([]);
    expect(ids('basic')).toEqual(['CWE-80']);
    const capec = (filters: { filter: string; includeInactive?: boolean }) =>
      searchAttackPatterns(data, filters).map((entry) => entry.id);
    expect(capec({ filter: 'MITM' })).toEqual(['CAPEC-94', 'CAPEC-20']);
    expect(capec({ filter: 'mitm', includeInactive: true })).toEqual([
      'CAPEC-94',
      'CAPEC-95',
      'CAPEC-20',
    ]);
  });

  it('finds a token that matches a searched record on its own, within the searched records only', () => {
    const data = snapshot(
      [
        weakness(1, { name: 'Alpha name' }),
        weakness(2, { description: 'beta description' }),
        weakness(3, { extendedDescription: 'gamma extended' }),
        weakness(4, {
          alternateTerms: [{ term: 'DeltaTerm', description: 'epsilon explanation' }],
        }),
        weakness(900, { name: 'zeta category', type: 'category' }),
      ],
      [
        pattern(1, { name: 'Kappa' }),
        pattern(2, { name: 'Lambda', status: 'Deprecated' }),
        pattern(3, { description: 'mu value', status: 'Obsolete' }),
      ],
    );
    for (const [catalog, filter, includeInactive, expected] of [
      // Each searched field, in any case, after a token that matches nothing.
      ['cwe', 'zzqx ALPHA', false, true],
      ['cwe', 'zzqx beta', false, true],
      ['cwe', 'zzqx gamma', false, true],
      ['cwe', 'zzqx deltaterm', false, true],
      // Term explanations and categories are never searched, and no token crosses catalogs.
      ['cwe', 'zzqx epsilon', false, false],
      ['cwe', 'zzqx zeta', false, false],
      ['cwe', 'zzqx kappa', false, false],
      ['cwe', 'zzqx qqzz zzqx', false, false],
      ['capec', 'zzqx kappa', false, true],
      ['capec', 'zzqx alpha', false, false],
      // Inactive patterns count only when the search includes them.
      ['capec', 'zzqx lambda', false, false],
      ['capec', 'zzqx lambda', true, true],
      ['capec', 'zzqx mu', true, true],
    ] as const)
      expect(someTokenMatches(data, catalog, filter, includeInactive), `${catalog} ${filter}`).toBe(
        expected,
      );
  });

  it('collects actual vocabulary and resolves exact case-insensitive filters without fuzzy broadening', () => {
    const data = snapshot([
      weakness(1, {
        abstraction: 'Base',
        platforms: [
          { kind: 'language', name: 'C++', class: 'Compiled' },
          { kind: 'technology', name: 'Web Server' },
        ],
        consequences: [{ scopes: ['Integrity'], impacts: ['Modify Data'] }],
        examples: [{ index: 0, blocks: [{ kind: 'code', language: 'Rust', text: 'code' }] }],
        mitigations: [{ phases: ['Implementation'], description: 'Validate.' }],
      }),
      weakness(2, { abstraction: 'Class' }),
    ]);
    expect(resolveVocabulary(data, 'languages', 'language', ' c++ ')).toBe('C++');
    expect(data.vocabulary.get('cweAbstractions')).toEqual(['Base', 'Class']);
    expect(data.vocabulary.get('exampleLanguages')).toEqual(['Rust']);
    expect(
      searchWeaknesses(data, {
        language: 'compiled',
        technology: 'web server',
        abstraction: 'base',
        status: 'draft',
        consequenceImpact: 'modify data',
      }).map((entry) => entry.id),
    ).toEqual(['CWE-1']);
    expect(() => searchWeaknesses(data, { language: 'C' })).toThrow(
      expect.objectContaining({
        message: 'Unknown language "C"; supported values: C++, Compiled.',
        data: {
          reason: 'unknown_filter',
          retryable: false,
          field: 'language',
          value: 'C',
          supported: ['C++', 'Compiled'],
        },
      }),
    );
  });

  it('names the reference topic for a long vocabulary and escapes the quoted value', () => {
    const languages = Array.from({ length: 11 }, (_, index) => `Language ${index}`);
    const technologies = Array.from({ length: 10 }, (_, index) => `Technology ${index}`);
    const data = snapshot([
      weakness(1, {
        platforms: [
          ...languages.map((name) => ({ kind: 'language' as const, name })),
          ...technologies.map((name) => ({ kind: 'technology' as const, name })),
        ],
        examples: [{ index: 0, blocks: [{ kind: 'code', language: 'Rust', text: 'code' }] }],
      }),
    ]);
    // Eleven values name their topic, and the data lists none; ten or fewer are listed.
    expect(() => resolveVocabulary(data, 'languages', 'language', '*Cobol*')).toThrow(
      expect.objectContaining({
        message:
          'Unknown language "\\*Cobol\\*"; cwe_list_reference topic platforms lists the supported values.',
        data: { reason: 'unknown_filter', retryable: false, field: 'language', value: '*Cobol*' },
      }),
    );
    expect(() => resolveVocabulary(data, 'technologies', 'technology', 'Web')).toThrow(
      expect.objectContaining({
        message: `Unknown technology "Web"; supported values: ${technologies.join(', ')}.`,
        data: {
          reason: 'unknown_filter',
          retryable: false,
          field: 'technology',
          value: 'Web',
          supported: technologies,
        },
      }),
    );
    expect(() => resolveVocabulary(data, 'exampleLanguages', 'exampleLanguage', 'Go')).toThrow(
      'Unknown exampleLanguage "Go"; supported values: Rust.',
    );
    expect(() => resolveVocabulary(data, 'capecSeverities', 'severity', 'High')).toThrow(
      'Unknown severity "High"; supported values: none in the loaded catalog.',
    );
  });

  it('hydrates recorded crosslinks without inventing reverse mappings or missing names', () => {
    const data = snapshot(
      [
        weakness(1, { relatedAttackPatterns: [{ id: 'CAPEC-2' }, { id: 'CAPEC-99' }] }),
        weakness(2),
      ],
      [
        pattern(2, {
          name: 'Mapped',
          relatedWeaknesses: [{ id: 'CWE-2' }, { id: 'CWE-2' }, { id: 'CWE-99' }],
          relatedAttackPatterns: [{ nature: 'ChildOf', id: 'CAPEC-3' }],
        }),
        pattern(3, { name: 'Parent' }),
      ],
    );
    expect(data.cwe.weaknesses.get('CWE-1')?.relatedAttackPatterns).toEqual([
      { id: 'CAPEC-2', name: 'Mapped' },
      { id: 'CAPEC-99' },
    ]);
    expect(data.capec.attackPatterns.get('CAPEC-2')?.relatedWeaknesses).toEqual([
      { id: 'CWE-2', name: 'Other' },
      { id: 'CWE-2', name: 'Other' },
      { id: 'CWE-99' },
    ]);
    expect(data.attackPatternsByWeakness.get('CWE-2')).toEqual(['CAPEC-2']);
    expect(data.attackPatternsByWeakness.has('CWE-1')).toBe(false);
    expect(data.capec.attackPatterns.get('CAPEC-2')?.relatedAttackPatterns).toEqual([
      { nature: 'ChildOf', id: 'CAPEC-3', name: 'Parent' },
    ]);
    expect('set' in data.cwe.weaknesses).toBe(false);
    expect(Object.isFrozen(data.cwe.weaknesses.get('CWE-1')?.relatedAttackPatterns)).toBe(true);
  });

  it('names recorded weakness relations from the loaded index and omits names it cannot resolve', () => {
    const data = snapshot([
      weakness(1, {
        relatedWeaknesses: [
          { nature: 'ChildOf', id: 'CWE-2', viewId: 'CWE-1000', ordinal: 'Primary' },
          { nature: 'PeerOf', id: 'CWE-99', viewId: 'CWE-1000' },
          { nature: 'MemberOf', id: 'CWE-900', viewId: 'CWE-699' },
        ],
      }),
      weakness(2, { name: 'Improper Neutralization' }),
      weakness(900, { name: 'Grouping', type: 'category' }),
      weakness(3),
    ]);
    expect(data.cwe.weaknesses.get('CWE-1')?.relatedWeaknesses).toEqual([
      {
        nature: 'ChildOf',
        id: 'CWE-2',
        viewId: 'CWE-1000',
        ordinal: 'Primary',
        name: 'Improper Neutralization',
      },
      { nature: 'PeerOf', id: 'CWE-99', viewId: 'CWE-1000' },
      { nature: 'MemberOf', id: 'CWE-900', viewId: 'CWE-699', name: 'Grouping' },
    ]);
    expect(data.cwe.weaknesses.get('CWE-3')).not.toHaveProperty('relatedWeaknesses');
    expect(Object.isFrozen(data.cwe.weaknesses.get('CWE-1')?.relatedWeaknesses?.[0])).toBe(true);
    // Topology still follows the recorded relation, named or not.
    expect(data.childrenByView.get('CWE-1000')?.get('CWE-2')).toEqual(['CWE-1']);
  });

  it('builds mapping usage vocabulary from weaknesses only and filters by its exact values', () => {
    const usage = (value: string) => ({ mappingNotes: { usage: value } });
    const data = snapshot([
      weakness(1, usage('Allowed')),
      weakness(2, usage('Allowed-with-Review')),
      weakness(3, { ...usage('Allowed'), status: 'Stable' }),
      weakness(4),
      weakness(900, { ...usage('Prohibited'), type: 'category' }),
    ]);
    expect(data.vocabulary.get('cweMappingUsages')).toEqual(['Allowed', 'Allowed-with-Review']);
    const ids = (mappingUsage: string, status?: string) =>
      searchWeaknesses(data, { mappingUsage, ...(status ? { status } : {}) }).map(
        (entry) => entry.id,
      );
    expect(ids(' allowed ')).toEqual(['CWE-1', 'CWE-3']);
    expect(ids('ALLOWED-WITH-REVIEW')).toEqual(['CWE-2']);
    expect(ids('allowed', 'stable')).toEqual(['CWE-3']);
    expect(searchWeaknesses(data, { mappingUsage: '  ' })).toHaveLength(4);
    for (const value of ['Allowed with Review', 'Allowed-With-Reviews', 'Prohibited', 'allow'])
      expect(() => searchWeaknesses(data, { mappingUsage: value })).toThrow(
        expect.objectContaining({
          data: {
            reason: 'unknown_filter',
            retryable: false,
            field: 'mappingUsage',
            value,
            supported: ['Allowed', 'Allowed-with-Review'],
          },
        }),
      );
  });

  it('follows nested membership and ChildOf cycles only within the requested view', () => {
    const data = snapshot([
      weakness(900, { type: 'category', members: [{ id: 'CWE-901', viewId: 'CWE-1000' }] }),
      weakness(901, {
        type: 'category',
        members: [
          { id: 'CWE-900', viewId: 'CWE-1000' },
          { id: 'CWE-1', viewId: 'CWE-1000' },
          { id: 'CWE-99', viewId: 'CWE-2000' },
        ],
      }),
      weakness(1, { relatedWeaknesses: [{ nature: 'ChildOf', id: 'CWE-2', viewId: 'CWE-1000' }] }),
      weakness(2, { relatedWeaknesses: [{ nature: 'ChildOf', id: 'CWE-1', viewId: 'CWE-1000' }] }),
      weakness(3, { relatedWeaknesses: [{ nature: 'PeerOf', id: 'CWE-1', viewId: 'CWE-1000' }] }),
      weakness(99),
    ]);
    expect([...weaknessesInView(data, 'CWE-1000')].sort()).toEqual(['CWE-1', 'CWE-2']);
    expect(searchWeaknesses(data, { viewId: 'CWE-1000' }).map((entry) => entry.id)).toEqual([
      'CWE-1',
      'CWE-2',
    ]);
    expect(data.cwe.views.get('CWE-1000')?.members[0]).toMatchObject({
      id: 'CWE-900',
      type: 'category',
      name: 'Other',
    });
    expect(() => weaknessesInView(data, 'CWE-404')).toThrow(
      expect.objectContaining({
        message: 'viewId CWE-404 is not a CWE view in the loaded catalog.',
        data: { reason: 'unknown_filter', retryable: false, field: 'viewId', value: 'CWE-404' },
      }),
    );
    expect(() => weaknessesInView(data, 'CWE-1')).toThrow(
      'viewId CWE-1 is a weakness, not a CWE view.',
    );
    expect(() => weaknessesInView(data, 'CWE-900')).toThrow(
      'viewId CWE-900 is a category, not a CWE view.',
    );
  });

  it('selects a filter-defined view from indexed fields beside its recorded members', () => {
    const maintenance = [{ type: 'Maintenance', text: 'Revisit.' }];
    const data = snapshot(
      [
        weakness(1, { abstraction: 'Base', platforms: [{ kind: 'language', name: 'C' }] }),
        weakness(2, {
          abstraction: 'Class',
          status: 'Deprecated',
          platforms: [{ kind: 'language', name: 'Other', class: 'C' }],
        }),
        weakness(3, { abstraction: 'Base', notes: maintenance }),
        weakness(900, { type: 'category', status: 'Deprecated', notes: maintenance }),
      ],
      [],
      [
        view(658, {
          filterDefinition:
            "/Weakness_Catalog/Weaknesses/Weakness[./Applicable_Platforms/Language/@Name='C']",
        }),
        view(1081, { filterDefinition: "/Weakness_Catalog/*/*[Notes/Note[@Type='Maintenance']]" }),
        view(604, { filterDefinition: "/Weakness_Catalog/*/*[@Status='Deprecated']" }),
        view(679, { status: 'Deprecated', filterDefinition: '/Weakness_Catalog[false()]' }),
        view(2001, {
          filterDefinition: "/Weakness_Catalog/Weaknesses/Weakness[@Abstraction='Class']",
          members: [{ id: 'CWE-3', viewId: 'CWE-2001' }],
        }),
        view(2002, {
          filterDefinition: "/Weakness_Catalog/Weaknesses/Weakness[@Likelihood='High']",
        }),
      ],
    );
    const ids = (viewId: string) => [...weaknessesInView(data, viewId)].sort();
    // Language/@Name reads the platform name only, never its class.
    expect(ids('CWE-658')).toEqual(['CWE-1']);
    // Filters over every record family select only their weaknesses.
    expect(ids('CWE-1081')).toEqual(['CWE-3']);
    expect(ids('CWE-604')).toEqual(['CWE-2']);
    expect(ids('CWE-679')).toEqual([]);
    expect(ids('CWE-2001')).toEqual(['CWE-2', 'CWE-3']);
    // A filter with an unrecognized part selects nothing rather than guessing.
    expect(ids('CWE-2002')).toEqual([]);
    expect(
      searchWeaknesses(data, { viewId: 'CWE-1081', abstraction: 'base' }).map((entry) => entry.id),
    ).toEqual(['CWE-3']);
  });

  it('excludes inactive CAPEC records and matches ATT&CK parent/subtechnique boundaries exactly', () => {
    const data = snapshot(
      [],
      [
        pattern(10, {
          name: 'needle thread',
          attackTechniqueIds: ['T1059.001'],
          relatedWeaknesses: [{ id: 'CWE-1' }],
          typicalSeverity: 'High',
          likelihoodOfAttack: 'Low',
        }),
        pattern(2, { name: 'needle thread', attackTechniqueIds: ['T1059'] }),
        pattern(3, { description: 'needle thread', attackTechniqueIds: ['T10590'] }),
        pattern(4, { status: 'Deprecated', attackTechniqueIds: ['T1059'] }),
        pattern(5, { status: 'Obsolete', attackTechniqueIds: ['T1059'] }),
        pattern(6, { status: 'Draft' }),
        pattern(7),
      ],
    );
    expect(
      searchAttackPatterns(data, { attackTechniqueId: 'T1059' }).map((entry) => entry.id),
    ).toEqual(['CAPEC-2', 'CAPEC-10']);
    expect(
      searchAttackPatterns(data, { attackTechniqueId: 'T1059.001' }).map((entry) => entry.id),
    ).toEqual(['CAPEC-10']);
    expect(
      searchAttackPatterns(data, { attackTechniqueId: 'T1059', includeInactive: true }).map(
        (entry) => entry.id,
      ),
    ).toEqual(['CAPEC-2', 'CAPEC-4', 'CAPEC-5', 'CAPEC-10']);
    expect(
      searchAttackPatterns(data, { filter: 'needle thread' }).map((entry) => entry.id),
    ).toEqual(['CAPEC-2', 'CAPEC-10', 'CAPEC-3']);
    expect(
      searchAttackPatterns(data, {
        cweId: 'CWE-1',
        severity: 'high',
        likelihood: 'low',
        abstraction: 'standard',
      }).map((entry) => entry.id),
    ).toEqual(['CAPEC-10']);
    expect(searchAttackPatterns(data, { cweId: 'CWE-999' })).toEqual([]);
    expect(searchAttackPatterns(data, {}).map((entry) => entry.id)).toContain('CAPEC-6');
  });
});

describe('search over parsed catalogs', () => {
  const fixture = (name: string) =>
    readFileSync(new URL(`../../fixtures/catalog/${name}`, import.meta.url), 'utf8');
  const cwe = parseCweCatalog(
    fixture('cwe-normalization.xml')
      .replace('Sparse description.', '(e.g. $varname, $varname_size).')
      .replace(
        '</Weaknesses>',
        `<Weakness ID="1289" Name="Names" Status="Draft"><Description>Blocks <xhtml:b>"&lt;script&gt;"</xhtml:b> tags.</Description></Weakness>
        <Weakness ID="1389" Name="Numbers" Status="Draft"><Description>Parsing.</Description><Extended_Description><xhtml:p>Calls <xhtml:code>inet_addr()</xhtml:code>.</xhtml:p></Extended_Description></Weakness>
        <Weakness ID="1420" Name="Speculation" Status="Draft"><Description>Transient execution [REF-1400].</Description></Weakness>
        <Weakness ID="30" Name="needle" Status="Draft"><Description>Name tier.</Description></Weakness>
        <Weakness ID="40" Name="Second" Status="Draft"><Description>A <xhtml:i>needle</xhtml:i> here.</Description></Weakness>
        <Weakness ID="10" Name="Third" Status="Draft"><Description>Other.</Description><Extended_Description><xhtml:b>needle</xhtml:b></Extended_Description></Weakness></Weaknesses>`,
      ),
  );
  const capec = parseCapecCatalog(
    fixture('capec-normalization.xml').replace(
      'Attack description.',
      'Overwrite <xhtml:code>$varname_size</xhtml:code> fields.',
    ),
  );
  const parsed = (cweCatalog: CweCatalog = cwe, capecCatalog: CapecCatalog = capec) =>
    buildCatalogSnapshot(cweCatalog, capecCatalog, { cwe: health, capec: health }, health.loadedAt);
  const ids = (entries: readonly { id: string }[]) => entries.map((entry) => entry.id);

  it('matches source tokens that the stored CommonMark escapes or wraps in syntax', () => {
    const data = parsed();
    expect(ids(searchWeaknesses(data, { filter: 'varname_size' }))).toEqual(['CWE-20']);
    expect(ids(searchWeaknesses(data, { filter: 'inet_addr()' }))).toEqual(['CWE-1389']);
    expect(ids(searchWeaknesses(data, { filter: '"<script>"' }))).toEqual(['CWE-1289']);
    expect(ids(searchWeaknesses(data, { filter: '[ref-1400]' }))).toEqual(['CWE-1420']);
    expect(ids(searchAttackPatterns(data, { filter: '$varname_size' }))).toEqual(['CAPEC-1']);
    const stored = 'Blocks "\\<**script**>" tags.';
    expect(data.cwe.weaknesses.get('CWE-1289')?.description).toBe(stored);
    expect(searchWeaknesses(data, { filter: stored })).toEqual([]);
  });

  it('evaluates the source filter of a parsed filter-defined view', () => {
    // View 1001's filter selects every Draft record; category 900 is Stable.
    expect([...weaknessesInView(parsed(), 'CWE-1001')].sort()).toEqual(
      ['CWE-10', 'CWE-1289', 'CWE-1389', 'CWE-1420', 'CWE-30', 'CWE-40', 'CWE-79'].sort(),
    );
    expect([...weaknessesInView(parsed(), 'CWE-1000')].sort()).toEqual(['CWE-20', 'CWE-79']);
  });

  it('keeps the name, description, then extended-description tiers', () => {
    expect(ids(searchWeaknesses(parsed(), { filter: 'NEEDLE' }))).toEqual([
      'CWE-30',
      'CWE-40',
      'CWE-10',
    ]);
  });

  it('finds parsed alternate terms but never their stored explanations', () => {
    const data = parsed(
      parseCweCatalog(
        fixture('cwe-normalization.xml').replace(
          '<Related_Weaknesses>',
          '<Alternate_Terms><Alternate_Term><Term>ReDoS</Term><Description>Short for <xhtml:b>regex_dos</xhtml:b>.</Description></Alternate_Term></Alternate_Terms><Related_Weaknesses>',
        ),
      ),
    );
    expect(ids(searchWeaknesses(data, { filter: 'redos' }))).toEqual(['CWE-79']);
    expect(data.cwe.weaknesses.get('CWE-79')?.alternateTerms).toEqual([
      { term: 'ReDoS', description: 'Short for **regex_dos**.' },
    ]);
    expect(searchWeaknesses(data, { filter: 'regex_dos' })).toEqual([]);
  });

  it('fails loudly when a searched record has no projection', () => {
    const without = (catalog: CweCatalog | CapecCatalog, id: string) =>
      new Map([...catalog.searchText].filter(([key]) => key !== id));
    const data = parsed(
      { ...cwe, searchText: without(cwe, 'CWE-20') },
      { ...capec, searchText: without(capec, 'CAPEC-1') },
    );
    expect(ids(searchWeaknesses(data, {}))).toContain('CWE-20');
    expect(() => searchWeaknesses(data, { filter: 'varname' })).toThrow(
      'No search projection exists for CWE-20.',
    );
    expect(() => searchAttackPatterns(data, { filter: 'varname' })).toThrow(
      'No search projection exists for CAPEC-1.',
    );
  });
});
