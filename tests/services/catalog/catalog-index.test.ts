/**
 * @fileoverview Full-corpus index, membership, vocabulary and recorded mapping tests.
 * @module tests/services/catalog/catalog-index.test
 */
import { describe, expect, it } from 'vitest';
import {
  buildCatalogSnapshot,
  resolveVocabulary,
  searchAttackPatterns,
  searchWeaknesses,
  weaknessesInView,
} from '@/services/catalog/catalog-index.js';
import type { AttackPattern, CatalogHealth, Weakness } from '@/services/catalog/types.js';

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
  name: 'Other',
  description: 'Other',
  status: 'Stable',
  abstraction: 'Standard',
  sourceUrl: `https://capec.mitre.org/data/definitions/${id}.html`,
  ...fields,
});
function snapshot(entries: Weakness[], patterns: AttackPattern[] = []) {
  const health: CatalogHealth = {
    version: 'test',
    date: '2026-10-20',
    counts: {},
    loadedAt: '2026-10-20T00:00:00Z',
    nextCheckAt: '2026-10-21T00:00:00Z',
    sourceUrl: 'https://example.test',
  };
  return buildCatalogSnapshot(
    {
      version: '4.test',
      date: '2026-10-20',
      weaknesses: new Map(entries.map((entry) => [entry.id, entry])),
      views: new Map([
        [
          'CWE-1000',
          {
            id: 'CWE-1000',
            name: 'Navigation',
            type: 'Graph',
            status: 'Stable',
            sourceUrl: 'https://cwe.mitre.org/data/definitions/1000.html',
            members: [{ id: 'CWE-900', viewId: 'CWE-1000' }],
          },
        ],
      ]),
    },
    {
      version: '3.test',
      date: '2023-01-24',
      attackPatterns: new Map(patterns.map((entry) => [entry.id, entry])),
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
    expect(resolveVocabulary(data, 'languages', ' c++ ')).toBe('C++');
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
        data: expect.objectContaining({ reason: 'unknown_filter', supported: ['C++', 'Compiled'] }),
      }),
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
      expect.objectContaining({ data: expect.objectContaining({ reason: 'unknown_filter' }) }),
    );
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
