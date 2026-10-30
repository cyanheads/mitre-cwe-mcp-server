/**
 * @fileoverview CWE schema-version compatibility and sparse CAPEC normalization contracts.
 * @module tests/services/catalog/schema-compatibility.test
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseCapecCatalog, parseCweCatalog } from '@/services/catalog/xml-normalization.js';

const fixture = (name: string) =>
  readFileSync(new URL(`../../fixtures/catalog/${name}`, import.meta.url), 'utf8');
const schema8 = fixture('cwe-schema8.xml');

describe('catalog schema compatibility', () => {
  it('keeps schema-7 and CAPEC sparse identities free of synthetic fields', () => {
    const cwe = parseCweCatalog(fixture('cwe-normalization.xml'));
    expect(cwe.weaknesses.get('CWE-20')).toEqual({
      id: 'CWE-20',
      type: 'weakness',
      name: 'Sparse',
      status: 'Incomplete',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/20.html',
      description: 'Sparse description.',
    });
    expect(cwe.weaknesses.get('CWE-900')?.type).toBe('category');
    const capec = parseCapecCatalog(fixture('capec-normalization.xml'));
    expect(capec.attackPatterns.get('CAPEC-2')).toEqual({
      id: 'CAPEC-2',
      type: 'attack_pattern',
      name: 'Sparse pattern',
      status: 'Deprecated',
      abstraction: 'Meta',
      sourceUrl: 'https://capec.mitre.org/data/definitions/2.html',
      description: 'Only identity and description.',
    });
  });

  it('loads schema-8 groupings with distinct identity and ordered dimensions', () => {
    const catalog = parseCweCatalog(schema8);
    expect(catalog.version).toBe('5.test');
    expect(catalog.weaknesses.size).toBe(4);
    expect(catalog.weaknesses.get('CWE-900')).toMatchObject({
      type: 'grouping',
      description: 'Organizational **summary**.',
      mappingNotes: { usage: 'Prohibited', reasons: ['Grouping'] },
      members: [
        {
          id: 'CWE-901',
          viewId: 'CWE-1000',
          dimensions: [{ type: 'Technology', value: 'Hardware' }],
        },
      ],
    });
    expect(catalog.weaknesses.get('CWE-901')?.members).toEqual([
      { id: 'CWE-1209', viewId: 'CWE-1000' },
    ]);
    expect(catalog.views.get('CWE-1000')?.members).toEqual([
      {
        id: 'CWE-900',
        viewId: 'CWE-1000',
        dimensions: [{ type: 'Resource-Type', value: 'Device' }],
      },
    ]);
    expect(catalog.weaknesses.get('CWE-1209')).toMatchObject({
      technicalNuance: 'Precise **nuance**.\n\nSecond paragraph.',
      dimensions: [
        { type: 'Behavior-Type', value: 'Comparison' },
        { type: 'Code-Property', value: 'Incompatible' },
      ],
      relatedWeaknesses: [
        {
          nature: 'Overlaps',
          id: 'CWE-1461',
          viewId: 'CWE-1000',
          dimensions: [{ type: 'Resource-Type', value: 'Memory' }],
        },
      ],
      alternateTerms: [
        {
          term: 'Alt_name',
          roles: ['Common-Name', 'Attack-Focused'],
          description: 'Term **meaning**.',
        },
      ],
      platforms: [
        { kind: 'language', name: 'Algorithm', prevalence: 'None', note: 'Platform *caveat*.' },
        { kind: 'OS', name: 'Other' },
      ],
    });
  });

  it('retains categories alongside groupings and rejects collisions between them', () => {
    const xml = schema8.replace(
      '<Groupings>',
      '<Categories><Category ID="800" Name="Category" Status="Stable"><Summary>Category summary.</Summary></Category></Categories><Groupings>',
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-800')).toEqual({
      id: 'CWE-800',
      type: 'category',
      name: 'Category',
      status: 'Stable',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/800.html',
      description: 'Category summary.',
    });
    expect(() => parseCweCatalog(xml.replace('Category ID="800"', 'Category ID="900"'))).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it('preserves all introduction and mitigation/detection phases, custom domains and notes', () => {
    const catalog = parseCweCatalog(schema8);
    const weakness = catalog.weaknesses.get('CWE-1209');
    expect(weakness?.modesOfIntroduction).toEqual([
      { phase: 'Architecture and Design', note: 'Shared **note**.' },
      { phase: 'Implementation', note: 'Shared **note**.' },
      { phase: 'Training', domain: 'AI', note: 'Mixed.' },
      { phase: 'Testing', note: 'Mixed.' },
      { phase: 'Hardware Manufacturing', domain: 'Hardware', note: 'Mixed.' },
    ]);
    expect(catalog.weaknesses.get('CWE-1461')?.modesOfIntroduction).toEqual([
      { phase: 'Implementation & Physical Design', domain: 'Hardware', note: 'Hardware note.' },
    ]);
    expect(weakness?.mitigations).toEqual([
      {
        phases: ['Training', 'Implementation', 'Output Processing'],
        phaseDetails: [
          { phase: 'Training', domain: 'AI' },
          { phase: 'Implementation' },
          { phase: 'Output Processing', domain: 'AI' },
        ],
        description: 'Mitigate.',
      },
      { phases: ['Testing'], description: 'Standard.' },
    ]);
    expect(weakness?.detectionMethods).toEqual([
      {
        method: 'Manual Analysis',
        phases: ['Testing', 'Prompting'],
        phaseDetails: [{ phase: 'Testing' }, { phase: 'Prompting', domain: 'AI' }],
        description: 'Inspect.',
      },
      { method: 'Other', description: 'No phases.' },
    ]);
  });

  it('retains new reference, observed-example and note metadata as sparse source values', () => {
    const catalog = parseCweCatalog(schema8);
    expect(catalog.weaknesses.get('CWE-1209')?.references).toEqual([
      {
        id: 'REF-8',
        title: 'Source',
        url: 'https://example.test/source',
        section: '2',
        altUrl: 'https://example.test/alt_a?q=1&b=2',
        altUrlDate: '2026-10-23',
        mediaTypes: ['Video', 'Text'],
        accessRestrictions: 'Minimal-Registration',
        rationales: ['Early-Publication', 'Other'],
      },
    ]);
    expect(catalog.weaknesses.get('CWE-1209')?.observedExamples).toEqual([
      {
        reference: 'CVE-2026-1234',
        description: 'Example.',
        link: 'https://example.test/observed',
        rationales: ['Chain', 'Early-Publication'],
      },
    ]);
    expect(catalog.weaknesses.get('CWE-1209')?.notes).toEqual([
      {
        type: 'Maintenance',
        text: 'Maintenance **note**.',
        version: '5.0',
        releaseDate: '2026-10-28',
      },
    ]);
    expect(catalog.views.get('CWE-1000')?.notes).toEqual([
      {
        type: 'Maintenance',
        text: 'View note.',
        version: '5.0',
        releaseDate: '2026-10-28',
      },
    ]);
  });

  it('preserves only actual notes for legal schema-8 introductions without any phase', () => {
    const xml = schema8.replace(
      '<Modes_Of_Introduction>',
      '<Modes_Of_Introduction><Introduction/><Introduction><Note>Unphased <xhtml:b>note</xhtml:b>.</Note></Introduction><Introduction><Note>Second.</Note></Introduction>',
    );
    const weakness = parseCweCatalog(xml).weaknesses.get('CWE-1209');
    expect(weakness?.unphasedIntroductionNotes).toEqual(['Unphased **note**.', 'Second.']);
    expect(weakness?.modesOfIntroduction?.[0]?.phase).toBe('Architecture and Design');
  });

  it.each([
    [
      'future namespace',
      schema8.replaceAll('http://cwe.mitre.org/cwe-8', 'http://cwe.mitre.org/cwe-9'),
    ],
    [
      'wrong namespace',
      schema8.replaceAll('http://cwe.mitre.org/cwe-8', 'http://example.test/cwe-8'),
    ],
    ['wrong root', schema8.replaceAll('Weakness_Catalog', 'Attack_Pattern_Catalog')],
    ['duplicate grouping ID', schema8.replace('Grouping ID="901"', 'Grouping ID="900"')],
    ['grouping/weakness collision', schema8.replace('Grouping ID="900"', 'Grouping ID="1209"')],
    ['grouping/view collision', schema8.replace('Grouping ID="900"', 'Grouping ID="1000"')],
    ['custom phase missing domain', schema8.replace(' Domain="Hardware"', '')],
    ['dimension missing type', schema8.replace(' Type="Technology"', '')],
    ['DTD', `<!DOCTYPE Weakness_Catalog>${schema8}`],
    ['entity', `<!ENTITY external SYSTEM "https://example.test/secret">${schema8}`],
  ])('rejects schema-8 %s with the existing invalid_catalog contract', (_label, xml) => {
    expect(() => parseCweCatalog(xml)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });
});
