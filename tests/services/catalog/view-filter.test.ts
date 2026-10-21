/**
 * @fileoverview View source-filter shapes evaluated over indexed weakness fields, and parse time.
 * @module tests/services/catalog/view-filter.test
 */
import { describe, expect, it } from 'vitest';
import type { Weakness } from '@/services/catalog/types.js';
import { compileViewFilter } from '@/services/catalog/view-filter.js';
import { expectLinearTime } from '../../helpers/cpu-timing.js';

const weakness = (id: number, fields: Partial<Weakness> = {}): Weakness => ({
  id: `CWE-${id}`,
  name: 'Weakness',
  description: 'Description.',
  status: 'Draft',
  type: 'weakness',
  sourceUrl: `https://cwe.mitre.org/data/definitions/${id}.html`,
  ...fields,
});
const records = [
  weakness(1, {
    abstraction: 'Base',
    structure: 'Simple',
    platforms: [
      { kind: 'language', name: 'C' },
      { kind: 'technology', class: 'Mobile' },
    ],
    modesOfIntroduction: [{ phase: 'Architecture and Design' }, { phase: 'Implementation' }],
  }),
  weakness(2, {
    abstraction: 'Class',
    status: 'Deprecated',
    structure: 'Composite',
    platforms: [{ kind: 'language', name: 'C++', class: 'C' }],
    ordinalities: [{ ordinality: 'Indirect' }],
    notes: [{ type: 'Maintenance', text: 'Revisit.' }],
  }),
  weakness(3, {
    abstraction: 'Base',
    status: 'Stable',
    structure: 'Composite',
    modesOfIntroduction: [{ phase: 'Implementation', note: 'Architecture and Design' }],
    ordinalities: [{ ordinality: 'Primary' }, { ordinality: 'Indirect' }],
    taxonomyMappings: [{ taxonomy: 'ISA/IEC 62443', id: 'Part 4-1' }],
    // Only a note's type is compared, never its text.
    notes: [{ type: 'Relationship', text: 'Maintenance' }],
  }),
  weakness(4, {
    abstraction: 'Variant',
    structure: 'Chain',
    platforms: [{ kind: 'OS', name: 'Windows', class: 'Windows' }],
    notes: [
      { type: 'Relationship', text: 'See also.' },
      { type: 'Maintenance', text: 'Revisit.' },
    ],
  }),
  // Sparse: no abstraction, structure, platforms, phases, ordinalities, mappings, or notes.
  weakness(5),
];
/** The IDs a filter selects from the records, or undefined when it is not recognized. */
function selected(filter: string): string[] | undefined {
  const predicate = compileViewFilter(filter);
  return predicate && records.filter(predicate).map((entry) => entry.id.slice(4));
}
const root = '/Weakness_Catalog/Weaknesses/Weakness';

describe('compileViewFilter', () => {
  // Every filter MITRE publishes in CWE 4.20, verbatim, with the records each selects here.
  it.each([
    ["/Weakness_Catalog/*/*[@Status='Deprecated']", ['2']],
    [`${root}[./Applicable_Platforms/Language/@Name='C']`, ['1']],
    [`${root}[./Applicable_Platforms/Language/@Name='C++']`, ['2']],
    [`${root}[./Applicable_Platforms/Language/@Name='Java']`, []],
    [`${root}[./Applicable_Platforms/Language/@Name='PHP']`, []],
    [`${root}[@Abstraction='Base'][not(@Status='Deprecated')]`, ['1', '3']],
    [`${root}[@Structure='Composite'][not(@Status='Deprecated')]`, ['3']],
    ['/Weakness_Catalog[false()]', []],
    [
      `${root}[(@Abstraction='Base') or (@Abstraction='Class')][./Modes_Of_Introduction/Introduction/Phase='Architecture and Design']`,
      ['1'],
    ],
    [`${root}[./Modes_Of_Introduction/Introduction/Phase='Implementation']`, ['1', '3']],
    [`${root}[@Structure='Chain']`, ['4']],
    [`${root}[./Applicable_Platforms/Technology/@Class='Mobile']`, ['1']],
    [`${root}[Weakness_Ordinalities/Weakness_Ordinality/Ordinality='Indirect']`, ['2', '3']],
    ["/Weakness_Catalog/*/*[Notes/Note[@Type='Maintenance']]", ['2', '4']],
    [`${root}[./Taxonomy_Mappings/Taxonomy_Mapping/@Taxonomy_Name='ISA/IEC 62443']`, ['3']],
    ['/Weakness_Catalog/*[not(self::External_References)]/*', ['1', '2', '3', '4', '5']],
  ])('evaluates %s exactly', (filter, expected) => {
    expect(selected(filter)).toEqual(expected);
  });

  it.each([
    // Whitespace between tokens, double-quoted literals, and an unspaced `or` read the same.
    [`  ${root} [ @Status = "Deprecated" ]\n`, ['2']],
    [`${root}[(@Abstraction='Base')or(@Abstraction='Class')]`, ['1', '2', '3']],
    // `path[@Attribute='x']` holds exactly when `path/@Attribute='x'` does.
    [`${root}[Notes/Note/@Type='Maintenance']`, ['2', '4']],
    [`${root}[Applicable_Platforms/Operating_System/@Class='Windows']`, ['4']],
    [`${root}[./Applicable_Platforms/Language[@Name='C']]`, ['1']],
    [`${root}[@Abstraction='Base' or not(@Structure='Simple')]`, ['1', '2', '3', '4', '5']],
    // `false()` holds for no weakness, so only the other term selects.
    [`${root}[false() or @Structure='Chain']`, ['4']],
    // Literals compare case-sensitively, as XPath does.
    [`${root}[@Status='deprecated']`, []],
    // `not()` negates "some value equals": a weakness with no phase, or none equal, is selected.
    [`${root}[not(Modes_Of_Introduction/Introduction/Phase='Implementation')]`, ['2', '4', '5']],
    [root, ['1', '2', '3', '4', '5']],
    // The bare catalog root selects the catalog element, never a weakness.
    ['/Weakness_Catalog', []],
    ["/Weakness_Catalog[@Status='Draft']", []],
  ])('reads the equivalent shape %s', (filter, expected) => {
    expect(selected(filter)).toEqual(expected);
  });

  it.each([
    ["status = 'Draft'", 'no root'],
    ["/Weakness_Catalog/Categories/Category[@Status='Draft']", 'unsupported root'],
    ['/Weakness_Catalog/Weaknesses/WeaknessX', 'root followed by more name'],
    [`${root}/Description`, 'path step after the root'],
    ['/Weakness_Catalog//Weakness', 'descendant axis'],
    [`${root}[@Likelihood='High']`, 'unindexed attribute'],
    [`${root}[./Applicable_Platforms/Language/@Prevalence='Often']`, 'unindexed path'],
    [`${root}[.//Language/@Name='C']`, 'descendant path'],
    [`${root}[@Status!='Draft']`, 'other operator'],
    [`${root}[@Status='Draft' and @Abstraction='Base']`, 'and'],
    [`${root}[@Status='Draft' or]`, 'dangling or'],
    [`${root}[@Status='Draft' order]`, 'trailing word'],
    [`${root}[@Status='Draft']x`, 'trailing text'],
    [`${root}[@Status='Draft'`, 'unclosed predicate'],
    [`${root}[@Status='Draft]`, 'unterminated literal'],
    [`${root}[]`, 'empty predicate'],
    [`${root}[@Status]`, 'existence test'],
    [`${root}[not(not(@Status='Draft'))]`, 'nested negation'],
    [`${root}[((@Status='Draft'))]`, 'nested parentheses'],
    [`${root}[contains(@Name,'X')]`, 'function'],
    [`${root}[Notes/Note[@Type='x']='y']`, 'comparison after a nested predicate'],
    [`${root}[Notes/Note[Type='x']]`, 'nested element predicate'],
    ['/Weakness_Catalog/*/*[@ID = (187, 498)]', 'sequence'],
    [`${root}[@Structure='Chain'] | ${root}[@Structure='Composite']`, 'union'],
    ['', 'empty filter'],
  ])('does not evaluate %s (%s)', (filter) => {
    expect(compileViewFilter(filter)).toBeUndefined();
  });

  it('parses in linear time', { timeout: 60_000 }, () => {
    const repeat = (unit: string, length: number) => unit.repeat(Math.ceil(length / unit.length));
    const shapes: [string, (length: number) => string][] = [
      ['repeated openers', (length) => `${root}${repeat('[', length)}`],
      ['nested openers', (length) => `${root}${repeat('[not((', length)}`],
      ['unterminated literal', (length) => `${root}[@Status='${repeat('x', length)}`],
      ['valid predicates', (length) => `${root}${repeat("[@Status='Draft']", length)}`],
      ['or chain', (length) => `${root}[${repeat("@Status='x' or ", length)}@Status='y']`],
      ['long name', (length) => `${root}[${repeat('a', length)}='x']`],
      ['digit literal', (length) => `${root}[@Status='${repeat('1', length)}']`],
      ['one long line', (length) => `${root}[@Status='${repeat('§1 x', length)}\ny']`],
      ['breaks throughout', (length) => `${root}${repeat('  \r\n', length)}[false()]`],
    ];
    for (const [label, build] of shapes) expectLinearTime(label, build, compileViewFilter);
  });
});
