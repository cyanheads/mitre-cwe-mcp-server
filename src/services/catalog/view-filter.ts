/**
 * @fileoverview Evaluation of CWE view source filters over indexed weakness fields. Comparisons are
 * exact over the stored values, which are whitespace-collapsed where XPath compares raw string
 * values, so a selection equals the XPath result whenever the source values carry no irregular
 * whitespace, as in CWE 4.20.
 * @module services/catalog/view-filter
 */
import type { Weakness } from './types.js';

/** A compiled view filter: whether the filter selects this weakness. */
type ViewFilter = (entry: Weakness) => boolean;
type Field = (entry: Weakness) => readonly (string | undefined)[];

const PLATFORM_ELEMENTS = {
  Language: 'language',
  Technology: 'technology',
  Operating_System: 'OS',
  Architecture: 'architecture',
} as const satisfies Record<string, NonNullable<Weakness['platforms']>[number]['kind']>;

/**
 * Relative paths a predicate may compare, each read from the indexed field holding that source
 * value. Like an XPath `=` over a node-set, a comparison holds when any value equals the literal.
 */
const FIELDS = new Map<string, Field>([
  ['@Status', (entry) => [entry.status]],
  ['@Abstraction', (entry) => [entry.abstraction]],
  ['@Structure', (entry) => [entry.structure]],
  [
    'Modes_Of_Introduction/Introduction/Phase',
    (entry) => entry.modesOfIntroduction?.map((mode) => mode.phase) ?? [],
  ],
  [
    'Weakness_Ordinalities/Weakness_Ordinality/Ordinality',
    (entry) => entry.ordinalities?.map((item) => item.ordinality) ?? [],
  ],
  [
    'Taxonomy_Mappings/Taxonomy_Mapping/@Taxonomy_Name',
    (entry) => entry.taxonomyMappings?.map((mapping) => mapping.taxonomy) ?? [],
  ],
  ['Notes/Note/@Type', (entry) => entry.notes?.map((note) => note.type) ?? []],
  ...Object.entries(PLATFORM_ELEMENTS).flatMap(([element, kind]) =>
    (['Name', 'Class'] as const).map((attribute): [string, Field] => [
      `Applicable_Platforms/${element}/@${attribute}`,
      (entry) =>
        entry.platforms
          ?.filter((platform) => platform.kind === kind)
          .map((platform) => (attribute === 'Name' ? platform.name : platform.class)) ?? [],
    ]),
  ),
]);

/**
 * Filter roots, longest first, and whether the records they select include weaknesses. The bare
 * catalog root selects the catalog element itself, never a record.
 */
const ROOTS: readonly [root: string, selectsWeaknesses: boolean][] = [
  ['/Weakness_Catalog/*[not(self::External_References)]/*', true],
  ['/Weakness_Catalog/Weaknesses/Weakness', true],
  ['/Weakness_Catalog/*/*', true],
  ['/Weakness_Catalog', false],
];

function isSpace(character: string | undefined): boolean {
  return character === ' ' || character === '\t' || character === '\n' || character === '\r';
}
function isNameCharacter(character: string | undefined): boolean {
  if (character === undefined) return false;
  const code = character.charCodeAt(0);
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    '_.-/@'.includes(character)
  );
}

/**
 * Parse the bracketed predicates after a root. Each predicate is one term or several joined by
 * `or`; a term is a comparison, a parenthesized comparison, `not(comparison)`, or `false()`. A
 * comparison is `path = 'literal'`, or `path[@Attribute = 'literal']`, which holds exactly when
 * `path/@Attribute = 'literal'` does. One left-to-right pass with no backtracking or recursion.
 */
function parsePredicates(source: string, start: number): ViewFilter[] | undefined {
  let index = start;
  const skipSpace = () => {
    while (isSpace(source[index])) index++;
  };
  const accept = (character: string) => {
    skipSpace();
    if (source[index] !== character) return false;
    index++;
    return true;
  };
  const name = () => {
    skipSpace();
    const from = index;
    while (isNameCharacter(source[index])) index++;
    return source.slice(from, index);
  };
  const literal = () => {
    skipSpace();
    const quote = source[index];
    if (quote !== "'" && quote !== '"') return;
    const end = source.indexOf(quote, index + 1);
    if (end === -1) return;
    const value = source.slice(index + 1, end);
    index = end + 1;
    return value;
  };
  const comparison = (path: string): ViewFilter | undefined => {
    let key = path.startsWith('./') ? path.slice(2) : path;
    if (accept('[')) {
      const attribute = name();
      if (!attribute.startsWith('@')) return undefined;
      key = `${key}/${attribute}`;
      const value = accept('=') ? literal() : undefined;
      if (value === undefined || !accept(']')) return undefined;
      return field(key, value);
    }
    const value = accept('=') ? literal() : undefined;
    return value === undefined ? undefined : field(key, value);
  };
  const term = (): ViewFilter | undefined => {
    if (accept('(')) {
      const inner = comparison(name());
      return inner && accept(')') ? inner : undefined;
    }
    const word = name();
    if (word === 'false') return accept('(') && accept(')') ? () => false : undefined;
    if (word === 'not') {
      const inner = accept('(') ? comparison(name()) : undefined;
      return inner && accept(')') ? (entry) => !inner(entry) : undefined;
    }
    return comparison(word);
  };
  const predicates: ViewFilter[] = [];
  for (;;) {
    skipSpace();
    if (index === source.length) return predicates;
    if (!accept('[')) return undefined;
    const terms: ViewFilter[] = [];
    let word: string;
    do {
      const next = term();
      if (!next) return undefined;
      terms.push(next);
      word = name();
    } while (word === 'or');
    if (word || !accept(']')) return undefined;
    predicates.push(
      terms.length === 1 ? (terms[0] as ViewFilter) : (entry) => terms.some((item) => item(entry)),
    );
  }
}
function field(key: string, value: string): ViewFilter | undefined {
  const read = FIELDS.get(key);
  return read && ((entry) => read(entry).includes(value));
}

/**
 * Compile a view's source XPath filter into a predicate over indexed weakness fields. A filter is
 * matched as a known root plus bracketed predicates of the supported shapes; any other part makes
 * the whole filter unrecognized (`undefined`), never partly evaluated. Linear in the filter length.
 */
export function compileViewFilter(filter: string): ViewFilter | undefined {
  const source = filter.trim();
  for (const [root, selectsWeaknesses] of ROOTS) {
    if (!source.startsWith(root)) continue;
    const predicates = parsePredicates(source, root.length);
    if (!predicates) continue;
    return selectsWeaknesses ? (entry) => predicates.every((item) => item(entry)) : () => false;
  }
  return undefined;
}
