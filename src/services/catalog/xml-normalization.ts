/**
 * @fileoverview Ordered, entity-safe XML normalization for the MITRE catalogs.
 * @module services/catalog/xml-normalization
 */
import { serializationError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { XMLParser } from 'fast-xml-parser';
import { SyntaxValidator } from 'fast-xml-validator';
import { escapeMarkdown, Mark, PROSE_FIELDS } from './markdown-escape.js';
import type {
  AlternateTerm,
  AttackPattern,
  CapecCatalog,
  CapecGrouping,
  CatalogNote,
  CatalogReference,
  CatalogView,
  Consequence,
  CweCatalog,
  DemonstrativeExample,
  ExampleBlock,
  Member,
  SearchText,
  TaxonomyMapping,
  Weakness,
  WeaknessOrdinality,
} from './types.js';

/** fast-xml-parser's preserveOrder representation, used only during ingestion. */
export interface OrderedNode {
  [key: string]: unknown;
}

function malformed(message = 'The MITRE catalog has an invalid structure.'): never {
  throw serializationError(message, { reason: 'invalid_catalog', retryable: false });
}

function local(name: string): string {
  return name.split(':').at(-1) ?? name;
}
function tag(node: OrderedNode): string | undefined {
  return Object.keys(node).find(
    (key) => key !== ':@' && !key.startsWith('#') && !key.startsWith('?'),
  );
}
function contents(node: OrderedNode): OrderedNode[] {
  const name = tag(node);
  const value = name ? node[name] : undefined;
  return Array.isArray(value) ? (value as OrderedNode[]) : [];
}
function children(node: OrderedNode, name: string): OrderedNode[] {
  return contents(node).filter((item) => {
    const key = tag(item);
    return key !== undefined && local(key) === name;
  });
}
function child(node: OrderedNode, name: string): OrderedNode | undefined {
  return children(node, name)[0];
}
function nested(node: OrderedNode, container: string, name: string): OrderedNode[] {
  const parent = child(node, container);
  return parent ? children(parent, name) : [];
}
function attribute(node: OrderedNode, name: string): string | undefined {
  const attrs = node[':@'];
  if (typeof attrs !== 'object' || attrs === null) return undefined;
  const value = Object.entries(attrs).find(([key]) => local(key.replace(/^@_/, '')) === name)?.[1];
  return typeof value === 'string' ? value : undefined;
}
/**
 * Source text with whitespace collapsed, the stored form of every field that is not prose and of
 * other MITRE text rendered as a plain value. CommonMark trims the same whitespace at a paragraph's
 * ends, so a collapsed value parses back exactly.
 */
export function collapse(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}
function rawRequiredAttribute(node: OrderedNode, name: string): string {
  const value = attribute(node, name);
  if (!value?.trim()) malformed(`The MITRE catalog is missing a required ${name} attribute.`);
  return value;
}
function requiredAttribute(node: OrderedNode, name: string): string {
  return collapse(rawRequiredAttribute(node, name));
}
/** Identifiers are checked as written, so surrounding whitespace stays invalid. */
function id(node: OrderedNode, prefix: 'CWE' | 'CAPEC', name = 'ID'): string {
  const value = rawRequiredAttribute(node, name);
  if (!/^[0-9]+$/.test(value) || /^0+$/.test(value))
    malformed('The MITRE catalog contains an invalid entry identifier.');
  return `${prefix}-${value.replace(/^0+/, '')}`;
}
const PREDEFINED_ENTITIES = new Map([
  ['amp', '&'],
  ['lt', '<'],
  ['gt', '>'],
  ['quot', '"'],
  ['apos', "'"],
]);
function decodeReferences(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (entity, name: string) => {
    if (!name.startsWith('#')) return PREDEFINED_ENTITIES.get(name) ?? entity;
    const code =
      name[1]?.toLowerCase() === 'x' ? Number.parseInt(name.slice(2), 16) : Number(name.slice(1));
    if (
      !(
        code === 9 ||
        code === 10 ||
        code === 13 ||
        (code >= 32 && code <= 0xd7ff) ||
        (code >= 0xe000 && code <= 0xfffd) ||
        (code >= 0x10000 && code <= 0x10ffff)
      )
    )
      malformed('The MITRE catalog contains an invalid XML character reference.');
    return String.fromCodePoint(code);
  });
}
/** Rows of a table in source order, through any thead/tbody/tfoot wrappers; cells are th/td. */
function tableRows(table: OrderedNode): OrderedNode[][] {
  const rows: OrderedNode[][] = [];
  const collect = (node: OrderedNode) => {
    for (const item of contents(node)) {
      const key = tag(item);
      const name = key && local(key);
      if (name === 'tr')
        rows.push(
          contents(item).filter((cell) => {
            const cellKey = tag(cell);
            return cellKey !== undefined && ['td', 'th'].includes(local(cellKey));
          }),
        );
      else if (name === 'thead' || name === 'tbody' || name === 'tfoot') collect(item);
    }
  };
  collect(table);
  return rows;
}
/** Pipe-table lines: the first row is the header, and short rows are padded to the widest. */
function pipeTable<T>(rows: readonly T[][], empty: T): { cells: T[]; delimiter?: true }[] {
  const width = rows.reduce((widest, row) => Math.max(widest, row.length), 0);
  if (!width) return [];
  const pad = (row: readonly T[]) =>
    Array.from({ length: width }, (_, index) => row[index] ?? empty);
  const [header = [], ...body] = rows;
  return [
    { cells: pad(header) },
    { cells: pad([]), delimiter: true },
    ...body.map((row) => ({ cells: pad(row) })),
  ];
}

function rawText(nodes: readonly OrderedNode[]): string {
  return nodes
    .map((node) => {
      if (typeof node['#text'] === 'string') return node['#text'];
      if (Array.isArray(node['#cdata'])) return rawText(node['#cdata'] as OrderedNode[]);
      const name = tag(node);
      if (!name) return '';
      if (local(name) === 'br') return '\n';
      if (local(name) === 'table')
        return pipeTable(
          tableRows(node).map((row) => row.map((cell) => plainText(cell))),
          '',
        )
          .map(({ cells, delimiter }) =>
            delimiter ? `|${' --- |'.repeat(cells.length)}\n` : `| ${cells.join(' | ')} |\n`,
          )
          .join('');
      const text = rawText(contents(node));
      return local(name) === 'div' || local(name) === 'p' ? `${text}\n` : text;
    })
    .join('');
}
/** An element's source text with whitespace collapsed, for every field that is not prose. */
function plainText(node: OrderedNode): string {
  return collapse(rawText(contents(node)));
}

/** A stretch of generated Markdown (mark 0) or of source text carrying escape-context marks. */
interface Run {
  mark: number;
  value: string;
}
/** Source text inside code: searchable, but literal, so never escaped or whitespace-folded. */
const CODE = 8;
/** Generated code-span padding, which a CommonMark parse strips, so the projection omits it. */
const PADDING = 16;
const SPACE: Run = { mark: Mark.text, value: ' ' };
const syntax = (value: string): Run[] => [{ mark: 0, value }];
const sourceText = (value: string, mark: number = Mark.text): Run[] => [{ mark, value }];
/** Add a context bit to the source text in `runs`. */
function withContext(runs: readonly Run[], bit: number): Run[] {
  return runs.map((run) => (run.mark & Mark.text ? { ...run, mark: run.mark | bit } : run));
}
/** Remove whitespace at both ends across run boundaries, reporting which ends had any. */
function trimRuns(runs: readonly Run[]): { runs: Run[]; leading: boolean; trailing: boolean } {
  let first = 0;
  let last = runs.length - 1;
  let leading = false;
  let trailing = false;
  while (first <= last && !(runs[first] as Run).value.trim()) {
    leading ||= (runs[first] as Run).value !== '';
    first++;
  }
  while (last >= first && !(runs[last] as Run).value.trim()) {
    trailing ||= (runs[last] as Run).value !== '';
    last--;
  }
  const result = runs.slice(first, last + 1).map((run) => ({ ...run }));
  const head = result[0];
  const tail = result.at(-1);
  if (head && tail) {
    const start = head.value.trimStart();
    leading ||= start !== head.value;
    head.value = start;
    const end = tail.value.trimEnd();
    trailing ||= end !== tail.value;
    tail.value = end;
  }
  return { runs: result, leading, trailing };
}
/** Wrap trimmed content while keeping the element's edge whitespace outside the syntax. */
function wrapTrimmed(runs: readonly Run[], wrap: (body: Run[]) => Run[]): Run[] {
  const { runs: body, leading, trailing } = trimRuns(runs);
  return [...(leading ? [SPACE] : []), ...wrap(body), ...(trailing ? [SPACE] : [])];
}
const EDGE = /[\s\p{P}\p{S}]/u;
/**
 * Move source punctuation and whitespace at the content's edges outside an emphasis span, so its
 * delimiters always open and close whatever text surrounds the element.
 */
function peelEdges(runs: readonly Run[]): { before: Run[]; body: Run[]; after: Run[] } {
  const body = runs.map((run) => ({ ...run }));
  const before: Run[] = [];
  const after: Run[] = [];
  let first = 0;
  let last = body.length - 1;
  for (; first <= last && (body[first] as Run).mark & Mark.text; first++) {
    const run = body[first] as Run;
    let cut = 0;
    while (cut < run.value.length && EDGE.test(run.value[cut] as string)) cut++;
    if (cut) before.push({ mark: run.mark, value: run.value.slice(0, cut) });
    if (cut < run.value.length) {
      run.value = run.value.slice(cut);
      break;
    }
  }
  for (; last >= first && (body[last] as Run).mark & Mark.text; last--) {
    const run = body[last] as Run;
    let cut = run.value.length;
    while (cut > 0 && EDGE.test(run.value[cut - 1] as string)) cut--;
    if (cut < run.value.length) after.push({ mark: run.mark, value: run.value.slice(cut) });
    if (cut) {
      run.value = run.value.slice(0, cut);
      break;
    }
  }
  return { before, body: body.slice(first, last + 1), after: after.reverse() };
}
/** Continue each later line of a list item at the item's content column. */
function indentRuns(runs: readonly Run[], indent: string): Run[] {
  return runs.flatMap((run) =>
    run.value
      .split('\n')
      .flatMap((part, index) => [
        ...(index ? [{ mark: run.mark, value: '\n' }, ...syntax(indent)] : []),
        ...(part ? [{ mark: run.mark, value: part }] : []),
      ]),
  );
}
/** Fold line breaks to single spaces, for a table cell that must stay on one line. */
function oneLine(runs: readonly Run[]): Run[] {
  return runs.map((run) => {
    if (!run.value.includes('\n')) return run;
    const parts = run.value.split('\n');
    const value = parts
      .map((part, index) =>
        index === 0 ? part.trimEnd() : index === parts.length - 1 ? part.trimStart() : part.trim(),
      )
      .join(' ');
    return { ...run, value };
  });
}
/** Link destinations encode their delimiters and keep `&` from reading as an entity. */
function destination(url: string): string {
  return url
    .replace(/[\\<>\s]/g, (character) => encodeURIComponent(character))
    .replace(/&/g, '&amp;');
}
const CWE_ORIGIN = 'https://cwe.mitre.org';
/** An image source that may be shown: absolute HTTP(S), or root-relative on the CWE site. */
function imageSource(src: string | undefined): string | undefined {
  if (!src) return undefined;
  if (/^https?:\/\//i.test(src)) return URL.canParse(src) ? src : undefined;
  if (!src.startsWith('/') || !URL.canParse(src, CWE_ORIGIN)) return undefined;
  const url = new URL(src, CWE_ORIGIN);
  return url.origin === CWE_ORIGIN ? url.href : undefined;
}
/** A backtick fence longer than any backtick run in the code. */
function codeFence(code: string, minimum: number): string {
  let longest = 0;
  for (const match of code.matchAll(/`+/g)) longest = Math.max(longest, match[0].length);
  return '`'.repeat(Math.max(minimum, longest + 1));
}

/** `label` is set inside a generated link label. */
function renderNodes(nodes: readonly OrderedNode[], label = false): Run[] {
  return nodes.flatMap((node) => renderNode(node, label));
}
function renderNode(node: OrderedNode, label: boolean): Run[] {
  if (typeof node['#text'] === 'string') return sourceText(node['#text'].replace(/\s+/g, ' '));
  if (Array.isArray(node['#cdata']))
    return sourceText(rawText(node['#cdata'] as OrderedNode[]).replace(/\r\n?/g, '\n'));
  const key = tag(node);
  if (!key) return [];
  const name = local(key);
  const inner = () => renderNodes(contents(node), label);
  switch (name) {
    case 'br':
      return syntax('  \n');
    case 'p':
    case 'div':
      return [...syntax('\n\n'), ...trimRuns(inner()).runs, ...syntax('\n\n')];
    case 'ul':
    case 'ol': {
      const items = children(node, 'li').map((entry, index) => {
        const marker = name === 'ol' ? `${index + 1}. ` : '- ';
        const body = trimRuns(renderNodes(contents(entry), label)).runs;
        return [...syntax(marker), ...indentRuns(body, ' '.repeat(marker.length))];
      });
      return [
        ...syntax('\n\n'),
        ...items.flatMap((item, index) => (index ? [...syntax('\n'), ...item] : item)),
        ...syntax('\n\n'),
      ];
    }
    case 'li':
      return [...syntax('\n- '), ...trimRuns(inner()).runs, ...syntax('\n')];
    case 'a': {
      const href = attribute(node, 'href');
      if (!href) return inner();
      const link = /^https?:\/\//i.test(href) && URL.canParse(href);
      return wrapTrimmed(renderNodes(contents(node), label || link), (text) =>
        link
          ? [
              ...syntax('['),
              ...withContext(text, Mark.linkText),
              ...syntax(`](<${destination(href)}>)`),
            ]
          : [...text, ...syntax(' ('), ...sourceText(href), ...syntax(')')],
      );
    }
    case 'img': {
      const alt = collapse(attribute(node, 'alt') ?? '');
      const src = imageSource(attribute(node, 'src'));
      return src
        ? [
            ...syntax('!['),
            ...sourceText(alt, Mark.text | Mark.linkText),
            ...syntax(`](<${destination(src)}>)`),
          ]
        : sourceText(alt);
    }
    case 'b':
    case 'strong':
    case 'i':
    case 'em': {
      const delimiter = name === 'b' || name === 'strong' ? '**' : '*';
      return wrapTrimmed(inner(), (content) => {
        const { before, body, after } = peelEdges(content);
        return [
          ...before,
          ...(body.length ? [...syntax(delimiter), ...body, ...syntax(delimiter)] : []),
          ...after,
        ];
      });
    }
    case 'sup':
      return [...syntax('^'), ...inner()];
    case 'code': {
      // A code span shows each line ending as a space; a blank line would end the span early.
      const code = rawText(contents(node)).replace(/\r\n?|\n/g, ' ');
      // A link reference definition's label is read without code spans, so code in a generated
      // label is label text, escaped like the rest of it.
      if (label) return sourceText(code.replace(/\s+/g, ' '));
      const fence = codeFence(code, 1);
      const padding: Run = { mark: PADDING, value: ' ' };
      return [...syntax(fence), padding, { mark: CODE, value: code }, padding, ...syntax(fence)];
    }
    case 'pre': {
      const code = rawText(contents(node));
      const fence = codeFence(code, 3);
      return [
        ...syntax(`\n\n${fence}\n`),
        { mark: CODE, value: code },
        ...syntax(`\n${fence}\n\n`),
      ];
    }
    case 'table': {
      const rows = tableRows(node).map((row) =>
        row.map((cell) =>
          withContext(trimRuns(oneLine(renderNodes(contents(cell), label))).runs, Mark.tableCell),
        ),
      );
      return [
        ...syntax('\n\n'),
        ...pipeTable(rows, []).flatMap(({ cells, delimiter }) =>
          delimiter
            ? syntax(`|${' --- |'.repeat(cells.length)}\n`)
            : [
                ...syntax('|'),
                ...cells.flatMap((cell) => [...syntax(' '), ...cell, ...syntax(' |')]),
                ...syntax('\n'),
              ],
        ),
        ...syntax('\n'),
      ];
    }
    default:
      return inner();
  }
}

/** A rendered Markdown document and the role of each of its UTF-16 code units. */
interface MarkedDocument {
  marks: Uint8Array;
  text: string;
}
function isSpace(code: number | undefined): boolean {
  return code === 32 || code === 9 || code === 10 || code === 12 || code === 13;
}
/**
 * Join runs into one document. Source whitespace folds as in HTML: never at the start of a line
 * (so source text cannot indent itself into a code block) and never after other whitespace. Lines
 * holding only whitespace become blank, runs of blank lines collapse to one, code is kept verbatim,
 * and the document is trimmed.
 */
function flatten(runs: readonly Run[]): MarkedDocument {
  const size = runs.reduce((total, run) => total + run.value.length, 0);
  const units = new Uint16Array(size);
  const marks = new Uint8Array(size);
  let written = 0;
  let lineStart = 0;
  let lineContent = false;
  let blankLines = 0;
  for (const { mark, value } of runs) {
    for (let index = 0; index < value.length; index++) {
      const code = value.charCodeAt(index);
      if (code === 10 && !(mark & CODE)) {
        if (lineContent) blankLines = 0;
        else {
          written = lineStart;
          if (blankLines++) continue;
        }
      } else if (code === 10) blankLines = 0;
      else if (isSpace(code)) {
        if (mark & Mark.text && (!lineContent || isSpace(units[written - 1]))) continue;
      } else lineContent = true;
      units[written] = code;
      marks[written++] = mark;
      if (code === 10) {
        lineStart = written;
        lineContent = false;
      } else if (mark & CODE) lineContent = true;
    }
  }
  let start = 0;
  let end = written;
  while (start < end && isSpace(units[start])) start++;
  while (end > start && isSpace(units[end - 1])) end--;
  let text = '';
  for (let index = start; index < end; index += 8192)
    text += Reflect.apply(
      String.fromCharCode,
      null,
      units.subarray(index, Math.min(end, index + 8192)),
    );
  return { text, marks: marks.slice(start, end) };
}
function renderProse(nodes: readonly OrderedNode[]): MarkedDocument {
  return flatten(renderNodes(nodes));
}
/**
 * The source text of a rendered document: generated syntax removed, generated whitespace kept
 * as word boundaries, and whitespace collapsed.
 */
function projectText({ text, marks }: MarkedDocument): string {
  let result = '';
  for (let index = 0; index < text.length; index++) {
    const character = text[index] as string;
    const mark = marks[index] ?? 0;
    if (mark & (Mark.text | CODE)) result += character;
    else if (!(mark & PADDING) && isSpace(character.charCodeAt(0))) result += ' ';
  }
  return collapse(result);
}

/**
 * Convert mixed XHTML into inert CommonMark in document order. A CommonMark parse of the result
 * shows the source text: Markdown syntax appears only for structure the XHTML has, and a backslash
 * only where a source character would otherwise read as syntax.
 */
export function orderedContentToMarkdown(nodes: readonly OrderedNode[]): string {
  const document = renderProse(nodes);
  return escapeMarkdown(document.text, document.marks);
}

/** Convert an element under its output key: CommonMark for prose keys, source text otherwise. */
function convert(node: OrderedNode, key: string): string {
  return PROSE_FIELDS.has(key) ? orderedContentToMarkdown(contents(node)) : plainText(node);
}
function text(node: OrderedNode, name: string, key: string): string | undefined {
  const target = child(node, name);
  return target ? convert(target, key) : undefined;
}
function requiredText(node: OrderedNode, name: string, key: string): string {
  const value = text(node, name, key);
  if (value === undefined) malformed(`The MITRE catalog is missing required ${name} content.`);
  return value;
}
function optionalTexts(
  node: OrderedNode,
  fields: Readonly<Record<string, string>>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(fields).flatMap(([output, source]) => {
      const value = text(node, source, output);
      return value === undefined ? [] : [[output, value]];
    }),
  );
}
/** The search projection of a prose element: its source text, never serialized. */
function projection(node: OrderedNode, name: string): string | undefined {
  const target = child(node, name);
  return target ? projectText(renderProse(contents(target))) : undefined;
}
/**
 * Search projections of a record's alternate terms, required description, and optional extended
 * description. A term is stored as plain source text, so the stored term is its own projection.
 */
function searchText(
  node: OrderedNode,
  terms: readonly AlternateTerm[] | undefined,
  description: string,
  extended?: string,
): SearchText {
  const extendedDescription = extended === undefined ? undefined : projection(node, extended);
  return {
    ...(terms ? { alternateTerms: terms.map(({ term }) => term) } : {}),
    description:
      projection(node, description) ??
      malformed(`The MITRE catalog is missing required ${description} content.`),
    ...(extendedDescription === undefined ? {} : { extendedDescription }),
  };
}
/** A URL element's source text with whitespace collapsed, like every other plain field. */
function optionalUrl(
  node: OrderedNode,
  name: string,
  output: 'url' | 'link',
): Record<string, string> {
  const target = child(node, name);
  return target ? { [output]: plainText(target) } : {};
}
/** A view's XPath `Filter`, only trimmed so it is copied exactly. */
function optionalFilter(node: OrderedNode): { filterDefinition?: string } {
  const target = child(node, 'Filter');
  return target ? { filterDefinition: rawText(contents(target)).trim() } : {};
}
function optionalAttributes(
  node: OrderedNode,
  fields: Readonly<Record<string, string>>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(fields).flatMap(([output, source]) => {
      const value = attribute(node, source);
      return value === undefined ? [] : [[output, collapse(value)]];
    }),
  );
}
function texts(node: OrderedNode, name: string, key: string): string[] {
  return children(node, name).map((entry) => convert(entry, key));
}
function arrayField<T>(
  node: OrderedNode,
  container: string,
  name: string,
  output: string,
  map: (item: OrderedNode, index: number) => T,
): Record<string, T[]> {
  return child(node, container) ? { [output]: nested(node, container, name).map(map) } : {};
}
function textList(
  node: OrderedNode,
  container: string,
  name: string,
  output: string,
): Record<string, string[]> {
  return arrayField(node, container, name, output, (entry) => convert(entry, output));
}

function examples(node: OrderedNode): DemonstrativeExample[] {
  return nested(node, 'Demonstrative_Examples', 'Demonstrative_Example').map((example, index) => {
    const blocks: ExampleBlock[] = [];
    for (const element of contents(example)) {
      const key = tag(element);
      if (!key) {
        if (typeof element['#text'] === 'string' && element['#text'].trim()) {
          blocks.push({ kind: 'prose', text: orderedContentToMarkdown([element]) });
        }
        continue;
      }
      if (local(key) === 'Example_Code') {
        const nodes = contents(element);
        const wrappers = nodes.filter((item) => tag(item) !== undefined);
        const codeNodes = wrappers.length
          ? nodes.filter((item) => typeof item['#text'] !== 'string' || item['#text'].trim() !== '')
          : nodes;
        // Wrapper divs delimit source lines; only the final structural newline is removed.
        const code = rawText(codeNodes);
        blocks.push({
          kind: 'code',
          text: wrappers.length && code.endsWith('\n') ? code.slice(0, -1) : code,
          ...optionalAttributes(element, { language: 'Language', nature: 'Nature' }),
        });
      } else {
        blocks.push({ kind: 'prose', text: convert(element, 'text') });
      }
    }
    return { index, blocks };
  });
}

/** Recorded alternate terms in source order: the term as plain text, its explanation as prose. */
function alternateTerms(node: OrderedNode): Record<string, AlternateTerm[]> {
  return arrayField(node, 'Alternate_Terms', 'Alternate_Term', 'alternateTerms', (entry) => ({
    term: requiredText(entry, 'Term', 'term'),
    ...optionalTexts(entry, { description: 'Description' }),
  }));
}
/**
 * Recorded notes in source order: the source type label as plain text, the note as prose. Every
 * record family that carries `Notes` (CWE weaknesses, categories, and views; CAPEC records) shares it.
 */
function notes(node: OrderedNode): Record<string, CatalogNote[]> {
  return arrayField(node, 'Notes', 'Note', 'notes', (entry) => ({
    type: requiredAttribute(entry, 'Type'),
    text: convert(entry, 'text'),
  }));
}
/** Recorded ordinalities in source order: the value as plain text, its reason as prose. */
function ordinalities(node: OrderedNode): Record<string, WeaknessOrdinality[]> {
  return arrayField(
    node,
    'Weakness_Ordinalities',
    'Weakness_Ordinality',
    'ordinalities',
    (entry) => ({
      ordinality: requiredText(entry, 'Ordinality', 'ordinality'),
      ...optionalTexts(entry, { description: 'Description' }),
    }),
  );
}
function consequences(node: OrderedNode, container: string): Record<string, Consequence[]> {
  return arrayField(node, container, 'Consequence', 'consequences', (entry) => ({
    scopes: texts(entry, 'Scope', 'scopes'),
    impacts: texts(entry, 'Impact', 'impacts'),
    ...optionalTexts(entry, { likelihood: 'Likelihood', note: 'Note' }),
  }));
}
function taxonomies(node: OrderedNode): TaxonomyMapping[] {
  return nested(node, 'Taxonomy_Mappings', 'Taxonomy_Mapping').map((entry) => ({
    taxonomy: requiredAttribute(entry, 'Taxonomy_Name'),
    ...optionalTexts(entry, { id: 'Entry_ID', name: 'Entry_Name', fit: 'Mapping_Fit' }),
  }));
}
function externalReferences(root: OrderedNode): Map<string, CatalogReference> {
  const result = new Map<string, CatalogReference>();
  for (const entry of nested(root, 'External_References', 'External_Reference')) {
    const reference: CatalogReference = {
      id: requiredAttribute(entry, 'Reference_ID'),
      ...optionalTexts(entry, {
        title: 'Title',
        edition: 'Edition',
        publication: 'Publication',
        publicationYear: 'Publication_Year',
        publicationMonth: 'Publication_Month',
        publicationDay: 'Publication_Day',
        publisher: 'Publisher',
        urlDate: 'URL_Date',
      }),
      ...optionalUrl(entry, 'URL', 'url'),
      ...(children(entry, 'Author').length ? { authors: texts(entry, 'Author', 'authors') } : {}),
    };
    if (result.has(reference.id))
      malformed('The MITRE catalog contains duplicate external reference identifiers.');
    result.set(reference.id, reference);
  }
  return result;
}
function references(
  node: OrderedNode,
  external: ReadonlyMap<string, CatalogReference>,
): Record<string, CatalogReference[]> {
  return arrayField(node, 'References', 'Reference', 'references', (entry) => {
    const referenceId = requiredAttribute(entry, 'External_Reference_ID');
    const resolved = external.get(referenceId);
    return { id: referenceId, ...resolved, ...optionalAttributes(entry, { section: 'Section' }) };
  });
}
function members(node: OrderedNode, container: string): Member[] {
  return nested(node, container, 'Has_Member').map((entry) => ({
    id: id(entry, 'CWE', 'CWE_ID'),
    viewId: id(entry, 'CWE', 'View_ID'),
  }));
}
const PLATFORM_KINDS = new Map<string, NonNullable<Weakness['platforms']>[number]['kind']>([
  ['Language', 'language'],
  ['Technology', 'technology'],
  ['Operating_System', 'OS'],
  ['Architecture', 'architecture'],
]);
function normalizeWeakness(
  node: OrderedNode,
  type: Weakness['type'],
  external: ReadonlyMap<string, CatalogReference>,
): Weakness {
  const entryId = id(node, 'CWE');
  const mappingNotes = child(node, 'Mapping_Notes');
  const platforms = child(node, 'Applicable_Platforms');
  return {
    id: entryId,
    type,
    name: requiredAttribute(node, 'Name'),
    status: requiredAttribute(node, 'Status'),
    sourceUrl: `https://cwe.mitre.org/data/definitions/${entryId.slice(4)}.html`,
    description: requiredText(node, type === 'category' ? 'Summary' : 'Description', 'description'),
    ...optionalAttributes(node, { abstraction: 'Abstraction', structure: 'Structure' }),
    ...optionalTexts(node, {
      extendedDescription: 'Extended_Description',
      likelihoodOfExploit: 'Likelihood_Of_Exploit',
    }),
    ...ordinalities(node),
    ...textList(node, 'Background_Details', 'Background_Detail', 'backgroundDetails'),
    ...alternateTerms(node),
    ...arrayField(
      node,
      'Modes_Of_Introduction',
      'Introduction',
      'modesOfIntroduction',
      (entry) => ({
        phase: requiredText(entry, 'Phase', 'phase'),
        ...optionalTexts(entry, { note: 'Note' }),
      }),
    ),
    ...(mappingNotes
      ? {
          mappingNotes: {
            ...optionalTexts(mappingNotes, {
              usage: 'Usage',
              rationale: 'Rationale',
              comments: 'Comments',
            }),
            ...arrayField(mappingNotes, 'Reasons', 'Reason', 'reasons', (entry) =>
              requiredAttribute(entry, 'Type'),
            ),
          },
        }
      : {}),
    ...consequences(node, 'Common_Consequences'),
    ...arrayField(node, 'Potential_Mitigations', 'Mitigation', 'mitigations', (entry) => ({
      phases: texts(entry, 'Phase', 'phases'),
      description: requiredText(entry, 'Description', 'description'),
      ...optionalTexts(entry, {
        strategy: 'Strategy',
        effectiveness: 'Effectiveness',
        effectivenessNotes: 'Effectiveness_Notes',
      }),
    })),
    ...arrayField(node, 'Related_Weaknesses', 'Related_Weakness', 'relatedWeaknesses', (entry) => ({
      nature: requiredAttribute(entry, 'Nature'),
      id: id(entry, 'CWE', 'CWE_ID'),
      viewId: id(entry, 'CWE', 'View_ID'),
      ...optionalAttributes(entry, { ordinal: 'Ordinal' }),
    })),
    ...arrayField(
      node,
      'Related_Attack_Patterns',
      'Related_Attack_Pattern',
      'relatedAttackPatterns',
      (entry) => ({ id: id(entry, 'CAPEC', 'CAPEC_ID') }),
    ),
    ...(child(node, 'Relationships') ? { members: members(node, 'Relationships') } : {}),
    ...(child(node, 'Demonstrative_Examples') ? { examples: examples(node) } : {}),
    ...arrayField(node, 'Detection_Methods', 'Detection_Method', 'detectionMethods', (entry) => ({
      method: requiredText(entry, 'Method', 'method'),
      ...optionalTexts(entry, {
        description: 'Description',
        effectiveness: 'Effectiveness',
        effectivenessNotes: 'Effectiveness_Notes',
      }),
    })),
    ...arrayField(node, 'Observed_Examples', 'Observed_Example', 'observedExamples', (entry) => ({
      ...optionalTexts(entry, { reference: 'Reference', description: 'Description' }),
      ...optionalUrl(entry, 'Link', 'link'),
    })),
    ...(platforms
      ? {
          platforms: contents(platforms).flatMap((entry) => {
            const key = tag(entry);
            const kind = key ? PLATFORM_KINDS.get(local(key)) : undefined;
            return kind
              ? [
                  {
                    kind,
                    ...optionalAttributes(entry, {
                      name: 'Name',
                      class: 'Class',
                      prevalence: 'Prevalence',
                    }),
                  },
                ]
              : [];
          }),
        }
      : {}),
    ...textList(node, 'Functional_Areas', 'Functional_Area', 'functionalAreas'),
    ...textList(node, 'Affected_Resources', 'Affected_Resource', 'affectedResources'),
    ...(child(node, 'Taxonomy_Mappings') ? { taxonomyMappings: taxonomies(node) } : {}),
    ...references(node, external),
    ...notes(node),
  };
}

/** A filter-defined (Implicit) view carries its XPath `Filter` directly under `View`, not `Members`. */
function normalizeView(node: OrderedNode): CatalogView {
  const entryId = id(node, 'CWE');
  return {
    id: entryId,
    name: requiredAttribute(node, 'Name'),
    type: requiredAttribute(node, 'Type'),
    status: requiredAttribute(node, 'Status'),
    sourceUrl: `https://cwe.mitre.org/data/definitions/${entryId.slice(4)}.html`,
    ...optionalTexts(node, { objective: 'Objective' }),
    ...arrayField(node, 'Audience', 'Stakeholder', 'audience', (entry) =>
      optionalTexts(entry, { type: 'Type', description: 'Description' }),
    ),
    members: members(node, 'Members'),
    ...optionalFilter(node),
    ...notes(node),
  };
}

function normalizeAttackPattern(
  node: OrderedNode,
  external: ReadonlyMap<string, CatalogReference>,
): AttackPattern {
  const entryId = id(node, 'CAPEC');
  const mappings = taxonomies(node);
  const attackIds = mappings.flatMap((mapping) => {
    if (mapping.taxonomy.toUpperCase() !== 'ATTACK' || !mapping.id) return [];
    const value = mapping.id.replace(/^T/i, '');
    if (!/^\d{4}(?:\.\d{3})?$/.test(value))
      malformed('The MITRE catalog contains an invalid ATTACK taxonomy identifier.');
    return [`T${value}`];
  });
  return {
    id: entryId,
    type: 'attack_pattern',
    name: requiredAttribute(node, 'Name'),
    status: requiredAttribute(node, 'Status'),
    abstraction: requiredAttribute(node, 'Abstraction'),
    sourceUrl: `https://capec.mitre.org/data/definitions/${entryId.slice(6)}.html`,
    description: requiredText(node, 'Description', 'description'),
    ...optionalTexts(node, {
      extendedDescription: 'Extended_Description',
      typicalSeverity: 'Typical_Severity',
      likelihoodOfAttack: 'Likelihood_Of_Attack',
    }),
    ...alternateTerms(node),
    ...textList(node, 'Prerequisites', 'Prerequisite', 'prerequisites'),
    ...arrayField(node, 'Execution_Flow', 'Attack_Step', 'executionFlow', (entry) => ({
      step: requiredText(entry, 'Step', 'step'),
      phase: requiredText(entry, 'Phase', 'phase'),
      description: requiredText(entry, 'Description', 'description'),
      ...(children(entry, 'Technique').length
        ? { techniques: texts(entry, 'Technique', 'techniques') }
        : {}),
      ...(children(entry, 'Indicator').length
        ? { indicators: texts(entry, 'Indicator', 'indicators') }
        : {}),
    })),
    ...textList(node, 'Indicators', 'Indicator', 'indicators'),
    ...arrayField(node, 'Skills_Required', 'Skill', 'skills', (entry) => ({
      description: convert(entry, 'description'),
      ...optionalAttributes(entry, { level: 'Level' }),
    })),
    ...textList(node, 'Resources_Required', 'Resource', 'resourcesRequired'),
    ...consequences(node, 'Consequences'),
    ...textList(node, 'Mitigations', 'Mitigation', 'mitigations'),
    ...textList(node, 'Example_Instances', 'Example', 'exampleInstances'),
    ...arrayField(
      node,
      'Related_Attack_Patterns',
      'Related_Attack_Pattern',
      'relatedAttackPatterns',
      (entry) => ({
        nature: requiredAttribute(entry, 'Nature'),
        id: id(entry, 'CAPEC', 'CAPEC_ID'),
      }),
    ),
    ...arrayField(node, 'Related_Weaknesses', 'Related_Weakness', 'relatedWeaknesses', (entry) => ({
      id: id(entry, 'CWE', 'CWE_ID'),
    })),
    ...(child(node, 'Taxonomy_Mappings')
      ? {
          taxonomyMappings: mappings,
          ...(attackIds.length ? { attackTechniqueIds: [...new Set(attackIds)] } : {}),
        }
      : {}),
    ...references(node, external),
    ...notes(node),
  };
}

/**
 * A CAPEC category (members under `Relationships`) or view (members under `Members`, or an XPath
 * `Filter` for a filter-defined view). CAPEC `Has_Member` records no view ID.
 */
function normalizeCapecGrouping(
  node: OrderedNode,
  type: CapecGrouping['type'],
  external: ReadonlyMap<string, CatalogReference>,
): CapecGrouping {
  const entryId = id(node, 'CAPEC');
  return {
    id: entryId,
    type,
    name: requiredAttribute(node, 'Name'),
    status: requiredAttribute(node, 'Status'),
    sourceUrl: `https://capec.mitre.org/data/definitions/${entryId.slice(6)}.html`,
    ...(type === 'category'
      ? { description: requiredText(node, 'Summary', 'description') }
      : optionalTexts(node, { description: 'Objective' })),
    ...arrayField(
      node,
      type === 'category' ? 'Relationships' : 'Members',
      'Has_Member',
      'members',
      (entry) => ({ id: id(entry, 'CAPEC', 'CAPEC_ID') }),
    ),
    ...optionalFilter(node),
    ...(child(node, 'Taxonomy_Mappings') ? { taxonomyMappings: taxonomies(node) } : {}),
    ...references(node, external),
    ...notes(node),
  };
}

function parseRoot(xml: string, name: string, namespace: string): OrderedNode {
  if (/^\s*<(?:!doctype\s+html|html[\s>])/i.test(xml)) {
    throw serviceUnavailable('MITRE returned HTML instead of a catalog.', {
      reason: 'upstream_html',
      retryable: true,
    });
  }
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml))
    malformed('XML declarations of document types or entities are not accepted.');
  let nodes: OrderedNode[];
  try {
    SyntaxValidator.validate(xml);
    nodes = new XMLParser({
      preserveOrder: true,
      ignoreAttributes: false,
      parseTagValue: false,
      parseAttributeValue: false,
      trimValues: false,
      processEntities: false,
      htmlEntities: false,
      cdataPropName: '#cdata',
      ignoreDeclaration: true,
      ignorePiTags: true,
      tagValueProcessor: (_name, value) => decodeReferences(value),
      attributeValueProcessor: (_name, value) => decodeReferences(value),
    }).parse(xml) as OrderedNode[];
  } catch (cause) {
    throw serializationError(
      'The MITRE catalog could not be parsed.',
      { reason: 'invalid_catalog', retryable: false },
      { cause },
    );
  }
  const roots = nodes.filter((node) => tag(node) !== undefined);
  const root = roots[0];
  if (roots.length !== 1 || !root || tag(root) !== name || attribute(root, 'xmlns') !== namespace)
    malformed('The MITRE catalog uses an unsupported root or schema namespace.');
  return root;
}
function insert<T extends { id: string }>(map: Map<string, T>, entry: T): void {
  if (map.has(entry.id)) malformed('The MITRE catalog contains duplicate entry identifiers.');
  map.set(entry.id, entry);
}

/** Parse and validate a complete CWE XML document without retaining its raw tree. */
export function parseCweCatalog(xml: string): CweCatalog {
  const root = parseRoot(xml, 'Weakness_Catalog', 'http://cwe.mitre.org/cwe-7');
  const external = externalReferences(root);
  const weaknesses = new Map<string, Weakness>();
  const views = new Map<string, CatalogView>();
  const weaknessNodes = nested(root, 'Weaknesses', 'Weakness');
  const categoryNodes = nested(root, 'Categories', 'Category');
  const viewNodes = nested(root, 'Views', 'View');
  if (!weaknessNodes.length || !categoryNodes.length || !viewNodes.length)
    malformed('The CWE catalog is missing an expected record family.');
  const searchTexts = new Map<string, SearchText>();
  for (const [nodes, type] of [
    [weaknessNodes, 'weakness'],
    [categoryNodes, 'category'],
  ] as const)
    for (const node of nodes) {
      const entry = normalizeWeakness(node, type, external);
      insert(weaknesses, entry);
      searchTexts.set(
        entry.id,
        searchText(
          node,
          entry.alternateTerms,
          type === 'category' ? 'Summary' : 'Description',
          'Extended_Description',
        ),
      );
    }
  for (const node of viewNodes) {
    const view = normalizeView(node);
    if (weaknesses.has(view.id))
      malformed('The CWE catalog reuses an identifier across record families.');
    insert(views, view);
  }
  return {
    version: requiredAttribute(root, 'Version'),
    date: requiredAttribute(root, 'Date'),
    weaknesses,
    views,
    searchText: searchTexts,
  };
}

/** Parse and validate a complete CAPEC XML document. */
export function parseCapecCatalog(xml: string): CapecCatalog {
  const root = parseRoot(xml, 'Attack_Pattern_Catalog', 'http://capec.mitre.org/capec-3');
  const external = externalReferences(root);
  const attackPatterns = new Map<string, AttackPattern>();
  const searchTexts = new Map<string, SearchText>();
  for (const node of nested(root, 'Attack_Patterns', 'Attack_Pattern')) {
    const entry = normalizeAttackPattern(node, external);
    insert(attackPatterns, entry);
    searchTexts.set(entry.id, searchText(node, entry.alternateTerms, 'Description'));
  }
  if (!attackPatterns.size) malformed('The CAPEC catalog contains no attack patterns.');
  const categories = new Map<string, CapecGrouping>();
  const views = new Map<string, CapecGrouping>();
  for (const [container, name, type, family] of [
    ['Categories', 'Category', 'category', categories],
    ['Views', 'View', 'view', views],
  ] as const)
    for (const node of nested(root, container, name)) {
      const entry = normalizeCapecGrouping(node, type, external);
      // One CAPEC ID names one record, whatever its family.
      if (attackPatterns.has(entry.id) || (family === views && categories.has(entry.id)))
        malformed('The CAPEC catalog reuses an identifier across record families.');
      insert(family, entry);
    }
  return {
    version: requiredAttribute(root, 'Version'),
    date: requiredAttribute(root, 'Date'),
    attackPatterns,
    categories,
    views,
    searchText: searchTexts,
  };
}
