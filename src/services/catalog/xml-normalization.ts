/**
 * @fileoverview Ordered, entity-safe XML normalization for the MITRE catalogs.
 * @module services/catalog/xml-normalization
 */
import { serializationError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { XMLParser } from 'fast-xml-parser';
import { SyntaxValidator } from 'fast-xml-validator';
import { escapeMarkdown, isWhitespace, Mark, PROSE_FIELDS } from './markdown-escape.js';
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

/** ASCII whitespace, which HTML folds; U+00A0 is text. */
const FOLDED_SPACE = /[ \t\n\r\f]+/;
const MARGIN_LEFT = /(?:^|;)\s*margin-left\s*:/i;
const CODE_INDENT = '    ';
/** An element being laid out: its remaining children and what closing it does. */
interface LayoutFrame {
  /** A block element ends the open line when it closes. */
  block: boolean;
  indent: boolean;
  /** `li` children numbered so far, in an `ol`. */
  items: number;
  list: 'ul' | 'ol' | undefined;
  next: number;
  nodes: readonly OrderedNode[];
}
/**
 * Example code laid out as a browser shows MITRE's markup, whose code renders with
 * `white-space: normal`. ASCII whitespace folds to one space and drops at a line's ends; `br` ends
 * a line; `div`, `p`, `table`, `ul`, `ol`, and `li` start and end one without adding a blank line; a
 * list item starts with `-` or its number; a table keeps its pipe-table lines; each enclosing `div`
 * whose style sets `margin-left` indents 4 spaces. Edge blank lines are dropped. Code holding CDATA
 * is the author's literal text and is returned verbatim. One pass with an explicit stack, so deep
 * nesting costs no call stack.
 */
export function exampleCodeText(nodes: readonly OrderedNode[]): string {
  const lines: string[] = [];
  let line = '';
  let lineDepth = 0;
  let space = false;
  let depth = 0;
  const endLine = (blank: boolean) => {
    if (line) lines.push(CODE_INDENT.repeat(lineDepth) + line);
    else if (blank) lines.push('');
    line = '';
    space = false;
  };
  const write = (value: string) => {
    for (const [index, word] of value.split(FOLDED_SPACE).entries()) {
      if (index) space = true;
      if (!word) continue;
      if (!line) lineDepth = depth;
      else if (space) line += ' ';
      line += word;
      space = false;
    }
  };
  const stack: LayoutFrame[] = [
    { nodes, next: 0, block: false, indent: false, list: undefined, items: 0 },
  ];
  const open = (node: OrderedNode, block: boolean, indent = false, list?: 'ul' | 'ol') => {
    if (block) endLine(false);
    if (indent) depth++;
    stack.push({ nodes: contents(node), next: 0, block, indent, list, items: 0 });
  };
  for (let frame = stack.at(-1); frame; frame = stack.at(-1)) {
    const node = frame.nodes[frame.next++];
    if (!node) {
      stack.pop();
      if (frame.block) endLine(false);
      if (frame.indent) depth--;
      continue;
    }
    if (typeof node['#text'] === 'string') {
      write(node['#text']);
      continue;
    }
    if (Array.isArray(node['#cdata'])) return rawText(nodes);
    const key = tag(node);
    const name = key && local(key);
    if (name === 'br') endLine(true);
    else if (name === 'div' || name === 'p')
      open(node, true, name === 'div' && MARGIN_LEFT.test(attribute(node, 'style') ?? ''));
    else if (name === 'ul' || name === 'ol') open(node, true, false, name);
    else if (name === 'li') {
      open(node, true);
      write(frame.list === 'ol' ? `${++frame.items}.` : '-');
      space = true;
    } else if (name === 'table') {
      endLine(false);
      for (const { cells, delimiter } of pipeTable(
        tableRows(node).map((row) => row.map((cell) => plainText(cell))),
        '',
      ))
        lines.push(
          CODE_INDENT.repeat(depth) +
            (delimiter ? `|${' --- |'.repeat(cells.length)}` : `| ${cells.join(' | ')} |`),
        );
    } else if (key) open(node, false);
  }
  endLine(false);
  const first = lines.findIndex(Boolean);
  if (first === -1) return '';
  let last = lines.length;
  while (!lines[last - 1]) last--;
  return lines.slice(first, last).join('\n');
}

/** A stretch of generated Markdown (mark 0) or of source text carrying escape-context marks. */
interface Run {
  /**
   * Set on the separators around a list, list item, preformatted block, or table, whose syntax works
   * only at the start of a line: a span that would trim one from its content's edge cannot hold it.
   */
  block?: true;
  mark: number;
  value: string;
}
/** Source text inside code: searchable, but literal, so never escaped or whitespace-folded. */
const CODE = 8;
/** Generated code-span padding, which a CommonMark parse strips, so the projection omits it. */
const PADDING = 16;
/**
 * A generated emphasis (`*`) or bold (`**`) delimiter. Whether it stays is decided against the
 * finished document (`resolveEmphasis`), so every one is marked with its kind.
 */
const EMPHASIS = 32;
const STRONG = 64;
/** A generated code-span fence, which `mergeCodeSpans` reads to find spans whose fences touch. */
const FENCE = 128;
const HARD_BREAK = '  \n';
const SPACE: Run = { mark: Mark.text, value: ' ' };
const syntax = (value: string): Run[] => [{ mark: 0, value }];
const blockSeparator = (value: string): Run[] => [{ mark: 0, value, block: true }];
const sourceText = (value: string, mark: number = Mark.text): Run[] => [{ mark, value }];
const isHardBreak = (run: Run): boolean => run.mark === 0 && run.value === HARD_BREAK;
/** Add a context bit to the source text in `runs`. */
function withContext(runs: readonly Run[], bit: number): Run[] {
  return runs.map((run) => (run.mark & Mark.text ? { ...run, mark: run.mark | bit } : run));
}
/**
 * Remove whitespace at both ends across run boundaries. `leading` and `trailing` are what each end
 * held, for a caller that keeps it outside its syntax: the end's hard breaks, otherwise one space
 * when it had any whitespace. `block` is set when a removed run was a line-start block separator.
 */
function trimRuns(runs: readonly Run[]): {
  runs: Run[];
  leading: Run[];
  trailing: Run[];
  block: boolean;
} {
  let first = 0;
  let last = runs.length - 1;
  const leadingBreaks: Run[] = [];
  const trailingBreaks: Run[] = [];
  let leading = false;
  let trailing = false;
  let block = false;
  for (; first <= last && !(runs[first] as Run).value.trim(); first++) {
    const run = runs[first] as Run;
    block ||= run.block === true;
    if (isHardBreak(run)) leadingBreaks.push(run);
    else leading ||= run.value !== '';
  }
  for (; last >= first && !(runs[last] as Run).value.trim(); last--) {
    const run = runs[last] as Run;
    block ||= run.block === true;
    if (isHardBreak(run)) trailingBreaks.push(run);
    else trailing ||= run.value !== '';
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
  const edge = (breaks: Run[], space: boolean) => (breaks.length ? breaks : space ? [SPACE] : []);
  return {
    runs: result,
    leading: edge(leadingBreaks, leading),
    trailing: edge(trailingBreaks.reverse(), trailing),
    block,
  };
}
const EDGE = /[\s\p{P}\p{S}]/u;
/**
 * Move source punctuation and whitespace at the content's edges outside an emphasis span, so its
 * delimiters open and close whatever source text surrounds the element. Generated syntax at an edge
 * stays inside; `resolveEmphasis` drops the delimiters where it leaves them unable to.
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
/**
 * Whether rendered content crosses a block boundary, where CommonMark never pairs delimiters: a line
 * break other than a hard break, or hard breaks with only whitespace between, which leave a blank line.
 */
function spansBlocks(runs: readonly Run[]): boolean {
  let blank = false;
  for (const run of runs) {
    if (isHardBreak(run)) {
      if (blank) return true;
      blank = true;
    } else if (run.value.includes('\n')) return true;
    else if (run.value.trim()) blank = false;
  }
  return false;
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
/**
 * A code span showing `code`. A parse strips one space from each end of code holding any other
 * character, so such code is padded with one; code of only spaces is shown as written and gets none.
 * Empty code has no span, since its two fences would touch and read as one backtick run.
 */
function codeSpan(code: string): Run[] {
  if (!code) return [];
  const fence: Run = { mark: FENCE, value: codeFence(code, 1) };
  const padding: Run[] = /[^ ]/.test(code) ? [{ mark: PADDING, value: ' ' }] : [];
  return [fence, ...padding, { mark: CODE, value: code }, ...padding, fence];
}

/** Inside a generated link label. */
const LABEL = 1;
/** Inside a pipe-table cell, which holds one line. */
const CELL = 2;
/** Each item's content between word boundaries, for a list or table inside a one-line cell. */
function inlineItems(items: readonly Run[][]): Run[] {
  return items.flatMap((item) => [SPACE, ...item, SPACE]);
}
/** `context` holds `LABEL` and `CELL`; `open` holds the emphasis kinds around the nodes. */
function renderNodes(nodes: readonly OrderedNode[], context = 0, open = 0): Run[] {
  return nodes.flatMap((node) => renderNode(node, context, open));
}
function renderNode(node: OrderedNode, context: number, open: number): Run[] {
  if (typeof node['#text'] === 'string') return sourceText(node['#text'].replace(/\s+/g, ' '));
  if (Array.isArray(node['#cdata']))
    return sourceText(rawText(node['#cdata'] as OrderedNode[]).replace(/\r\n?/g, '\n'));
  const key = tag(node);
  if (!key) return [];
  const name = local(key);
  const inner = () => renderNodes(contents(node), context, open);
  switch (name) {
    case 'br':
      return syntax(HARD_BREAK);
    case 'p':
    case 'div': {
      // A paragraph trims a line-start block at its edge, so its own separators take over the mark.
      const { runs, block } = trimRuns(inner());
      const separator = block ? blockSeparator('\n\n') : syntax('\n\n');
      return [...separator, ...runs, ...separator];
    }
    case 'ul':
    case 'ol': {
      const entries = children(node, 'li');
      // A list cannot sit on a cell's one line, so a cell keeps only its items' text.
      if (context & CELL)
        return inlineItems(entries.map((entry) => renderNodes(contents(entry), context, open)));
      const items = entries.map((entry, index) => {
        const marker = name === 'ol' ? `${index + 1}. ` : '- ';
        const body = trimRuns(renderNodes(contents(entry), context, open)).runs;
        return [...syntax(marker), ...indentRuns(body, ' '.repeat(marker.length))];
      });
      return [
        ...blockSeparator('\n\n'),
        ...items.flatMap((item, index) => (index ? [...syntax('\n'), ...item] : item)),
        ...blockSeparator('\n\n'),
      ];
    }
    case 'li':
      if (context & CELL) return inlineItems([inner()]);
      return [
        ...blockSeparator('\n'),
        ...syntax('- '),
        ...trimRuns(inner()).runs,
        ...blockSeparator('\n'),
      ];
    case 'a': {
      const href = attribute(node, 'href');
      if (!href) return inner();
      const link = /^https?:\/\//i.test(href) && URL.canParse(href);
      // CommonMark nests no link in another, and no link label crosses a block boundary or holds a
      // line-start block: such a link renders as its content alone, as if the anchor were absent.
      if (link && context & LABEL) return inner();
      const content = renderNodes(contents(node), link ? context | LABEL : context, open);
      const { runs: text, leading, trailing, block } = trimRuns(content);
      if (link && (block || spansBlocks(text))) return inner();
      if (!link) {
        // An inert link's address follows its content, keeping any line-start block at its edge.
        const address = [...syntax(' ('), ...sourceText(href), ...syntax(')')];
        return block ? [...content, ...address] : [...leading, ...text, ...address, ...trailing];
      }
      return [
        ...leading,
        ...syntax('['),
        ...withContext(text, Mark.linkText),
        ...syntax(`](<${destination(href)}>)`),
        ...trailing,
      ];
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
      const kind = name === 'b' || name === 'strong' ? STRONG : EMPHASIS;
      // A span inside one of its own kind adds no delimiters.
      if (open & kind) return inner();
      const delimiter: Run = { mark: kind, value: kind === STRONG ? '**' : '*' };
      const content = renderNodes(contents(node), context, open | kind);
      const { runs, leading, trailing, block } = trimRuns(content);
      // Delimiters around a line-start block at the content's edge would pull it off its line.
      if (block) return content;
      // Edge whitespace and breaks stay outside the delimiters.
      const { before, body, after } = peelEdges(runs);
      const paired = body.length > 0 && !spansBlocks(body);
      return [
        ...leading,
        ...before,
        ...(paired ? [delimiter, ...body, delimiter] : body),
        ...after,
        ...trailing,
      ];
    }
    case 'sup':
      return [...syntax('^'), ...inner()];
    case 'code': {
      // A code span shows each line ending as a space; a blank line would end the span early.
      const code = rawText(contents(node)).replace(/\r\n?|\n/g, ' ');
      // A link reference definition's label is read without code spans, so code in a generated
      // label is label text, escaped like the rest of it.
      if (context & LABEL) return sourceText(code.replace(/\s+/g, ' '));
      return codeSpan(code);
    }
    case 'pre': {
      const code = rawText(contents(node));
      // A preformatted block cannot sit on a cell's one line, so a cell shows it as a code span.
      if (context & CELL) return inlineItems([codeSpan(code.replace(/\r\n?|\n/g, ' '))]);
      const fence = codeFence(code, 3);
      return [
        ...blockSeparator('\n\n'),
        ...syntax(`${fence}\n`),
        { mark: CODE, value: code },
        ...syntax(`\n${fence}`),
        ...blockSeparator('\n\n'),
      ];
    }
    case 'table': {
      const rows = tableRows(node).map((row) =>
        row.map((cell) =>
          withContext(
            trimRuns(oneLine(renderNodes(contents(cell), context | CELL, open))).runs,
            Mark.tableCell,
          ),
        ),
      );
      // A table cannot sit on a cell's one line, so a cell keeps only its cells' text.
      if (context & CELL) return inlineItems(rows.flat());
      return [
        ...blockSeparator('\n\n'),
        ...pipeTable(rows, []).flatMap(({ cells, delimiter }) =>
          delimiter
            ? syntax(`|${' --- |'.repeat(cells.length)}\n`)
            : [
                ...syntax('|'),
                ...cells.flatMap((cell) => [...syntax(' '), ...cell, ...syntax(' |')]),
                ...syntax('\n'),
              ],
        ),
        ...blockSeparator('\n'),
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

const PUNCTUATION = /^[\p{P}\p{S}]/u;
/**
 * CommonMark's class of the character beside a delimiter run, `undefined` where parsers disagree:
 * U+000B, U+2028, U+2029, and U+FEFF, which commonmark.js reads as whitespace (`\s`) and the spec
 * does not, and astral punctuation such as an emoji, of which commonmark.js reads only the adjacent
 * surrogate. A document edge is whitespace.
 */
function delimiterNeighbour(
  text: string,
  index: number,
  before: boolean,
): 'space' | 'punctuation' | 'other' | undefined {
  if (index < 0 || index >= text.length) return 'space';
  const code = text.charCodeAt(index);
  if (code === 0x0b || code === 0x2028 || code === 0x2029 || code === 0xfeff) return undefined;
  const astral = before ? code >= 0xdc00 && code <= 0xdfff : code >= 0xd800 && code <= 0xdbff;
  const character = astral
    ? before
      ? text.slice(index - 1, index + 1)
      : text.slice(index, index + 2)
    : (text[index] as string);
  if (isWhitespace(character)) return 'space';
  if (!PUNCTUATION.test(character)) return 'other';
  return astral ? undefined : 'punctuation';
}
/** An unmatched delimiter run on CommonMark's emphasis stack. */
interface OpenRun {
  closes: boolean;
  /** Delimiters in the whole run, which CommonMark's rule of 3 reads. */
  length: number;
  remaining: number;
}
/**
 * Run CommonMark's emphasis matching for one delimiter run of `closing` closer delimiters followed
 * by `opening` opener delimiters against `stack`, the runs still open before it. True, with `stack`
 * updated, when the closers match exactly the innermost open delimiters and the openers stay open.
 */
function matchRun(
  stack: OpenRun[],
  closing: number,
  opening: number,
  opens: boolean,
  closes: boolean,
): boolean {
  const length = closing + opening;
  let remaining = length;
  while (closes && remaining > 0) {
    let index = stack.length - 1;
    // The rule of 3: a run that can both open and close never pairs to a total length divisible by
    // 3, unless both lengths are.
    while (
      index >= 0 &&
      (opens || (stack[index] as OpenRun).closes) &&
      length % 3 !== 0 &&
      ((stack[index] as OpenRun).length + length) % 3 === 0
    )
      index--;
    if (index < 0) break;
    const run = stack[index] as OpenRun;
    const used = remaining >= 2 && run.remaining >= 2 ? 2 : 1;
    // Pairing past the innermost open run, or past this run's closers, is not the source's nesting.
    if (index !== stack.length - 1 || length - remaining + used > closing) return false;
    run.remaining -= used;
    remaining -= used;
    if (!run.remaining) stack.pop();
  }
  if (length - remaining !== closing) return false;
  if (opening) stack.push({ length, remaining: opening, closes });
  return true;
}
/**
 * Keep only the emphasis and bold delimiters a CommonMark parse pairs as the source nests them,
 * dropping both delimiters of every other span and keeping its text.
 *
 * Adjacent delimiters form one run, and the characters around a run are never delimiters, so whether
 * it can open or close is fixed: a pair stays only when its opener's run can open and its closer's
 * run can close. Runs are then matched left to right as CommonMark does. A closer directly followed
 * by an opener of the same kind merges the two spans, and a run keeps the most of its openers that
 * still match as nested. A run left holding openers must have a length every later run of only their
 * closers can match under the rule of 3, so a run of only closers always matches and no decision is
 * revisited. At most one span of each kind is open at a time, so the stack holds at most two runs:
 * linear in the document.
 */
function resolveEmphasis(document: MarkedDocument): MarkedDocument {
  const { text, marks } = document;
  const starts: number[] = [];
  for (let index = 0; index < text.length; index++) {
    const kind = (marks[index] as number) & (EMPHASIS | STRONG);
    if (!kind) continue;
    starts.push(index);
    if (kind === STRONG) index++;
  }
  if (!starts.length) return document;
  const count = starts.length;
  const kindOf = (token: number) =>
    (marks[starts[token] as number] as number) & (EMPHASIS | STRONG);
  const size = (token: number) => (kindOf(token) === STRONG ? 2 : 1);
  // Spans of one kind never nest, so each kind's delimiters alternate opener, closer.
  const partner = new Int32Array(count);
  const opener = new Uint8Array(count);
  const open = new Map<number, number>();
  for (let token = 0; token < count; token++) {
    const start = open.get(kindOf(token));
    if (start === undefined) {
      opener[token] = 1;
      open.set(kindOf(token), token);
    } else {
      partner[token] = start;
      partner[start] = token;
      open.delete(kindOf(token));
    }
  }
  // Runs: maximal stretches of adjacent delimiters, each with the CommonMark flanking of its ends.
  const runStarts: number[] = [];
  const opens: boolean[] = [];
  const closes: boolean[] = [];
  const runOf = new Int32Array(count);
  for (let token = 0; token < count; token++) {
    const start = starts[token] as number;
    if (token && (starts[token - 1] as number) + size(token - 1) === start) {
      runOf[token] = runStarts.length - 1;
      continue;
    }
    let end = token;
    while (end + 1 < count && (starts[end] as number) + size(end) === starts[end + 1]) end++;
    const before = delimiterNeighbour(text, start - 1, true);
    const after = delimiterNeighbour(text, (starts[end] as number) + size(end), false);
    const known = before !== undefined && after !== undefined;
    runOf[token] = runStarts.length;
    runStarts.push(token);
    opens.push(known && after !== 'space' && (after !== 'punctuation' || before !== 'other'));
    closes.push(known && before !== 'space' && (before !== 'punctuation' || after !== 'other'));
  }
  const alive = new Uint8Array(count);
  for (let token = 0; token < count; token++)
    if (
      opener[token] &&
      opens[runOf[token] as number] &&
      closes[runOf[partner[token] as number] as number]
    )
      alive[token] = alive[partner[token] as number] = 1;
  const drop = (token: number) => {
    alive[token] = alive[partner[token] as number] = 0;
  };
  let stack: OpenRun[] = [];
  for (let run = 0; run < runStarts.length; run++) {
    const first = runStarts[run] as number;
    const end = run + 1 < runStarts.length ? (runStarts[run + 1] as number) : count;
    const closers: number[] = [];
    const openers: number[] = [];
    // Within a run every closer precedes every opener, and no kind opens twice.
    for (let token = first; token < end; token++)
      if (alive[token]) (opener[token] ? openers : closers).push(token);
    // Keep all openers, else the outer, else the inner, else none.
    const choices = openers.length === 2 ? [3, 1, 2, 0] : openers.length === 1 ? [1, 0] : [0];
    for (const choice of choices) {
      const kept = openers.filter((_, index) => choice & (1 << index));
      const tokens: number[] = [];
      const merged: number[] = [];
      for (const token of [...closers, ...kept]) {
        const previous = tokens.at(-1);
        if (
          opener[token] &&
          previous !== undefined &&
          !opener[previous] &&
          kindOf(previous) === kindOf(token)
        ) {
          tokens.pop();
          merged.push(previous, token);
        } else tokens.push(token);
      }
      let closing = 0;
      let opening = 0;
      let kinds = 0;
      for (const token of tokens) {
        if (opener[token]) {
          opening += size(token);
          kinds |= kindOf(token);
        } else closing += size(token);
      }
      const length = closing + opening;
      // A later run of only closers has length 1 (emphasis), 2 (bold), or 3 (both), and pairs with
      // this run under the rule of 3 only when the two lengths do not sum to a multiple of 3.
      const safe =
        kinds === 0 ||
        (kinds === EMPHASIS
          ? length % 3 !== 2
          : kinds === STRONG
            ? length % 3 !== 1
            : length % 3 === 0);
      const trial = stack.map((open) => ({ ...open }));
      if (
        !safe ||
        !matchRun(trial, closing, opening, opens[run] as boolean, closes[run] as boolean)
      )
        continue;
      stack = trial;
      for (const token of openers) if (!kept.includes(token)) drop(token);
      for (const token of merged) alive[token] = 0;
      break;
    }
  }
  let removed = 0;
  for (let token = 0; token < count; token++) if (!alive[token]) removed += size(token);
  if (!removed) return document;
  const keptMarks = new Uint8Array(text.length - removed);
  const parts: string[] = [];
  let copied = 0;
  let written = 0;
  for (let token = 0; token <= count; token++) {
    if (token < count && alive[token]) continue;
    const end = token < count ? (starts[token] as number) : text.length;
    keptMarks.set(marks.subarray(copied, end), written);
    parts.push(text.slice(copied, end));
    written += end - copied;
    if (token < count) copied = end + size(token);
  }
  return { text: parts.join(''), marks: keptMarks };
}
/**
 * Join code spans whose fences touch into one span showing each code in order, with a fence sized
 * for the joined code. CommonMark reads touching backtick runs as one run, so adjacent spans cannot
 * be written apart; they merge as adjacent emphasis spans of one kind do. Spans can touch only once
 * `resolveEmphasis` has dropped the delimiters between them, so this runs after it. Linear: every
 * fence and code character is read once.
 */
function mergeCodeSpans(document: MarkedDocument): MarkedDocument {
  const { text, marks } = document;
  const isFence = (index: number) => ((marks[index] ?? 0) & FENCE) !== 0;
  const texts: string[] = [];
  const markParts: Uint8Array[] = [];
  let copied = 0;
  for (let index = 0; index < text.length; ) {
    if (!isFence(index)) {
      index++;
      continue;
    }
    // A fence met here opens a span. Every span holds code, so its closing fence ends the next fence
    // stretch, and whatever of that stretch remains is the opening fence of a span it touches.
    const start = index;
    let fence = 0;
    while (isFence(index + fence)) fence++;
    let code = '';
    let spans = 0;
    for (;;) {
      index += fence;
      let end = index;
      while (!isFence(end)) end++;
      code += text.slice(
        (marks[index] as number) & PADDING ? index + 1 : index,
        (marks[end - 1] as number) & PADDING ? end - 1 : end,
      );
      spans++;
      let stretch = 0;
      while (isFence(end + stretch)) stretch++;
      index = end + fence;
      if (stretch === fence) break;
      fence = stretch - fence;
    }
    if (spans === 1) continue;
    const span = codeSpan(code);
    texts.push(text.slice(copied, start), ...span.map((run) => run.value));
    markParts.push(
      marks.subarray(copied, start),
      ...span.map((run) => new Uint8Array(run.value.length).fill(run.mark)),
    );
    copied = index;
  }
  if (!copied) return document;
  texts.push(text.slice(copied));
  markParts.push(marks.subarray(copied));
  const merged = new Uint8Array(markParts.reduce((total, part) => total + part.length, 0));
  let written = 0;
  for (const part of markParts) {
    merged.set(part, written);
    written += part.length;
  }
  return { text: texts.join(''), marks: merged };
}
function renderProse(nodes: readonly OrderedNode[]): MarkedDocument {
  return mergeCodeSpans(resolveEmphasis(flatten(renderNodes(nodes))));
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

/**
 * Demonstrative examples with their prose and code blocks in source order. The schema places an
 * example's `References` last, so its citations sit beside the blocks without losing order.
 */
function examples(
  node: OrderedNode,
  external: ReadonlyMap<string, CatalogReference>,
): DemonstrativeExample[] {
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
      if (local(key) === 'References') continue;
      if (local(key) === 'Example_Code') {
        blocks.push({
          kind: 'code',
          text: exampleCodeText(contents(element)),
          ...optionalAttributes(element, { language: 'Language', nature: 'Nature' }),
        });
      } else {
        blocks.push({ kind: 'prose', text: convert(element, 'text') });
      }
    }
    return { index, blocks, ...references(example, external) };
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
    ...(child(node, 'Demonstrative_Examples') ? { examples: examples(node, external) } : {}),
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
