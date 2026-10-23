/**
 * @fileoverview Shared catalog input, paging, and complete Markdown rendering contracts.
 * @module mcp-server/tools/shared
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { z } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { collapse, escapeMarkdown, Mark, PROSE_FIELDS, type Provenance } from '@/services/index.js';

/** Described source string. */
export const text = (description: string) => z.string().describe(description);
/** Described array whose element schema also carries its meaning. */
export const list = <T extends z.ZodType>(item: T, description: string) =>
  z.array(item).describe(description);
/** Accept unambiguous case and whitespace variants of a finite input vocabulary. */
export const inputEnum = <const T extends readonly [string, ...string[]]>(values: T) =>
  z.preprocess(
    (value) =>
      typeof value === 'string'
        ? (values.find((candidate) => candidate.toLowerCase() === value.trim().toLowerCase()) ??
          value)
        : value,
    z.enum(values),
  );
/** Optional vocabulary inputs treat a blank form field as omitted. */
export const optionalInputEnum = <const T extends readonly [string, ...string[]]>(values: T) =>
  z.preprocess(
    (value) => (typeof value === 'string' && !value.trim() ? undefined : value),
    inputEnum(values).optional(),
  );
/** Source metadata used throughout one captured snapshot. */
export const provenanceSchema = z
  .object({
    cweVersion: text('CWE catalog version.'),
    cweDate: text('CWE publication date.'),
    capecVersion: text('CAPEC catalog version.'),
    capecDate: text('CAPEC publication date.'),
    loadedAt: text('Combined snapshot load time.'),
  })
  .describe('Loaded catalog provenance.');
/** Local page metadata; totals precede slicing. */
export const paginationSchema = z
  .object({
    total: z.number().int().describe('Matching items before paging.'),
    shown: z.number().int().describe('Items on this page.'),
    hasMore: z.boolean().describe('Whether a continuation exists.'),
    nextCursor: text('Opaque continuation for the same normalized query.').optional(),
  })
  .describe('Local result pagination.');
/** Shared public list controls. */
export const pagingShape = {
  limit: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .default(20)
    .describe(
      'Maximum page size; capped at 100 and a 24,000-byte response budget with disclosure.',
    ),
  cursor: text('Opaque continuation returned by this tool.').optional(),
};
/**
 * Catalog ID grammar, shared by the advertised JSON Schema `pattern` and the handlers: surrounding
 * whitespace, a case-insensitive prefix followed by `-`, `_`, whitespace, or nothing, then a positive
 * integer whose leading zeros drop. Case is spelled with character classes, since Zod drops a
 * regex's flags from the emitted `pattern`. Any whitespace run may separate prefix and number, so an
 * `ids` item and its whitespace-collapsed echo always parse alike.
 */
export const CWE_ID = /^\s*(?:[Cc][Ww][Ee](?:[-_]|\s+)?)?0*([1-9]\d*)\s*$/;
/** A CWE ID, or blank for unset. */
export const OPTIONAL_CWE_ID = /^\s*(?:(?:[Cc][Ww][Ee](?:[-_]|\s+)?)?0*([1-9]\d*)\s*)?$/;
/** A CWE view ID or `all`, or blank for the default view. */
export const VIEW_ID = /^\s*(?:(?:(?:[Cc][Ww][Ee](?:[-_]|\s+)?)?0*([1-9]\d*)|([Aa][Ll][Ll]))\s*)?$/;
/** A CAPEC ID. */
export const CAPEC_ID = /^\s*(?:[Cc][Aa][Pp][Ee][Cc](?:[-_]|\s+)?)?0*([1-9]\d*)\s*$/;
/** An ATT&CK technique or subtechnique, with or without its `T`, or blank for unset. */
export const OPTIONAL_ATTACK_ID = /^\s*(?:[Tt]?(\d{4}(?:\.\d{3})?)\s*)?$/;
/**
 * A CVE ID in any case, or blank for unset. Linear: each whitespace run is bounded by an anchor or
 * the literal prefix, and the digit runs by literals, an anchor, or whitespace they cannot overlap.
 */
export const OPTIONAL_CVE_ID = /^\s*(?:[Cc][Vv][Ee]-\d{4}-\d{4,}\s*)?$/;
/** Accepted forms, named wherever a single-ID input is rejected. */
export const CWE_ID_FORMS =
  'Use a CWE ID: a positive integer, optionally after CWE and a -, _, or space, such as CWE-79, CWE79, or 79.';
export const VIEW_ID_FORMS =
  'Use a CWE view ID: a positive integer, optionally after CWE and a -, _, or space, such as CWE-1000 or 1000.';
export const ATTACK_ID_FORMS =
  'Use an ATT&CK technique ID: Tdddd or Tdddd.ddd, with or without the T, such as T1059 or T1059.001.';
export const CVE_ID_FORMS =
  'Use a CVE ID: CVE, a hyphen, a four-digit year, a hyphen, and a sequence of four or more digits, in any case, such as CVE-2021-44228.';

/** Catalog ID family. */
export type Family = 'CWE' | 'CAPEC';
const ID_PATTERN: Record<Family, RegExp> = { CWE: CWE_ID, CAPEC: CAPEC_ID };
/** The canonical `CWE-N` or `CAPEC-N` form of an ID, or undefined when the text is no such ID. */
export function parseId(value: string, family: Family): string | undefined {
  const digits = ID_PATTERN[family].exec(value)?.[1];
  return digits && `${family}-${digits}`;
}
/** Normalize a syntactically valid CWE ID without assuming membership. */
export function normalizeId(value: string): string {
  const id = parseId(value, 'CWE');
  if (!id) throw validationError(CWE_ID_FORMS, { retryable: false });
  return id;
}
/** Normalize an ATT&CK parent or subtechnique ID. */
export function normalizeAttackId(value: string): string {
  const digits = OPTIONAL_ATTACK_ID.exec(value)?.[1];
  if (!digits) throw validationError(ATTACK_ID_FORMS, { retryable: false });
  return `T${digits}`;
}
/** One distinct `ids` item: a canonical ID, or the collapsed item text when it is no catalog ID. */
export interface IdPosition {
  /** The family the item names; absent when it names neither. */
  family?: Family;
  id: string;
}
/**
 * Classify each submitted item once, in submitted order: an ID of the tool's family first, the other
 * family only with its explicit prefix (a bare integer is always the tool's own), otherwise the
 * collapsed text. Distinct positions beyond the first 20 are deferred whole.
 */
export function batchIds(values: readonly string[], family: Family) {
  const other: Family = family === 'CWE' ? 'CAPEC' : 'CWE';
  const positions = new Map<string, IdPosition>();
  for (const value of values) {
    const own = parseId(value, family);
    const foreign = own ? undefined : parseId(value, other);
    const position: IdPosition = own
      ? { id: own, family }
      : foreign
        ? { id: foreign, family: other }
        : { id: collapse(value) };
    if (!positions.has(position.id)) positions.set(position.id, position);
  }
  const all = [...positions.values()];
  return { ids: all.slice(0, 20), deferredIds: all.slice(20).map((position) => position.id) };
}
/** Longest echoed `ids` item that is not a catalog ID. */
const MAX_INVALID_ITEM = 150;
/**
 * Submitted IDs, without a per-item pattern so a malformed item is answered per item rather than
 * failing the batch. Two item shapes still reject the call: a control character, since no ID holds
 * one and `content[]` cannot carry U+0000, and text over the bound that is no ID of either family,
 * since that text is echoed back.
 */
export const idsSchema = (family: Family) =>
  list(
    text(
      `A ${family} ID such as ${family}-${family === 'CWE' ? '79' : '66'} or a positive bare integer. An item that is no ${family} ID is reported per item; an item holding a control character other than whitespace, or over ${MAX_INVALID_ITEM} characters and no CWE or CAPEC ID, rejects the call.`,
    )
      .refine(
        (value) => !holdsControl(value),
        'Remove control characters U+0000–U+0008 and U+000E–U+001F: no catalog ID contains them.',
      )
      .refine(
        (value) =>
          value.trim().length <= MAX_INVALID_ITEM ||
          parseId(value, 'CWE') !== undefined ||
          parseId(value, 'CAPEC') !== undefined,
        `An item that is not a catalog ID can be at most ${MAX_INVALID_ITEM} characters.`,
      ),
    'One to 200 submitted IDs; up to 20 distinct items are processed within the response budget.',
  )
    .min(1)
    .max(200);
/** Whitespace-only optional text is unset at the handler boundary. */
export function optionalText(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
}
/**
 * Whether text holds a C0 control other than whitespace (U+0000–U+0008, U+000E–U+001F). XML 1.0
 * text never contains one, and CommonMark shows U+0000 as U+FFFD.
 */
function holdsControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x09 || (code > 0x0d && code < 0x20)) return true;
  }
  return false;
}
/**
 * Optional all-token text filter, echoed in `appliedFilters` once `normalizeFilter` folds it. A
 * control character that catalog text cannot contain is rejected, since no match could exist.
 */
export const filterSchema = (description: string) =>
  text(description)
    .max(500)
    .refine(
      (value) => !holdsControl(value),
      'Remove control characters U+0000–U+0008 and U+000E–U+001F: catalog text never contains them, so this filter could never match.',
    )
    .optional();
/** Case-fold a filter and collapse its whitespace, so echoes and cursors bind one spelling. */
export function normalizeFilter(value: string | undefined): string | undefined {
  return optionalText(value)?.toLowerCase().split(/\s+/).join(' ');
}
/** A normalized text filter as a zero-hit notice names it, quoted and escaped as literal text. */
export function filterPhrase(filter: string, label = 'the text filter'): string {
  return `${filter.includes(' ') ? 'every token of ' : ''}${label} "${escapeMarkdown(filter)}"`;
}
/**
 * The terms change that can make a zero-hit text search return records. Fewer terms only when the
 * filter holds several tokens and one matches on its own (`matchesAlone`, called only then): fewer
 * terms of a one-token filter is a browse, and tokens that each match nothing have no matching subset.
 */
export function termsRepeat(filter: string, matchesAlone: () => boolean): string {
  if (!filter.includes(' ')) return 'a different term';
  return matchesAlone() ? 'fewer terms' : 'different terms';
}

const cursorKey = randomBytes(32);
function fingerprint(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
function sign(value: string): string {
  return createHmac('sha256', cursorKey).update(value).digest('base64url');
}
/** Page a complete ordered result and reject tampered, changed, or stale continuations. */
export function pageItems<T>(
  items: readonly T[],
  input: { limit: number; cursor?: string | undefined },
  binding: unknown,
  provenance: Provenance,
  measure?: (page: CatalogPage<T>) => number,
) {
  const query = fingerprint([binding, provenance]);
  let offset = 0;
  if (input.cursor && optionalText(input.cursor)) {
    const parts = input.cursor.split('.');
    const [body, signature] = parts;
    if (parts.length !== 2 || !body || !signature || signature !== sign(body))
      throw validationError('The cursor is invalid; repeat this tool without cursor.', {
        reason: 'invalid_cursor',
        retryable: false,
      });
    try {
      const decoded: unknown = JSON.parse(Buffer.from(body, 'base64url').toString());
      if (
        !decoded ||
        typeof decoded !== 'object' ||
        !('query' in decoded) ||
        decoded.query !== query ||
        !('offset' in decoded) ||
        typeof decoded.offset !== 'number' ||
        !Number.isSafeInteger(decoded.offset) ||
        decoded.offset < 0 ||
        decoded.offset > items.length
      )
        throw new Error('Invalid cursor');
      offset = decoded.offset;
    } catch {
      throw validationError(
        'The cursor does not match this query or catalog; repeat this tool without cursor.',
        { reason: 'invalid_cursor', retryable: false },
      );
    }
  }
  const limit = Math.min(input.limit, 100);
  const maximum = Math.min(limit, Math.max(0, items.length - offset));
  const build = (count: number, oversized: boolean): CatalogPage<T> => {
    const result = items.slice(offset, offset + count);
    const next = offset + result.length;
    const body = Buffer.from(JSON.stringify({ query, offset: next })).toString('base64url');
    const notice = [
      input.limit > 100 &&
        'The requested limit was capped at 100 items; follow nextCursor for the remainder.',
      count < maximum &&
        'The 24,000-byte response budget reduced this page; follow nextCursor for the remainder.',
      oversized &&
        'One complete item and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.',
    ]
      .filter(Boolean)
      .join(' ');
    return {
      items: result,
      pagination: {
        total: items.length,
        shown: result.length,
        hasMore: next < items.length,
        ...(next < items.length ? { nextCursor: `${body}.${sign(body)}` } : {}),
      },
      ...(notice ? { notice } : {}),
    };
  };
  return selectWithinBudget(maximum, build, measure);
}

/** Whole ordered page and its lossless continuation. */
interface CatalogPage<T> {
  items: T[];
  notice?: string;
  pagination: { total: number; shown: number; hasMore: boolean; nextCursor?: string };
}

/** Target for the serialized MCP result, excluding its JSON-RPC framing. */
export const RESPONSE_BUDGET = 24_000;

/**
 * Select the largest whole prefix within the budget; an indivisible first item always makes
 * forward progress. Below the complete result, every candidate carries the same cut disclosure and
 * grows with its count, so a binary search finds the same prefix as a walk down from `maximum`.
 * When no prefix fits, one final `build(1, true)` returns the first item with its oversize
 * disclosure, so a call builds at most `ceil(log2(maximum)) + 2` times.
 */
export function selectWithinBudget<T>(
  maximum: number,
  build: (count: number, oversized: boolean) => T,
  measure: ((result: T) => number) | undefined,
): T {
  const fits = (result: T) => !measure || measure(result) <= RESPONSE_BUDGET;
  const complete = build(maximum, false);
  if (fits(complete)) return complete;
  let fitting: T | undefined;
  let low = Math.min(1, maximum);
  let high = maximum - 1;
  while (low <= high) {
    const count = Math.ceil((low + high) / 2);
    const result = build(count, false);
    if (fits(result)) {
      fitting = result;
      low = count + 1;
    } else high = count - 1;
  }
  return fitting ?? build(Math.min(1, maximum), true);
}

/** Enrichment shared by all paged tools, measured before it reaches either surface. */
function pageEnrichment<T, F>(
  page: CatalogPage<T>,
  limit: number,
  appliedFilters: F,
  notice?: string,
) {
  const disclosure = [page.notice, notice].filter(Boolean).join(' ');
  return {
    totalCount: page.pagination.total,
    appliedFilters,
    ...(page.pagination.hasMore
      ? { truncated: true, shown: page.items.length, cap: Math.min(limit, 100) }
      : {}),
    ...(disclosure ? { notice: disclosure } : {}),
  };
}

/**
 * Page whole items within the response budget. The returned output and enrichment are
 * the ones measured; the effective limit joins the cursor binding and applied filters.
 */
export function pageResponse<T, O extends Record<string, unknown>, F extends object>(
  items: readonly T[],
  input: { limit: number; cursor?: string | undefined },
  options: {
    appliedFilters: F;
    binding: readonly unknown[];
    notice?: string | undefined;
    output: (page: CatalogPage<T>) => O;
    provenance: Provenance;
  },
) {
  const limit = Math.min(input.limit, 100);
  const enrichment = (page: CatalogPage<T>) =>
    pageEnrichment(page, input.limit, { ...options.appliedFilters, limit }, options.notice);
  const page = pageItems(
    items,
    input,
    [...options.binding, limit],
    options.provenance,
    (candidate) => deliveredSize(options.output(candidate), enrichment(candidate)),
  );
  return { output: options.output(page), enrichment: enrichment(page) };
}

const sentences = new Intl.Segmenter('en', { granularity: 'sentence' });
/** CommonMark's Unicode whitespace and punctuation, which decide emphasis flanking. */
const WHITESPACE = /[\p{Zs}\t\n\f\r]/u;
const PUNCTUATION = /[\p{P}\p{S}]/u;
const ASCII_PUNCTUATION = /[!-/:-@[-`{-~]/;

/** Whether the `*` or `_` run at `[start, end)` can open or close emphasis (CommonMark flanking). */
function emphasisRole(description: string, start: number, end: number) {
  const before = description[start - 1];
  const after = description[end];
  const spaceBefore = before === undefined || WHITESPACE.test(before);
  const spaceAfter = after === undefined || WHITESPACE.test(after);
  const punctuationBefore = before !== undefined && PUNCTUATION.test(before);
  const punctuationAfter = after !== undefined && PUNCTUATION.test(after);
  const left = !spaceAfter && (!punctuationAfter || spaceBefore || punctuationBefore);
  const right = !spaceBefore && (!punctuationBefore || spaceAfter || punctuationAfter);
  return description[start] === '*'
    ? { opens: left, closes: right }
    : {
        opens: left && (!right || punctuationBefore),
        closes: right && (!left || punctuationAfter),
      };
}
function runEnd(description: string, start: number): number {
  let end = start + 1;
  while (description[end] === description[start]) end++;
  return end;
}
/** Whether the line starting at `start` reads as a pipe-table row: it opens and closes with `|`. */
function tableRow(description: string, start: number): boolean {
  let end = start;
  while (end < description.length && description[end] !== '\n' && description[end] !== '\r') end++;
  while (start < end && (description[start] === ' ' || description[start] === '\t')) start++;
  while (end > start && (description[end - 1] === ' ' || description[end - 1] === '\t')) end--;
  return end - start > 1 && description[start] === '|' && description[end - 1] === '|';
}

/**
 * The first complete sentence of a CommonMark description, for list previews. Sentence segments
 * join while a break falls inside a token (`.NET`, `(.LNK)`), a `(` or `[`, escaped or not, is still
 * open (`(e.g. GET)`), a code span, backtick fence, or emphasis is open, the break falls inside a
 * pipe-table row, or the preview holds no letter yet (a leading list marker, fence, or ordinal).
 * A bracket or emphasis that never closes yields the whole description, never a fragment.
 *
 * Linear: one pass records backtick runs and the last run of `*` and `_` that can close emphasis,
 * then one pass over the segments reads each character once.
 */
export function firstSentence(description: string): string {
  // A backtick run opens a code span only when a later run of the same length closes it.
  const backtickRuns = new Map<number, { starts: number[]; next: number }>();
  const lastCloser = { '*': -1, _: -1 };
  for (let position = 0; position < description.length; ) {
    const character = description[position] as string;
    const next = description[position + 1];
    if (character === '\\' && next !== '`' && next !== undefined && ASCII_PUNCTUATION.test(next))
      position += 2;
    else if (character === '`' || character === '*' || character === '_') {
      const end = runEnd(description, position);
      if (character === '`') {
        const runs = backtickRuns.get(end - position) ?? { starts: [], next: 0 };
        runs.starts.push(position);
        backtickRuns.set(end - position, runs);
      } else if (emphasisRole(description, position, end).closes) lastCloser[character] = position;
      position = end;
    } else position++;
  }
  const closingRun = (length: number, from: number) => {
    const runs = backtickRuns.get(length);
    if (!runs) return;
    while ((runs.starts[runs.next] ?? Number.POSITIVE_INFINITY) < from) runs.next++;
    return runs.starts[runs.next];
  };
  const firstLetter = description.search(/\p{L}/u);
  const open = { '*': 0, _: 0 };
  let parentheses = 0;
  let brackets = 0;
  let codeEnd = 0;
  let row = tableRow(description, 0);
  let cursor = 0;
  let end = 0;
  for (const { index, segment } of sentences.segment(description)) {
    end = index + segment.length;
    while (cursor < end) {
      const character = description[cursor] as string;
      if (character === '\n' || character === '\r') {
        cursor++;
        if (description[cursor] !== '\n') row = tableRow(description, cursor);
        continue;
      }
      if (cursor < codeEnd) {
        cursor++;
        continue;
      }
      const next = description[cursor + 1];
      if (character === '\\' && next !== undefined && ASCII_PUNCTUATION.test(next)) {
        // An escaped bracket still counts toward the open brackets.
        if (next === '(') parentheses++;
        else if (next === ')' && parentheses) parentheses--;
        else if (next === '[') brackets++;
        else if (next === ']' && brackets) brackets--;
        cursor += 2;
      } else if (character === '`') {
        const runEnds = runEnd(description, cursor);
        const closer = closingRun(runEnds - cursor, runEnds);
        if (closer !== undefined) codeEnd = closer + runEnds - cursor;
        cursor = runEnds;
      } else if (character === '*' || character === '_') {
        const runEnds = runEnd(description, cursor);
        const role = emphasisRole(description, cursor, runEnds);
        let length = runEnds - cursor;
        if (role.closes) {
          const closed = Math.min(length, open[character]);
          open[character] -= closed;
          length -= closed;
        }
        if (role.opens && lastCloser[character] >= runEnds) open[character] += length;
        cursor = runEnds;
      } else {
        if (character === '(') parentheses++;
        else if (character === ')' && parentheses) parentheses--;
        else if (character === '[') brackets++;
        else if (character === ']' && brackets) brackets--;
        cursor++;
      }
    }
    const last = description[end - 1] as string;
    if (
      !parentheses &&
      !brackets &&
      cursor >= codeEnd &&
      !open['*'] &&
      !open._ &&
      firstLetter !== -1 &&
      firstLetter < end &&
      /\s/.test(last) &&
      (!row || last === '\n' || last === '\r')
    )
      break;
  }
  return description.slice(0, end).trim();
}

function quote(value: string): string {
  return value
    .split('\n')
    .map((line) => `> ${line}`)
    .join('\n');
}
function fence(value: string): string {
  const runs = value.match(/`+/g) ?? [];
  return '`'.repeat(Math.max(3, ...runs.map((run) => run.length + 1)));
}
/**
 * Markdown whose parse is a plain value. The value fills its own quoted paragraph, so it escapes as
 * a complete source-text document: a character gains a backslash only where it could form syntax.
 */
function literal(value: string): string {
  return escapeMarkdown(value, new Uint8Array(value.length).fill(Mark.text));
}
/**
 * A URL value as a link whose label and destination both parse back to exactly the URL. The label
 * escapes as link text, its `&` written as generated `&amp;`; the destination writes `\` as `\\` and
 * `&` as `&amp;`, and the URL pattern admits no `<`, `>`, or whitespace that would end it.
 */
function link(url: string): string {
  const label = url.replaceAll('&', '&amp;');
  const marks = new Uint8Array(label.length).fill(Mark.text | Mark.linkText);
  for (let index = label.indexOf('&'); index !== -1; index = label.indexOf('&', index + 5))
    marks.fill(0, index, index + 5);
  const destination = url.replaceAll('\\', '\\\\').replaceAll('&', '&amp;');
  return `[${escapeMarkdown(label, marks)}](<${destination}>)`;
}
function render(value: unknown, field = ''): string {
  if (typeof value === 'string') {
    if (/^https?:\/\/[^\s<>]+$/.test(value)) return link(value);
    // A base64url continuation holds no backtick, so a code span keeps it exactly copyable.
    if (field === 'nextCursor') return quote(`\`${value}\``);
    return quote(PROSE_FIELDS.has(field) ? value : literal(value));
  }
  if (Array.isArray(value))
    return value.length
      ? value.map((item, index) => `**${index + 1}**\n\n${render(item, field)}`).join('\n\n')
      : '[]';
  if (value !== null && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return Object.entries(object)
      .map(([key, item]) => {
        if (object.kind === 'code' && key === 'text' && typeof item === 'string') {
          const delimiter = fence(item);
          return `**${key}**\n\n${delimiter}\n${item}\n${delimiter}`;
        }
        return `**${key}**\n\n${render(item, key)}`;
      })
      .join('\n\n');
  }
  return String(value);
}
/** Render every selected field without slicing, executing HTML, or hiding code. */
export function formatCatalog(result: unknown): [{ type: 'text'; text: string }] {
  return [{ type: 'text' as const, text: render(result) }];
}

function renderEnrichment(key: string, value: unknown): string {
  // Close the final Markdown container so the framework joins every field identically.
  return `${key === 'totalCount' ? `**${String(value)} total**` : formatCatalog({ [key]: value })[0].text}\n\n`;
}
/** The same explicit enrichment renderers drive delivery and byte accounting. */
export const catalogEnrichmentTrailer = Object.fromEntries(
  ['totalCount', 'appliedFilters', 'truncated', 'shown', 'cap', 'notice'].map((key) => [
    key,
    { render: (value: unknown) => renderEnrichment(key, value) },
  ]),
);
/** Detail tools have no applied-filter echo. */
export const detailEnrichmentTrailer = Object.fromEntries(
  Object.entries(catalogEnrichmentTrailer).filter(([key]) => key !== 'appliedFilters'),
);

/** Measure both complete MCP surfaces, including the enrichment trailer. */
export function deliveredSize(
  domain: Record<string, unknown>,
  enrichment: Record<string, unknown>,
): number {
  const fields = Object.entries(enrichment).filter(([, value]) => value !== undefined);
  const content = formatCatalog(domain);
  const trailer = fields.length
    ? [
        {
          type: 'text',
          text: `\n\n${fields.map(([key, value]) => renderEnrichment(key, value)).join('\n')}`,
        },
      ]
    : [];
  return Buffer.byteLength(
    JSON.stringify({
      structuredContent: { ...domain, ...enrichment },
      content: [...content, ...trailer],
    }),
    'utf8',
  );
}
