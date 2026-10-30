/**
 * @fileoverview Position-aware CommonMark escaping and the catalog's prose-field list.
 * @module services/catalog/markdown-escape
 */

/**
 * Output keys whose values are CommonMark prose. Normalization converts these from XHTML and the
 * Markdown renderer embeds them verbatim; every other catalog string holds plain source text.
 */
export const PROSE_FIELDS: ReadonlySet<string> = new Set([
  'description',
  'descriptionPreview',
  'notice',
  'extendedDescription',
  'technicalNuance',
  'unphasedIntroductionNotes',
  'backgroundDetails',
  'note',
  'comments',
  'rationale',
  'effectivenessNotes',
  'objective',
  'text',
  'mitigations',
  'prerequisites',
  'exampleInstances',
  'techniques',
  'indicators',
  'resourcesRequired',
]);

/**
 * Character roles in a marked document. Generated Markdown syntax is 0 and never escaped;
 * `text` marks source text, and the context bits widen what source text must escape.
 */
export const Mark = {
  text: 1,
  /** Inside a generated link or image label: `[` and `]` always escape. */
  linkText: 2,
  /** Inside a generated pipe-table cell: `|` always escapes. */
  tableCell: 4,
} as const;

/** CommonMark's Unicode whitespace that every implementation also treats as whitespace. */
export function isWhitespace(character: string | undefined): boolean {
  if (character === undefined) return false;
  return (
    character === ' ' ||
    character === '\t' ||
    character === '\n' ||
    character === '\r' ||
    character === '\f' ||
    /\p{Zs}/u.test(character)
  );
}
function isAlphanumeric(character: string | undefined): boolean {
  return character !== undefined && /[\p{L}\p{N}]/u.test(character);
}
function isAsciiPunctuation(character: string | undefined): boolean {
  return character !== undefined && /[!-/:-@[-`{-~]/.test(character);
}
function isDigit(character: string | undefined): boolean {
  return character !== undefined && character >= '0' && character <= '9';
}
/** Characters that can follow `<` in an autolink (scheme or email local part) or raw HTML. */
const ANGLE_OPENERS = /[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]/;

/**
 * Whether `&` at `index` begins an entity or numeric character reference. When the value is
 * `open` (text may follow it), a reference cut off by the end counts.
 */
function startsReference(value: string, index: number, open: boolean): boolean {
  let cursor = index + 1;
  const end = Math.min(value.length, index + 40);
  if (value[cursor] === '#') {
    cursor++;
    const hex = value[cursor] === 'x' || value[cursor] === 'X';
    if (hex) cursor++;
    const digits = cursor;
    while (
      cursor < end &&
      (hex ? /[0-9A-Fa-f]/.test(value[cursor] as string) : isDigit(value[cursor]))
    )
      cursor++;
    if (cursor === value.length) return open;
    return cursor > digits && cursor - digits <= (hex ? 6 : 7) && value[cursor] === ';';
  }
  if (cursor === value.length) return open;
  if (!/[A-Za-z]/.test(value[cursor] as string)) return false;
  while (cursor < end && /[A-Za-z0-9]/.test(value[cursor] as string)) cursor++;
  return cursor === value.length ? open : value[cursor] === ';';
}
/** Whether a source `]` is escaped: before `(`, in a generated label, or ending open text. */
function escapesCloser(next: string | undefined, mark: number): boolean {
  return next === undefined || next === '(' || (mark & Mark.linkText) !== 0;
}
/**
 * The line-start source `[` positions that would open a link reference definition in the escaped
 * output. A label closes at the first bracket the parser reads unescaped after its `[`, and the line
 * is a definition when that bracket is a `]` followed by `:`, or, in open text, when no bracket
 * follows before the end. Brackets are read as escaped exactly when this pass escapes them, or, in
 * generated text, after an odd run of generated backslashes. Starts are decided right to left, so a
 * label that runs past a later line's `[` reads that `[` as finally escaped or not. Labels are not
 * capped at CommonMark's length limit, which can only add an escape the parse would not need.
 */
function definitionStarts(
  value: string,
  starts: readonly number[],
  markAt: (index: number) => number,
  outside: string | undefined,
): Set<number> {
  const escaped = new Set<number>();
  // The nearest bracket after the cursor that the parser reads unescaped; -1 when none.
  let following = -1;
  let start = starts.length - 1;
  for (let index = value.length - 1; index >= 0; index--) {
    const character = value[index];
    if (character !== '[' && character !== ']') continue;
    if (index === starts[start]) {
      start--;
      const opens =
        following === -1
          ? outside === undefined
          : value[following] === ']' && value[following + 1] === ':';
      if (opens) escaped.add(index);
      else following = index;
      continue;
    }
    const mark = markAt(index);
    let unescaped: boolean;
    if (mark & Mark.text)
      unescaped =
        character === '['
          ? !(mark & Mark.linkText)
          : !escapesCloser(index + 1 < value.length ? value[index + 1] : outside, mark);
    else {
      let backslashes = 0;
      while (
        value[index - backslashes - 1] === '\\' &&
        !(markAt(index - backslashes - 1) & Mark.text)
      )
        backslashes++;
      unescaped = backslashes % 2 === 0;
    }
    if (unescaped) following = index;
  }
  return escaped;
}

/**
 * The position to escape when a block construct other than a link reference definition opens at
 * `start`, the first source character on its line; `-1` when none can. `end` is the line's end.
 */
function blockMarker(value: string, start: number, end: number): number {
  const character = value[start] as string;
  const after = (offset: number) =>
    start + offset === end || value[start + offset] === ' ' || value[start + offset] === '\t';
  if (character === '>') return start;
  if (character === '#') {
    let count = 1;
    while (count < 7 && value[start + count] === '#') count++;
    return count <= 6 && after(count) ? start : -1;
  }
  if ((character === '-' || character === '+' || character === '*') && after(1)) return start;
  if (character === '-' || character === '*' || character === '_' || character === '=') {
    let cursor = start;
    while (
      cursor < end &&
      (value[cursor] === character || value[cursor] === ' ' || value[cursor] === '\t')
    )
      cursor++;
    return cursor === end ? start : -1;
  }
  if (character === '~') return value[start + 1] === '~' && value[start + 2] === '~' ? start : -1;
  if (isDigit(character)) {
    let count = 1;
    while (count < 10 && isDigit(value[start + count])) count++;
    const delimiter = value[start + count];
    return count <= 9 && (delimiter === '.' || delimiter === ')') && after(count + 1)
      ? start + count
      : -1;
  }
  return -1;
}

/**
 * Escape source text so that a CommonMark parse shows it literally, adding a backslash only where
 * a character could otherwise parse as syntax.
 *
 * Without `marks`, the whole value is source text whose surroundings are unknown, so text before
 * and after it is assumed to be the worst case. With `marks`, the value is a complete Markdown
 * document whose ends are block boundaries: positions marked 0 are generated syntax and stay as
 * they are, while every rule still reads the real neighbouring characters.
 *
 * A source space or tab that starts a line is written as a numeric character reference, so the
 * line can never become indented code and keeps its leading whitespace. No line opens a link
 * reference definition, which would hide its text and turn `[label]` elsewhere in the document into
 * a link to its destination.
 *
 * Linear in the input: each rule reads a bounded window or scans its own line once, and link
 * reference definitions are decided in one right-to-left pass over the brackets.
 */
export function escapeMarkdown(value: string, marks?: Uint8Array): string {
  const length = value.length;
  const open = marks === undefined;
  const markAt = (index: number) => (marks ? (marks[index] ?? 0) : Mark.text);
  const outside = open ? undefined : '\n';
  // Per line: a source space or tab that starts it, and the block marker or label `[` at its first
  // source character. Lines are scanned in order, so the positions arrive sorted.
  const lineStarts: number[] = [];
  const blockEscapes: number[] = [];
  const labelStarts: number[] = [];
  for (let lineStart = 0; lineStart <= length; ) {
    let end = lineStart;
    while (end < length && value[end] !== '\n' && value[end] !== '\r') end++;
    if ((value[lineStart] === ' ' || value[lineStart] === '\t') && markAt(lineStart) & Mark.text)
      lineStarts.push(lineStart);
    let first = lineStart;
    while (
      first < end &&
      (!(markAt(first) & Mark.text) || value[first] === ' ' || value[first] === '\t')
    )
      first++;
    if (first < end) {
      // A label `[` is escaped anyway inside a generated label; elsewhere its line decides.
      if (value[first] === '[') {
        if (!(markAt(first) & Mark.linkText)) labelStarts.push(first);
      } else {
        const marker = blockMarker(value, first, end);
        if (marker !== -1 && markAt(marker) & Mark.text) blockEscapes.push(marker);
      }
    }
    lineStart = end + 1;
  }
  const definitions = definitionStarts(value, labelStarts, markAt, outside);
  const candidates = /[\\`*_[\]<&|!]/g;
  let candidate = candidates.exec(value);
  let lineCursor = 0;
  let blockCursor = 0;
  let output = '';
  let copied = 0;
  for (;;) {
    const index = Math.min(
      candidate?.index ?? length,
      lineStarts[lineCursor] ?? length,
      blockEscapes[blockCursor] ?? length,
    );
    if (index === length) break;
    if (candidate?.index === index) candidate = candidates.exec(value);
    if (lineStarts[lineCursor] === index) {
      lineCursor++;
      output += `${value.slice(copied, index)}&#${value[index] === ' ' ? 32 : 9};`;
      copied = index + 1;
      continue;
    }
    let needsEscape = blockEscapes[blockCursor] === index;
    if (needsEscape) blockCursor++;
    const mark = markAt(index);
    if (!(mark & Mark.text)) continue;
    const character = value[index] as string;
    const previous = index ? value[index - 1] : outside;
    const next = index + 1 < length ? value[index + 1] : outside;
    switch (character) {
      case '\\':
        needsEscape ||=
          next === undefined || next === '\n' || next === '\r' || isAsciiPunctuation(next);
        break;
      case '`':
        needsEscape = true;
        break;
      case '*':
        needsEscape ||= !(isWhitespace(previous) && isWhitespace(next));
        break;
      case '_':
        needsEscape ||= !(
          (isWhitespace(previous) && isWhitespace(next)) ||
          (isAlphanumeric(previous) && isAlphanumeric(next))
        );
        break;
      case '[':
        needsEscape ||= (mark & Mark.linkText) !== 0 || definitions.has(index);
        break;
      case ']':
        needsEscape ||= escapesCloser(next, mark);
        break;
      case '<':
        needsEscape ||= next === undefined || ANGLE_OPENERS.test(next);
        break;
      case '&':
        needsEscape ||= startsReference(value, index, open);
        break;
      case '|':
        needsEscape ||= (mark & Mark.tableCell) !== 0;
        break;
      // Before a generated link's `[`, a source `!` would turn the link into an image.
      case '!':
        needsEscape ||= next === '[' && !(markAt(index + 1) & Mark.text);
        break;
    }
    if (needsEscape) {
      output += `${value.slice(copied, index)}\\`;
      copied = index;
    }
  }
  return output + value.slice(copied);
}
