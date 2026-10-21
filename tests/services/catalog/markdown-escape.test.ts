/**
 * @fileoverview Position-aware CommonMark escaping: rule table, document marks, round trips, timing.
 * @module tests/services/catalog/markdown-escape.test
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { escapeMarkdown, Mark } from '@/services/catalog/markdown-escape.js';
import { parseMarkdown, referenceDefinitions, visibleText } from '../../helpers/commonmark.js';
import { expectLinearTime } from '../../helpers/cpu-timing.js';

/** Build a marked document from [value, mark] parts; mark 0 is generated syntax. */
function marked(parts: readonly (readonly [string, number])[]): [string, Uint8Array] {
  const value = parts.map(([part]) => part).join('');
  const marks = new Uint8Array(value.length);
  let offset = 0;
  for (const [part, mark] of parts) {
    marks.fill(mark, offset, offset + part.length);
    offset += part.length;
  }
  return [value, marks];
}
/** Every character is source text in a complete document. */
const asDocument = (value: string) =>
  escapeMarkdown(value, new Uint8Array(value.length).fill(Mark.text));
const INLINE = ['document', 'paragraph', 'text'];

describe('escapeMarkdown plain-text rules', () => {
  // [source, stored]: a backslash or reference only where the character could parse as syntax.
  const rules: [string, string][] = [
    ['1. x', '1\\. x'],
    ['2) x', '2\\) x'],
    ['# x', '\\# x'],
    ['####### x', '####### x'],
    ['- x', '\\- x'],
    ['+ x', '\\+ x'],
    ['* x', '\\* x'],
    ['> x', '\\> x'],
    ['---', '\\---'],
    ['===', '\\==='],
    ['- - -', '\\- - -'],
    ['~~~', '\\~~~'],
    ['[a]: b', '\\[a]: b'],
    ['[a] b', '[a] b'],
    // The `]` before `(` is escaped, so the label runs on to the later `]:`.
    ['[a](b]: c', '\\[a\\](b]: c'],
    // The second line's `[` is escaped, so the first line's label runs on through it.
    ['[a\n[b]: c', '\\[a\n\\[b]: c'],
    ['<script>', '\\<script>'],
    ['</p>', '\\</p>'],
    ['<!-- c -->', '\\<!-- c -->'],
    ['<?x?>', '\\<?x?>'],
    ['<1@example.com>', '\\<1@example.com>'],
    ['a < b', 'a < b'],
    ['&lt;', '\\&lt;'],
    ['&#65;', '\\&#65;'],
    ['&#x41;', '\\&#x41;'],
    ['a & b', 'a & b'],
    ['AT&T', 'AT\\&T'],
    ['*p', '\\*p'],
    ['a * b', 'a * b'],
    ['a*b', 'a\\*b'],
    ['__init__', '\\_\\_init\\_\\_'],
    ['a_b', 'a_b'],
    ['x](y)', 'x\\](y)'],
    ['`', '\\`'],
    ['\\\\server', '\\\\\\server'],
    ['C:\\dir', 'C:\\dir'],
    ['a\\', 'a\\\\'],
    ['    code', '&#32;   code'],
    ['\tcode', '&#9;code'],
    ['a\n# b', 'a\n\\# b'],
    ['a\r# b', 'a\r\\# b'],
  ];
  it.each(rules)('stores %j as %j, which parses back to the source text', (source, stored) => {
    expect(escapeMarkdown(source)).toBe(stored);
    const visible = source.replace(/\r/g, '\n');
    const parsed = parseMarkdown(stored);
    expect(parsed.text).toBe(visible);
    expect(parsed.nodes.every((node) => [...INLINE, 'softbreak'].includes(node))).toBe(true);
    expect(referenceDefinitions(stored)).toEqual([]);
    // Plain text assumes the worst case on both sides: a paragraph line before, more text after.
    expect(parseMarkdown(`p\n${stored}(y);`).text).toBe(`p\n${visible}(y);`);
  });
});

describe('escapeMarkdown document marks', () => {
  it('never escapes generated syntax and escapes the same characters as source text', () => {
    const syntax = '# *x* _y_ `z` [a](b) <p> &amp; \\';
    expect(escapeMarkdown(syntax, new Uint8Array(syntax.length))).toBe(syntax);
    expect(asDocument(syntax)).toBe('\\# \\*x\\* \\_y\\_ \\`z\\` [a\\](b) \\<p> \\&amp; \\\\');
  });

  it('reads real neighbours across generated syntax', () => {
    const [list, listMarks] = marked([
      ['- ', 0],
      ['1. x', Mark.text],
    ]);
    expect(escapeMarkdown(list, listMarks)).toBe('- 1\\. x');
    const [bold, boldMarks] = marked([
      ['**', 0],
      ['bold', Mark.text],
      ['**', 0],
      [' a*b', Mark.text],
    ]);
    expect(escapeMarkdown(bold, boldMarks)).toBe('**bold** a\\*b');
  });

  it('treats the document ends as block boundaries', () => {
    expect(asDocument('see [REF-1]')).toBe('see [REF-1]');
    expect(escapeMarkdown('see [REF-1]')).toBe('see [REF-1\\]');
    expect(asDocument('AT&T')).toBe('AT&T');
    expect(asDocument('a <')).toBe('a <');
    const parsed = parseMarkdown(asDocument('see [REF-1]'));
    expect(parsed.text).toBe('see [REF-1]');
    expect(parsed.nodes.every((node) => INLINE.includes(node))).toBe(true);
  });

  it('escapes every bracket inside a generated link label', () => {
    const [link, marks] = marked([
      ['[', 0],
      ['a [b] c', Mark.text | Mark.linkText],
      ['](<https://example.test/>)', 0],
    ]);
    const stored = escapeMarkdown(link, marks);
    expect(stored).toBe('[a \\[b\\] c](<https://example.test/>)');
    const parsed = parseMarkdown(stored);
    expect(parsed.text).toBe('a [b] c');
    expect(parsed.nodes.filter((node) => node === 'link')).toHaveLength(1);
  });

  it('decides a line-start bracket against the brackets the parser reads after it', () => {
    // Generated text (code, in practice) keeps its backslash, which escapes the next `]` in a label.
    const [code, codeMarks] = marked([
      ['[x ', Mark.text],
      ['` \\] `', 0],
      [']: javascript:alert(1)', Mark.text],
    ]);
    const escaped = escapeMarkdown(code, codeMarks);
    expect(escaped).toBe('\\[x ` \\] `]: javascript:alert(1)');
    expect(referenceDefinitions(escaped)).toEqual([]);
    expect(parseMarkdown(escaped).text).toBe('[x \\]]: javascript:alert(1)');
    // A generated `[` ends any label begun before it, so nothing needs escaping.
    const [link, linkMarks] = marked([
      ['[a ', Mark.text],
      ['[', 0],
      ['b', Mark.text | Mark.linkText],
      ['](<https://example.test/>)', 0],
      [']: c', Mark.text],
    ]);
    expect(escapeMarkdown(link, linkMarks)).toBe(link);
    expect(referenceDefinitions(link)).toEqual([]);
    expect(parseMarkdown(link).text).toBe('[a b]: c');
  });

  it('escapes a pipe only inside a generated table cell', () => {
    const [table, marks] = marked([
      ['| ', 0],
      ['a|b', Mark.text | Mark.tableCell],
      [' |\n| --- |\n', 0],
      ['c|d', Mark.text],
    ]);
    expect(escapeMarkdown(table, marks)).toBe('| a\\|b |\n| --- |\nc|d');
  });
});

describe('escapeMarkdown round trip', () => {
  const alphabet = [...'ab1 \t\\`*_[]()<>&#;!-+=~|:./?"\'x9@', 'é', '\u00a0', '\u3000', '\u0301'];
  const line = fc.string({ unit: fc.constantFrom(...alphabet), maxLength: 24 });
  /**
   * A single line reaches the escaper with no whitespace at either end: catalog values and search
   * filters are whitespace-collapsed where they enter, and every other plain value is trimmed. The
   * reference parser trims the same JavaScript whitespace at a paragraph's ends, so every such value
   * must parse back exactly, whatever whitespace it holds inside.
   */
  const singleLine = line.map((value) => value.trim());
  const lines = fc
    .tuple(fc.array(line, { maxLength: 6 }), fc.constantFrom('\n', '\r', '\r\n'))
    .map(([parts, separator]) => parts.join(separator));
  const modes = [
    ['plain text', (value: string) => escapeMarkdown(value)],
    ['a document', asDocument],
  ] as const;

  it.each(modes)('parses single-line %s back exactly as text', (_mode, store) => {
    fc.assert(
      fc.property(singleLine, (value) => {
        const parsed = parseMarkdown(store(value));
        expect(parsed.text).toBe(value);
        expect(parsed.nodes.every((node) => INLINE.includes(node))).toBe(true);
      }),
      { seed: 20261020, numRuns: 1500 },
    );
  });

  it.each(modes)('parses multi-line %s back as paragraphs of the source text', (_mode, store) => {
    fc.assert(
      fc.property(lines, (value) => {
        const stored = store(value);
        expect(visibleText(stored)).toBe(value.replace(/\s+/g, ' ').trim());
        expect(
          parseMarkdown(stored).nodes.every((node) =>
            [...INLINE, 'softbreak', 'linebreak'].includes(node),
          ),
        ).toBe(true);
      }),
      { seed: 20261020, numRuns: 1500 },
    );
  });
});

describe('escapeMarkdown link reference definitions', () => {
  const unit = fc.constantFrom(...'[]()[]:\\ ab<>`!"', '\n', '\r\n', ']:', '](', '[a]');
  const value = fc.string({ unit, maxLength: 20 });

  it('never leaves a definition in a complete document, as stored or quoted', () => {
    fc.assert(
      fc.property(value, (candidate) => {
        const stored = asDocument(candidate);
        expect(referenceDefinitions(stored)).toEqual([]);
        const quoted = stored
          .split('\n')
          .map((part) => `> ${part}`)
          .join('\n');
        expect(referenceDefinitions(quoted)).toEqual([]);
        expect(visibleText(stored)).toBe(candidate.replace(/\s+/g, ' ').trim());
      }),
      { seed: 20261021, numRuns: 4000 },
    );
  });

  it('never leaves a definition in plain text, whatever follows it', () => {
    fc.assert(
      fc.property(
        value,
        fc.constantFrom('', ': x', ']: x', ' ]: x', '\n]: x'),
        (candidate, after) => {
          const stored = escapeMarkdown(candidate);
          expect(referenceDefinitions(`${stored}${after}`)).toEqual([]);
          expect(visibleText(`${stored}${after}`)).toBe(
            `${candidate}${after}`.replace(/\s+/g, ' ').trim(),
          );
        },
      ),
      { seed: 20261021, numRuns: 4000 },
    );
  });
});

describe('escapeMarkdown timing', () => {
  const shapes: [string, (length: number) => string][] = [
    ['digit run', (length) => '7'.repeat(length)],
    ['one long line, then a break', (length) => `${'§1 x'.repeat(length / 4)}\ny`],
    ['breaks throughout', (length) => '  \r\n'.repeat(length / 4)],
    ['open brackets', (length) => '['.repeat(length)],
    ['bracketed line starts', (length) => '[a\n'.repeat(Math.floor(length / 3))],
    ['reference starts', (length) => '&a'.repeat(length / 2)],
    ['asterisks', (length) => '*'.repeat(length)],
    ['underscores', (length) => '_'.repeat(length)],
    ['backslashes', (length) => '\\'.repeat(length)],
    ['angle openers', (length) => '<a'.repeat(length / 2)],
    ['dashes before text', (length) => `${'-'.repeat(length)}x`],
    ['line starts sharing one label', (length) => `${'[\n'.repeat(length / 2)}]: x`],
    ['escaped closers in one label', (length) => `[${'a](b'.repeat(length / 4)}]: x`],
    ['labels closing at every line', (length) => '[a]:\n'.repeat(length / 5)],
  ];
  it('stays linear on adversarial plain text and documents', { timeout: 60_000 }, () => {
    for (const [label, build] of shapes) {
      expectLinearTime(`${label} as plain text`, build, (value) => escapeMarkdown(value));
      expectLinearTime(`${label} as a document`, build, asDocument);
    }
  });
});
