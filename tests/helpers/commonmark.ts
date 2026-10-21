/**
 * @fileoverview Reference CommonMark parse for round-trip assertions: what a reader sees and which
 * link reference definitions the parse consumed.
 * @module tests/helpers/commonmark
 */
import { HtmlRenderer, type NodeType, Parser } from 'commonmark';

const parser = new Parser();
const renderer = new HtmlRenderer();
const BLOCKS = new Set<NodeType>(['paragraph', 'heading', 'code_block', 'html_block', 'item']);

/**
 * Parse Markdown with the CommonMark reference implementation. `text` is the visible text: text,
 * code, and HTML literals in order, line breaks as `\n`, and blocks separated by `\n`. `nodes` lists
 * every node type entered, so a test can assert that no link, heading, or list formed.
 */
export function parseMarkdown(markdown: string): { text: string; nodes: NodeType[] } {
  const walker = parser.parse(markdown).walker();
  const nodes: NodeType[] = [];
  let text = '';
  for (let event = walker.next(); event; event = walker.next()) {
    const { node, entering } = event;
    if (!entering) {
      if (BLOCKS.has(node.type) && !text.endsWith('\n')) text += '\n';
      continue;
    }
    nodes.push(node.type);
    if (node.type === 'softbreak' || node.type === 'linebreak') text += '\n';
    else if (node.literal !== null) text += node.literal;
  }
  return { text: text.replace(/\n+$/, ''), nodes };
}

/** The visible text with every whitespace run folded to one space, for whole-document checks. */
export function visibleText(markdown: string): string {
  return parseMarkdown(markdown).text.replace(/\s+/g, ' ').trim();
}

/** The reference HTML rendering, for assertions about block nesting. */
export function renderHtml(markdown: string): string {
  return renderer.render(parser.parse(markdown));
}

/**
 * Normalized labels of every link reference definition the parse consumed. A definition removes its
 * line from the visible text and resolves `[label]` anywhere in the document, so a rendered document
 * must define none. The parser keeps the map on itself after `parse()`; the typings omit it.
 */
export function referenceDefinitions(markdown: string): string[] {
  parser.parse(markdown);
  const refmap: unknown = Reflect.get(parser, 'refmap');
  if (typeof refmap !== 'object' || refmap === null)
    throw new Error('commonmark no longer exposes its reference map after parse()');
  return Object.keys(refmap);
}
