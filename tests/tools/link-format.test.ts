/**
 * @fileoverview XML URL preservation through normalized Markdown and catalog formatting.
 * @module tests/tools/link-format.test
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { formatCatalog } from '@/mcp-server/tools/shared.js';
import { parseCweCatalog } from '@/services/catalog/xml-normalization.js';

const cweXml = readFileSync(
  new URL('../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const url = 'https://example.test/a_b/[record](revision)?q=&copy;&next=%26lt%3B';
const xmlUrl = url.replaceAll('&', '&amp;');
const markdownUrl = url.replaceAll('&', '&amp;');

describe('entity-looking URL data', () => {
  it('preserves an XML inline link destination through normalized prose and formatting', () => {
    const xml = cweXml.replace(
      '<Description>Sparse description.</Description>',
      `<Description><xhtml:a href="${xmlUrl}">source</xhtml:a></Description>`,
    );
    const record = parseCweCatalog(xml).weaknesses.get('CWE-20');
    expect(record?.description).toBe(`[source](<${markdownUrl}>)`);
    expect(formatCatalog(record)[0].text).toContain(`> [source](<${markdownUrl}>)`);
  });

  it('keeps scalar URLs raw while encoding their rendered link label and destination', () => {
    const xml = cweXml.replace('<URL>https://example.test/ref</URL>', `<URL>${xmlUrl}</URL>`);
    const references = parseCweCatalog(xml).weaknesses.get('CWE-79')?.references;
    expect(references?.[0]?.url).toBe(url);
    const label = markdownUrl.replace(/[[\]\\]/g, '\\$&');
    expect(formatCatalog({ references })[0].text).toContain(`[${label}](<${markdownUrl}>)`);
  });
});

describe('inert XML anchor destinations', () => {
  it.each(['javascript:alert(1)', 'data:text/html;base64,PHNjcmlwdD4='])(
    'keeps unsupported destination %s visible without making it a link',
    (href) => {
      const xml = cweXml.replace(
        '<Description>Sparse description.</Description>',
        `<Description>Before <xhtml:a href="${href}">source label</xhtml:a> after.</Description>`,
      );
      const description = parseCweCatalog(xml).weaknesses.get('CWE-20')?.description;
      expect(description).toContain('Before');
      expect(description).toContain('source label');
      expect(description).toContain(href);
      expect(description).toContain('after.');
      expect(description).not.toContain('](<');
      const rendered = formatCatalog({ description })[0].text;
      expect(rendered).toContain(href);
      expect(rendered).toContain('source label');
      expect(rendered).not.toContain('](<');
    },
  );

  it.each(['https', 'http'])(
    'keeps %s destination delimiters and backslashes inside one safe source link',
    (scheme) => {
      const href = `${scheme}://example.test/a\\>)[injected](https://evil.test)![image](https://evil.test/i)<tail`;
      const encoded = href.replaceAll('\\', '%5C').replaceAll('>', '%3E').replaceAll('<', '%3C');
      const xmlHref = href.replaceAll('>', '&gt;').replaceAll('<', '&lt;');
      const xml = cweXml.replace(
        '<Description>Sparse description.</Description>',
        `<Description><xhtml:a href="${xmlHref}">source label</xhtml:a></Description>`,
      );
      const description = parseCweCatalog(xml).weaknesses.get('CWE-20')?.description;
      expect(description).toBe(`[source label](<${encoded}>)`);
      expect(formatCatalog({ description })[0].text).toContain(`> [source label](<${encoded}>)`);
    },
  );
});
