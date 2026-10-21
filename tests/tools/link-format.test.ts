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
