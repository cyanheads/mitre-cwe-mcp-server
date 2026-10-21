/**
 * @fileoverview Ordered, entity-safe XML normalization for the MITRE catalogs.
 * @module services/catalog/xml-normalization
 */
import { serializationError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { XMLParser } from 'fast-xml-parser';
import { SyntaxValidator } from 'fast-xml-validator';
import type {
  AttackPattern,
  CapecCatalog,
  CatalogReference,
  CatalogView,
  Consequence,
  CweCatalog,
  DemonstrativeExample,
  ExampleBlock,
  Member,
  TaxonomyMapping,
  Weakness,
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
function requiredAttribute(node: OrderedNode, name: string): string {
  const value = attribute(node, name);
  if (!value?.trim()) malformed(`The MITRE catalog is missing a required ${name} attribute.`);
  return value;
}
function id(node: OrderedNode, prefix: 'CWE' | 'CAPEC', name = 'ID'): string {
  const value = requiredAttribute(node, name);
  if (!/^[0-9]+$/.test(value) || /^0+$/.test(value))
    malformed('The MITRE catalog contains an invalid entry identifier.');
  return `${prefix}-${value.replace(/^0+/, '')}`;
}
function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/([\\`*_[\]<>])/g, '\\$1');
}
function decodeReferences(value: string): string {
  const predefined = new Map([
    ['amp', '&'],
    ['lt', '<'],
    ['gt', '>'],
    ['quot', '"'],
    ['apos', "'"],
  ]);
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (entity, name: string) => {
    if (!name.startsWith('#')) return predefined.get(name) ?? entity;
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
function rawText(nodes: readonly OrderedNode[]): string {
  return nodes
    .map((node) => {
      if (typeof node['#text'] === 'string') return node['#text'];
      if (Array.isArray(node['#cdata'])) return rawText(node['#cdata'] as OrderedNode[]);
      const name = tag(node);
      if (!name) return '';
      if (local(name) === 'br') return '\n';
      const text = rawText(contents(node));
      return local(name) === 'div' || local(name) === 'p' ? `${text}\n` : text;
    })
    .join('');
}

/** Convert mixed XHTML into inert Markdown while retaining document order. */
export function orderedContentToMarkdown(nodes: readonly OrderedNode[]): string {
  const render = (items: readonly OrderedNode[], inList = false): string =>
    items
      .map((node) => {
        if (typeof node['#text'] === 'string')
          return escapeText(node['#text'].replace(/\s+/g, ' '));
        if (Array.isArray(node['#cdata']))
          return escapeText(rawText(node['#cdata'] as OrderedNode[]));
        const key = tag(node);
        if (!key) return '';
        const name = local(key);
        const inner = render(contents(node), name === 'ul' || name === 'ol');
        if (name === 'br') return '  \n';
        if (name === 'p' || name === 'div') return `\n\n${inner.trim()}\n\n`;
        if (name === 'ul' || name === 'ol') {
          const list = children(node, 'li')
            .map((entry, index) => {
              const body = render(contents(entry)).trim();
              const marker = name === 'ol' ? `${index + 1}. ` : '- ';
              return `${marker}${body.replace(/\n/g, '\n  ')}`;
            })
            .join('\n');
          return `\n\n${list}\n\n`;
        }
        if (name === 'li') return inList ? inner : `\n- ${inner.trim()}\n`;
        if (name === 'a') {
          const href = attribute(node, 'href');
          if (!href) return inner;
          if (!/^https?:\/\//i.test(href) || !URL.canParse(href))
            return `${inner.trim()} (${escapeText(href)})`;
          const destination = href
            .replace(/[\\<>\s]/g, (character) => encodeURIComponent(character))
            .replace(/&/g, '&amp;');
          return `[${inner.trim()}](<${destination}>)`;
        }
        if (name === 'b' || name === 'strong') return `**${inner.trim()}**`;
        if (name === 'i' || name === 'em') return `*${inner.trim()}*`;
        if (name === 'code') {
          const code = rawText(contents(node));
          const fence = '`'.repeat(
            Math.max(1, ...Array.from(code.matchAll(/`+/g), (match) => match[0].length + 1)),
          );
          return `${fence} ${code} ${fence}`;
        }
        if (name === 'pre') {
          const code = rawText(contents(node));
          const fence = '`'.repeat(
            Math.max(3, ...Array.from(code.matchAll(/`+/g), (match) => match[0].length + 1)),
          );
          return `\n\n${fence}\n${code}\n${fence}\n\n`;
        }
        return inner;
      })
      .join('');
  let fence: string | undefined;
  let blankLines = 0;
  const lines: string[] = [];
  for (const line of render(nodes).split('\n')) {
    if (fence !== undefined) {
      lines.push(line);
      if (line === fence) fence = undefined;
      continue;
    }
    const opening = /^(`{3,})$/.exec(line);
    if (opening) {
      fence = opening[1];
      lines.push(line);
      blankLines = 0;
    } else if (!line.trim()) {
      if (blankLines === 0) lines.push('');
      blankLines++;
    } else {
      lines.push(line);
      blankLines = 0;
    }
  }
  return lines.join('\n').trim();
}

function text(node: OrderedNode, name?: string): string | undefined {
  const target = name ? child(node, name) : node;
  return target ? orderedContentToMarkdown(contents(target)) : undefined;
}
function requiredText(node: OrderedNode, name: string): string {
  const value = text(node, name);
  if (value === undefined) malformed(`The MITRE catalog is missing required ${name} content.`);
  return value;
}
function optionalTexts(
  node: OrderedNode,
  fields: Readonly<Record<string, string>>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(fields).flatMap(([output, source]) => {
      const value = text(node, source);
      return value === undefined ? [] : [[output, value]];
    }),
  );
}
function optionalUrl(
  node: OrderedNode,
  name: string,
  output: 'url' | 'link',
): Record<string, string> {
  const target = child(node, name);
  return target ? { [output]: rawText(contents(target)).trim() } : {};
}
function optionalAttributes(
  node: OrderedNode,
  fields: Readonly<Record<string, string>>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(fields).flatMap(([output, source]) => {
      const value = attribute(node, source);
      return value === undefined ? [] : [[output, value]];
    }),
  );
}
function texts(node: OrderedNode, name: string): string[] {
  return children(node, name).map((item) => text(item) ?? '');
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
        blocks.push({ kind: 'prose', text: text(element) ?? '' });
      }
    }
    return { index, blocks };
  });
}

function consequences(node: OrderedNode, container: string): Record<string, Consequence[]> {
  return arrayField(node, container, 'Consequence', 'consequences', (entry) => ({
    scopes: texts(entry, 'Scope'),
    impacts: texts(entry, 'Impact'),
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
      ...(children(entry, 'Author').length ? { authors: texts(entry, 'Author') } : {}),
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
function normalizeWeakness(
  node: OrderedNode,
  type: Weakness['type'],
  external: ReadonlyMap<string, CatalogReference>,
): Weakness {
  const entryId = id(node, 'CWE');
  const mappings = taxonomies(node);
  const mappingNotes = child(node, 'Mapping_Notes');
  return {
    id: entryId,
    type,
    name: requiredAttribute(node, 'Name'),
    status: requiredAttribute(node, 'Status'),
    sourceUrl: `https://cwe.mitre.org/data/definitions/${entryId.slice(4)}.html`,
    description: requiredText(node, type === 'category' ? 'Summary' : 'Description'),
    ...optionalAttributes(node, { abstraction: 'Abstraction' }),
    ...optionalTexts(node, {
      extendedDescription: 'Extended_Description',
      likelihoodOfExploit: 'Likelihood_Of_Exploit',
    }),
    ...arrayField(
      node,
      'Modes_Of_Introduction',
      'Introduction',
      'modesOfIntroduction',
      (entry) => ({
        phase: requiredText(entry, 'Phase'),
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
      phases: texts(entry, 'Phase'),
      description: requiredText(entry, 'Description'),
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
      method: requiredText(entry, 'Method'),
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
    ...(child(node, 'Applicable_Platforms')
      ? {
          platforms: contents(child(node, 'Applicable_Platforms') as OrderedNode).flatMap(
            (entry) => {
              const key = tag(entry);
              const kinds = new Map([
                ['Language', 'language'],
                ['Technology', 'technology'],
                ['Operating_System', 'OS'],
                ['Architecture', 'architecture'],
              ] as const);
              const kind = key ? kinds.get(local(key) as 'Language') : undefined;
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
            },
          ),
        }
      : {}),
    ...(child(node, 'Taxonomy_Mappings') ? { taxonomyMappings: mappings } : {}),
    ...references(node, external),
  };
}

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
    ...(child(node, 'Members') &&
    text(child(node, 'Members') as OrderedNode, 'Filter') !== undefined
      ? { filterDefinition: text(child(node, 'Members') as OrderedNode, 'Filter') as string }
      : {}),
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
    name: requiredAttribute(node, 'Name'),
    status: requiredAttribute(node, 'Status'),
    abstraction: requiredAttribute(node, 'Abstraction'),
    sourceUrl: `https://capec.mitre.org/data/definitions/${entryId.slice(6)}.html`,
    description: requiredText(node, 'Description'),
    ...optionalTexts(node, {
      extendedDescription: 'Extended_Description',
      typicalSeverity: 'Typical_Severity',
      likelihoodOfAttack: 'Likelihood_Of_Attack',
    }),
    ...arrayField(
      node,
      'Prerequisites',
      'Prerequisite',
      'prerequisites',
      (entry) => text(entry) ?? '',
    ),
    ...arrayField(node, 'Execution_Flow', 'Attack_Step', 'executionFlow', (entry) => ({
      step: requiredText(entry, 'Step'),
      phase: requiredText(entry, 'Phase'),
      description: requiredText(entry, 'Description'),
      ...(children(entry, 'Technique').length ? { techniques: texts(entry, 'Technique') } : {}),
      ...(children(entry, 'Indicator').length ? { indicators: texts(entry, 'Indicator') } : {}),
    })),
    ...arrayField(node, 'Indicators', 'Indicator', 'indicators', (entry) => text(entry) ?? ''),
    ...arrayField(node, 'Skills_Required', 'Skill', 'skills', (entry) => ({
      description: text(entry) ?? '',
      ...optionalAttributes(entry, { level: 'Level' }),
    })),
    ...arrayField(
      node,
      'Resources_Required',
      'Resource',
      'resourcesRequired',
      (entry) => text(entry) ?? '',
    ),
    ...consequences(node, 'Consequences'),
    ...arrayField(node, 'Mitigations', 'Mitigation', 'mitigations', (entry) => text(entry) ?? ''),
    ...arrayField(
      node,
      'Example_Instances',
      'Example',
      'exampleInstances',
      (entry) => text(entry) ?? '',
    ),
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
  for (const node of weaknessNodes)
    insert(weaknesses, normalizeWeakness(node, 'weakness', external));
  for (const node of categoryNodes)
    insert(weaknesses, normalizeWeakness(node, 'category', external));
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
  };
}

/** Parse and validate a complete CAPEC XML document. */
export function parseCapecCatalog(xml: string): CapecCatalog {
  const root = parseRoot(xml, 'Attack_Pattern_Catalog', 'http://capec.mitre.org/capec-3');
  const external = externalReferences(root);
  const attackPatterns = new Map<string, AttackPattern>();
  for (const node of nested(root, 'Attack_Patterns', 'Attack_Pattern'))
    insert(attackPatterns, normalizeAttackPattern(node, external));
  if (!attackPatterns.size) malformed('The CAPEC catalog contains no attack patterns.');
  return {
    version: requiredAttribute(root, 'Version'),
    date: requiredAttribute(root, 'Date'),
    attackPatterns,
  };
}
