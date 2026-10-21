/**
 * @fileoverview Shared catalog input, paging, and complete Markdown rendering contracts.
 * @module mcp-server/tools/shared
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { z } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import type { Provenance } from '@/services/index.js';

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
/** Normalize syntactically valid catalog identifiers without assuming membership. */
export function normalizeId(value: string, prefix: 'CWE' | 'CAPEC'): string {
  const match = new RegExp(`^(?:${prefix}-)?(\\d+)$`, 'i').exec(value.trim());
  const digits = match?.[1]?.replace(/^0+/, '');
  if (!digits)
    throw validationError(`Use ${prefix}-N or a positive bare integer.`, { retryable: false });
  return `${prefix}-${digits}`;
}
/** Normalize an ATT&CK parent or subtechnique ID. */
export function normalizeAttackId(value: string): string {
  const match = /^(?:T)?(\d{4}(?:\.\d{3})?)$/i.exec(value.trim());
  if (!match?.[1])
    throw validationError('Use Tdddd or Tdddd.ddd for an ATT&CK identifier.', { retryable: false });
  return `T${match[1]}`;
}
/** First-submitted distinct IDs, with an explicit processing cap. */
export function batchIds(values: readonly string[], prefix: 'CWE' | 'CAPEC') {
  const ids = [...new Set(values.map((value) => normalizeId(value, prefix)))];
  return { ids: ids.slice(0, 20), deferredIds: ids.slice(20) };
}
/** Shared submitted-ID ceiling; normalization retains first-submitted order. */
export const idsSchema = list(
  text('A prefixed catalog ID or positive bare integer.'),
  'One to 200 submitted IDs; up to 20 distinct IDs are processed within the response budget.',
)
  .min(1)
  .max(200);
/** Whitespace-only optional text is unset at the handler boundary. */
export function optionalText(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
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
  const build = (count: number, oversized = false): CatalogPage<T> => {
    const result = items.slice(offset, offset + count);
    const next = offset + result.length;
    const body = Buffer.from(JSON.stringify({ query, offset: next })).toString('base64url');
    const notice = [
      ...(input.limit > 100
        ? ['The requested limit was capped at 100 items; follow nextCursor for the remainder.']
        : []),
      ...(count < maximum
        ? [
            'The 24,000-byte response budget reduced this page; follow nextCursor for the remainder.',
          ]
        : []),
      ...(oversized
        ? [
            'One complete item and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.',
          ]
        : []),
    ].join(' ');
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
  return selectWithinBudget(
    maximum,
    (count) => build(count),
    measure,
    () => build(Math.min(1, maximum), true),
  );
}

/** Whole ordered page and its lossless continuation. */
export interface CatalogPage<T> {
  items: T[];
  notice?: string;
  pagination: { total: number; shown: number; hasMore: boolean; nextCursor?: string };
}

/** Target for the serialized MCP result, excluding its JSON-RPC framing. */
export const RESPONSE_BUDGET = 24_000;

/** Select a whole prefix; an indivisible first item always makes forward progress. */
export function selectWithinBudget<T>(
  maximum: number,
  build: (count: number) => T,
  measure: ((result: T) => number) | undefined,
  oversized: () => T,
): T {
  for (let count = maximum; count >= Math.min(1, maximum); count--) {
    const result = build(count);
    if (!measure || measure(result) <= RESPONSE_BUDGET) return result;
  }
  return oversized();
}

/** Enrichment shared by all paged tools, measured before it reaches either surface. */
export function pageEnrichment<T, F>(
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
const proseFields = new Set([
  'description',
  'descriptionPreview',
  'notice',
  'extendedDescription',
  'note',
  'comments',
  'rationale',
  'effectivenessNotes',
  'objective',
  'filterDefinition',
  'text',
  'mitigations',
  'prerequisites',
  'exampleInstances',
  'techniques',
  'indicators',
  'resourcesRequired',
]);
function render(value: unknown, field = ''): string {
  if (typeof value === 'string') {
    if (/^https?:\/\/[^\s<>]+$/.test(value))
      return `[${value.replace(/&/g, '&amp;').replace(/[[\]\\]/g, '\\$&')}](<${value.replace(/&/g, '&amp;').replace(/>/g, '%3E')}>)`;
    return quote(
      proseFields.has(field)
        ? value
        : value
            .replace(/&/g, '&amp;')
            .replace(/([\\`*_{}[\]()#+.!|>~-])/g, '\\$1')
            .replace(/</g, '&lt;'),
    );
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
