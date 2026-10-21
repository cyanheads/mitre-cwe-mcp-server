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
    .describe('Page size; values above 100 are capped with disclosure.'),
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
  'One to 200 submitted IDs; first 20 distinct IDs are processed.',
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
  const result = items.slice(offset, offset + limit);
  const next = offset + result.length;
  const body = Buffer.from(JSON.stringify({ query, offset: next })).toString('base64url');
  return {
    items: result,
    pagination: {
      total: items.length,
      shown: result.length,
      hasMore: next < items.length,
      ...(next < items.length ? { nextCursor: `${body}.${sign(body)}` } : {}),
    },
    ...(input.limit > 100
      ? {
          notice:
            'The requested limit was capped at 100 items; follow nextCursor for the remainder.',
        }
      : {}),
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
