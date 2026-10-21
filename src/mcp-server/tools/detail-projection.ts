/**
 * @fileoverview Complete per-record section selection, outlines, and example continuation.
 * @module mcp-server/tools/detail-projection
 */
import type { CapecRecord, CatalogSnapshot, Provenance, Weakness } from '@/services/index.js';
import { resolveVocabulary } from '@/services/index.js';
import { attackPatternEntrySchema, weaknessEntrySchema } from './catalog-schemas.js';
import {
  batchIds,
  deliveredSize,
  type Family,
  formatCatalog,
  type IdPosition,
  optionalText,
  RESPONSE_BUDGET,
  selectWithinBudget,
} from './shared.js';
/** All supported CWE sections. */
export const weaknessSections = [
  'summary',
  'consequences',
  'mitigations',
  'relations',
  'examples',
  'detection',
  'observed',
  'platforms',
  'mappings',
  'notes',
] as const;
/** All supported CAPEC sections. */
export const attackPatternSections = [
  'summary',
  'prerequisites',
  'execution',
  'skills',
  'consequences',
  'mitigations',
  'examples',
  'relations',
  'mappings',
  'notes',
] as const;
type SectionMap = Record<string, readonly string[]>;
const cweFields: SectionMap = {
  summary: [
    'description',
    'extendedDescription',
    'ordinalities',
    'backgroundDetails',
    'alternateTerms',
    'likelihoodOfExploit',
    'modesOfIntroduction',
    'mappingNotes',
  ],
  consequences: ['consequences'],
  mitigations: ['mitigations'],
  relations: ['relatedWeaknesses', 'relatedAttackPatterns', 'members'],
  examples: ['examples'],
  detection: ['detectionMethods'],
  observed: ['observedExamples'],
  platforms: ['platforms', 'functionalAreas', 'affectedResources'],
  mappings: ['taxonomyMappings', 'references'],
  notes: ['notes'],
};
const capecFields: SectionMap = {
  summary: [
    'description',
    'extendedDescription',
    'alternateTerms',
    'typicalSeverity',
    'likelihoodOfAttack',
  ],
  prerequisites: ['prerequisites'],
  execution: ['executionFlow', 'indicators'],
  skills: ['skills', 'resourcesRequired'],
  consequences: ['consequences'],
  mitigations: ['mitigations'],
  examples: ['exampleInstances'],
  relations: ['relatedAttackPatterns', 'members', 'filterDefinition'],
  mappings: ['relatedWeaknesses', 'attackTechniqueIds', 'taxonomyMappings', 'references'],
  notes: ['notes'],
};
function pick(entry: Weakness | CapecRecord, fields: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(entry).filter(([key, value]) => fields.includes(key) && value !== undefined),
  );
}
/** Delivered bytes of one section on both surfaces: its JSON and its rendered `content[]` text. */
function sectionSize(fields: Record<string, unknown>): number {
  return (
    Buffer.byteLength(JSON.stringify(fields)) +
    Buffer.byteLength(JSON.stringify(formatCatalog(fields)[0].text))
  );
}
/**
 * Project the selected sections of one record. `omitted` names selected sections left out to fit
 * the response budget (a `partial` entry); `undefined` asks for an identity outline instead.
 */
function project(
  entry: Weakness | CapecRecord,
  groups: SectionMap,
  sections: readonly string[],
  omitted: readonly string[] | undefined,
  toolName: 'cwe_get_weakness' | 'cwe_get_attack_pattern',
) {
  const fieldsOf = (section: string) => pick(entry, groups[section] ?? []);
  const availableSections = Object.keys(groups).filter(
    (section) => Object.keys(fieldsOf(section)).length > 0,
  );
  const identity = {
    id: entry.id,
    name: entry.name,
    status: entry.status,
    sourceUrl: entry.sourceUrl,
    type: entry.type,
    ...('abstraction' in entry && entry.abstraction !== undefined
      ? { abstraction: entry.abstraction }
      : {}),
    requestedSections: [...sections],
    availableSections,
  };
  const sized = (list: readonly string[]) =>
    list.map((section) => ({ section, sizeInBytes: sectionSize(fieldsOf(section)) }));
  if (sections.length === 0 || omitted === undefined)
    return {
      ...identity,
      kind: 'outline' as const,
      outline: sized(availableSections),
      notice: `Repeat ${toolName} with this ID and explicit sections, one section at a time for large records.`,
    };
  const absent = sections.filter((section) => !availableSections.includes(section));
  const notice = [
    absent.length &&
      `The source entry has no content for these selected sections: ${absent.join(', ')}.`,
    omitted.length &&
      `Omitted to fit the 24,000-byte response budget: ${omitted.join(', ')}. Repeat ${toolName} with this ID and sections ${JSON.stringify(omitted)}.`,
  ]
    .filter(Boolean)
    .join(' ');
  return {
    ...identity,
    kind: omitted.length ? ('partial' as const) : ('full' as const),
    ...Object.assign({}, ...sections.filter((section) => !omitted.includes(section)).map(fieldsOf)),
    ...(omitted.length ? { outline: sized(omitted) } : {}),
    ...(notice ? { notice } : {}),
  };
}

/** Projected entry fields the section fill reads. */
type Projected = { requestedSections: string[]; availableSections: string[] };
/**
 * Fill a default selection: keep each selected section, in order, whose addition still lets
 * `respond(entry)` fit the budget, and outline the entry when none does. Returns the chosen entry
 * with its response; `fits` is false only for an outline that still does not fit.
 */
function fillSections<T extends Projected, R>(
  project: (omitted: readonly string[] | undefined) => T,
  respond: (entry: T) => R,
  fits: (response: R) => boolean,
): { entry: T; response: R; fits: boolean } {
  const full = project([]);
  const whole = respond(full);
  if (fits(whole)) return { entry: full, response: whole, fits: true };
  const sections = full.requestedSections.filter((section) =>
    full.availableSections.includes(section),
  );
  const kept: string[] = [];
  let best: { entry: T; response: R } | undefined;
  for (const section of sections) {
    const entry = project(
      sections.filter((candidate) => candidate !== section && !kept.includes(candidate)),
    );
    const response = respond(entry);
    if (!fits(response)) continue;
    kept.push(section);
    best = { entry, response };
  }
  if (best) return { ...best, fits: true };
  const outline = project(undefined);
  const response = respond(outline);
  return { entry: outline, response, fits: fits(response) };
}

type Miss = { id: string; reason: 'not_found' | 'wrong_type' | 'invalid_id'; guidance: string };
type DetailBatch<T> = {
  entries: T[];
  notFound: Miss[];
  deferredIds: string[];
  provenance: Provenance;
  guidance?: string;
};

/** Totals and actual processed counts for a size- or count-limited detail batch. */
export function detailEnrichment<T>(result: DetailBatch<T>) {
  const shown = result.entries.length + result.notFound.length;
  return {
    totalCount: shown + result.deferredIds.length,
    ...(result.deferredIds.length
      ? { truncated: true, shown, cap: 20, notice: result.guidance }
      : {}),
  };
}

/**
 * Resolve a batch from one snapshot, then defer whole IDs past the response budget. A default
 * selection is filled per record in its own response; when even the first record does not fit
 * beside the deferred-ID metadata, that record is refilled against the response carrying it.
 */
function resolveDetails<S extends object, T extends Projected>(
  batch: { ids: IdPosition[]; deferredIds: string[] },
  provenance: Provenance,
  options: {
    family: Family;
    lookup: (id: string) => S | undefined;
    /** A position that names no record of this family: absent, another family, or no ID at all. */
    miss: (position: IdPosition) => Miss;
    /** Default selections omit whole sections that do not fit; explicit ones stay complete. */
    fill: boolean;
    project: (source: S, omitted: readonly string[] | undefined) => T;
    toolName: string;
  },
): DetailBatch<T> {
  const size = (result: DetailBatch<T>) => deliveredSize(result, detailEnrichment(result));
  const fits = (result: DetailBatch<T>) => size(result) <= RESPONSE_BUDGET;
  const found = new Map<string, { source: S; entry: T }>();
  const absent = new Map<string, Miss>();
  const ids = batch.ids.map((position) => position.id);
  for (const position of batch.ids) {
    const { id } = position;
    const source = position.family === options.family ? options.lookup(id) : undefined;
    if (!source) {
      absent.set(id, options.miss(position));
      continue;
    }
    const project = (omitted: readonly string[] | undefined) => options.project(source, omitted);
    const entry = options.fill
      ? fillSections(
          project,
          (candidate): DetailBatch<T> => ({
            entries: [candidate],
            notFound: [],
            deferredIds: [],
            provenance,
          }),
          fits,
        ).entry
      : project([]);
    found.set(id, { source, entry });
  }
  /**
   * The first `count` positions; `first` replaces the first record's entry. An oversized response
   * names what overflows: the first result itself, or the deferred IDs echoed beside it.
   */
  const compose = (count: number, oversized: boolean, first?: T): DetailBatch<T> => {
    const selected = ids.slice(0, count);
    const deferredIds = [...ids.slice(count), ...batch.deferredIds];
    const entries = selected.flatMap((id, index) =>
      index === 0 && first ? [first] : (found.get(id)?.entry ?? []),
    );
    const notFound = selected.flatMap((id) => absent.get(id) ?? []);
    const guidance = [
      count < ids.length && 'The 24,000-byte response budget deferred whole identifiers.',
      oversized &&
        (fits({ entries, notFound, deferredIds: [], provenance })
          ? 'The identifiers echoed in deferredIds exceed the 24,000-byte response budget beside the first result, which fits on its own; all are returned so none is lost.'
          : 'One complete selected record and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.'),
      deferredIds.length > 0 &&
        `Repeat ${options.toolName} with deferredIds to retrieve the remaining entries.`,
    ]
      .filter(Boolean)
      .join(' ');
    return {
      entries,
      notFound,
      deferredIds,
      ...(guidance ? { guidance } : {}),
      provenance,
    };
  };
  const build = (count: number, oversized: boolean): DetailBatch<T> => {
    const first = found.get(ids[0] ?? '');
    if (!oversized || !options.fill || !first) return compose(count, oversized);
    // No prefix fits: refill the first record against the response that defers the rest.
    const refill = fillSections(
      (omitted) => options.project(first.source, omitted),
      (entry) => compose(count, false, entry),
      fits,
    );
    return refill.fits ? refill.response : compose(count, true, refill.entry);
  };
  return selectWithinBudget(ids.length, build, size);
}
/** NVD's placeholders for a vulnerability it could not map to a CWE entry. */
const NVD_PLACEHOLDER = /^NVD-CWE-(?:noinfo|Other)$/i;
/** Resolve CWE batches from one captured catalog snapshot. */
export function getWeaknessDetails(
  snapshot: CatalogSnapshot,
  input: {
    ids: readonly string[];
    sections?: readonly string[] | undefined;
    exampleLanguage?: string | undefined;
    exampleOffset: number;
    exampleLimit: number;
  },
) {
  const batch = batchIds(input.ids, 'CWE');
  const languageInput = optionalText(input.exampleLanguage);
  const language = languageInput
    ? resolveVocabulary(snapshot, 'exampleLanguages', 'exampleLanguage', languageInput)
    : undefined;
  const sections = input.sections ?? ['summary', 'consequences', 'mitigations', 'relations'];
  return resolveDetails(batch, snapshot.provenance, {
    toolName: 'cwe_get_weakness',
    family: 'CWE',
    fill: input.sections === undefined,
    lookup: (id) => snapshot.cwe.weaknesses.get(id),
    miss: ({ id, family }): Miss => {
      if (family === undefined)
        return {
          id,
          reason: 'invalid_id',
          guidance: NVD_PLACEHOLDER.test(id)
            ? 'NVD-CWE-noinfo and NVD-CWE-Other are NVD placeholders that name no CWE entry. Call cwe_search_weaknesses with terms from the vulnerability description to find the weakness.'
            : 'Use one CWE ID per item, such as CWE-79, CWE79, or 79. Call cwe_search_weaknesses to find a CWE ID, then repeat cwe_get_weakness.',
        };
      if (family === 'CAPEC')
        return {
          id,
          reason: 'wrong_type',
          guidance: 'This is a CAPEC ID. Call cwe_get_attack_pattern with it.',
        };
      const wrongType = snapshot.cwe.views.has(id);
      return {
        id,
        reason: wrongType ? 'wrong_type' : 'not_found',
        guidance: wrongType
          ? 'Call cwe_get_view with this view ID to retrieve its direct members.'
          : 'Call cwe_search_weaknesses to find an existing CWE ID, then repeat cwe_get_weakness.',
      };
    },
    project: (source, omitted) => {
      const projected = project(source, cweFields, sections, omitted, 'cwe_get_weakness');
      if ('examples' in projected && source.examples !== undefined) {
        const examples = source.examples.filter(
          (example) =>
            !language ||
            example.blocks.some(
              (block) =>
                block.kind === 'code' && block.language?.toLowerCase() === language.toLowerCase(),
            ),
        );
        const offset = input.exampleOffset;
        const selected = examples.slice(offset, offset + input.exampleLimit);
        const next = offset + selected.length;
        Object.assign(projected, {
          examples: selected,
          examplePage: {
            total: examples.length,
            shown: selected.length,
            offset,
            hasMore: next < examples.length,
            ...(next < examples.length ? { nextOffset: next } : {}),
          },
        });
      }
      return weaknessEntrySchema.parse(projected);
    },
  });
}
/** Default CAPEC sections per record type: categories and views carry no attack mechanics. */
const capecDefaults: Record<CapecRecord['type'], readonly string[]> = {
  attack_pattern: ['summary', 'prerequisites', 'execution', 'mitigations', 'mappings'],
  category: ['summary', 'relations'],
  view: ['summary', 'relations'],
};
/** Resolve CAPEC batches of patterns, categories, and views, keeping deprecated records retrievable. */
export function getAttackPatternDetails(
  snapshot: CatalogSnapshot,
  input: { ids: readonly string[]; sections?: readonly string[] | undefined },
) {
  const batch = batchIds(input.ids, 'CAPEC');
  const { attackPatterns, categories, views } = snapshot.capec;
  return resolveDetails(batch, snapshot.provenance, {
    toolName: 'cwe_get_attack_pattern',
    family: 'CAPEC',
    fill: input.sections === undefined,
    lookup: (id): CapecRecord | undefined =>
      attackPatterns.get(id) ?? categories.get(id) ?? views.get(id),
    miss: ({ id, family }): Miss =>
      family === undefined
        ? {
            id,
            reason: 'invalid_id',
            guidance:
              'Use one CAPEC ID per item, such as CAPEC-66, CAPEC66, or 66. Call cwe_search_attack_patterns to find a CAPEC ID, then repeat cwe_get_attack_pattern.',
          }
        : family === 'CWE'
          ? {
              id,
              reason: 'wrong_type',
              guidance:
                'This is a CWE ID. Call cwe_get_weakness with it, or cwe_get_view for a CWE view.',
            }
          : {
              id,
              reason: 'not_found',
              guidance:
                'Call cwe_search_attack_patterns to find an existing CAPEC ID, then repeat cwe_get_attack_pattern.',
            },
    project: (source, omitted) =>
      attackPatternEntrySchema.parse(
        project(
          source,
          capecFields,
          input.sections ?? capecDefaults[source.type],
          omitted,
          'cwe_get_attack_pattern',
        ),
      ),
  });
}
