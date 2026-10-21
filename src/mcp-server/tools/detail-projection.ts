/**
 * @fileoverview Complete per-record section selection, outlines, and example continuation.
 * @module mcp-server/tools/detail-projection
 */
import type { AttackPattern, CatalogSnapshot, Provenance, Weakness } from '@/services/index.js';
import { resolveVocabulary } from '@/services/index.js';
import { attackPatternEntrySchema, weaknessEntrySchema } from './catalog-schemas.js';
import {
  batchIds,
  deliveredSize,
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
] as const;
type SectionMap = Record<string, readonly string[]>;
const cweFields: SectionMap = {
  summary: [
    'description',
    'extendedDescription',
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
  platforms: ['platforms'],
  mappings: ['taxonomyMappings', 'references'],
};
const capecFields: SectionMap = {
  summary: ['description', 'extendedDescription', 'typicalSeverity', 'likelihoodOfAttack'],
  prerequisites: ['prerequisites'],
  execution: ['executionFlow', 'indicators'],
  skills: ['skills', 'resourcesRequired'],
  consequences: ['consequences'],
  mitigations: ['mitigations'],
  examples: ['exampleInstances'],
  relations: ['relatedAttackPatterns'],
  mappings: ['relatedWeaknesses', 'attackTechniqueIds', 'taxonomyMappings', 'references'],
};
function pick(entry: Weakness | AttackPattern, fields: readonly string[]): Record<string, unknown> {
  const values = Object.entries(entry);
  return Object.fromEntries(
    values.filter(([key, value]) => fields.includes(key) && value !== undefined),
  );
}
function project(
  entry: Weakness | AttackPattern,
  groups: SectionMap,
  sections: readonly string[],
  outline = false,
) {
  const availableSections = Object.entries(groups)
    .filter(([, fields]) => Object.keys(pick(entry, fields)).length > 0)
    .map(([key]) => key);
  const identity = {
    id: entry.id,
    name: entry.name,
    status: entry.status,
    sourceUrl: entry.sourceUrl,
    ...('type' in entry ? { type: entry.type } : {}),
    ...(entry.abstraction !== undefined ? { abstraction: entry.abstraction } : {}),
    requestedSections: [...sections],
    availableSections,
  };
  const selected = Object.assign(
    {},
    ...sections.map((section) => pick(entry, groups[section] ?? [])),
  );
  const full = { ...identity, kind: 'full' as const, ...selected };
  const absent = sections.filter((section) => !availableSections.includes(section));
  if (sections.length === 0 || outline)
    return {
      ...identity,
      kind: 'outline' as const,
      outline: availableSections.map((section) => ({
        section,
        sizeInBytes: Buffer.byteLength(JSON.stringify(pick(entry, groups[section] ?? []))),
      })),
      notice: `Repeat ${'type' in entry ? 'cwe_get_weakness' : 'cwe_get_attack_pattern'} with this ID and explicit sections, one section at a time for large records.`,
    };
  return {
    ...full,
    ...(absent.length
      ? {
          notice: `The source entry has no content for these selected sections: ${absent.join(', ')}.`,
        }
      : {}),
  };
}

type Miss = { id: string; reason: 'not_found' | 'wrong_type'; guidance: string };
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

function singleDetail<T>(entry: T, provenance: Provenance): DetailBatch<T> {
  return { entries: [entry], notFound: [], deferredIds: [], provenance };
}

function budgetDetails<T extends { id: string }>(
  batch: { ids: string[]; deferredIds: string[] },
  entries: T[],
  misses: Miss[],
  provenance: Provenance,
  toolName: string,
  outlineFirst?: (entry: T) => T,
) {
  const found = new Map(entries.map((entry) => [entry.id, entry]));
  const absent = new Map(misses.map((miss) => [miss.id, miss]));
  const build = (count: number, oversized = false): DetailBatch<T> => {
    const selected = batch.ids.slice(0, count);
    const deferredIds = [...batch.ids.slice(count), ...batch.deferredIds];
    const guidance = [
      ...(count < batch.ids.length
        ? ['The 24,000-byte response budget deferred whole identifiers.']
        : []),
      ...(oversized
        ? [
            'One complete selected record and its metadata exceed the 24,000-byte response budget; returned intact to preserve forward progress.',
          ]
        : []),
      ...(deferredIds.length
        ? [`Repeat ${toolName} with deferredIds to retrieve the remaining entries.`]
        : []),
    ].join(' ');
    return {
      entries: selected.flatMap((id) => {
        const entry = found.get(id);
        return entry ? [entry] : [];
      }),
      notFound: selected.flatMap((id) => {
        const miss = absent.get(id);
        return miss ? [miss] : [];
      }),
      deferredIds,
      ...(guidance ? { guidance } : {}),
      provenance,
    };
  };
  return selectWithinBudget(
    batch.ids.length,
    (count) => build(count),
    (result) => deliveredSize(result, detailEnrichment(result)),
    () => {
      const firstId = batch.ids[0];
      const first = firstId ? found.get(firstId) : undefined;
      if (first && outlineFirst) {
        found.set(first.id, outlineFirst(first));
        const outlined = build(1);
        if (deliveredSize(outlined, detailEnrichment(outlined)) <= RESPONSE_BUDGET) return outlined;
      }
      return build(1, true);
    },
  );
}
/** Resolve CWE batches from one captured catalog snapshot. */
export function getWeaknessDetails(
  snapshot: CatalogSnapshot,
  input: {
    ids: readonly string[];
    sections?: readonly string[] | undefined;
    exampleLanguage?: string | undefined;
    exampleOffset?: number;
    exampleLimit?: number;
  },
) {
  const batch = batchIds(input.ids, 'CWE');
  const languageInput = optionalText(input.exampleLanguage);
  const language = languageInput
    ? resolveVocabulary(snapshot, 'exampleLanguages', languageInput)
    : undefined;
  const sections = input.sections ?? ['summary', 'consequences', 'mitigations', 'relations'];
  const entries: ReturnType<typeof weaknessEntrySchema.parse>[] = [];
  const notFound: { id: string; reason: 'not_found' | 'wrong_type'; guidance: string }[] = [];
  for (const id of batch.ids) {
    const source = snapshot.cwe.weaknesses.get(id);
    if (!source) {
      const wrongType = snapshot.cwe.views.has(id);
      notFound.push({
        id,
        reason: wrongType ? 'wrong_type' : 'not_found',
        guidance: wrongType
          ? 'Call cwe_get_view with this view ID to retrieve its direct members.'
          : 'Call cwe_search_weaknesses to find an existing CWE ID, then repeat cwe_get_weakness.',
      });
      continue;
    }
    let projected = project(source, cweFields, sections);
    if (
      projected.kind === 'full' &&
      sections.includes('examples') &&
      source.examples !== undefined
    ) {
      const examples = source.examples.filter(
        (example) =>
          !language ||
          example.blocks.some(
            (block) =>
              block.kind === 'code' && block.language?.toLowerCase() === language.toLowerCase(),
          ),
      );
      const offset = input.exampleOffset ?? 0;
      const selected = examples.slice(offset, offset + (input.exampleLimit ?? 3));
      Object.assign(projected, {
        examples: selected,
        examplePage: {
          total: examples.length,
          shown: selected.length,
          offset,
          hasMore: offset + selected.length < examples.length,
          ...(offset + selected.length < examples.length
            ? { nextOffset: offset + selected.length }
            : {}),
        },
      });
    }
    let entry = weaknessEntrySchema.parse(projected);
    const single = singleDetail(entry, snapshot.provenance);
    if (
      input.sections === undefined &&
      deliveredSize(single, detailEnrichment(single)) > RESPONSE_BUDGET
    ) {
      projected = project(source, cweFields, sections, true);
      entry = weaknessEntrySchema.parse(projected);
    }
    entries.push(entry);
  }
  return budgetDetails(
    batch,
    entries,
    notFound,
    snapshot.provenance,
    'cwe_get_weakness',
    input.sections === undefined
      ? (entry) => {
          const source = snapshot.cwe.weaknesses.get(entry.id);
          if (!source)
            throw new Error(
              `Projected CWE entry is absent from its captured snapshot: ${entry.id}`,
            );
          return weaknessEntrySchema.parse(project(source, cweFields, sections, true));
        }
      : undefined,
  );
}
/** Resolve CAPEC batches, keeping deprecated records retrievable. */
export function getAttackPatternDetails(
  snapshot: CatalogSnapshot,
  input: { ids: readonly string[]; sections?: readonly string[] | undefined },
) {
  const batch = batchIds(input.ids, 'CAPEC');
  const sections = input.sections ?? [
    'summary',
    'prerequisites',
    'execution',
    'mitigations',
    'mappings',
  ];
  const entries: ReturnType<typeof attackPatternEntrySchema.parse>[] = [];
  const notFound: { id: string; reason: 'not_found'; guidance: string }[] = [];
  for (const id of batch.ids) {
    const source = snapshot.capec.attackPatterns.get(id);
    if (!source) {
      notFound.push({
        id,
        reason: 'not_found',
        guidance:
          'Call cwe_search_attack_patterns to find an existing CAPEC ID, then repeat cwe_get_attack_pattern.',
      });
      continue;
    }
    let entry = attackPatternEntrySchema.parse(project(source, capecFields, sections));
    const single = singleDetail(entry, snapshot.provenance);
    if (
      input.sections === undefined &&
      deliveredSize(single, detailEnrichment(single)) > RESPONSE_BUDGET
    )
      entry = attackPatternEntrySchema.parse(project(source, capecFields, sections, true));
    entries.push(entry);
  }
  return budgetDetails(
    batch,
    entries,
    notFound,
    snapshot.provenance,
    'cwe_get_attack_pattern',
    input.sections === undefined
      ? (entry) => {
          const source = snapshot.capec.attackPatterns.get(entry.id);
          if (!source)
            throw new Error(
              `Projected CAPEC entry is absent from its captured snapshot: ${entry.id}`,
            );
          return attackPatternEntrySchema.parse(project(source, capecFields, sections, true));
        }
      : undefined,
  );
}
