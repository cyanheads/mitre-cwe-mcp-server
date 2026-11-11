/**
 * @fileoverview Complete per-record section selection, outlines, and example continuation.
 * @module mcp-server/tools/detail-projection
 */
import type { CapecRecord, CatalogSnapshot, Provenance, Weakness } from '@/services/index.js';
import { resolveVocabulary } from '@/services/index.js';
import { attackPatternEntrySchema, weaknessEntrySchema } from './catalog-schemas.js';
import { batchIds, type Family, formatCatalog, type IdPosition, optionalText } from './shared.js';
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
    'technicalNuance',
    'dimensions',
    'ordinalities',
    'backgroundDetails',
    'alternateTerms',
    'likelihoodOfExploit',
    'modesOfIntroduction',
    'unphasedIntroductionNotes',
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
  relations: ['relatedAttackPatterns', 'childAttackPatterns', 'members', 'filterDefinition'],
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
/** Project the selected sections or an explicit outline of the available sections. */
function project(
  entry: Weakness | CapecRecord,
  groups: SectionMap,
  sections: readonly string[],
  toolName: 'cwe_get_weakness' | 'cwe_get_attack_pattern',
  exampleFields?: Record<string, unknown>,
) {
  const rawFieldsOf = (section: string) => pick(entry, groups[section] ?? []);
  const fieldsOf = (section: string) =>
    section === 'examples' && exampleFields ? exampleFields : rawFieldsOf(section);
  const availableSections = Object.keys(groups).filter(
    (section) => Object.keys(rawFieldsOf(section)).length > 0,
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
  if (sections.length === 0) {
    return {
      ...identity,
      kind: 'outline' as const,
      outline: availableSections.map((section) => ({
        section,
        sizeInBytes: sectionSize(fieldsOf(section)),
      })),
      notice: `Repeat ${toolName} with this ID and explicit sections, one section at a time for large records.`,
    };
  }
  const absent = sections.filter((section) => !availableSections.includes(section));
  return {
    ...identity,
    kind: 'full' as const,
    ...Object.assign({}, ...sections.map(fieldsOf)),
    ...(absent.length
      ? {
          notice: `The source entry has no content for these selected sections: ${absent.join(', ')}.`,
        }
      : {}),
  };
}

type Miss = { id: string; reason: 'not_found' | 'wrong_type' | 'invalid_id'; guidance: string };
type DetailBatch<T> = {
  entries: T[];
  notFound: Miss[];
  deferredIds: string[];
  provenance: Provenance;
  guidance?: string;
};

/** Distinct position counts and whole-ID continuation for a detail batch. */
export function detailEnrichment<T>(result: DetailBatch<T>) {
  const shown = result.entries.length + result.notFound.length;
  return {
    totalCount: shown + result.deferredIds.length,
    ...(result.deferredIds.length
      ? { truncated: true, shown, cap: 20, notice: result.guidance }
      : {}),
  };
}

/** Resolve the first distinct positions in one snapshot and return the rest for continuation. */
function resolveDetails<S extends object, T>(
  batch: { ids: IdPosition[]; deferredIds: string[] },
  provenance: Provenance,
  options: {
    family: Family;
    lookup: (id: string) => S | undefined;
    miss: (position: IdPosition) => Miss;
    project: (source: S) => T;
    toolName: string;
    callGuidance?: string | undefined;
  },
): DetailBatch<T> {
  const entries: T[] = [];
  const notFound: Miss[] = [];
  for (const position of batch.ids) {
    const source = position.family === options.family ? options.lookup(position.id) : undefined;
    if (source) entries.push(options.project(source));
    else notFound.push(options.miss(position));
  }
  const guidance = [
    batch.deferredIds.length > 0 &&
      `Repeat ${options.toolName} with deferredIds to retrieve the remaining entries.`,
    options.callGuidance,
  ]
    .filter(Boolean)
    .join(' ');
  return {
    entries,
    notFound,
    deferredIds: batch.deferredIds,
    ...(guidance ? { guidance } : {}),
    provenance,
  };
}
/** NVD's placeholders for a vulnerability it could not map to a CWE entry. */
const NVD_PLACEHOLDER = /^NVD-CWE-(?:noinfo|Other)$/i;
/** The `exampleLimit` default; any other value puts the example parameters in effect. */
export const DEFAULT_EXAMPLE_LIMIT = 3;
/**
 * Resolve CWE batches from one captured catalog snapshot. Example parameters in effect (a language,
 * an offset above 0, or a limit other than the default) add `examples` to a default selection.
 * An explicit selection without `examples` stays unchanged and the batch guidance
 * gives the re-call that applies them.
 */
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
  const { exampleOffset: offset, exampleLimit: limit } = input;
  /** The example parameters in effect, as a re-call names them; empty when none is. */
  const exampleArgs = [
    language !== undefined && `exampleLanguage ${JSON.stringify(language)}`,
    offset > 0 && `exampleOffset ${offset}`,
    limit !== DEFAULT_EXAMPLE_LIMIT && `exampleLimit ${limit}`,
  ]
    .filter(Boolean)
    .join(', ');
  const sections = input.sections ?? [
    'summary',
    'consequences',
    'mitigations',
    'relations',
    ...(exampleArgs ? ['examples'] : []),
  ];
  const selectsExamples = sections.includes('examples');
  /**
   * The language-filtered example page the parameters select; with `plain`, the default page that a
   * re-call naming no example parameter returns, which an outline of unselected examples reports.
   */
  const examplePage = (source: NonNullable<Weakness['examples']>, plain = false) => {
    const lang = plain ? undefined : language;
    const start = plain ? 0 : offset;
    const examples = source.filter(
      (example) =>
        !lang ||
        example.blocks.some(
          (block) => block.kind === 'code' && block.language?.toLowerCase() === lang.toLowerCase(),
        ),
    );
    const selected = examples.slice(start, start + (plain ? DEFAULT_EXAMPLE_LIMIT : limit));
    const next = start + selected.length;
    return {
      examples: selected,
      examplePage: {
        total: examples.length,
        shown: selected.length,
        offset: start,
        hasMore: next < examples.length,
        ...(next < examples.length ? { nextOffset: next } : {}),
      },
    };
  };
  return resolveDetails(batch, snapshot.provenance, {
    toolName: 'cwe_get_weakness',
    family: 'CWE',
    callGuidance:
      exampleArgs && !selectsExamples
        ? `The example parameters (${exampleArgs}) apply only to section examples, which the selected sections exclude. Repeat cwe_get_weakness with sections ${JSON.stringify([...sections, 'examples'])} to apply them.`
        : undefined,
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
    project: (source) =>
      weaknessEntrySchema.parse(
        project(
          source,
          cweFields,
          sections,
          'cwe_get_weakness',
          source.examples && (selectsExamples || sections.length === 0)
            ? examplePage(source.examples, !selectsExamples)
            : undefined,
        ),
      ),
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
    project: (source) =>
      attackPatternEntrySchema.parse(
        project(
          source,
          capecFields,
          input.sections ?? capecDefaults[source.type],
          'cwe_get_attack_pattern',
        ),
      ),
  });
}
