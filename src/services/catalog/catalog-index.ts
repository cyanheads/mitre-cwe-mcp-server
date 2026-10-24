/**
 * @fileoverview Immutable catalog snapshots, crosswalk indexes, and local filtering.
 * @module services/catalog/catalog-index
 */
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdown } from './markdown-escape.js';
import type {
  AttackPattern,
  CapecCatalog,
  CapecGrouping,
  CapecMember,
  CapecRecord,
  CatalogHealth,
  CatalogSnapshot,
  CweCatalog,
  Member,
  SearchText,
  TaxonomyMapping,
  Weakness,
} from './types.js';
import { compileViewFilter } from './view-filter.js';
import { collapse } from './xml-normalization.js';

/** Hide mutable Map methods, including from JavaScript consumers. */
function readonlyMap<K, V>(source: ReadonlyMap<K, V>): ReadonlyMap<K, V> {
  const copy = new Map(source);
  const result: ReadonlyMap<K, V> = {
    get size() {
      return copy.size;
    },
    get: (key) => copy.get(key),
    has: (key) => copy.has(key),
    entries: () => copy.entries(),
    keys: () => copy.keys(),
    values: () => copy.values(),
    [Symbol.iterator]: () => copy[Symbol.iterator](),
    forEach(callback, thisArg) {
      copy.forEach((value, key) => {
        callback.call(thisArg, value, key, result);
      });
    },
  };
  return Object.freeze(result);
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** Freeze every list before hiding the map's mutators. */
function readonlyLists<K>(source: Map<K, string[]>): ReadonlyMap<K, readonly string[]> {
  for (const values of source.values()) Object.freeze(values);
  return readonlyMap(source);
}
function append(map: Map<string, string[]>, key: string, value: string): void {
  const values = map.get(key);
  if (values) {
    if (!values.includes(value)) values.push(value);
  } else map.set(key, [value]);
}
/** Attach the loaded record name to a recorded relation whose target exists. */
function withName<T extends { id: string }>(
  related: T,
  records: ReadonlyMap<string, { name: string }>,
) {
  const record = records.get(related.id);
  return { ...related, ...(record ? { name: record.name } : {}) };
}
const PLATFORM_VOCABULARY = {
  language: 'languages',
  technology: 'technologies',
  OS: 'operatingSystems',
  architecture: 'architectures',
} as const satisfies Record<NonNullable<Weakness['platforms']>[number]['kind'], string>;

/** Build replacement indexes before publication; never mutate an existing snapshot. */
export function buildCatalogSnapshot(
  cwe: CweCatalog,
  capec: CapecCatalog,
  health: { cwe: CatalogHealth; capec: CatalogHealth },
  loadedAt: string,
): CatalogSnapshot {
  const hydrate = (member: Member): Member => {
    const entry = cwe.weaknesses.get(member.id);
    const view = cwe.views.get(member.id);
    return {
      ...member,
      ...(entry
        ? {
            name: entry.name,
            type: entry.type,
            status: entry.status,
            ...(entry.abstraction ? { abstraction: entry.abstraction } : {}),
          }
        : view
          ? { name: view.name, type: 'view', status: view.status }
          : {}),
    };
  };
  const weaknesses = new Map<string, Weakness>();
  const attackPatterns = new Map<string, AttackPattern>();
  const attackPatternsByWeakness = new Map<string, string[]>();
  const childrenByView = new Map<string, Map<string, string[]>>();
  const vocabulary = new Map<string, string[]>();
  const addVocabulary = (key: string, values: readonly (string | undefined)[]) => {
    for (const value of values) if (value !== undefined) append(vocabulary, key, value);
  };
  const categoryStatuses = new Set<string>();
  const addChild = (viewId: string, parent: string, child: string) => {
    let view = childrenByView.get(viewId);
    if (!view) {
      view = new Map();
      childrenByView.set(viewId, view);
    }
    append(view, parent, child);
  };
  for (const [id, source] of cwe.weaknesses) {
    const entry: Weakness = {
      ...source,
      ...(source.members ? { members: source.members.map(hydrate) } : {}),
      ...(source.relatedWeaknesses
        ? {
            relatedWeaknesses: source.relatedWeaknesses.map((related) =>
              withName(related, cwe.weaknesses),
            ),
          }
        : {}),
      ...(source.relatedAttackPatterns
        ? {
            relatedAttackPatterns: source.relatedAttackPatterns.map((related) =>
              withName(related, capec.attackPatterns),
            ),
          }
        : {}),
    };
    weaknesses.set(id, freeze(entry));
    if (entry.type === 'weakness') {
      addVocabulary('cweStatuses', [entry.status]);
      addVocabulary('cweAbstractions', [entry.abstraction]);
      addVocabulary('cweMappingUsages', [entry.mappingNotes?.usage]);
      addVocabulary(
        'cweTaxonomyNames',
        entry.taxonomyMappings?.map((mapping) => mapping.taxonomy) ?? [],
      );
    } else categoryStatuses.add(entry.status);
    addVocabulary('consequenceImpacts', entry.consequences?.flatMap((item) => item.impacts) ?? []);
    addVocabulary('mitigationPhases', entry.mitigations?.flatMap((item) => item.phases) ?? []);
    addVocabulary(
      'exampleLanguages',
      entry.examples?.flatMap((example) =>
        example.blocks.flatMap((block) => (block.kind === 'code' ? [block.language] : [])),
      ) ?? [],
    );
    for (const platform of entry.platforms ?? [])
      addVocabulary(PLATFORM_VOCABULARY[platform.kind], [platform.name, platform.class]);
    for (const relation of entry.relatedWeaknesses ?? []) {
      addVocabulary('relationshipNatures', [relation.nature]);
      if (relation.nature === 'ChildOf') addChild(relation.viewId, relation.id, entry.id);
    }
    for (const member of entry.members ?? []) addChild(member.viewId, entry.id, member.id);
  }
  // Statuses only categories carry resolve as filter values but are never listed.
  const weaknessStatuses = vocabulary.get('cweStatuses') ?? [];
  addVocabulary(
    CATEGORY_ONLY_STATUSES,
    [...categoryStatuses].filter((status) => !weaknessStatuses.includes(status)),
  );
  for (const [id, source] of capec.attackPatterns) {
    const entry: AttackPattern = {
      ...source,
      ...(source.relatedWeaknesses
        ? {
            relatedWeaknesses: source.relatedWeaknesses.map((related) => {
              append(attackPatternsByWeakness, related.id, source.id);
              return withName(related, cwe.weaknesses);
            }),
          }
        : {}),
      ...(source.relatedAttackPatterns
        ? {
            relatedAttackPatterns: source.relatedAttackPatterns.map((related) =>
              withName(related, capec.attackPatterns),
            ),
          }
        : {}),
    };
    attackPatterns.set(id, freeze(entry));
    addVocabulary('capecStatuses', [entry.status]);
    addVocabulary('capecAbstractions', [entry.abstraction]);
    addVocabulary('capecSeverities', [entry.typicalSeverity]);
    addVocabulary('capecLikelihoods', [entry.likelihoodOfAttack]);
    addVocabulary(
      'relationshipNatures',
      entry.relatedAttackPatterns?.map((item) => item.nature) ?? [],
    );
  }
  const views = new Map(
    [...cwe.views].map(([id, view]) => {
      for (const member of view.members) addChild(member.viewId, view.id, member.id);
      return [id, freeze({ ...view, members: view.members.map(hydrate) })] as const;
    }),
  );
  const capecRecord = (id: string): CapecRecord | undefined =>
    capec.attackPatterns.get(id) ?? capec.categories.get(id) ?? capec.views.get(id);
  const hydrateCapec = (member: CapecMember): CapecMember => {
    const record = capecRecord(member.id);
    return {
      ...member,
      ...(record
        ? {
            name: record.name,
            type: record.type,
            status: record.status,
            ...(record.type === 'attack_pattern' ? { abstraction: record.abstraction } : {}),
          }
        : {}),
    };
  };
  const capecGroupings = (source: ReadonlyMap<string, CapecGrouping>) =>
    readonlyMap(
      new Map(
        [...source].map(([id, entry]) => [
          id,
          freeze({
            ...entry,
            ...(entry.members ? { members: entry.members.map(hydrateCapec) } : {}),
          }),
        ]),
      ),
    );
  for (const values of vocabulary.values()) values.sort((a, b) => a.localeCompare(b, 'en'));
  const frozenTexts = (texts: ReadonlyMap<string, SearchText>) =>
    readonlyMap(new Map([...texts].map(([id, text]) => [id, freeze({ ...text })])));
  return freeze({
    cwe: {
      version: cwe.version,
      date: cwe.date,
      weaknesses: readonlyMap(weaknesses),
      views: readonlyMap(views),
      searchText: frozenTexts(cwe.searchText),
    },
    capec: {
      version: capec.version,
      date: capec.date,
      attackPatterns: readonlyMap(attackPatterns),
      categories: capecGroupings(capec.categories),
      views: capecGroupings(capec.views),
      searchText: frozenTexts(capec.searchText),
    },
    provenance: {
      cweVersion: cwe.version,
      cweDate: cwe.date,
      capecVersion: capec.version,
      capecDate: capec.date,
      loadedAt,
    },
    health: { cwe: freeze({ ...health.cwe }), capec: freeze({ ...health.capec }) },
    attackPatternsByWeakness: readonlyLists(attackPatternsByWeakness),
    childrenByView: readonlyMap(
      new Map([...childrenByView].map(([view, entries]) => [view, readonlyLists(entries)])),
    ),
    vocabulary: readonlyLists(vocabulary),
  });
}

/** The `cwe_list_reference` topics that list loaded vocabulary, and the vocabulary keys of each. */
export const REFERENCE_VOCABULARIES = {
  abstraction_levels: ['cweAbstractions', 'capecAbstractions'],
  mitigation_phases: ['mitigationPhases'],
  platforms: ['languages', 'technologies', 'operatingSystems', 'architectures', 'exampleLanguages'],
  relationship_natures: ['relationshipNatures'],
  filter_values: [
    'consequenceImpacts',
    'cweStatuses',
    'cweMappingUsages',
    'cweTaxonomyNames',
    'capecStatuses',
    'capecSeverities',
    'capecLikelihoods',
  ],
} as const satisfies Record<string, readonly string[]>;
/** A loaded vocabulary that a reference topic lists. */
export type VocabularyKey =
  (typeof REFERENCE_VOCABULARIES)[keyof typeof REFERENCE_VOCABULARIES][number];
/** The unlisted vocabulary of CWE statuses that categories carry and no weakness does. */
const CATEGORY_ONLY_STATUSES = 'cweCategoryOnlyStatuses';
/** Vocabularies this short are listed in full in an `unknown_filter` message. */
const LISTED_VOCABULARY = 10;

/**
 * Resolve a dynamic filter without broadening it. An unknown value names the field and the value,
 * and lists a short vocabulary or names the reference topic that lists a longer one.
 */
export function resolveVocabulary(
  snapshot: CatalogSnapshot,
  key: VocabularyKey,
  field: string,
  value: string,
): string {
  const normalized = value.trim().toLowerCase();
  const supported = snapshot.vocabulary.get(key) ?? [];
  const match = supported.find((item) => item.toLowerCase() === normalized);
  if (match !== undefined) return match;
  const listed = supported.length <= LISTED_VOCABULARY;
  const topic = Object.entries(REFERENCE_VOCABULARIES).find(([, keys]) =>
    (keys as readonly string[]).includes(key),
  )?.[0];
  throw validationError(
    `Unknown ${field} "${escapeMarkdown(value)}"; ${
      listed
        ? `supported values: ${supported.length ? supported.map((item) => escapeMarkdown(item)).join(', ') : 'none in the loaded catalog'}.`
        : `cwe_list_reference topic ${topic} lists the supported values.`
    }`,
    {
      reason: 'unknown_filter',
      retryable: false,
      field,
      value,
      ...(listed ? { supported } : {}),
    },
  );
}

/** CWE statuses that occur on categories and on no weakness, which search therefore never matches. */
export function categoryOnlyStatuses(snapshot: CatalogSnapshot): readonly string[] {
  return snapshot.vocabulary.get(CATEGORY_ONLY_STATUSES) ?? [];
}

/**
 * Resolve a CWE status filter. A status that only categories carry is accepted, since search
 * excludes categories and an empty result is the correct answer, but it is never listed, so an
 * unknown status lists only the statuses weaknesses carry.
 */
export function resolveWeaknessStatus(snapshot: CatalogSnapshot, value: string): string {
  const normalized = value.trim().toLowerCase();
  return (
    categoryOnlyStatuses(snapshot).find((status) => status.toLowerCase() === normalized) ??
    resolveVocabulary(snapshot, 'cweStatuses', 'status', value)
  );
}

/** Why a CWE ID cannot scope by view: the record family it names, or its absence. */
export function nonViewSentence(snapshot: CatalogSnapshot, viewId: string): string {
  const type = snapshot.cwe.weaknesses.get(viewId)?.type;
  return type
    ? `viewId ${viewId} is a ${type}, not a CWE view.`
    : `viewId ${viewId} is not a CWE view in the loaded catalog.`;
}

/**
 * A view's weaknesses: its source-recorded, same-view membership closure (with cycle protection),
 * plus every weakness its source filter selects. A filter with a part outside the supported shapes
 * selects none.
 */
export function weaknessesInView(snapshot: CatalogSnapshot, viewId: string): ReadonlySet<string> {
  const view = snapshot.cwe.views.get(viewId);
  if (!view)
    throw validationError(nonViewSentence(snapshot, viewId), {
      reason: 'unknown_filter',
      retryable: false,
      field: 'viewId',
      value: viewId,
    });
  const links = snapshot.childrenByView.get(viewId);
  const visited = new Set<string>();
  const pending = [
    ...view.members.filter((member) => member.viewId === viewId).map((member) => member.id),
    ...(links?.get(viewId) ?? []),
  ];
  const result = new Set<string>();
  while (pending.length) {
    const id = pending.pop() as string;
    if (visited.has(id)) continue;
    visited.add(id);
    if (snapshot.cwe.weaknesses.get(id)?.type === 'weakness') result.add(id);
    pending.push(...(links?.get(id) ?? []));
  }
  const filter =
    view.filterDefinition === undefined ? undefined : compileViewFilter(view.filterDefinition);
  if (filter)
    for (const entry of snapshot.cwe.weaknesses.values())
      if (entry.type === 'weakness' && filter(entry)) result.add(entry.id);
  return result;
}

/** Local CWE filters, applied before full-result sorting and pagination. */
export interface WeaknessFilters {
  abstraction?: string;
  consequenceImpact?: string;
  filter?: string;
  language?: string;
  mappingUsage?: string;
  observedCveId?: string;
  status?: string;
  taxonomyEntryId?: string;
  taxonomyName?: string;
  technology?: string;
  viewId?: string;
}
/** Local CAPEC filters, with inactive records excluded unless explicitly requested. */
export interface AttackPatternFilters {
  abstraction?: string;
  attackTechniqueId?: string;
  cweId?: string;
  filter?: string;
  includeInactive?: boolean;
  likelihood?: string;
  severity?: string;
}

function compareIds(a: { id: string }, b: { id: string }): number {
  return Number(a.id.replace(/^\D+/, '')) - Number(b.id.replace(/^\D+/, ''));
}
function tokens(filter: string | undefined): string[] {
  return filter?.trim().toLowerCase().split(/\s+/).filter(Boolean) ?? [];
}
/**
 * At `lastIndex`, a word start: a letter or digit after any other character, or a camelCase hump,
 * an uppercase letter after a lowercase one or between an uppercase and a lowercase one.
 */
const WORD_START =
  /(?<![\p{L}\p{N}])(?=[\p{L}\p{N}])|(?<=\p{Ll})(?=\p{Lu})|(?<=\p{Lu})(?=\p{Lu}\p{Ll})/uy;
/** The next word start at or after `lastIndex`. */
const NEXT_WORD_START = new RegExp(WORD_START.source, 'gu');
/** At `lastIndex`, a digit. */
const DIGIT = /\p{N}/uy;
const WORD_LED = /^[\p{L}\p{N}]/u;
const DIGIT_ENDED = /\p{N}$/u;
const PREFIX_ELIGIBLE = /^\p{L}{4,}$/u;
function holdsAt(pattern: RegExp, text: string, index: number): boolean {
  pattern.lastIndex = index;
  return pattern.test(text);
}

/**
 * The filter-token test that every text filter shares, bound to one text. A lowercased token
 * starting with a letter or digit matches at a word start: the text start, after any other
 * character (`_` included), or at a camelCase hump in the original-case text (`dos` in ReDoS, `path`
 * in XPath). A token ending in a digit never matches before a digit (`79` skips RFC 793). A token
 * starting with punctuation (`.net`, `"<script>"`) matches anywhere. The search is literal, with
 * one-character boundary tests beside it and no pattern built from the token. After a rejected
 * occurrence it resumes at the next word start, so each run of word characters is passed once.
 * Tokens of at least four Unicode letters also match after one literal un or mis prefix at an
 * existing word start. Prefixes are never stripped recursively; spelling coincidences can match.
 */
export function tokenMatcher(text: string): (token: string) => boolean {
  /**
   * Lowercase with every code unit at its source position, so a boundary test reads the original
   * case at a match. U+0130 is the one character whose lowercase is longer (i + U+0307): it folds
   * to i here, and its lowercase folds to i in the token.
   */
  const folded = text.toLowerCase();
  const lower =
    folded.length === text.length ? folded : text.replaceAll('\u0130', 'i').toLowerCase();
  return (raw) => {
    const token = raw.replaceAll('i\u0307', 'i');
    let index = lower.indexOf(token);
    if (index === -1 || !WORD_LED.test(token)) return index !== -1;
    const digitEnded = DIGIT_ENDED.test(token);
    const prefixEligible = PREFIX_ELIGIBLE.test(token);
    while (index !== -1) {
      if (
        (holdsAt(WORD_START, text, index) ||
          (prefixEligible &&
            ((lower.slice(index - 2, index) === 'un' && holdsAt(WORD_START, text, index - 2)) ||
              (lower.slice(index - 3, index) === 'mis' &&
                holdsAt(WORD_START, text, index - 3))))) &&
        !(digitEnded && holdsAt(DIGIT, text, index + token.length))
      )
        return true;
      NEXT_WORD_START.lastIndex = index + 1;
      const next = NEXT_WORD_START.exec(text);
      if (!next) return false;
      index = lower.indexOf(token, next.index);
    }
    return false;
  };
}
/** A record's plain-text search projection, which every searched record has. */
function projection(entry: { id: string }, texts: ReadonlyMap<string, SearchText>): SearchText {
  const text = texts.get(entry.id);
  if (!text) throw new Error(`No search projection exists for ${entry.id}.`);
  return text;
}
/** Every field a filter token is matched against, joined by a line break that no token holds. */
function searchedText(entry: { name: string }, text: SearchText): string {
  return [
    entry.name,
    ...(text.alternateTerms ?? []),
    text.description,
    text.extendedDescription ?? '',
  ].join('\n');
}
/**
 * Match every filter token (`tokenMatcher`) against the name and the record's search projection:
 * tier 0 when the name or one alternate term holds every token, 1 when the description does, 2 when
 * they are spread across the searched fields, and undefined when a token is absent. A name token
 * plus a token from an unrelated term is a spread match, never tier 0.
 */
function matchTier(
  entry: { id: string; name: string },
  texts: ReadonlyMap<string, SearchText>,
  filterTokens: readonly string[],
): number | undefined {
  if (!filterTokens.length) return 0;
  const text = projection(entry, texts);
  const matchesAll = (value: string) => filterTokens.every(tokenMatcher(value));
  if (!matchesAll(searchedText(entry, text))) return undefined;
  if ([entry.name, ...(text.alternateTerms ?? [])].some(matchesAll)) return 0;
  return matchesAll(text.description) ? 1 : 2;
}
/** Deprecated and Obsolete patterns, which CAPEC search excludes unless asked to include them. */
function inactive(entry: AttackPattern): boolean {
  return ['deprecated', 'obsolete'].includes(entry.status.toLowerCase());
}
/** Order matches by tier, then numeric ID. */
function ranked<T extends { id: string }>(matches: { entry: T; tier: number }[]): T[] {
  return matches
    .sort((a, b) => a.tier - b.tier || compareIds(a.entry, b.entry))
    .map(({ entry }) => entry);
}
function onPlatform(entry: Weakness, kind: 'language' | 'technology', value: string) {
  return entry.platforms?.some(
    (platform) => platform.kind === kind && (platform.name === value || platform.class === value),
  );
}
function canonical(
  snapshot: CatalogSnapshot,
  key: VocabularyKey,
  field: string,
  value: string | undefined,
): string | undefined {
  return value?.trim() ? resolveVocabulary(snapshot, key, field, value) : undefined;
}

/** One observed example a weakness records. */
type ObservedExample = NonNullable<Weakness['observedExamples']>[number];
/**
 * The recorded-evidence tests of one weakness search, resolved once: a taxonomy mapping test when
 * `taxonomyName` or `taxonomyEntryId` applies, both holding on the same mapping, and an observed
 * example test when `observedCveId` applies. The name resolves through `cweTaxonomyNames`; the
 * Entry_ID compares case-insensitively in the trimmed, whitespace-collapsed form it is stored in;
 * the CVE compares uppercased with the recorded reference.
 */
export function evidenceMatchers(
  snapshot: CatalogSnapshot,
  filters: WeaknessFilters,
): {
  mapping?: (mapping: TaxonomyMapping) => boolean;
  example?: (example: ObservedExample) => boolean;
} {
  const taxonomy = canonical(snapshot, 'cweTaxonomyNames', 'taxonomyName', filters.taxonomyName);
  const entryId = filters.taxonomyEntryId?.trim()
    ? collapse(filters.taxonomyEntryId).toLowerCase()
    : undefined;
  const cve = filters.observedCveId?.trim().toUpperCase() || undefined;
  return {
    ...(taxonomy || entryId
      ? {
          mapping: (mapping: TaxonomyMapping) =>
            (!taxonomy || mapping.taxonomy === taxonomy) &&
            (!entryId || mapping.id?.toLowerCase() === entryId),
        }
      : {}),
    ...(cve ? { example: (example: ObservedExample) => example.reference === cve } : {}),
  };
}
/**
 * The Entry_ID spelling a weakness mapping records for a `taxonomyEntryId` filter, matched as the
 * search matches it, or the trimmed, whitespace-collapsed value when no weakness records it.
 */
export function recordedEntryId(snapshot: CatalogSnapshot, value: string): string {
  const id = collapse(value);
  const folded = id.toLowerCase();
  for (const entry of snapshot.cwe.weaknesses.values())
    if (entry.type === 'weakness')
      for (const mapping of entry.taxonomyMappings ?? [])
        if (mapping.id?.toLowerCase() === folded) return mapping.id;
  return id;
}

/** Search weaknesses, preserving deterministic documented ordering over all matches. */
export function searchWeaknesses(snapshot: CatalogSnapshot, filters: WeaknessFilters): Weakness[] {
  const language = canonical(snapshot, 'languages', 'language', filters.language);
  const technology = canonical(snapshot, 'technologies', 'technology', filters.technology);
  const abstraction = canonical(snapshot, 'cweAbstractions', 'abstraction', filters.abstraction);
  const status = filters.status?.trim()
    ? resolveWeaknessStatus(snapshot, filters.status)
    : undefined;
  const mappingUsage = canonical(
    snapshot,
    'cweMappingUsages',
    'mappingUsage',
    filters.mappingUsage,
  );
  const impact = canonical(
    snapshot,
    'consequenceImpacts',
    'consequenceImpact',
    filters.consequenceImpact,
  );
  const { mapping, example } = evidenceMatchers(snapshot, filters);
  const scope = filters.viewId ? weaknessesInView(snapshot, filters.viewId) : undefined;
  const terms = tokens(filters.filter);
  return ranked(
    [...snapshot.cwe.weaknesses.values()].flatMap((entry) => {
      if (
        entry.type !== 'weakness' ||
        (scope && !scope.has(entry.id)) ||
        (mapping && !entry.taxonomyMappings?.some(mapping)) ||
        (example && !entry.observedExamples?.some(example)) ||
        (abstraction && entry.abstraction !== abstraction) ||
        (status && entry.status !== status) ||
        (mappingUsage && entry.mappingNotes?.usage !== mappingUsage) ||
        (language && !onPlatform(entry, 'language', language)) ||
        (technology && !onPlatform(entry, 'technology', technology)) ||
        (impact && !entry.consequences?.some((consequence) => consequence.impacts.includes(impact)))
      )
        return [];
      const tier = matchTier(entry, snapshot.cwe.searchText, terms);
      return tier === undefined ? [] : [{ entry, tier }];
    }),
  );
}

/** Search recorded CAPEC mappings; parent ATT&CK IDs match only subtechnique boundaries. */
export function searchAttackPatterns(
  snapshot: CatalogSnapshot,
  filters: AttackPatternFilters,
): AttackPattern[] {
  const abstraction = canonical(snapshot, 'capecAbstractions', 'abstraction', filters.abstraction);
  const severity = canonical(snapshot, 'capecSeverities', 'severity', filters.severity);
  const likelihood = canonical(snapshot, 'capecLikelihoods', 'likelihood', filters.likelihood);
  const terms = tokens(filters.filter);
  return ranked(
    [...snapshot.capec.attackPatterns.values()].flatMap((entry) => {
      if (
        (!filters.includeInactive && inactive(entry)) ||
        (abstraction && entry.abstraction !== abstraction) ||
        (severity && entry.typicalSeverity !== severity) ||
        (likelihood && entry.likelihoodOfAttack !== likelihood) ||
        (filters.cweId && !entry.relatedWeaknesses?.some((item) => item.id === filters.cweId)) ||
        (filters.attackTechniqueId &&
          !entry.attackTechniqueIds?.some(
            (item) =>
              item === filters.attackTechniqueId ||
              item.startsWith(`${filters.attackTechniqueId}.`),
          ))
      )
        return [];
      const tier = matchTier(entry, snapshot.capec.searchText, terms);
      return tier === undefined ? [] : [{ entry, tier }];
    }),
  );
}

/**
 * Whether one token of a text filter matches, on its own, a weakness or a pattern the inactive
 * setting admits. When none does, no subset of the tokens matches either, so a zero-hit notice
 * suggests fewer terms only when this holds. Tokens match as the search matches them
 * (`tokenMatcher`), including its bounded prefix cases. One pass that
 * lowercases each record once and stops at the first match.
 */
export function someTokenMatches(
  snapshot: CatalogSnapshot,
  catalog: 'cwe' | 'capec',
  filter: string,
  includeInactive = false,
): boolean {
  const terms = [...new Set(tokens(filter))];
  const records =
    catalog === 'cwe'
      ? [...snapshot.cwe.weaknesses.values()].filter((entry) => entry.type === 'weakness')
      : [...snapshot.capec.attackPatterns.values()].filter(
          (entry) => includeInactive || !inactive(entry),
        );
  const texts = snapshot[catalog].searchText;
  return records.some((entry) =>
    terms.some(tokenMatcher(searchedText(entry, projection(entry, texts)))),
  );
}
