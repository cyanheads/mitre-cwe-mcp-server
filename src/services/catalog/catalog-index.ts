/**
 * @fileoverview Immutable catalog snapshots, crosswalk indexes, and local filtering.
 * @module services/catalog/catalog-index
 */
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import type {
  AttackPattern,
  CapecCatalog,
  CatalogHealth,
  CatalogSnapshot,
  CweCatalog,
  Member,
  Weakness,
} from './types.js';

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
function append(map: Map<string, string[]>, key: string, value: string): void {
  const values = map.get(key);
  if (values) {
    if (!values.includes(value)) values.push(value);
  } else map.set(key, [value]);
}

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
      ...(source.relatedAttackPatterns
        ? {
            relatedAttackPatterns: source.relatedAttackPatterns.map((related) => {
              const pattern = capec.attackPatterns.get(related.id);
              return { ...related, ...(pattern ? { name: pattern.name } : {}) };
            }),
          }
        : {}),
    };
    weaknesses.set(id, freeze(entry));
    addVocabulary('cweStatuses', [entry.status]);
    if (entry.type === 'weakness') addVocabulary('cweAbstractions', [entry.abstraction]);
    addVocabulary(
      'consequenceImpacts',
      entry.consequences?.flatMap((item) => [...item.impacts]) ?? [],
    );
    addVocabulary('mitigationPhases', entry.mitigations?.flatMap((item) => [...item.phases]) ?? []);
    addVocabulary(
      'exampleLanguages',
      entry.examples?.flatMap((example) =>
        example.blocks.flatMap((block) => (block.kind === 'code' ? [block.language] : [])),
      ) ?? [],
    );
    for (const platform of entry.platforms ?? []) {
      const vocabularyKey =
        platform.kind === 'language'
          ? 'languages'
          : platform.kind === 'technology'
            ? 'technologies'
            : platform.kind === 'OS'
              ? 'operatingSystems'
              : 'architectures';
      addVocabulary(vocabularyKey, [platform.name, platform.class]);
    }
    for (const relation of entry.relatedWeaknesses ?? []) {
      addVocabulary('relationshipNatures', [relation.nature]);
      if (relation.nature === 'ChildOf') addChild(relation.viewId, relation.id, entry.id);
    }
    for (const member of entry.members ?? []) addChild(member.viewId, entry.id, member.id);
  }
  for (const [id, source] of capec.attackPatterns) {
    const entry: AttackPattern = {
      ...source,
      ...(source.relatedWeaknesses
        ? {
            relatedWeaknesses: source.relatedWeaknesses.map((related) => {
              append(attackPatternsByWeakness, related.id, source.id);
              const weakness = cwe.weaknesses.get(related.id);
              return { ...related, ...(weakness ? { name: weakness.name } : {}) };
            }),
          }
        : {}),
      ...(source.relatedAttackPatterns
        ? {
            relatedAttackPatterns: source.relatedAttackPatterns.map((related) => {
              const pattern = capec.attackPatterns.get(related.id);
              return { ...related, ...(pattern ? { name: pattern.name } : {}) };
            }),
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
  for (const values of vocabulary.values()) values.sort((a, b) => a.localeCompare(b, 'en'));
  return freeze({
    cwe: {
      version: cwe.version,
      date: cwe.date,
      weaknesses: readonlyMap(weaknesses),
      views: readonlyMap(views),
    },
    capec: {
      version: capec.version,
      date: capec.date,
      attackPatterns: readonlyMap(attackPatterns),
    },
    provenance: {
      cweVersion: cwe.version,
      cweDate: cwe.date,
      capecVersion: capec.version,
      capecDate: capec.date,
      loadedAt,
    },
    health: { cwe: freeze({ ...health.cwe }), capec: freeze({ ...health.capec }) },
    attackPatternsByWeakness: readonlyMap(
      new Map([...attackPatternsByWeakness].map(([id, values]) => [id, Object.freeze(values)])),
    ),
    childrenByView: readonlyMap(
      new Map(
        [...childrenByView].map(([view, entries]) => [
          view,
          readonlyMap(new Map([...entries].map(([id, values]) => [id, Object.freeze(values)]))),
        ]),
      ),
    ),
    vocabulary: readonlyMap(
      new Map([...vocabulary].map(([key, values]) => [key, Object.freeze(values)])),
    ),
  });
}

/** Resolve a dynamic filter without broadening it, or expose supported vocabulary. */
export function resolveVocabulary(snapshot: CatalogSnapshot, key: string, value: string): string {
  const normalized = value.trim().toLowerCase();
  const supported = snapshot.vocabulary.get(key) ?? [];
  const match = supported.find((item) => item.toLowerCase() === normalized);
  if (match === undefined)
    throw validationError('The filter value is not present in the loaded catalog vocabulary.', {
      reason: 'unknown_filter',
      retryable: false,
      vocabulary: key,
      supported,
    });
  return match;
}

/** Follow source-recorded, same-view membership with cycle protection. */
export function weaknessesInView(snapshot: CatalogSnapshot, viewId: string): ReadonlySet<string> {
  const view = snapshot.cwe.views.get(viewId);
  if (!view)
    throw validationError('The requested CWE view is not in the loaded catalog.', {
      reason: 'unknown_filter',
      retryable: false,
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
  return result;
}

/** Local CWE filters, applied before full-result sorting and pagination. */
export interface WeaknessFilters {
  abstraction?: string;
  consequenceImpact?: string;
  filter?: string;
  language?: string;
  status?: string;
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
function containsAll(value: string, terms: readonly string[]): boolean {
  const lower = value.toLowerCase();
  return terms.every((term) => lower.includes(term));
}
function rank(entry: { name: string; description: string }, terms: readonly string[]): number {
  return containsAll(entry.name, terms) ? 0 : containsAll(entry.description, terms) ? 1 : 2;
}
function canonical(
  snapshot: CatalogSnapshot,
  key: string,
  value: string | undefined,
): string | undefined {
  return value?.trim() ? resolveVocabulary(snapshot, key, value) : undefined;
}

/** Search weaknesses, preserving deterministic documented ordering over all matches. */
export function searchWeaknesses(snapshot: CatalogSnapshot, filters: WeaknessFilters): Weakness[] {
  const language = canonical(snapshot, 'languages', filters.language);
  const technology = canonical(snapshot, 'technologies', filters.technology);
  const abstraction = canonical(snapshot, 'cweAbstractions', filters.abstraction);
  const status = canonical(snapshot, 'cweStatuses', filters.status);
  const impact = canonical(snapshot, 'consequenceImpacts', filters.consequenceImpact);
  const scope = filters.viewId ? weaknessesInView(snapshot, filters.viewId) : undefined;
  const terms = tokens(filters.filter);
  return [...snapshot.cwe.weaknesses.values()]
    .filter(
      (entry) =>
        entry.type === 'weakness' &&
        (!scope || scope.has(entry.id)) &&
        (!abstraction || entry.abstraction === abstraction) &&
        (!status || entry.status === status) &&
        (!language ||
          entry.platforms?.some(
            (platform) =>
              platform.kind === 'language' &&
              (platform.name === language || platform.class === language),
          )) &&
        (!technology ||
          entry.platforms?.some(
            (platform) =>
              platform.kind === 'technology' &&
              (platform.name === technology || platform.class === technology),
          )) &&
        (!impact ||
          entry.consequences?.some((consequence) => consequence.impacts.includes(impact))) &&
        containsAll(
          `${entry.name}\n${entry.description}\n${entry.extendedDescription ?? ''}`,
          terms,
        ),
    )
    .sort((a, b) => rank(a, terms) - rank(b, terms) || compareIds(a, b));
}

/** Search recorded CAPEC mappings; parent ATT&CK IDs match only subtechnique boundaries. */
export function searchAttackPatterns(
  snapshot: CatalogSnapshot,
  filters: AttackPatternFilters,
): AttackPattern[] {
  const abstraction = canonical(snapshot, 'capecAbstractions', filters.abstraction);
  const severity = canonical(snapshot, 'capecSeverities', filters.severity);
  const likelihood = canonical(snapshot, 'capecLikelihoods', filters.likelihood);
  const terms = tokens(filters.filter);
  return [...snapshot.capec.attackPatterns.values()]
    .filter(
      (entry) =>
        (filters.includeInactive ||
          !['deprecated', 'obsolete'].includes(entry.status.toLowerCase())) &&
        (!abstraction || entry.abstraction === abstraction) &&
        (!severity || entry.typicalSeverity === severity) &&
        (!likelihood || entry.likelihoodOfAttack === likelihood) &&
        (!filters.cweId || entry.relatedWeaknesses?.some((item) => item.id === filters.cweId)) &&
        (!filters.attackTechniqueId ||
          entry.attackTechniqueIds?.some(
            (item) =>
              item === filters.attackTechniqueId ||
              item.startsWith(`${filters.attackTechniqueId}.`),
          )) &&
        containsAll(`${entry.name}\n${entry.description}`, terms),
    )
    .sort((a, b) => rank(a, terms) - rank(b, terms) || compareIds(a, b));
}
