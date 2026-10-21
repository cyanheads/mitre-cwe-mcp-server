/**
 * @fileoverview Normalized MITRE catalog contracts and injectable runtime boundaries.
 * @module services/catalog/types
 */
import type { RequestContext } from '@cyanheads/mcp-ts-core/utils';

/** Ordered narrative and executable-looking source data; code is never executed. */
export type ExampleBlock =
  | { kind: 'prose'; text: string }
  | { kind: 'code'; text: string; language?: string; nature?: string };

/** A complete source example, indexed in its original catalog order. */
export interface DemonstrativeExample {
  blocks: readonly ExampleBlock[];
  index: number;
}

/** A source-recorded crosswalk; optional fields preserve missing upstream facts. */
export interface TaxonomyMapping {
  fit?: string;
  id?: string;
  name?: string;
  taxonomy: string;
}

/** A catalog reference resolved from its external reference definition. */
export interface CatalogReference {
  authors?: readonly string[];
  edition?: string;
  id: string;
  publication?: string;
  publicationDay?: string;
  publicationMonth?: string;
  publicationYear?: string;
  publisher?: string;
  section?: string;
  title?: string;
  url?: string;
  urlDate?: string;
}

/** A relationship to a catalog entry, retaining source order and view scope. */
export interface Member {
  abstraction?: string;
  id: string;
  name?: string;
  status?: string;
  type?: 'weakness' | 'category' | 'view';
  viewId: string;
}

/** Source consequence vocabulary and narrative. */
export interface Consequence {
  impacts: readonly string[];
  likelihood?: string;
  note?: string;
  scopes: readonly string[];
}

/** A CWE weakness or category with sparse, complete normalized sections. */
export interface Weakness {
  abstraction?: string;
  consequences?: readonly Consequence[];
  description: string;
  detectionMethods?: readonly {
    method: string;
    description?: string;
    effectiveness?: string;
    effectivenessNotes?: string;
  }[];
  examples?: readonly DemonstrativeExample[];
  extendedDescription?: string;
  id: string;
  likelihoodOfExploit?: string;
  mappingNotes?: {
    usage?: string;
    rationale?: string;
    comments?: string;
    reasons?: readonly string[];
  };
  members?: readonly Member[];
  mitigations?: readonly {
    phases: readonly string[];
    description: string;
    strategy?: string;
    effectiveness?: string;
    effectivenessNotes?: string;
  }[];
  modesOfIntroduction?: readonly { phase: string; note?: string }[];
  name: string;
  observedExamples?: readonly { reference?: string; description?: string; link?: string }[];
  platforms?: readonly {
    kind: 'language' | 'technology' | 'OS' | 'architecture';
    name?: string;
    class?: string;
    prevalence?: string;
  }[];
  references?: readonly CatalogReference[];
  relatedAttackPatterns?: readonly { id: string; name?: string }[];
  relatedWeaknesses?: readonly { nature: string; id: string; viewId: string; ordinal?: string }[];
  sourceUrl: string;
  status: string;
  taxonomyMappings?: readonly TaxonomyMapping[];
  type: 'weakness' | 'category';
}

/** A CWE view and its direct, source-ordered members. */
export interface CatalogView {
  audience?: readonly { type?: string; description?: string }[];
  filterDefinition?: string;
  id: string;
  members: readonly Member[];
  name: string;
  objective?: string;
  sourceUrl: string;
  status: string;
  type: string;
}

/** A CAPEC attack pattern with source-provided mechanics and mappings. */
export interface AttackPattern {
  abstraction: string;
  attackTechniqueIds?: readonly string[];
  consequences?: readonly Consequence[];
  description: string;
  exampleInstances?: readonly string[];
  executionFlow?: readonly {
    step: string;
    phase: string;
    description: string;
    techniques?: readonly string[];
    indicators?: readonly string[];
  }[];
  extendedDescription?: string;
  id: string;
  indicators?: readonly string[];
  likelihoodOfAttack?: string;
  mitigations?: readonly string[];
  name: string;
  prerequisites?: readonly string[];
  references?: readonly CatalogReference[];
  relatedAttackPatterns?: readonly { nature: string; id: string; name?: string }[];
  relatedWeaknesses?: readonly { id: string; name?: string }[];
  resourcesRequired?: readonly string[];
  skills?: readonly { level?: string; description: string }[];
  sourceUrl: string;
  status: string;
  taxonomyMappings?: readonly TaxonomyMapping[];
  typicalSeverity?: string;
}

/** The root's authoritative version and publication date. */
export interface CatalogMetadata {
  date: string;
  version: string;
}

/** Parsed CWE data before cross-catalog indexing. */
export interface CweCatalog extends CatalogMetadata {
  views: ReadonlyMap<string, CatalogView>;
  weaknesses: ReadonlyMap<string, Weakness>;
}

/** Parsed CAPEC data before cross-catalog indexing. */
export interface CapecCatalog extends CatalogMetadata {
  attackPatterns: ReadonlyMap<string, AttackPattern>;
}

/** Source and refresh health, disclosed by the versions reference topic. */
export interface CatalogHealth extends CatalogMetadata {
  apiDate?: string;
  apiVersion?: string;
  counts: Readonly<Record<string, number>>;
  etag?: string;
  lastCheckAt?: string;
  lastModified?: string;
  lastRefreshError?: { code: number; message: string; time: string };
  lastSuccessfulCheckAt?: string;
  loadedAt: string;
  nextCheckAt: string;
  sourceUrl: string;
}

/** Shared provenance captures the pair of catalogs used throughout one call. */
export interface Provenance {
  capecDate: string;
  capecVersion: string;
  cweDate: string;
  cweVersion: string;
  loadedAt: string;
}

/** Complete published state; readers capture one snapshot per call. */
export interface CatalogSnapshot {
  attackPatternsByWeakness: ReadonlyMap<string, readonly string[]>;
  capec: CapecCatalog;
  childrenByView: ReadonlyMap<string, ReadonlyMap<string, readonly string[]>>;
  cwe: CweCatalog;
  health: { cwe: CatalogHealth; capec: CatalogHealth };
  provenance: Provenance;
  vocabulary: ReadonlyMap<string, readonly string[]>;
}

/** All service traffic passes through this injectable fixed-destination boundary. */
export type HttpRequest = (
  url: string,
  options: {
    signal: AbortSignal;
    headers?: NonNullable<RequestInit['headers']>;
    acceptNotModified?: boolean;
  },
  timeoutMs: number,
  context: RequestContext,
) => Promise<Response>;

/** Refresh scheduling can be driven entirely by a deterministic test clock. */
export interface CatalogClock {
  now(): number;
  schedule(callback: () => void, delayMs: number): { cancel(): void };
}

/** The fixed REST hierarchy routes use these directions. */
export type HierarchyDirection = 'parents' | 'children' | 'ancestors' | 'descendants';

/** A live hierarchy node retains upstream type/view identity even when unknown locally. */
export interface HierarchyNode {
  abstraction?: string;
  id: string;
  name?: string;
  sourceUrl?: string;
  status?: string;
  type: string;
  viewId: string;
}

/** View-scoped directed topology; absence of a primary flag remains unknown. */
export interface HierarchyEdge {
  childId: string;
  parentId: string;
  primaryParent?: boolean;
  viewId: string;
}
