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
  /** The example's own citations, resolved like the record's references. */
  references?: readonly CatalogReference[];
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
  accessRestrictions?: string;
  altUrl?: string;
  altUrlDate?: string;
  authors?: readonly string[];
  edition?: string;
  id: string;
  mediaTypes?: readonly string[];
  publication?: string;
  publicationDay?: string;
  publicationMonth?: string;
  publicationYear?: string;
  publisher?: string;
  rationales?: readonly string[];
  section?: string;
  title?: string;
  url?: string;
  urlDate?: string;
}

/** A source dimension label and its value, retaining source order. */
export interface CatalogDimension {
  type: string;
  value: string;
}

/** A standard lifecycle phase, or a custom phase with its source domain. */
export interface CatalogPhase {
  domain?: string;
  phase: string;
}

/** A relationship to a catalog entry, retaining source order and view scope. */
export interface Member {
  abstraction?: string;
  dimensions?: readonly CatalogDimension[];
  id: string;
  name?: string;
  status?: string;
  type?: Weakness['type'] | 'view';
  viewId: string;
}

/** Another name MITRE records for an entry: plain source text and optional CommonMark explanation. */
export interface AlternateTerm {
  description?: string;
  roles?: readonly string[];
  term: string;
}

/**
 * A note MITRE records on a CWE or CAPEC entry: its source type label (an open string such as
 * Relationship, Maintenance, or Terminology) and its CommonMark text.
 */
export interface CatalogNote {
  releaseDate?: string;
  text: string;
  type: string;
  version?: string;
}

/** Whether a weakness is a root cause or a consequence: the source value and its optional reason. */
export interface WeaknessOrdinality {
  description?: string;
  ordinality: string;
}

/** Source consequence vocabulary and narrative. */
export interface Consequence {
  impacts: readonly string[];
  likelihood?: string;
  note?: string;
  scopes: readonly string[];
}

/** A CWE weakness, category, or grouping with sparse, complete normalized sections. */
export interface Weakness {
  abstraction?: string;
  affectedResources?: readonly string[];
  alternateTerms?: readonly AlternateTerm[];
  /** CommonMark explanations of the underlying mechanism, in source order. */
  backgroundDetails?: readonly string[];
  consequences?: readonly Consequence[];
  description: string;
  detectionMethods?: readonly {
    method: string;
    description?: string;
    effectiveness?: string;
    effectivenessNotes?: string;
    phases?: readonly string[];
    phaseDetails?: readonly CatalogPhase[];
  }[];
  dimensions?: readonly CatalogDimension[];
  examples?: readonly DemonstrativeExample[];
  extendedDescription?: string;
  functionalAreas?: readonly string[];
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
    phaseDetails?: readonly CatalogPhase[];
    description: string;
    strategy?: string;
    effectiveness?: string;
    effectivenessNotes?: string;
  }[];
  modesOfIntroduction?: readonly (CatalogPhase & { note?: string })[];
  name: string;
  notes?: readonly CatalogNote[];
  observedExamples?: readonly {
    reference?: string;
    description?: string;
    link?: string;
    rationales?: readonly string[];
  }[];
  ordinalities?: readonly WeaknessOrdinality[];
  platforms?: readonly {
    kind: 'language' | 'technology' | 'OS' | 'architecture';
    name?: string;
    class?: string;
    prevalence?: string;
    note?: string;
  }[];
  references?: readonly CatalogReference[];
  relatedAttackPatterns?: readonly { id: string; name?: string }[];
  /** `name` is the loaded target's name, attached at indexing and absent when it is not loaded. */
  relatedWeaknesses?: readonly {
    nature: string;
    id: string;
    viewId: string;
    ordinal?: string;
    name?: string;
    dimensions?: readonly CatalogDimension[];
  }[];
  sourceUrl: string;
  status: string;
  /** Source `Structure` attribute (Simple, Composite, Chain); indexed for view filters, never returned. */
  structure?: string;
  taxonomyMappings?: readonly TaxonomyMapping[];
  technicalNuance?: string;
  type: 'weakness' | 'category' | 'grouping';
  /** Notes on schema-8 introductions with no phase children, in source order. */
  unphasedIntroductionNotes?: readonly string[];
}

/** A CWE view and its direct, source-ordered members. */
export interface CatalogView {
  audience?: readonly { type?: string; description?: string }[];
  /** The source XPath `Filter` of a filter-defined (Implicit) view, exactly as published. */
  filterDefinition?: string;
  id: string;
  members: readonly Member[];
  name: string;
  notes?: readonly CatalogNote[];
  objective?: string;
  sourceUrl: string;
  status: string;
  type: string;
}

/** A CAPEC attack pattern with source-provided mechanics and mappings. */
export interface AttackPattern {
  abstraction: string;
  alternateTerms?: readonly AlternateTerm[];
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
  notes?: readonly CatalogNote[];
  prerequisites?: readonly string[];
  references?: readonly CatalogReference[];
  relatedAttackPatterns?: readonly { nature: string; id: string; name?: string }[];
  relatedWeaknesses?: readonly { id: string; name?: string }[];
  resourcesRequired?: readonly string[];
  skills?: readonly { level?: string; description: string }[];
  sourceUrl: string;
  status: string;
  taxonomyMappings?: readonly TaxonomyMapping[];
  type: 'attack_pattern';
  typicalSeverity?: string;
}

/**
 * A direct member of a CAPEC category or view, in source order. Name, type, status, and a
 * pattern's abstraction are attached at indexing and absent when the member is not loaded.
 */
export interface CapecMember {
  abstraction?: string;
  id: string;
  name?: string;
  status?: string;
  type?: CapecRecord['type'];
}

/**
 * A CAPEC category or view: an organizational record that groups patterns and categories. Its
 * description is the category `Summary` or view `Objective`; a filter-defined (Implicit) view has
 * a raw XPath `filterDefinition` instead of members.
 */
export interface CapecGrouping {
  description?: string;
  filterDefinition?: string;
  id: string;
  members?: readonly CapecMember[];
  name: string;
  notes?: readonly CatalogNote[];
  references?: readonly CatalogReference[];
  sourceUrl: string;
  status: string;
  taxonomyMappings?: readonly TaxonomyMapping[];
  type: 'category' | 'view';
}

/** Any CAPEC record a CAPEC ID names; IDs never repeat across the three families. */
export type CapecRecord = AttackPattern | CapecGrouping;

/** The root's authoritative version and publication date. */
export interface CatalogMetadata {
  date: string;
  version: string;
}

/**
 * Plain-text projection of a record's searched text, built from the XML source during
 * normalization: no Markdown syntax and no escapes. Search reads it; no response carries it.
 */
export interface SearchText {
  /** Each recorded alternate term, present only when the record has any; descriptions are not searched. */
  alternateTerms?: readonly string[];
  description: string;
  extendedDescription?: string;
}

/** Parsed CWE data before cross-catalog indexing. */
export interface CweCatalog extends CatalogMetadata {
  /** Keyed by weakness, category, or grouping ID. */
  searchText: ReadonlyMap<string, SearchText>;
  views: ReadonlyMap<string, CatalogView>;
  weaknesses: ReadonlyMap<string, Weakness>;
}

/** Parsed CAPEC data before cross-catalog indexing. */
export interface CapecCatalog extends CatalogMetadata {
  attackPatterns: ReadonlyMap<string, AttackPattern>;
  categories: ReadonlyMap<string, CapecGrouping>;
  /** Keyed by attack pattern ID; CAPEC search reads the description and alternate terms. */
  searchText: ReadonlyMap<string, SearchText>;
  views: ReadonlyMap<string, CapecGrouping>;
}

/** Source and refresh health, disclosed by the versions reference topic. */
export interface CatalogHealth extends CatalogMetadata {
  apiDate?: string;
  apiVersion?: string;
  counts: Readonly<Record<string, number>>;
  etag?: string;
  /** When the served bytes were downloaded; absent for a cached file with no matching sidecar. */
  fetchedAt?: string;
  lastCheckAt?: string;
  lastModified?: string;
  lastRefreshError?: { code: number; message: string; time: string };
  lastSuccessfulCheckAt?: string;
  loadedAt: string;
  nextCheckAt: string;
  /** `cache`: loaded from the cache directory at start and not downloaded since; `upstream`: downloaded by this process. */
  source: 'cache' | 'upstream';
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
