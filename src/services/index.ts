/**
 * @fileoverview Public catalog integration boundary for handlers and fixture tests.
 * @module services
 */

export {
  type AcquiredCatalog,
  acquireCapec,
  acquireCwe,
  acquireCweVersion,
  BYTE_LIMITS,
  defaultHttpRequest,
  extractCweXml,
  readBoundedBody,
  SOURCE_URLS,
} from './catalog/acquisition.js';
export {
  type AttackPatternFilters,
  buildCatalogSnapshot,
  resolveVocabulary,
  searchAttackPatterns,
  searchWeaknesses,
  type WeaknessFilters,
  weaknessesInView,
} from './catalog/catalog-index.js';
export {
  CatalogService,
  type CatalogServiceOptions,
  disposeCatalogService,
  getCatalogService,
  initCatalogService,
  REFRESH_INTERVALS,
  systemCatalogClock,
} from './catalog/catalog-service.js';
export {
  disposeHierarchyService,
  getHierarchyService,
  HIERARCHY_RECOVERY,
  type HierarchyInput,
  type HierarchyResult,
  HierarchyService,
  type HierarchyServiceOptions,
  initHierarchyService,
  normalizeHierarchy,
} from './catalog/hierarchy-service.js';
export * from './catalog/types.js';
export {
  type OrderedNode,
  orderedContentToMarkdown,
  parseCapecCatalog,
  parseCweCatalog,
} from './catalog/xml-normalization.js';
