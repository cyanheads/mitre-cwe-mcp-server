/**
 * @fileoverview Public catalog integration boundary for handlers and fixture tests.
 * @module services
 */

export { SOURCE_URLS } from './catalog/acquisition.js';
export {
  type AttackPatternFilters,
  categoryOnlyStatuses,
  evidenceMatchers,
  nonViewSentence,
  REFERENCE_VOCABULARIES,
  recordedEntryId,
  resolveVocabulary,
  resolveWeaknessStatus,
  searchAttackPatterns,
  searchWeaknesses,
  someTokenMatches,
  tokenMatcher,
  type VocabularyKey,
  type WeaknessFilters,
} from './catalog/catalog-index.js';
export {
  disposeCatalogService,
  getCatalogService,
  initCatalogService,
} from './catalog/catalog-service.js';
export {
  disposeHierarchyService,
  getHierarchyService,
  HIERARCHY_RECOVERY,
  initHierarchyService,
} from './catalog/hierarchy-service.js';
export { escapeMarkdown, Mark, PROSE_FIELDS } from './catalog/markdown-escape.js';
export * from './catalog/types.js';
export { compileViewFilter } from './catalog/view-filter.js';
export { collapse } from './catalog/xml-normalization.js';
