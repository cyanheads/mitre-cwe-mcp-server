/**
 * @fileoverview Described sparse schemas for complete CWE and CAPEC projections.
 * @module mcp-server/tools/catalog-schemas
 */
import { z } from '@cyanheads/mcp-ts-core';
import { list, provenanceSchema, text } from './shared.js';

const strings = (description: string) => list(text(description), description);
const consequence = z
  .object({
    scopes: strings('Affected scopes.'),
    impacts: strings('Recorded impacts.'),
    likelihood: text('Source likelihood.').optional(),
    note: text('Source explanatory note in CommonMark.').optional(),
  })
  .describe('Source consequence.');
const alternateTerms = list(
  z
    .object({
      term: text('Alternate name as recorded.'),
      description: text('Source explanation of the term in CommonMark.').optional(),
    })
    .describe('Recorded alternate term.'),
  'Alternate terms MITRE records for this entry, in source order; absent when none are recorded.',
);
/** Shared by CWE weaknesses, categories, and views and CAPEC records. */
export const notesSchema = list(
  z
    .object({
      type: text(
        'Source note type such as Relationship, Maintenance, Terminology, or Research Gap.',
      ),
      text: text('Complete note in CommonMark.'),
    })
    .describe('Recorded MITRE note.'),
  'Notes MITRE records for this entry, in source order; absent when none are recorded.',
);
const mapping = z
  .object({
    taxonomy: text('Taxonomy name.'),
    id: text('Recorded entry ID.').optional(),
    name: text('Recorded entry name.').optional(),
    fit: text('Source mapping fit.').optional(),
  })
  .describe('Recorded taxonomy crosswalk.');
const reference = z
  .object({
    id: text('External reference identifier.'),
    authors: strings('Reference authors.').optional(),
    edition: text('Edition.').optional(),
    publication: text('Publication.').optional(),
    publicationDay: text('Publication day.').optional(),
    publicationMonth: text('Publication month.').optional(),
    publicationYear: text('Publication year.').optional(),
    publisher: text('Publisher.').optional(),
    section: text('Reference section.').optional(),
    title: text('Reference title.').optional(),
    url: text('Reference URL.').optional(),
    urlDate: text('URL access date.').optional(),
  })
  .describe('Resolved catalog reference.');
const member = z
  .object({
    id: text('CWE member ID.'),
    viewId: text('Source relationship view ID.'),
    name: text('Resolved member name.').optional(),
    type: z.enum(['weakness', 'category', 'view']).describe('Resolved member type.').optional(),
    abstraction: text('Source abstraction.').optional(),
    status: text('Source status.').optional(),
  })
  .describe('Direct catalog member.');
const outline = list(
  z
    .object({
      section: text('Section to request.'),
      sizeInBytes: z
        .number()
        .int()
        .describe(
          'Delivered UTF-8 size of the section on both surfaces: its structuredContent JSON plus its rendered content[] text.',
        ),
    })
    .describe('Section not included in this entry, and its size.'),
  'Sections available but not included in this entry, with sizes: every available section of an outline, or the selected sections a partial entry omitted.',
);
const identity = {
  id: text('Canonical catalog ID.'),
  name: text('Source entry name.'),
  status: text('Source lifecycle status.'),
  abstraction: text('Source abstraction level.').optional(),
  sourceUrl: text('Official definition URL.'),
  kind: z
    .enum(['full', 'partial', 'outline'])
    .describe(
      'full: every selected section the entry has, complete. partial: default sections that fit the 24,000-byte response budget, complete, with the omitted ones in outline. outline: identity and section sizes only.',
    ),
  requestedSections: strings('Sections selected for this response.'),
  availableSections: strings('Sections actually present in the catalog entry.'),
  outline: outline.optional(),
  notice: text('Projection or recall guidance.').optional(),
};
/** CWE selected-record output schema. */
export const weaknessEntrySchema = z
  .object({
    ...identity,
    type: z.enum(['weakness', 'category']).describe('CWE record type.'),
    description: text('Complete source description in CommonMark.').optional(),
    extendedDescription: text('Complete extended description in CommonMark.').optional(),
    ordinalities: list(
      z
        .object({
          ordinality: text('Source ordinality such as Primary, Resultant, or Indirect.'),
          description: text('Source explanation of the ordinality in CommonMark.').optional(),
        })
        .describe('Recorded weakness ordinality.'),
      'Recorded ordinalities in source order: Primary when the weakness exists independently of others, Resultant when it results from another weakness, and Indirect when it makes other weaknesses easier to introduce or harder to detect.',
    ).optional(),
    backgroundDetails: strings(
      'Complete background details on the underlying mechanism in CommonMark.',
    ).optional(),
    alternateTerms: alternateTerms.optional(),
    likelihoodOfExploit: text('Source exploit likelihood.').optional(),
    modesOfIntroduction: list(
      z
        .object({
          phase: text('Introduction phase.'),
          note: text('Source phase note in CommonMark.').optional(),
        })
        .describe('Introduction phase.'),
      'Recorded modes of introduction.',
    ).optional(),
    mappingNotes: z
      .object({
        usage: text('Mapping usage.').optional(),
        rationale: text('Mapping rationale in CommonMark.').optional(),
        comments: text('Mapping comments in CommonMark.').optional(),
        reasons: strings('Mapping reasons.').optional(),
      })
      .describe('Vulnerability mapping notes.')
      .optional(),
    consequences: list(consequence, 'Recorded consequences.').optional(),
    mitigations: list(
      z
        .object({
          phases: strings('Mitigation phases.'),
          description: text('Complete mitigation description in CommonMark.'),
          strategy: text('Mitigation strategy.').optional(),
          effectiveness: text('Source effectiveness.').optional(),
          effectivenessNotes: text('Effectiveness explanation in CommonMark.').optional(),
        })
        .describe('Source mitigation.'),
      'Complete mitigations.',
    ).optional(),
    relatedWeaknesses: list(
      z
        .object({
          nature: text('Relationship nature.'),
          id: text('Related CWE ID.'),
          name: text('Resolved related weakness name.').optional(),
          viewId: text('Relationship view ID.'),
          ordinal: text('Source ordinal.').optional(),
        })
        .describe('Recorded CWE relation.'),
      'Recorded weakness relations.',
    ).optional(),
    relatedAttackPatterns: list(
      z
        .object({ id: text('Related CAPEC ID.'), name: text('Resolved pattern name.').optional() })
        .describe('Recorded CAPEC mapping.'),
      'Recorded CAPEC mappings.',
    ).optional(),
    members: list(member, 'Direct category members in source order.').optional(),
    examples: list(
      z
        .object({
          index: z.number().int().describe('Stable zero-based source example index.'),
          blocks: list(
            z
              .discriminatedUnion('kind', [
                z
                  .object({
                    kind: z.literal('prose').describe('Narrative block.'),
                    text: text('Complete narrative in CommonMark.'),
                  })
                  .describe('Complete source narrative block.'),
                z
                  .object({
                    kind: z.literal('code').describe('Code block.'),
                    text: text('Complete code with original whitespace.'),
                    language: text('Source code language.').optional(),
                    nature: text(
                      'Open source code nature such as Bad, Good, or Attack.',
                    ).optional(),
                  })
                  .describe('Complete source code block and its available labels.'),
              ])
              .describe('Ordered source prose or code block.'),
            'All ordered blocks belonging to this example.',
          ),
        })
        .describe('Complete demonstrative example.'),
      'Selected complete examples.',
    ).optional(),
    examplePage: z
      .object({
        total: z.number().int().describe('Examples after language filtering.'),
        shown: z.number().int().describe('Complete examples returned.'),
        offset: z.number().int().describe('Filtered-array offset.'),
        hasMore: z.boolean().describe('Whether more examples remain.'),
        nextOffset: z.number().int().describe('Offset for the next example page.').optional(),
      })
      .describe('Example continuation.')
      .optional(),
    detectionMethods: list(
      z
        .object({
          method: text('Detection method.'),
          description: text('Detection description in CommonMark.').optional(),
          effectiveness: text('Source effectiveness.').optional(),
          effectivenessNotes: text('Effectiveness notes in CommonMark.').optional(),
        })
        .describe('Detection method.'),
      'Recorded detection methods.',
    ).optional(),
    observedExamples: list(
      z
        .object({
          reference: text('Observed example reference.').optional(),
          description: text('Observed example description in CommonMark.').optional(),
          link: text('Observed example URL.').optional(),
        })
        .describe('Observed example.'),
      'Recorded observed examples.',
    ).optional(),
    platforms: list(
      z
        .object({
          kind: z
            .enum(['language', 'technology', 'OS', 'architecture'])
            .describe('Platform dimension.'),
          name: text('Source platform name.').optional(),
          class: text('Source platform class.').optional(),
          prevalence: text('Source prevalence.').optional(),
        })
        .describe('Applicable source platform.'),
      'Applicable platforms.',
    ).optional(),
    functionalAreas: strings('Functional areas of a product where the weakness occurs.').optional(),
    affectedResources: strings(
      'System resources the weakness affects, such as Memory or File or Directory.',
    ).optional(),
    taxonomyMappings: list(mapping, 'Recorded taxonomy crosswalks.').optional(),
    references: list(reference, 'Resolved external references.').optional(),
    notes: notesSchema.optional(),
  })
  .describe('Projected CWE weakness or category.');
const capecRecordType = z.enum(['attack_pattern', 'category', 'view']);
const capecMember = z
  .object({
    id: text('Member CAPEC ID.'),
    name: text('Resolved member name.').optional(),
    type: capecRecordType.describe('Resolved CAPEC record type.').optional(),
    abstraction: text('Source abstraction of a member attack pattern.').optional(),
    status: text('Source status.').optional(),
  })
  .describe('Direct category or view member.');
/** CAPEC selected-record output schema: an attack pattern, category, or view. */
export const attackPatternEntrySchema = z
  .object({
    ...identity,
    type: capecRecordType.describe(
      'CAPEC record type: an attack pattern, or a category or view that organizes patterns.',
    ),
    description: text(
      'Complete source description in CommonMark: a pattern description, category summary, or view objective.',
    ).optional(),
    extendedDescription: text('Complete extended description in CommonMark.').optional(),
    alternateTerms: alternateTerms.optional(),
    typicalSeverity: text('Source typical severity.').optional(),
    likelihoodOfAttack: text('Source attack likelihood.').optional(),
    prerequisites: strings('Complete prerequisites in CommonMark.').optional(),
    executionFlow: list(
      z
        .object({
          step: text('Source step string.'),
          phase: text('Source execution phase.'),
          description: text('Complete step description in CommonMark.'),
          techniques: strings('Complete source techniques in CommonMark.').optional(),
          indicators: strings('Recorded step indicators in CommonMark.').optional(),
        })
        .describe('Ordered execution step.'),
      'Complete execution flow in source order.',
    ).optional(),
    indicators: strings('Recorded pattern indicators in CommonMark.').optional(),
    skills: list(
      z
        .object({
          level: text('Source skill level.').optional(),
          description: text('Complete skill description in CommonMark.'),
        })
        .describe('Required skill.'),
      'Recorded skills.',
    ).optional(),
    resourcesRequired: strings('Required resources in CommonMark.').optional(),
    consequences: list(consequence, 'Recorded consequences.').optional(),
    mitigations: strings('Complete mitigations in CommonMark.').optional(),
    exampleInstances: strings('Complete example instances in CommonMark.').optional(),
    relatedAttackPatterns: list(
      z
        .object({
          nature: text('Relationship nature.'),
          id: text('Related CAPEC ID.'),
          name: text('Resolved name.').optional(),
        })
        .describe('Pattern relationship.'),
      'Recorded pattern relationships.',
    ).optional(),
    members: list(capecMember, 'Direct members of a category or view in source order.').optional(),
    filterDefinition: text(
      'Source XPath filter defining a filter-defined view’s membership, exactly as published.',
    ).optional(),
    relatedWeaknesses: list(
      z
        .object({ id: text('Related CWE ID.'), name: text('Resolved weakness name.').optional() })
        .describe('Recorded weakness mapping.'),
      'Recorded CWE mappings.',
    ).optional(),
    attackTechniqueIds: strings('Recorded ATT&CK IDs; not a current validation.').optional(),
    taxonomyMappings: list(mapping, 'All recorded taxonomy mappings.').optional(),
    references: list(reference, 'Resolved external references.').optional(),
    notes: notesSchema.optional(),
  })
  .describe('Projected CAPEC attack pattern, category, or view.');
const missSchema = z
  .object({
    id: text(
      'Canonical requested ID, or for invalid_id the submitted item trimmed, with whitespace runs collapsed to one space.',
    ),
    reason: z
      .enum(['not_found', 'wrong_type', 'invalid_id'])
      .describe(
        'Missing record, record of another family or type, or an item that is no catalog ID.',
      ),
    guidance: text('Tool-specific recovery instruction.'),
  })
  .describe('Per-ID resolver miss.');
/** Common batch envelope, preserving misses and deferred IDs. */
export function batchOutput<T extends z.ZodType>(entry: T) {
  return z.object({
    entries: list(entry, 'Found projected entries in request order.'),
    notFound: list(missSchema, 'Per-ID misses; an all-missing batch is success.'),
    deferredIds: strings(
      'Distinct items to submit in a later call: canonical IDs, or the collapsed text of an item that is no ID.',
    ),
    guidance: text('Batch continuation guidance.').optional(),
    provenance: provenanceSchema,
  });
}
