/**
 * @fileoverview Pure catalog parsing tests using synthetic MITRE-shaped XML.
 * @module tests/services/catalog/xml-normalization.test
 */
import { readFileSync } from 'node:fs';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  exampleCodeText,
  type OrderedNode,
  orderedContentToMarkdown,
  parseCapecCatalog,
  parseCweCatalog,
} from '@/services/catalog/xml-normalization.js';
import { parseMarkdown, referenceDefinitions, renderHtml } from '../../helpers/commonmark.js';
import { expectLinearTime } from '../../helpers/cpu-timing.js';

const cweXml = readFileSync(
  new URL('../../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const capecXml = readFileSync(
  new URL('../../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);
/** CWE-20's stored description after replacing its source XML content. */
function description(content: string): string | undefined {
  return parseCweCatalog(cweXml.replace('Sparse description.', content)).weaknesses.get('CWE-20')
    ?.description;
}
const textNode = (value: string): OrderedNode => ({ '#text': value });

describe('parseCweCatalog', () => {
  it('retains an unresolved external reference identity and recorded section', () => {
    const xml = cweXml.replace('External_Reference_ID="REF-1"', 'External_Reference_ID="missing"');
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.references).toEqual([
      { id: 'missing', section: '2' },
    ]);
  });

  it('preserves scalar external-reference URLs without Markdown escaping', () => {
    const url = 'https://example.test/a_b/[record](revision)?q=%5Bvalue%5D&next=a_b';
    const xml = cweXml.replace(
      '<URL>https://example.test/ref</URL>',
      `<URL>${url.replaceAll('&', '&amp;')}</URL>`,
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.references?.[0]?.url).toBe(url);
  });

  it('preserves scalar observed-example links without Markdown escaping', () => {
    const url = 'https://example.test/a_b/[record](revision)?q=%28value%29&next=a_b';
    const xml = cweXml.replace(
      '</Demonstrative_Examples>',
      `</Demonstrative_Examples><Observed_Examples><Observed_Example><Link>${url.replaceAll('&', '&amp;')}</Link></Observed_Example></Observed_Examples>`,
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.observedExamples?.[0]?.link).toBe(url);
  });

  it('preserves prose order, markup, line breaks and exactly-once entities', () => {
    const catalog = parseCweCatalog(cweXml);
    expect(catalog.version).toBe('4.test');
    expect(catalog.date).toBe('2026-04-30');
    expect(catalog.weaknesses.get('CWE-79')).toMatchObject({
      name: 'Synthetic & weakness',
      description:
        'First & A \\&lt; sentence.  \nSecond **bold** and *emphasis*.\n\n- one\n- two\n\nRead [source](<https://example.test/?a=1&amp;b=2>).',
      relatedWeaknesses: [
        { nature: 'ChildOf', id: 'CWE-20', viewId: 'CWE-1000', ordinal: 'Primary' },
      ],
      relatedAttackPatterns: [{ id: 'CAPEC-1' }],
      taxonomyMappings: [{ taxonomy: 'OWASP', id: 'A03', name: 'Injection', fit: 'Exact' }],
      references: [
        {
          id: 'REF-1',
          authors: ['Alice', 'Bob'],
          title: 'Reference',
          publicationYear: '2026',
          url: 'https://example.test/ref',
          section: '2',
        },
      ],
    });
  });

  it('keeps alternating prose and code, source indices, indentation, CDATA literal and example references', () => {
    expect(parseCweCatalog(cweXml).weaknesses.get('CWE-79')?.examples).toEqual([
      {
        index: 0,
        blocks: [
          { kind: 'prose', text: 'Before code.' },
          {
            kind: 'code',
            language: 'C',
            nature: 'Bad',
            text: 'if (a < b) {\n    call("x");\n}\nnext();',
          },
          { kind: 'prose', text: 'Between code.' },
          { kind: 'code', text: '  literal <tag> &amp;\n    next();' },
          { kind: 'prose', text: 'After code.' },
        ],
        references: [
          {
            id: 'REF-2',
            authors: ['Carol'],
            title: 'Example source',
            url: 'https://example.test/example-source',
            section: 'Figure 3',
          },
        ],
      },
      { index: 1, blocks: [{ kind: 'prose', text: 'Second example.' }] },
    ]);
  });

  it('turns an example’s References into its references, never a prose block', () => {
    const xml = cweXml.replace(
      '<Reference External_Reference_ID="REF-2" Section="Figure 3"/>',
      '<Reference External_Reference_ID="REF-2"/><Reference External_Reference_ID="REF-404"/>',
    );
    const [first] = parseCweCatalog(xml).weaknesses.get('CWE-79')?.examples ?? [];
    expect(first?.blocks.map(({ kind }) => kind)).toEqual([
      'prose',
      'code',
      'prose',
      'code',
      'prose',
    ]);
    expect(first?.references).toEqual([
      {
        id: 'REF-2',
        authors: ['Carol'],
        title: 'Example source',
        url: 'https://example.test/example-source',
      },
      { id: 'REF-404' },
    ]);
  });

  describe('example code layout', () => {
    /** CWE-79's first code block after replacing its source XML content. */
    function code(content: string): string | undefined {
      const xml = cweXml.replace(
        /(<Example_Code Nature="Bad" Language="C">)[\s\S]*?(<\/Example_Code>)/,
        (_match, open: string, close: string) => `${open}${content}${close}`,
      );
      const block = parseCweCatalog(xml).weaknesses.get('CWE-79')?.examples?.[0]?.blocks[1];
      return block?.kind === 'code' ? block.text : undefined;
    }
    const margin = (content: string) =>
      `<xhtml:div style="margin-left:1em;">${content}</xhtml:div>`;

    it('folds ASCII whitespace runs to one space and drops them at line ends, keeping U+00A0', () => {
      expect(code('\n\t\t\t  a  \t b\r\n\t\t c\n\t')).toBe('a b c');
      // XML forbids a literal form feed, so it reaches the layout only from another tree.
      expect(exampleCodeText([textNode('\f a\f\fb \f')])).toBe('a b');
      expect(
        code('<xhtml:div>\n\t  x =&#160;&#160;1;  </xhtml:div>\n\t<xhtml:div>&#160;y</xhtml:div>'),
      ).toBe('x =  1;\n y');
    });

    it('ends a line at each break, leaving blank lines between consecutive breaks', () => {
      expect(code('a<xhtml:br/><xhtml:br/>b<xhtml:br/>\n   c')).toBe('a\n\nb\nc');
      // A break that is a block's last content adds no line.
      expect(code('<xhtml:div>a<xhtml:br/></xhtml:div><xhtml:div>b<xhtml:br/></xhtml:div>c')).toBe(
        'a\nb\nc',
      );
      expect(code('<xhtml:div>a<xhtml:br/><xhtml:br/></xhtml:div>b')).toBe('a\n\nb');
    });

    it('starts and ends a line at each block without adding blank lines', () => {
      expect(code('x<xhtml:div>y</xhtml:div>z<xhtml:p>p</xhtml:p><xhtml:div></xhtml:div>w')).toBe(
        'x\ny\nz\np\nw',
      );
      expect(
        code(
          `<xhtml:div>if (str1 == str2) {${margin('System.out.println(&quot;str1 == str2&quot;);')}}</xhtml:div>`,
        ),
      ).toBe('if (str1 == str2) {\n    System.out.println("str1 == str2");\n}');
    });

    it('writes list items as lines with their marker', () => {
      expect(
        code(
          '<xhtml:ul>\n <xhtml:li>one</xhtml:li> <xhtml:li>two <xhtml:b>bold</xhtml:b></xhtml:li></xhtml:ul><xhtml:ol><xhtml:li>first</xhtml:li><xhtml:li></xhtml:li><xhtml:li>third</xhtml:li></xhtml:ol>after',
        ),
      ).toBe('- one\n- two bold\n1. first\n2.\n3. third\nafter');
    });

    it('indents 4 spaces for each enclosing margin-left div, at any depth', () => {
      // Seven levels, the deepest CWE 4.20 nests (CWE-1221).
      const nest = (level: number): string =>
        level > 7 ? '' : margin(`L${level} {${nest(level + 1)}}`);
      const pad = (level: number) => ' '.repeat(4 * level);
      expect(code(nest(1))?.split('\n')).toEqual([
        `${pad(1)}L1 {`,
        `${pad(2)}L2 {`,
        `${pad(3)}L3 {`,
        `${pad(4)}L4 {`,
        `${pad(5)}L5 {`,
        `${pad(6)}L6 {`,
        `${pad(7)}L7 {}`,
        `${pad(6)}}`,
        `${pad(5)}}`,
        `${pad(4)}}`,
        `${pad(3)}}`,
        `${pad(2)}}`,
        `${pad(1)}}`,
      ]);
      expect(
        code(
          `${margin('<xhtml:table><xhtml:tr><xhtml:th>A</xhtml:th></xhtml:tr><xhtml:tr><xhtml:td>1</xhtml:td></xhtml:tr></xhtml:table>')}<xhtml:div style="color: red">flat</xhtml:div><xhtml:div style="padding: 0; MARGIN-LEFT: 2em">in</xhtml:div>`,
        ),
      ).toBe('    | A |\n    | --- |\n    | 1 |\nflat\n    in');
    });

    it('trims leading and trailing blank lines and writes no line ending in whitespace', () => {
      const text = code('<xhtml:br/>\n\t<xhtml:br/>  a \t<xhtml:br/>  <xhtml:br/>\n<xhtml:br/>');
      expect(text).toBe('a');
      expect(code(margin('<xhtml:br/>x<xhtml:br/><xhtml:br/>y'))).toBe('    x\n\n    y');
    });

    it('lays out in linear time', { timeout: 60_000 }, () => {
      const style = { '@_style': 'margin-left:1em;' };
      const shapes: [string, (length: number) => OrderedNode[]][] = [
        [
          'nested margin-left divs',
          (length) => {
            // One `<xhtml:div style="margin-left:1em;">` and its close tag span 48 characters.
            let node: OrderedNode = textNode('x');
            for (let level = 0; level < length / 48; level++) node = { ':@': style, div: [node] };
            return [node];
          },
        ],
        ['digit run', (length) => [textNode('7'.repeat(length))]],
        ['one long line, then a break', (length) => [textNode(`${'§1 x'.repeat(length / 4)}\ny`)]],
        ['breaks throughout', (length) => [textNode('  \r\n'.repeat(length / 4))]],
        [
          'hard breaks throughout',
          (length) => Array.from({ length: length / 4 }, () => [textNode('a'), { br: [] }]).flat(),
        ],
        [
          'indented lines throughout',
          (length) =>
            Array.from({ length: length / 48 }, () => ({ ':@': style, div: [textNode('x;')] })),
        ],
        [
          'list items throughout',
          (length) => [{ ol: Array.from({ length: length / 8 }, () => ({ li: [textNode('i')] })) }],
        ],
      ];
      for (const [label, build] of shapes) expectLinearTime(label, build, exampleCodeText);
      expectLinearTime(
        'parse a long example',
        (length) =>
          cweXml.replace(
            '<xhtml:div>next();</xhtml:div>',
            `<xhtml:div style="margin-left:1em;">a = b;<xhtml:br/></xhtml:div>`.repeat(length / 64),
          ),
        parseCweCatalog,
      );
    });
  });

  it('does not invent absent optional fields', () => {
    expect(parseCweCatalog(cweXml).weaknesses.get('CWE-20')).toEqual({
      id: 'CWE-20',
      type: 'weakness',
      name: 'Sparse',
      status: 'Incomplete',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/20.html',
      description: 'Sparse description.',
    });
  });

  it('distinguishes category summaries, ordered membership and filter-only views', () => {
    const catalog = parseCweCatalog(cweXml);
    expect(catalog.weaknesses.get('CWE-900')).toEqual({
      id: 'CWE-900',
      type: 'category',
      name: 'Category',
      status: 'Stable',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/900.html',
      description: 'Organizational summary.',
      members: [
        { id: 'CWE-79', viewId: 'CWE-1000' },
        { id: 'CWE-20', viewId: 'CWE-1000' },
      ],
    });
    expect(catalog.views.get('CWE-1000')).toMatchObject({
      audience: [{ type: 'Developer', description: 'Build software.' }],
      members: [
        { id: 'CWE-900', viewId: 'CWE-1000' },
        { id: 'CWE-79', viewId: 'CWE-1000' },
      ],
    });
    expect(catalog.views.get('CWE-1001')).toMatchObject({
      members: [],
      filterDefinition: "/Weakness_Catalog/*/*[@Status='Draft']",
    });
    expect(catalog.views.get('CWE-1000')).not.toHaveProperty('filterDefinition');
  });

  it('stores a view filter as its raw source XPath and keeps the weakness structure', () => {
    // Interior whitespace is kept: only plain display fields collapse it.
    const filter =
      "/Weakness_Catalog/Weaknesses/Weakness[(@Abstraction='Base') or (@Abstraction  =  'Class')][not(@Status='Deprecated')]";
    const catalog = parseCweCatalog(
      cweXml
        .replace(
          "/Weakness_Catalog/*/*[@Status='Draft']",
          `\n  ${filter.replaceAll("'", '&apos;')}  \n`,
        )
        .replace('Abstraction="Base">', 'Abstraction="Base" Structure="Composite">'),
    );
    expect(catalog.views.get('CWE-1001')).toEqual({
      id: 'CWE-1001',
      name: 'Filtered',
      type: 'Implicit',
      status: 'Draft',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/1001.html',
      members: [],
      filterDefinition: filter,
    });
    expect(catalog.weaknesses.get('CWE-79')?.structure).toBe('Composite');
    expect(catalog.weaknesses.get('CWE-20')).not.toHaveProperty('structure');
  });

  it('stores every non-prose field as its source text', () => {
    const xml = cweXml
      .replace(
        '<Title>Reference</Title>',
        '<Title>Using size_t &amp; &lt;T&gt; [REF-1] *x* `y`</Title><Publisher>A_B &amp; Sons</Publisher><Edition>2nd *ed*</Edition>',
      )
      .replace('<Author>Alice</Author>', '<Author>Al_ice</Author>')
      .replace('<Entry_Name>Injection</Entry_Name>', '<Entry_Name>a size_t</Entry_Name>')
      .replace(
        '</Demonstrative_Examples>',
        '</Demonstrative_Examples><Observed_Examples><Observed_Example><Reference>[REF-1100]</Reference><Description>See [REF-1100] for <xhtml:b>details</xhtml:b>.</Description></Observed_Example></Observed_Examples>',
      );
    const entry = parseCweCatalog(xml).weaknesses.get('CWE-79');
    expect(entry?.references?.[0]).toMatchObject({
      title: 'Using size_t & <T> [REF-1] *x* `y`',
      publisher: 'A_B & Sons',
      edition: '2nd *ed*',
      authors: ['Al_ice', 'Bob'],
    });
    expect(entry?.taxonomyMappings?.[0]?.name).toBe('a size_t');
    expect(entry?.observedExamples?.[0]).toEqual({
      reference: '[REF-1100]',
      description: 'See [REF-1100] for **details**.',
    });
  });

  it('collapses whitespace in plain fields read from attributes, as in element text', () => {
    const catalog = parseCweCatalog(
      cweXml
        .replace('Name="Sparse"', 'Name=" Sparse&#9; record "')
        .replace('Abstraction="Base"', 'Abstraction="Base "')
        .replace(
          'Section="2"',
          'Section="Chapter 6, &#34;Determining&#xA;                  Appropriate&#34; Page 171"',
        )
        .replace('Ordinal="Primary"', 'Ordinal="&#xA;Primary"'),
    );
    const entry = catalog.weaknesses.get('CWE-79');
    expect(catalog.weaknesses.get('CWE-20')?.name).toBe('Sparse record');
    expect(entry?.abstraction).toBe('Base');
    expect(entry?.references?.[0]?.section).toBe('Chapter 6, "Determining Appropriate" Page 171');
    expect(entry?.relatedWeaknesses?.[0]?.ordinal).toBe('Primary');
    const capec = parseCapecCatalog(
      capecXml.replace('Name="Sparse pattern"', 'Name="DEPRECATED:  Install Rootkit "'),
    );
    expect(capec.attackPatterns.get('CAPEC-2')?.name).toBe('DEPRECATED: Install Rootkit');
  });

  it('collapses whitespace in reference URLs and observed-example links like other plain fields', () => {
    const entry = parseCweCatalog(
      cweXml
        .replace(
          '<URL>https://example.test/ref</URL>',
          '<URL>\n  https://example.test/a&#13;\n  b&#160;</URL>',
        )
        .replace(
          '</Demonstrative_Examples>',
          '</Demonstrative_Examples><Observed_Examples><Observed_Example><Link>&#12288;https://example.test/c\r\nd</Link></Observed_Example></Observed_Examples>',
        ),
    ).weaknesses.get('CWE-79');
    expect(entry?.references?.[0]?.url).toBe('https://example.test/a b');
    expect(entry?.observedExamples?.[0]?.link).toBe('https://example.test/c d');
  });

  it('stores prose whose CommonMark parse is the source text', () => {
    expect(description('such as "&lt;", "&gt;", and "&amp;" that')).toBe(
      'such as "<", ">", and "&" that',
    );
    expect(description('(e.g. $varname, $varname_size, $varname_name).')).toBe(
      '(e.g. $varname, $varname_size, $varname_name).',
    );
    const steps = description(
      '<xhtml:p>Errors occur when:</xhtml:p><xhtml:p>1. An attacker can specify a path.</xhtml:p><xhtml:p>2. The attacker gains a capability.</xhtml:p>',
    ) as string;
    expect(steps).toBe(
      'Errors occur when:\n\n1\\. An attacker can specify a path.\n\n2\\. The attacker gains a capability.',
    );
    expect(parseMarkdown(steps).nodes).not.toContain('list');
    const rules = [
      '1. x',
      '# x',
      '- x',
      '[a]: b',
      '<script>',
      '&lt;',
      '*p',
      '__init__',
      'a_b',
      'x](y)',
      '`',
      '\\\\server',
    ];
    const xml = rules
      .map(
        (rule) =>
          `<xhtml:p>${rule.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')}</xhtml:p>`,
      )
      .join('');
    const parsed = parseMarkdown(description(xml) as string);
    expect(parsed.text).toBe(rules.join('\n'));
    expect(new Set(parsed.nodes)).toEqual(new Set(['document', 'paragraph', 'text']));
  });

  it('keeps a plain-text search projection beside, never inside, each searched record', () => {
    const catalog = parseCweCatalog(
      cweXml.replace(
        '<Related_Weaknesses>',
        '<Extended_Description><xhtml:p>Calls <xhtml:code>inet_addr</xhtml:code>() with "&lt;script&gt;" and $varname_size.</xhtml:p></Extended_Description><Related_Weaknesses>',
      ),
    );
    expect(Object.fromEntries(catalog.searchText)).toEqual({
      'CWE-79': {
        description: 'First & A &lt; sentence. Second bold and emphasis. one two Read source.',
        extendedDescription: 'Calls inet_addr() with "<script>" and $varname_size.',
      },
      'CWE-20': { description: 'Sparse description.' },
      'CWE-900': { description: 'Organizational summary.' },
    });
    const entry = catalog.weaknesses.get('CWE-79');
    expect(entry?.extendedDescription).toBe(
      'Calls ` inet_addr `() with "\\<script>" and $varname_size.',
    );
    expect(Object.keys(entry ?? {})).not.toContain('searchText');
  });

  it('stores alternate terms in source order: the term as plain text, its explanation as prose', () => {
    const catalog = parseCweCatalog(
      cweXml.replace(
        '<Related_Weaknesses>',
        `<Alternate_Terms><Alternate_Term><Term>XSS</Term><Description><xhtml:p>A common <xhtml:b>acronym</xhtml:b> for $var_name and &lt;script&gt;.</xhtml:p></Description></Alternate_Term><Alternate_Term><Term> Type_1 [XSS]
          *stored* &lt;b&gt; </Term></Alternate_Term></Alternate_Terms><Related_Weaknesses>`,
      ),
    );
    const terms = catalog.weaknesses.get('CWE-79')?.alternateTerms;
    expect(terms).toEqual([
      { term: 'XSS', description: 'A common **acronym** for $var_name and \\<script>.' },
      { term: 'Type_1 [XSS] *stored* <b>' },
    ]);
    expect(parseMarkdown(terms?.[0]?.description ?? '').text).toBe(
      'A common acronym for $var_name and <script>.',
    );
    expect(catalog.weaknesses.get('CWE-20')).not.toHaveProperty('alternateTerms');
    // Terms join the record's search projection; their explanations do not.
    expect(catalog.searchText.get('CWE-79')).toEqual({
      alternateTerms: ['XSS', 'Type_1 [XSS] *stored* <b>'],
      description: 'First & A &lt; sentence. Second bold and emphasis. one two Read source.',
    });
    expect(catalog.searchText.get('CWE-20')).toEqual({ description: 'Sparse description.' });
  });

  it('stores ordinalities, background details, functional areas and affected resources in source order', () => {
    const catalog = parseCweCatalog(
      cweXml.replace(
        '<Related_Weaknesses>',
        `<Weakness_Ordinalities><Weakness_Ordinality><Ordinality>Resultant</Ordinality><Description>Follows
          <xhtml:b>input_validation</xhtml:b> gaps &lt;here&gt;.</Description></Weakness_Ordinality><Weakness_Ordinality><Ordinality> Primary </Ordinality></Weakness_Ordinality></Weakness_Ordinalities><Background_Details><Background_Detail><xhtml:p>Cookies hold *state*.</xhtml:p><xhtml:ul><xhtml:li>one</xhtml:li><xhtml:li>two</xhtml:li></xhtml:ul></Background_Detail><Background_Detail>1. Not a list_item.</Background_Detail></Background_Details><Functional_Areas><Functional_Area>Memory_Management
          *raw* &lt;T&gt;</Functional_Area><Functional_Area>File Processing</Functional_Area></Functional_Areas><Affected_Resources><Affected_Resource>File or Directory</Affected_Resource><Affected_Resource>CPU</Affected_Resource></Affected_Resources><Related_Weaknesses>`,
      ),
    );
    const entry = catalog.weaknesses.get('CWE-79');
    expect(entry?.ordinalities).toEqual([
      { ordinality: 'Resultant', description: 'Follows **input_validation** gaps \\<here>.' },
      { ordinality: 'Primary' },
    ]);
    expect(parseMarkdown(entry?.ordinalities?.[0]?.description ?? '').text).toBe(
      'Follows input_validation gaps <here>.',
    );
    expect(entry?.backgroundDetails).toEqual([
      'Cookies hold \\*state\\*.\n\n- one\n- two',
      '1\\. Not a list_item.',
    ]);
    expect(parseMarkdown(entry?.backgroundDetails?.[1] ?? '').nodes).not.toContain('list');
    expect(entry?.functionalAreas).toEqual(['Memory_Management *raw* <T>', 'File Processing']);
    expect(entry?.affectedResources).toEqual(['File or Directory', 'CPU']);
    for (const key of ['ordinalities', 'backgroundDetails', 'functionalAreas', 'affectedResources'])
      expect(catalog.weaknesses.get('CWE-20')).not.toHaveProperty(key);
    // Background details are returned, never searched.
    expect(catalog.searchText.get('CWE-79')).toEqual({
      description: 'First & A &lt; sentence. Second bold and emphasis. one two Read source.',
    });
  });

  it('stores notes on weaknesses, categories and views: the type as plain text, the note as prose', () => {
    const catalog = parseCweCatalog(
      cweXml
        .replace(
          '</Weakness>',
          `<Notes><Note Type="Relationship">Related to <xhtml:b>CWE-20</xhtml:b> via $var_name [REF-1].</Note><Note Type=" Research
            Gap "><xhtml:p>First paragraph.</xhtml:p><xhtml:p># Not a heading.</xhtml:p></Note><Note Type="Other"></Note></Notes></Weakness>`,
        )
        .replace(
          '</Relationships></Category>',
          '</Relationships><Notes><Note Type="Maintenance">Category note.</Note></Notes></Category>',
        )
        .replace(
          '</Filter></View>',
          '</Filter><Notes><Note Type="Other">View note &amp; *caveat*.</Note></Notes></View>',
        ),
    );
    const notes = catalog.weaknesses.get('CWE-79')?.notes;
    expect(notes).toEqual([
      { type: 'Relationship', text: 'Related to **CWE-20** via $var_name [REF-1].' },
      { type: 'Research Gap', text: 'First paragraph.\n\n\\# Not a heading.' },
      { type: 'Other', text: '' },
    ]);
    expect(notes?.map(({ text }) => parseMarkdown(text).text)).toEqual([
      'Related to CWE-20 via $var_name [REF-1].',
      'First paragraph.\n# Not a heading.',
      '',
    ]);
    expect(catalog.weaknesses.get('CWE-900')?.notes).toEqual([
      { type: 'Maintenance', text: 'Category note.' },
    ]);
    expect(catalog.views.get('CWE-1001')?.notes).toEqual([
      { type: 'Other', text: 'View note & \\*caveat\\*.' },
    ]);
    expect(catalog.weaknesses.get('CWE-20')).not.toHaveProperty('notes');
    expect(catalog.views.get('CWE-1000')).not.toHaveProperty('notes');
    // Mapping notes are a separate element, never read as notes.
    expect(
      parseCweCatalog(
        cweXml.replace(
          '</Weakness>',
          '<Mapping_Notes><Usage>Allowed</Usage></Mapping_Notes></Weakness>',
        ),
      ).weaknesses.get('CWE-79'),
    ).not.toHaveProperty('notes');
  });
});

describe('parseCapecCatalog', () => {
  it('stores CAPEC alternate terms on the pattern and in its search projection', () => {
    const catalog = parseCapecCatalog(
      capecXml.replace(
        '<Prerequisites>',
        '<Alternate_Terms><Alternate_Term><Term>Man-in-the-Middle / MITM</Term></Alternate_Term><Alternate_Term><Term>On-path Attacker</Term><Description>Preferred <xhtml:i>neutral</xhtml:i> term.</Description></Alternate_Term></Alternate_Terms><Prerequisites>',
      ),
    );
    expect(catalog.attackPatterns.get('CAPEC-1')?.alternateTerms).toEqual([
      { term: 'Man-in-the-Middle / MITM' },
      { term: 'On-path Attacker', description: 'Preferred *neutral* term.' },
    ]);
    expect(catalog.attackPatterns.get('CAPEC-2')).not.toHaveProperty('alternateTerms');
    expect(Object.fromEntries(catalog.searchText)).toEqual({
      'CAPEC-1': {
        alternateTerms: ['Man-in-the-Middle / MITM', 'On-path Attacker'],
        description: 'Attack description.',
      },
      'CAPEC-2': { description: 'Only identity and description.' },
    });
  });

  it('stores CAPEC notes with the shared note shape and leaves patterns without notes unchanged', () => {
    const catalog = parseCapecCatalog(
      capecXml.replace(
        '</References>',
        '</References><Notes><Note Type="Terminology">HTTP Splitting – "a <xhtml:i>quoted</xhtml:i> term" [REF-117].</Note><Note Type="Other">Second_note.</Note></Notes>',
      ),
    );
    expect(catalog.attackPatterns.get('CAPEC-1')?.notes).toEqual([
      { type: 'Terminology', text: 'HTTP Splitting – "a *quoted* term" [REF-117].' },
      { type: 'Other', text: 'Second_note.' },
    ]);
    expect(catalog.attackPatterns.get('CAPEC-2')).not.toHaveProperty('notes');
  });

  it('retains a present but empty description on a draft attack pattern', () => {
    const xml = capecXml
      .replace('Name="Sparse pattern" Status="Deprecated"', 'Name="Sparse pattern" Status="Draft"')
      .replace(
        '<Description>Only identity and description.</Description>',
        '<Description></Description>',
      );
    expect(parseCapecCatalog(xml).attackPatterns.get('CAPEC-2')).toMatchObject({
      id: 'CAPEC-2',
      status: 'Draft',
      description: '',
    });
  });

  it('retains unresolved references with and without recorded sections', () => {
    const xml = capecXml.replace(
      '<Reference External_Reference_ID="CAP-REF"/>',
      '<Reference External_Reference_ID="missing" Section="Appendix A"/><Reference External_Reference_ID="other-missing"/>',
    );
    expect(parseCapecCatalog(xml).attackPatterns.get('CAPEC-1')?.references).toEqual([
      { id: 'missing', section: 'Appendix A' },
      { id: 'other-missing' },
    ]);
  });

  it('preserves nested execution steps and recorded crosswalks without deriving absent mappings', () => {
    const catalog = parseCapecCatalog(capecXml);
    expect(catalog.attackPatterns.get('CAPEC-1')).toMatchObject({
      prerequisites: ['First prerequisite.', 'Second prerequisite.'],
      executionFlow: [
        {
          step: '1',
          phase: 'Explore',
          description: 'Find **input**.\n\n1. inspect\n2. trace',
          techniques: ['Probe one.', 'Probe two.'],
          indicators: ['Signal one.', 'Signal two.'],
        },
        { step: '2', phase: 'Exploit', description: 'Use input.' },
      ],
      skills: [{ level: 'Low', description: 'Read source.' }, { description: 'Write payload.' }],
      consequences: [
        {
          scopes: ['Confidentiality', 'Integrity'],
          impacts: ['Read Data', 'Modify Data'],
          note: 'Conditional.',
        },
      ],
      mitigations: ['Validate.', 'Encode.'],
      relatedWeaknesses: [{ id: 'CWE-79' }],
      relatedAttackPatterns: [{ nature: 'ChildOf', id: 'CAPEC-2' }],
      attackTechniqueIds: ['T1059.001'],
      taxonomyMappings: [
        { taxonomy: 'ATTACK', id: '1059.001', name: 'PowerShell' },
        { taxonomy: 'ATTACK', id: 'T1059.001' },
        { taxonomy: 'Other' },
      ],
      references: [{ id: 'CAP-REF', title: 'Attack reference' }],
    });
    expect(catalog.attackPatterns.get('CAPEC-2')).toEqual({
      id: 'CAPEC-2',
      type: 'attack_pattern',
      name: 'Sparse pattern',
      status: 'Deprecated',
      abstraction: 'Meta',
      sourceUrl: 'https://capec.mitre.org/data/definitions/2.html',
      description: 'Only identity and description.',
    });
  });

  it('parses categories and views as records beside patterns, with ordered members and raw filters', () => {
    const catalog = parseCapecCatalog(capecXml);
    const url = (id: number) => `https://capec.mitre.org/data/definitions/${id}.html`;
    expect(catalog.categories.get('CAPEC-118')).toEqual({
      id: 'CAPEC-118',
      type: 'category',
      name: 'Collect and Analyze Information',
      status: 'Stable',
      sourceUrl: url(118),
      description: 'Patterns that focus on **gathering** information.',
      members: [{ id: 'CAPEC-2' }, { id: 'CAPEC-1' }],
      taxonomyMappings: [{ taxonomy: 'WASC', id: '13', name: 'Information Leakage' }],
      references: [{ id: 'CAP-REF', title: 'Attack reference', section: '2' }],
      notes: [{ type: 'Maintenance', text: 'Category *note*.' }],
    });
    expect(catalog.categories.get('CAPEC-119')).toEqual({
      id: 'CAPEC-119',
      type: 'category',
      name: 'DEPRECATED: Deplete Resources',
      status: 'Deprecated',
      sourceUrl: url(119),
      description: 'No longer used by any view.',
    });
    expect(catalog.views.get('CAPEC-1000')).toEqual({
      id: 'CAPEC-1000',
      type: 'view',
      name: 'Mechanisms of Attack',
      status: 'Stable',
      sourceUrl: url(1000),
      description: 'Organizes patterns by the mechanism they employ.',
      members: [{ id: 'CAPEC-118' }, { id: 'CAPEC-119' }, { id: 'CAPEC-404' }],
    });
    expect(catalog.views.get('CAPEC-282')).toEqual({
      id: 'CAPEC-282',
      type: 'view',
      name: 'Meta Abstractions',
      status: 'Draft',
      sourceUrl: url(282),
      description: 'Meta abstraction attack patterns.',
      filterDefinition:
        "/Attack_Pattern_Catalog/Attack_Patterns/Attack_Pattern[@Abstraction='Meta']",
      references: [{ id: 'CAP-REF', title: 'Attack reference' }],
      notes: [{ type: 'Other', text: 'View note.' }],
    });
    // Every pattern names its record family; search projections stay pattern-only.
    expect(catalog.attackPatterns.get('CAPEC-1')?.type).toBe('attack_pattern');
    expect([...catalog.searchText.keys()]).toEqual(['CAPEC-1', 'CAPEC-2']);
  });

  it('keeps both the members and the filter of a CAPEC view that records both', () => {
    const view = parseCapecCatalog(
      capecXml.replace(
        '<Filter>',
        '<Members><Has_Member CAPEC_ID="2"/><Has_Member CAPEC_ID="118"/></Members><Filter>',
      ),
    ).views.get('CAPEC-282');
    expect(view).toMatchObject({
      members: [{ id: 'CAPEC-2' }, { id: 'CAPEC-118' }],
      filterDefinition:
        "/Attack_Pattern_Catalog/Attack_Patterns/Attack_Pattern[@Abstraction='Meta']",
    });
  });

  it('parses ATT&CK Entry_IDs from source text and keeps mapping names raw', () => {
    const catalog = parseCapecCatalog(
      capecXml.replace(
        '<Entry_ID>1059.001</Entry_ID><Entry_Name>PowerShell</Entry_Name>',
        '<Entry_ID>\n  1059.001\n</Entry_ID><Entry_Name>Command_Line *Interface*</Entry_Name>',
      ),
    );
    const entry = catalog.attackPatterns.get('CAPEC-1');
    expect(entry?.attackTechniqueIds).toEqual(['T1059.001']);
    expect(entry?.taxonomyMappings?.[0]).toEqual({
      taxonomy: 'ATTACK',
      id: '1059.001',
      name: 'Command_Line *Interface*',
    });
    expect(Object.fromEntries(catalog.searchText)).toEqual({
      'CAPEC-1': { description: 'Attack description.' },
      'CAPEC-2': { description: 'Only identity and description.' },
    });
  });
});

describe('catalog validation boundaries', () => {
  const invalidCwe = [
    ['malformed XML', cweXml.replace('</Weaknesses>', '</Wrong>')],
    ['wrong root', cweXml.replaceAll('Weakness_Catalog', 'Other_Catalog')],
    ['wrong namespace', cweXml.replace('http://cwe.mitre.org/cwe-7', 'http://example.test/schema')],
    ['missing root version', cweXml.replace(' Version="4.test"', '')],
    ['missing name', cweXml.replace(' Name="Sparse"', '')],
    ['blank status', cweXml.replace('Status="Incomplete"', 'Status=" "')],
    ['zero identifier', cweXml.replace('ID="0079"', 'ID="000"')],
    ['nonnumeric identifier', cweXml.replace('ID="0079"', 'ID="79x"')],
    ['padded identifier', cweXml.replace('ID="0079"', 'ID=" 0079 "')],
    ['padded relation identifier', cweXml.replace('CWE_ID="20"', 'CWE_ID="20 "')],
    [
      'duplicate normalized identifier',
      cweXml.replace('ID="20" Name="Sparse"', 'ID="79" Name="Sparse"'),
    ],
    ['cross-family duplicate', cweXml.replace('ID="1001"', 'ID="79"')],
    ['missing family', cweXml.replace(/<Categories>[\s\S]*?<\/Categories>/, '')],
    ['missing description', cweXml.replace('<Description>Sparse description.</Description>', '')],
    [
      'alternate term without its term',
      cweXml.replace(
        '<Related_Weaknesses>',
        '<Alternate_Terms><Alternate_Term><Description>Orphan.</Description></Alternate_Term></Alternate_Terms><Related_Weaknesses>',
      ),
    ],
    [
      'note without its type',
      cweXml.replace('</Weakness>', '<Notes><Note>Untyped.</Note></Notes></Weakness>'),
    ],
    [
      'ordinality without its value',
      cweXml.replace(
        '<Related_Weaknesses>',
        '<Weakness_Ordinalities><Weakness_Ordinality><Description>Orphan.</Description></Weakness_Ordinality></Weakness_Ordinalities><Related_Weaknesses>',
      ),
    ],
    [
      'duplicate reference',
      cweXml.replace(
        '</External_References>',
        '<External_Reference Reference_ID="REF-1"/></External_References>',
      ),
    ],
    [
      'external entity declaration',
      `<!DOCTYPE Weakness_Catalog [<!ENTITY x SYSTEM "file:///etc/passwd">]>${cweXml}`,
    ],
    [
      'internal expansion declaration',
      `<!DOCTYPE Weakness_Catalog [<!ENTITY x "payload">]>${cweXml}`,
    ],
    ['multiple roots', `${cweXml}<other/>`],
  ];
  it.each(invalidCwe)('rejects %s as nonretryable invalid_catalog', (_name, xml) => {
    expect(() => parseCweCatalog(xml)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it.each([
    [
      'empty patterns',
      capecXml.replace(/<Attack_Patterns>[\s\S]*?<\/Attack_Patterns>/, '<Attack_Patterns/>'),
    ],
    ['missing abstraction', capecXml.replace(' Abstraction="Detailed"', '')],
    [
      'absent description',
      capecXml.replace('<Description>Only identity and description.</Description>', ''),
    ],
    [
      'duplicate patterns',
      capecXml.replace('ID="2" Name="Sparse pattern"', 'ID="1" Name="Sparse pattern"'),
    ],
    ['invalid ATTACK mapping', capecXml.replace('1059.001', '1059.0001')],
    ['missing execution phase', capecXml.replace('<Phase>Explore</Phase>', '')],
    [
      'note without its type',
      capecXml.replace('</References>', '</References><Notes><Note>Untyped.</Note></Notes>'),
    ],
    ['category reusing a pattern ID', capecXml.replace('Category ID="119"', 'Category ID="02"')],
    ['view reusing a pattern ID', capecXml.replace('View ID="282"', 'View ID="1"')],
    ['view reusing a category ID', capecXml.replace('View ID="282"', 'View ID="118"')],
    ['duplicate categories', capecXml.replace('Category ID="119"', 'Category ID="118"')],
    ['duplicate views', capecXml.replace('View ID="282"', 'View ID="1000"')],
    [
      'category without its summary',
      capecXml.replace('<Summary>No longer used by any view.</Summary>', ''),
    ],
    ['invalid member identifier', capecXml.replace('CAPEC_ID="404"', 'CAPEC_ID="40x"')],
  ])('rejects CAPEC %s', (_name, xml) => {
    expect(() => parseCapecCatalog(xml)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it.each([parseCweCatalog, parseCapecCatalog])(
    'classifies an HTML outage as retryable',
    (parse) => {
      expect(() => parse('<!DOCTYPE html><html><body>Unavailable</body></html>')).toThrow(
        expect.objectContaining({
          data: expect.objectContaining({ reason: 'upstream_html', retryable: true }),
        }),
      );
    },
  );
});

describe('orderedContentToMarkdown', () => {
  const el = (name: string, ...content: OrderedNode[]): OrderedNode => ({ [name]: content });
  const link = (href: string, ...content: OrderedNode[]): OrderedNode => ({
    ':@': { '@_href': href },
    a: content,
  });
  const image = (src: string, alt: string): OrderedNode => ({
    ':@': { '@_src': src, '@_alt': alt },
    img: [],
  });
  /** [source, stored, visible text, node types after the document] */
  type Case = [OrderedNode[], string, string, string[]];
  function expectDocuments(cases: Case[]) {
    for (const [nodes, stored, visible, types] of cases) {
      const markdown = orderedContentToMarkdown(nodes);
      expect(markdown).toBe(stored);
      expect(parseMarkdown(markdown)).toEqual({ text: visible, nodes: ['document', ...types] });
    }
  }
  /** Cases that convert to one paragraph, listing the node types inside it. */
  const expectCases = (cases: Case[]) =>
    expectDocuments(
      cases.map(
        ([nodes, stored, visible, inline]): Case => [
          nodes,
          stored,
          visible,
          ['paragraph', ...inline],
        ],
      ),
    );

  it('sizes code fences beyond source delimiters and retains blank lines inside code', () => {
    expect(orderedContentToMarkdown([{ pre: [{ '#text': '  start\n\n\n    ```\n  end' }] }])).toBe(
      '````\n  start\n\n\n    ```\n  end\n````',
    );
  });

  it('escapes data syntax and keeps nested lists in source order', () => {
    expect(orderedContentToMarkdown([{ '#text': '<script>*data*</script>' }])).toBe(
      '\\<script>\\*data\\*\\</script>',
    );
    expect(
      orderedContentToMarkdown([
        {
          ol: [
            { li: [{ '#text': 'outer' }, { ul: [{ li: [{ '#text': 'inner' }] }] }] },
            { li: [{ '#text': 'second' }] },
          ],
        },
      ]),
    ).toBe('1. outer\n\n   - inner\n2. second');
  });

  it('decides escapes against neighbours in other elements', () => {
    const link = orderedContentToMarkdown([
      { span: [textNode('[x]')] },
      textNode('(javascript:alert(1))'),
    ]);
    expect(link).toBe('[x\\](javascript:alert(1))');
    expect(parseMarkdown(link).nodes).not.toContain('link');
    const list = orderedContentToMarkdown([{ span: [textNode('1')] }, textNode('. x')]);
    expect(list).toBe('1\\. x');
    expect(parseMarkdown(list)).toMatchObject({ text: '1. x' });
    expect(parseMarkdown(list).nodes).not.toContain('list');
    const bold = orderedContentToMarkdown([{ b: [textNode('label:')] }, textNode('text')]);
    expect(bold).toBe('**label**:text');
    expect(parseMarkdown(bold)).toEqual({
      text: 'label:text',
      nodes: ['document', 'paragraph', 'strong', 'text', 'text'],
    });
  });

  it('never opens a link reference definition, across lines, code, or link labels', () => {
    const cases: [OrderedNode[], string, string][] = [
      [
        [{ p: [textNode('[a](b]: x')] }, { p: [textNode('see [a](b]')] }],
        '\\[a\\](b]: x\n\nsee [a\\](b]',
        '[a](b]: x\nsee [a](b]',
      ],
      [
        [textNode('[a'), { br: [] }, textNode('[b]: javascript:alert(1)')],
        '\\[a  \n\\[b]: javascript:alert(1)',
        '[a\n[b]: javascript:alert(1)',
      ],
      [
        [
          { p: [textNode('[x '), { code: [textNode('\\]')] }, textNode(']: evil.html')] },
          { p: [textNode('see [x '), { code: [textNode('\\]')] }, textNode(']')] },
        ],
        '\\[x ` \\] `]: evil.html\n\nsee [x ` \\] `]',
        '[x \\]]: evil.html\nsee [x \\]]',
      ],
      // A definition label is read without code spans, so code in a link label is label text.
      [
        [
          {
            ':@': { '@_href': 'https://example.test/' },
            a: [{ code: [textNode(']:')] }, textNode('evil.html')],
          },
        ],
        '[\\]:evil.html](<https://example.test/>)',
        ']:evil.html',
      ],
    ];
    for (const [nodes, stored, visible] of cases) {
      const markdown = orderedContentToMarkdown(nodes);
      expect(markdown).toBe(stored);
      expect(referenceDefinitions(markdown)).toEqual([]);
      expect(parseMarkdown(markdown).text).toBe(visible);
    }
    expect(renderHtml(cases[3]![1])).toBe(
      '<p><a href="https://example.test/">]:evil.html</a></p>\n',
    );
  });

  it('never leaves a definition or a non-HTTP(S) link in converted prose', () => {
    const word = fc.constantFrom(
      '[',
      ']',
      '(',
      ')',
      ':',
      '\\',
      ' ',
      'a',
      '!',
      '`',
      '<',
      '[a]',
      ']:',
      '](',
      'javascript:x',
    );
    const text = fc.string({ unit: word, minLength: 1, maxLength: 8 }).map(textNode);
    const { node } = fc.letrec<{ node: OrderedNode }>((tie) => {
      const content = (maxLength: number) => fc.array(tie('node'), { maxLength });
      return {
        node: fc.oneof(
          { depthSize: 'small', withCrossShrink: true },
          text,
          fc.constant<OrderedNode>({ br: [] }),
          content(4).map((nodes) => ({ p: nodes })),
          content(3).map((nodes) => ({ code: nodes })),
          content(3).map((nodes) => ({ b: nodes })),
          content(3).map((nodes) => ({ ul: nodes.map((item) => ({ li: [item] })) })),
          fc
            .tuple(fc.constantFrom('https://example.test/', 'javascript:alert(1)'), content(3))
            .map(([href, nodes]) => ({ ':@': { '@_href': href }, a: nodes })),
        ),
      };
    });
    fc.assert(
      fc.property(fc.array(node, { maxLength: 5 }), (nodes) => {
        const markdown = orderedContentToMarkdown(nodes);
        expect(referenceDefinitions(markdown)).toEqual([]);
        for (const [, destination] of renderHtml(markdown).matchAll(/(?:href|src)="([^"]*)"/g))
          expect(destination).toMatch(/^https:\/\//);
      }),
      { seed: 20261021, numRuns: 2000 },
    );
  });

  it('keeps inline code on one line, as a code span shows it', () => {
    // CommonMark already shows a line ending inside a code span as a space.
    expect(parseMarkdown(orderedContentToMarkdown([{ code: [textNode('a\nb')] }])).text).toBe(
      'a b',
    );
    const breakout = orderedContentToMarkdown([
      textNode('x '),
      { code: [textNode('a\n\n[c](evil.html)')] },
      textNode(' y'),
    ]);
    expect(breakout).toBe('x ` a  [c](evil.html) ` y');
    expect(parseMarkdown(breakout)).toMatchObject({ text: 'x a  [c](evil.html) y' });
    expect(parseMarkdown(breakout).nodes).not.toContain('link');
    const html = orderedContentToMarkdown([
      { code: [textNode('a'), { br: [] }, { br: [] }, textNode('<img src=x onerror=alert(1)>')] },
    ]);
    expect(html).toBe('` a  <img src=x onerror=alert(1)> `');
    expect(parseMarkdown(html).nodes).toEqual(['document', 'paragraph', 'code']);
    const heading = orderedContentToMarkdown([{ code: [textNode('a\r\n# h\rb')] }]);
    expect(heading).toBe('` a # h b `');
    expect(parseMarkdown(heading).nodes).toEqual(['document', 'paragraph', 'code']);
  });

  it('converts tables to pipe tables that keep every cell in row order', () => {
    const cell = (name: 'td' | 'th', ...content: OrderedNode[]) => ({ [name]: content });
    expect(
      orderedContentToMarkdown([
        textNode('Intro'),
        {
          table: [
            { tr: [cell('th', textNode('Name')), cell('th', textNode('Value'))] },
            {
              tr: [
                cell('td', textNode('a|b')),
                cell('td', textNode('one'), { br: [] }, textNode('two')),
              ],
            },
            { tr: [cell('td', textNode('short'))] },
          ],
        },
        textNode('After'),
      ]),
    ).toBe('Intro\n\n| Name | Value |\n| --- | --- |\n| a\\|b | one two |\n| short |  |\n\nAfter');
    expect(
      orderedContentToMarkdown([
        {
          table: [
            {
              tbody: [
                { tr: [cell('td', textNode('h1')), cell('td', textNode('h2'))] },
                { tr: [cell('td', textNode('v1')), cell('td', { b: [textNode('v2')] })] },
              ],
            },
          ],
        },
      ]),
    ).toBe('| h1 | h2 |\n| --- | --- |\n| v1 | **v2** |');
  });

  it('converts a table inside example code to pipe-table code text', () => {
    const xml = cweXml.replace(
      '<xhtml:div>next();</xhtml:div>',
      '<xhtml:div>next();</xhtml:div><xhtml:table><xhtml:tr><xhtml:th>Reg</xhtml:th><xhtml:th>Bits</xhtml:th></xhtml:tr><xhtml:tr><xhtml:td>KEY_0</xhtml:td><xhtml:td>[0:31]   <xhtml:br/>key</xhtml:td></xhtml:tr></xhtml:table>',
    );
    expect(parseCweCatalog(xml).weaknesses.get('CWE-79')?.examples?.[0]?.blocks[1]?.text).toBe(
      'if (a < b) {\n    call("x");\n}\nnext();\n| Reg | Bits |\n| --- | --- |\n| KEY_0 | [0:31] key |',
    );
  });

  it('shows images only from absolute HTTP(S) or the CWE site, otherwise their alt text', () => {
    const image = (src: string) =>
      orderedContentToMarkdown([{ ':@': { '@_src': src, '@_alt': 'Diagram [v2]' }, img: [] }]);
    expect(image('/data/images/a b.png')).toBe(
      '![Diagram \\[v2\\]](<https://cwe.mitre.org/data/images/a%20b.png>)',
    );
    expect(image('https://example.test/y.png')).toBe(
      '![Diagram \\[v2\\]](<https://example.test/y.png>)',
    );
    expect(parseMarkdown(image('/data/images/x.png'))).toMatchObject({ text: 'Diagram [v2]' });
    for (const src of ['//evil.test/x.png', '/\\evil.test/x.png', 'javascript:alert(1)', 'x.png']) {
      const inert = image(src);
      expect(inert).toBe('Diagram [v2]');
      expect(parseMarkdown(inert).nodes).not.toContain('image');
    }
  });

  it('marks superscripts with a caret', () => {
    expect(
      orderedContentToMarkdown([
        textNode('P(x) = x'),
        { sup: [textNode('6')] },
        textNode('+x'),
        { sup: [textNode('4')] },
        textNode('+1'),
      ]),
    ).toBe('P(x) = x^6+x^4+1');
  });

  describe('bold and emphasis', () => {
    it('keeps pairs CommonMark can open and close beside generated syntax and each other', () => {
      expectCases([
        [
          [textNode('a '), el('b', link('https://e.test', textNode('y'))), textNode(' b')],
          'a **[y](<https://e.test>)** b',
          'a y b',
          ['text', 'strong', 'link', 'text', 'text'],
        ],
        [
          [textNode('a'), el('b', el('i', textNode('x'))), textNode('b')],
          'a***x***b',
          'axb',
          ['text', 'emph', 'strong', 'text', 'text'],
        ],
        [
          [textNode('a'), el('i', textNode('x')), el('b', textNode('y')), textNode('b')],
          'a*x***y**b',
          'axyb',
          ['text', 'emph', 'text', 'strong', 'text', 'text'],
        ],
        [
          [textNode('a'), el('b', textNode('x'), el('i', textNode('y'))), textNode('b')],
          'a**x*y***b',
          'axyb',
          ['text', 'strong', 'text', 'emph', 'text', 'text'],
        ],
        [
          [textNode('a '), el('b', textNode('x'), { br: [] }, textNode('y')), textNode(' b')],
          'a **x  \ny** b',
          'a x\ny b',
          ['text', 'strong', 'text', 'linebreak', 'text', 'text'],
        ],
        [
          [textNode('a'), link('https://e.test', el('b', textNode('y'))), textNode('b')],
          'a[**y**](<https://e.test>)b',
          'ayb',
          ['text', 'link', 'strong', 'text', 'text'],
        ],
      ]);
    });

    it('drops both delimiters of a pair that cannot open or close, keeping the text', () => {
      expectCases([
        [
          [textNode('a'), el('b', link('https://e.test', textNode('y'))), textNode('b')],
          'a[y](<https://e.test>)b',
          'ayb',
          ['text', 'link', 'text', 'text'],
        ],
        [
          [textNode('a'), el('b', el('code', textNode('c'))), textNode('b')],
          'a` c `b',
          'acb',
          ['text', 'code', 'text'],
        ],
        [
          [textNode('a'), el('i', image('https://e.test/x.png', 'x')), textNode('b')],
          'a![x](<https://e.test/x.png>)b',
          'axb',
          ['text', 'image', 'text', 'text'],
        ],
        [
          [textNode('a'), el('b', el('sup', textNode('2'))), textNode('b')],
          'a^2b',
          'a^2b',
          ['text'],
        ],
        [
          [textNode('a'), el('b', link('mailto:x', textNode('y'))), textNode('b')],
          'ay (mailto:x)b',
          'ay (mailto:x)b',
          ['text'],
        ],
        [
          [textNode('1'), el('b', el('code', textNode('c'))), textNode('2')],
          '1` c `2',
          '1c2',
          ['text', 'code', 'text'],
        ],
        [
          [textNode('漢'), el('i', link('https://e.test', textNode('y'))), textNode('字')],
          '漢[y](<https://e.test>)字',
          '漢y字',
          ['text', 'link', 'text', 'text'],
        ],
      ]);
    });

    it('merges adjacent spans of one kind and adds nothing for a span inside its own kind', () => {
      expectCases([
        [
          [textNode('a'), el('i', textNode('x')), el('i', textNode('y')), textNode('b')],
          'a*xy*b',
          'axyb',
          ['text', 'emph', 'text', 'text'],
        ],
        [
          [textNode('a '), el('i', textNode('x')), el('em', textNode('y')), textNode(' b')],
          'a *xy* b',
          'a xy b',
          ['text', 'emph', 'text', 'text'],
        ],
        [
          [textNode('a'), el('b', textNode('x')), el('strong', textNode('y')), textNode('b')],
          'a**xy**b',
          'axyb',
          ['text', 'strong', 'text', 'text'],
        ],
        [
          [
            textNode('a'),
            el('b', el('i', textNode('x'))),
            el('b', el('i', textNode('y'))),
            textNode('b'),
          ],
          'a***xy***b',
          'axyb',
          ['text', 'emph', 'strong', 'text', 'text'],
        ],
        [
          [textNode('a '), el('i', el('i', textNode('x'))), textNode(' b')],
          'a *x* b',
          'a x b',
          ['text', 'emph', 'text', 'text'],
        ],
        [
          [
            textNode('a '),
            el('b', textNode('x '), el('b', textNode('y')), textNode(' z')),
            textNode(' b'),
          ],
          'a **x y z** b',
          'a x y z b',
          ['text', 'strong', 'text', 'text'],
        ],
      ]);
    });

    it('drops the later span when CommonMark would pair its delimiters with another span', () => {
      expectCases([
        // `a**x*y****z*b` read the closing run of four as one closer and the opener of z as text.
        [
          [
            textNode('a'),
            el('b', textNode('x'), el('i', textNode('y'))),
            el('i', textNode('z')),
            textNode('b'),
          ],
          'a**x*y***zb',
          'axyzb',
          ['text', 'strong', 'text', 'emph', 'text', 'text'],
        ],
        // `a*x***y*z***b` let the opener before z close the bold.
        [
          [
            textNode('a'),
            el('i', textNode('x')),
            el('b', textNode('y'), el('i', textNode('z'))),
            textNode('b'),
          ],
          'a*x***yz**b',
          'axyzb',
          ['text', 'emph', 'text', 'strong', 'text', 'text'],
        ],
        // A run of four left open would make the bold's own closer unmatched.
        [
          [
            textNode('a'),
            el('i', textNode('w')),
            el('b', el('i', textNode('x')), textNode('y')),
            textNode('b'),
          ],
          'a*w***xy**b',
          'awxyb',
          ['text', 'emph', 'text', 'strong', 'text', 'text'],
        ],
      ]);
    });

    it('moves a hard break at an emphasis or link edge outside as a hard break', () => {
      expectCases([
        [
          [textNode('a'), el('b', textNode('x'), { br: [] }), textNode('y')],
          'a**x**  \ny',
          'ax\ny',
          ['text', 'strong', 'text', 'text', 'linebreak', 'text'],
        ],
        [
          [textNode('a'), el('i', { br: [] }, textNode('x')), textNode('y')],
          'a  \n*x*y',
          'a\nxy',
          ['text', 'linebreak', 'emph', 'text', 'text'],
        ],
        [
          [textNode('a'), link('https://e.test', textNode('x'), { br: [] }), textNode('y')],
          'a[x](<https://e.test>)  \ny',
          'ax\ny',
          ['text', 'link', 'text', 'text', 'linebreak', 'text'],
        ],
        // An inert link's address goes before the break, not after it.
        [
          [textNode('a'), link('mailto:x', textNode('x'), { br: [] }), textNode('b')],
          'ax (mailto:x)  \nb',
          'ax (mailto:x)\nb',
          ['text', 'linebreak', 'text'],
        ],
      ]);
    });

    it('adds no delimiters around content that spans blocks, which CommonMark never pairs', () => {
      const paragraphs = ['paragraph', 'text', 'paragraph', 'text'];
      expectDocuments([
        [
          [textNode('a '), el('b', textNode('x'), el('p', textNode('y'))), textNode(' z')],
          'a x\n\ny z',
          'a x\ny z',
          paragraphs,
        ],
        // Two breaks leave a blank line, which ends the paragraph.
        [
          [
            textNode('a '),
            el('i', textNode('x'), { br: [] }, { br: [] }, textNode('y')),
            textNode(' z'),
          ],
          'a x  \n\ny z',
          'a x\ny z',
          paragraphs,
        ],
      ]);
    });
  });

  describe('links, images, code, and blocks beside their neighbours', () => {
    const code = (value: string) => el('code', textNode(value));
    const ul = (...items: OrderedNode[][]): OrderedNode => ({
      ul: items.map((content) => ({ li: content })),
    });
    const table = (...rows: OrderedNode[][][]): OrderedNode => ({
      table: rows.map((cells) => ({ tr: cells.map((content) => ({ td: content })) })),
    });

    it('escapes a source ! before a generated link, which would otherwise read as an image', () => {
      expectCases([
        [
          [textNode('see!'), link('https://e.test/', textNode('y'))],
          'see\\![y](<https://e.test/>)',
          'see!y',
          ['text', 'text', 'link', 'text'],
        ],
        // The ! meets the link once the emphasis delimiters between them are dropped.
        [
          [textNode('a!'), el('i', link('https://e.test', textNode('y'))), textNode('b')],
          'a\\![y](<https://e.test>)b',
          'a!yb',
          ['text', 'text', 'link', 'text', 'text'],
        ],
        [
          [textNode('see!'), image('https://e.test/x.png', 'x')],
          'see!![x](<https://e.test/x.png>)',
          'see!x',
          ['text', 'text', 'image', 'text'],
        ],
      ]);
    });

    it('merges code spans whose fences touch, which CommonMark reads as one backtick run', () => {
      expectCases([
        [[code('a'), code('b')], '` ab `', 'ab', ['code']],
        [
          [textNode('x '), code('a'), code('b'), code('c'), textNode(' y')],
          'x ` abc ` y',
          'x abc y',
          ['text', 'code', 'text'],
        ],
        // Fences touch once the emphasis delimiters between them are dropped; kept ones separate.
        [
          [textNode('x'), code('a'), el('i', code('b')), textNode('y')],
          'x` ab `y',
          'xaby',
          ['text', 'code', 'text'],
        ],
        [
          [textNode('x '), code('a'), el('i', code('b')), textNode(' y')],
          'x ` a `*` b `* y',
          'x ab y',
          ['text', 'code', 'emph', 'code', 'text'],
        ],
        // The joined code sizes the fence, and keeps a space that ends or starts either code.
        [[code('a`'), code('`b')], '``` a``b ```', 'a``b', ['code']],
        [[code(' '), code('b')], '`  b `', ' b', ['code']],
        [[code('a'), el('sup', code('b'))], '` a `^` b `', 'a^b', ['code', 'text', 'code']],
      ]);
    });

    it('writes no span for empty code and no padding around code of only spaces', () => {
      expectCases([
        [[textNode('a'), el('code'), textNode('b')], 'ab', 'ab', ['text']],
        [[textNode('a'), code(''), textNode('b')], 'ab', 'ab', ['text']],
        [[textNode('a'), code(' '), textNode('b')], 'a` `b', 'a b', ['text', 'code', 'text']],
      ]);
    });

    it('renders a link as its content alone where CommonMark cannot hold one', () => {
      const paragraphs = ['paragraph', 'text', 'paragraph', 'text'];
      expectDocuments([
        [
          [link('https://e.test/', textNode('x'), el('p', textNode('y')))],
          'x\n\ny',
          'x\ny',
          paragraphs,
        ],
        // Two breaks leave a blank line, which ends the paragraph.
        [
          [link('https://e.test/', textNode('x'), { br: [] }, { br: [] }, textNode('y'))],
          'x  \n\ny',
          'x\ny',
          paragraphs,
        ],
        // Content renders as if the anchor were absent, so code inside is a code span again.
        [
          [link('https://e.test/', code('c'), el('p', textNode('y')))],
          '` c `\n\ny',
          'c\ny',
          ['paragraph', 'code', 'paragraph', 'text'],
        ],
        // No link holds another, at any depth.
        [
          [link('https://e.test/', textNode('x'), link('https://f.test/', textNode('y')))],
          '[xy](<https://e.test/>)',
          'xy',
          ['paragraph', 'link', 'text'],
        ],
        [
          [
            link(
              'https://e.test/',
              el('b', textNode('x '), link('https://f.test/', textNode('y'))),
            ),
          ],
          '[**x y**](<https://e.test/>)',
          'x y',
          ['paragraph', 'link', 'strong', 'text'],
        ],
        [
          [link('https://e.test/', textNode('x'), { br: [] }, textNode('y'))],
          '[x  \ny](<https://e.test/>)',
          'x\ny',
          ['paragraph', 'link', 'text', 'linebreak', 'text'],
        ],
      ]);
    });

    it('keeps a list, preformatted block, or table on its own lines inside a span', () => {
      const list = ['paragraph', 'text', 'list', 'item', 'paragraph', 'text', 'paragraph', 'text'];
      expectDocuments([
        [
          [textNode('a '), el('b', ul([textNode('x')])), textNode(' b')],
          'a \n\n- x\n\nb',
          'a\nx\nb',
          list,
        ],
        [
          [textNode('a '), link('https://e.test/', ul([textNode('x')])), textNode(' b')],
          'a \n\n- x\n\nb',
          'a\nx\nb',
          list,
        ],
        [
          [textNode('a '), link('mailto:x', ul([textNode('x')])), textNode(' b')],
          'a \n\n- x\n\n (mailto:x) b',
          'a\nx\n(mailto:x) b',
          list,
        ],
        // The fence pulled onto the line before read `b` as its info string.
        [
          [textNode('a'), el('b', el('pre', textNode('y'))), textNode('b')],
          'a\n\n```\ny\n```\n\nb',
          'a\ny\nb',
          ['paragraph', 'text', 'code_block', 'paragraph', 'text'],
        ],
        // A paragraph between the span and the list passes the list's edge on.
        [
          [el('b', el('p', ul([textNode('x')])))],
          '- x',
          'x',
          ['list', 'item', 'paragraph', 'text'],
        ],
        [
          [textNode('a'), el('b', table([[textNode('c')]])), textNode('b')],
          'a\n\n| c |\n| --- |\n\nb',
          'a\n| c |\n| --- |\nb',
          ['paragraph', 'text', 'paragraph', 'text', 'softbreak', 'text', 'paragraph', 'text'],
        ],
      ]);
    });

    it('keeps only the text of a list or table in a cell, and shows preformatted text as code', () => {
      const row = ['paragraph', 'text', 'softbreak', 'text'];
      expectDocuments([
        [
          [table([[ul([textNode('x')], [textNode('y')])]])],
          '| x y |\n| --- |',
          '| x y |\n| --- |',
          row,
        ],
        [[table([[{ li: [textNode('x')] }]])], '| x |\n| --- |', '| x |\n| --- |', row],
        [
          [table([[table([[textNode('c')], [textNode('d')]])]])],
          '| c d |\n| --- |',
          '| c d |\n| --- |',
          row,
        ],
        [
          [table([[code('a'), el('pre', textNode('y'))]])],
          '| ` a ` ` y ` |\n| --- |',
          '| a y |\n| --- |',
          ['paragraph', 'text', 'code', 'text', 'code', 'text', 'softbreak', 'text'],
        ],
      ]);
    });

    it('never shows generated syntax as text or changes the visible text', () => {
      const word = fc.constantFrom(
        'a',
        '7',
        ' ',
        '.',
        '*',
        '_',
        '\\',
        '漢',
        '(',
        ')',
        '[',
        ']',
        '!',
        '`',
      );
      const text = fc.string({ unit: word, minLength: 1, maxLength: 3 }).map(textNode);
      const codeText = fc.constantFrom('c', '', ' ', '`', 'a b', '``x', ' c ');
      // `inline` trees hold no block; `node` trees add paragraphs, preformatted text, tables, lists.
      const { node } = fc.letrec<{ inline: OrderedNode; node: OrderedNode }>((tie) => {
        const nodes = (kind: 'inline' | 'node', maxLength: number) =>
          fc.array(tie(kind), { maxLength });
        const shapes = (kind: 'inline' | 'node') => [
          text,
          fc.constant<OrderedNode>({ br: [] }),
          fc.constantFrom('x', '', ']').map((alt) => image('https://e.test/x.png', alt)),
          codeText.map(code),
          nodes(kind, 3).map((content) => el('sup', ...content)),
          nodes(kind, 4).map((content) => el('b', ...content)),
          nodes(kind, 4).map((content) => el('i', ...content)),
          nodes(kind, 3).map((content) => el('strong', ...content)),
          fc
            .tuple(fc.constantFrom('https://e.test/', 'mailto:x'), nodes(kind, 3))
            .map(([href, content]) => link(href, ...content)),
        ];
        const cells = fc.tuple(nodes('node', 2), nodes('node', 2));
        return {
          inline: fc.oneof({ depthSize: 'small', withCrossShrink: true }, ...shapes('inline')),
          node: fc.oneof(
            { depthSize: 'small', withCrossShrink: true },
            ...shapes('node'),
            nodes('node', 3).map((content) => el('p', ...content)),
            codeText.map((value) => el('pre', textNode(value))),
            fc.array(cells, { minLength: 1, maxLength: 2 }).map((rows) => table(...rows)),
            // An item led by text: a nested list whose first item is empty puts three markers on
            // one line, which CommonMark reads as a thematic break, a list layout case of its own.
            fc
              .array(nodes('node', 2), { minLength: 1, maxLength: 2 })
              .map((items) => ul(...items.map((content) => [textNode('a'), ...content]))),
          ),
        };
      });
      const key = (item: OrderedNode) =>
        Object.keys(item).find((name) => name !== ':@' && !name.startsWith('#'));
      // An inert link's address follows its content's last visible character, so the whitespace
      // around it depends on what ends the content; both sides fold it to single spaces.
      const fold = (value: string) =>
        value
          .replace(/\s*\(mailto:x\)\s*/g, ' (mailto:x) ')
          .replace(/\s+/g, ' ')
          .trim();
      const codeOf = (content: readonly OrderedNode[]) =>
        content.map((item) => item['#text']).join('');
      /** What a reader of the source sees, before whitespace folding. */
      const source = (nodes: readonly OrderedNode[], cell = false): string =>
        nodes
          .map((item) => {
            const name = key(item);
            if (!name) return item['#text'] as string;
            const content = item[name] as OrderedNode[];
            const attributes = item[':@'] as Record<string, string> | undefined;
            switch (name) {
              case 'br':
                return '\n';
              case 'img':
                return attributes?.['@_alt'] ?? '';
              case 'code':
                return codeOf(content);
              case 'pre':
                return `\n${codeOf(content)}\n`;
              case 'p':
                return `\n${source(content, cell)}\n`;
              case 'sup':
                return `^${source(content, cell)}`;
              case 'ul':
                return content
                  .map((entry) => `\n${source(entry.li as OrderedNode[], cell)}\n`)
                  .join('');
              case 'table': {
                const rows = content.map((row) =>
                  (row.tr as OrderedNode[]).map((entry) => source(entry.td as OrderedNode[], true)),
                );
                // A table in a cell keeps only its cells' text.
                if (cell)
                  return rows
                    .flat()
                    .map((entry) => ` ${entry} `)
                    .join('');
                const lines = rows.map((cells) => `| ${cells.map(fold).join(' | ')} |`);
                return `\n${[lines[0], '| --- | --- |', ...lines.slice(1)].join('\n')}\n`;
              }
              case 'a':
                return attributes?.['@_href'] === 'mailto:x'
                  ? `${source(content, cell)} (mailto:x)`
                  : source(content, cell);
              default:
                return source(content, cell);
            }
          })
          .join('');
      fc.assert(
        fc.property(fc.array(node, { maxLength: 6 }), (nodes) => {
          const markdown = orderedContentToMarkdown(nodes);
          expect(fold(parseMarkdown(markdown).text)).toBe(fold(source(nodes)));
          expect(referenceDefinitions(markdown)).toEqual([]);
        }),
        { seed: 20261022, numRuns: 4000 },
      );
    });
  });

  it('continues an ordered item at its marker width so later blocks stay inside it', () => {
    const items = Array.from({ length: 10 }, (_, index) => ({
      li:
        index === 9
          ? [{ p: [textNode('ten')] }, { p: [textNode('more')] }]
          : [textNode(`item ${index + 1}`)],
    }));
    const markdown = orderedContentToMarkdown([{ ol: items }]);
    expect(markdown.endsWith('\n10. ten\n\n    more')).toBe(true);
    expect(renderHtml(markdown)).toContain('<li>\n<p>ten</p>\n<p>more</p>\n</li>\n</ol>');
    expect(
      renderHtml(
        orderedContentToMarkdown([
          { ol: [{ li: [{ p: [textNode('a')] }, { p: [textNode('b')] }] }] },
        ]),
      ),
    ).toBe('<ol>\n<li>\n<p>a</p>\n<p>b</p>\n</li>\n</ol>\n');
  });

  it('converts in linear time', { timeout: 60_000 }, () => {
    const shapes: [string, (length: number) => OrderedNode[]][] = [
      [
        'many runs',
        (length) =>
          Array.from({ length: length / 8 }, () => [
            textNode('a '),
            { b: [textNode('bc')] },
            textNode(' '),
          ]).flat(),
      ],
      [
        'bold around many punctuation children',
        (length) => [
          {
            b: [
              ...Array.from({ length: length / 6 }, () => ({ i: [textNode('.')] })),
              textNode('x'),
            ],
          },
        ],
      ],
      ['digit run', (length) => [textNode('7'.repeat(length))]],
      ['one long line, then a break', (length) => [textNode(`${'§1 x'.repeat(length / 4)}\ny`)]],
      ['breaks throughout code', (length) => [{ pre: [textNode('  \r\n'.repeat(length / 4))] }]],
      [
        'hard breaks throughout',
        (length) => Array.from({ length: length / 4 }, () => [textNode('a'), { br: [] }]).flat(),
      ],
      [
        'adjacent spans of one kind',
        (length) => [
          textNode('a'),
          ...Array.from({ length: length / 3 }, () => ({ i: [textNode('x')] })),
          textNode('b'),
        ],
      ],
      [
        'alternating kinds side by side',
        (length) =>
          Array.from({ length: length / 7 }, () => [
            { i: [textNode('x')] },
            { b: [textNode('y')] },
          ]).flat(),
      ],
      [
        'nested emphasis openers side by side',
        (length) =>
          Array.from({ length: length / 7 }, () => ({
            b: [{ i: [textNode('x')] }, textNode('y')],
          })),
      ],
      [
        'spans the pass drops',
        (length) =>
          Array.from({ length: length / 10 }, () => [
            { b: [textNode('x'), { i: [textNode('y')] }] },
            { i: [textNode('z')] },
          ]).flat(),
      ],
      [
        'emphasis ending in a break',
        (length) => Array.from({ length: length / 7 }, () => ({ b: [textNode('x'), { br: [] }] })),
      ],
    ];
    for (const [label, build] of shapes) expectLinearTime(label, build, orderedContentToMarkdown);
    expectLinearTime(
      'parse and project a long description',
      (length) =>
        cweXml.replace('Sparse description.', 'a <xhtml:b>b_c</xhtml:b> 1. '.repeat(length / 28)),
      parseCweCatalog,
    );
  });

  it('converts links, code, and blocks beside their neighbours in linear time', {
    timeout: 60_000,
  }, () => {
    const code = (value: string) => el('code', textNode(value));
    const anchor = (...content: OrderedNode[]) => link('https://e.test/', ...content);
    const nest = (depth: number, inside: OrderedNode): OrderedNode =>
      depth ? anchor(nest(depth - 1, inside)) : inside;
    const shapes: [string, (length: number) => OrderedNode[]][] = [
      [
        'one long line of links, then a break',
        (length) => [
          ...Array.from({ length: length / 25 }, () => anchor(textNode('§1 x'))),
          { br: [] },
          textNode('y'),
        ],
      ],
      // Code of only spaces, all touching: one span the merge pass builds whole.
      [
        'breaks throughout code spans',
        (length) => Array.from({ length: length / 4 }, () => code('  \r\n')),
      ],
      ['adjacent code spans', (length) => Array.from({ length: length / 6 }, () => code('ab'))],
      [
        'code spans joined by dropped emphasis',
        (length) =>
          Array.from({ length: length / 16 }, () => [
            textNode('x'),
            code('a'),
            { i: [code('b')] },
            textNode('y'),
          ]).flat(),
      ],
      [
        'exclamation marks before links',
        (length) =>
          Array.from({ length: length / 24 }, () => [textNode('!'), anchor(textNode('y'))]).flat(),
      ],
      [
        'links whose content crosses blocks',
        (length) =>
          Array.from({ length: length / 7 }, () =>
            anchor(textNode('x'), { br: [] }, { br: [] }, textNode('y')),
          ),
      ],
      // Each group is six anchors, whose source runs past 150 characters.
      [
        'nested links around a paragraph',
        (length) => Array.from({ length: length / 40 }, () => nest(6, { p: [textNode('x')] })),
      ],
      [
        'lists inside emphasis',
        (length) =>
          Array.from({ length: length / 6 }, () => ({ b: [{ ul: [{ li: [textNode('x')] }] }] })),
      ],
      [
        'lists in table cells',
        (length) => [
          {
            table: Array.from({ length: length / 12 }, () => ({
              tr: [{ td: [{ ul: [{ li: [textNode('x')] }, { li: [textNode('y')] }] }] }],
            })),
          },
        ],
      ],
    ];
    for (const [label, build] of shapes) expectLinearTime(label, build, orderedContentToMarkdown);
  });
});
