#!/usr/bin/env node
/**
 * BIMI indicator SVG screening and SVG P/S diagnostics.
 *
 *   node src/core/bimi/svg.test.js
 *
 * ── What this suite proves, and what it deliberately does not ────────────
 *
 * `validateBimiSvg()` takes an injected `parseSvg`, so the RULES — which
 * element names are refused, which attributes are external references, which
 * profile requirements are diagnostics — are exercised here against a fixture
 * tree built by hand.
 *
 * That fixture is **not a parser and is not offered as one.** `OQ-ART-08`
 * settled that parsing behaviour is a property of the engine the browser
 * ships: entity expansion, DTD handling and malformed-XML recovery cannot be
 * shimmed, and `tests/build/local-input-security.test.mjs` is where the real
 * `DOMParser` is driven. The division is deliberate — traversal logic here,
 * parser behaviour there — and neither half is evidence for the other.
 *
 * The pre-parse rules are the exception: they run on the source TEXT, so they
 * are fully exercised here, and one of them is the reason the release is safe
 * at all. Chrome expands internal general entities (measured: a nine-level
 * billion-laughs document produced 59,049 characters), so `<!ENTITY>` has to
 * be refused before `parseSvg` is ever called. The assertion below that
 * `parsed` stays false is that guarantee, executable.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  validateBimiSvg, BIMI_SVG_REJECTIONS, BIMI_SVG_DIAGNOSTICS,
} from './svg.js';

const { eq, section, report } = createSuite();

/* ── A fixture tree, not a parser ─────────────────────────────────────── */

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Build one element node with the minimal surface the validator reads. */
function el(localName, attrs = {}, children = [], ns = SVG_NS) {
  return {
    nodeType: 1,
    localName,
    nodeName: localName,
    namespaceURI: ns,
    attributes: Object.entries(attrs).map(([name, value]) => ({
      name,
      // The measured shape: `xlink:href` reports localName `href`.
      localName: name.includes(':') ? name.split(':')[1] : name,
      value: String(value),
    })),
    childNodes: children,
    get textContent() {
      return children.map(c => (c.nodeType === 3 ? c.data : c.textContent)).join('');
    },
  };
}

const text = data => ({ nodeType: 3, data, textContent: data });

/** A conformant tiny-ps root, with whatever overrides a case needs. */
function conformant({ attrs = {}, children = null } = {}) {
  return el('svg', {
    baseProfile: 'tiny-ps', version: '1.2', viewBox: '0 0 64 64', ...attrs,
  }, children || [el('title', {}, [text('Example')])]);
}

const docOf = root => ({ documentElement: root });
/** The injected parser: hands back a prepared tree, ignoring the text. */
const parserFor = root => () => docOf(root);
const parseThrows = () => { throw new Error('boom'); };

/* Every case needs source text that survives the pre-parse scan, since that
 * scan runs on the string and not on the tree. */
const OK_TEXT = '<svg xmlns="http://www.w3.org/2000/svg"/>';
const check = (root, source = OK_TEXT) => validateBimiSvg(source, parserFor(root));

/* ── 1. The published vocabularies ────────────────────────────────────── */
section('1. State constants');

eq('the rejection vocabulary is frozen and complete',
  [Object.isFrozen(BIMI_SVG_REJECTIONS), [...BIMI_SVG_REJECTIONS]],
  [true, ['doctype-present', 'entity-declaration', 'malformed-xml', 'bad-root',
    'script-element', 'event-handler', 'foreign-object',
    'external-reference-element', 'external-reference', 'link-element',
    'external-style', 'animation']]);
eq('the diagnostic vocabulary is frozen and complete',
  [Object.isFrozen(BIMI_SVG_DIAGNOSTICS), [...BIMI_SVG_DIAGNOSTICS]],
  [true, ['namespace-not-svg', 'base-profile-not-tiny-ps', 'version-not-1-2',
    'title-missing', 'title-not-unique', 'desc-empty',
    'viewbox-missing', 'viewbox-not-square', 'root-has-position',
    'raster-data-uri', 'unsupported-attribute']]);
// XML makes a second root a parse error, measured in Chrome, so a
// "multiple-roots" diagnostic would be a state no fixture can reach.
eq('and multiple roots is NOT a diagnostic — XML makes it a parse error',
  BIMI_SVG_DIAGNOSTICS.some(t => t.includes('root') && t !== 'root-has-position'),
  false);

/* ── 2. The pre-parse scan, which is what makes this release safe ─────── */
section('2. Refused before the parser ever runs');

/* The parser is COUNTED, not inferred. An earlier version of this suite
 * asserted `parsed === false`, which a parser that was called and then threw
 * also satisfies — so the assertion passed while the bomb reached the parser.
 * Chrome expands internal entities, so "was it reached" is the only question
 * that matters, and only a spy answers it. */
let parserCalls = 0;
const spy = () => { parserCalls++; throw new Error('the parser must not run'); };

const bomb = '<!DOCTYPE lolz [<!ENTITY lol "lol">]><svg xmlns="' + SVG_NS + '"/>';
parserCalls = 0;
const bombed = validateBimiSvg(bomb, spy);
eq('a document declaring an entity is refused', bombed.rejections.includes('entity-declaration'), true);
eq('and its DOCTYPE is reported too', bombed.rejections.includes('doctype-present'), true);
eq('THE PARSER WAS NEVER INVOKED', parserCalls, 0);
eq('and `parsed` reports that it was never reached', bombed.parsed, false);
eq('the injected parser throwing did not surface, because it never ran',
  bombed.rejections.includes('malformed-xml'), false);

parserCalls = 0;
const doctypeOnly = validateBimiSvg('<!DOCTYPE svg><svg xmlns="' + SVG_NS + '"/>', spy);
eq('a DOCTYPE alone is also refused pre-parse',
  [doctypeOnly.rejections, doctypeOnly.parsed, parserCalls], [['doctype-present'], false, 0]);

// The other half: a clean document DOES reach the parser, so the assertions
// above are about the guard and not about the parser never being used.
parserCalls = 0;
validateBimiSvg(OK_TEXT, () => { parserCalls++; return docOf(conformant()); });
eq('a clean document does reach the parser', parserCalls, 1);

eq('an empty document is malformed, not parsed',
  [validateBimiSvg('   ', parserFor(conformant())).rejections,
    validateBimiSvg('   ', parserFor(conformant())).parsed],
  [['malformed-xml'], false]);
eq('a non-string is malformed', validateBimiSvg(null, parserFor(conformant())).rejections,
  ['malformed-xml']);
eq('a parser that throws is malformed rather than an escaping exception',
  [validateBimiSvg(OK_TEXT, parseThrows).rejections,
    validateBimiSvg(OK_TEXT, parseThrows).parsed],
  [['malformed-xml'], true]);
eq('and a missing parser is refused rather than assumed',
  validateBimiSvg(OK_TEXT, undefined).rejections, ['malformed-xml']);

/* ── 3. Root identity ─────────────────────────────────────────────────── */
section('3. The root');

eq('a conformant tiny-ps logo passes',
  [check(conformant()).valid, check(conformant()).rejections, check(conformant()).diagnostics],
  [true, [], []]);
eq('and its title is reported', check(conformant()).title, 'Example');

// Measured: HTML in a .svg file parses CLEANLY in Chrome, so nothing but an
// explicit root check catches it.
eq('HTML that parsed without error is still refused by root name',
  check(el('html', {}, [], 'http://www.w3.org/1999/xhtml')).rejections, ['bad-root']);
eq('a parsererror element anywhere is malformed',
  check(el('svg', {}, [el('parsererror', {}, [text('bad')], 'http://www.w3.org/1999/xhtml')])).rejections,
  ['malformed-xml']);
eq('a document with no root element is malformed',
  validateBimiSvg(OK_TEXT, () => ({ documentElement: null })).rejections, ['malformed-xml']);
eq('the right root name in the wrong namespace is a DIAGNOSTIC, not a refusal',
  [check(conformant({ attrs: {} })).valid,
    validateBimiSvg(OK_TEXT, parserFor(el('svg', {
      baseProfile: 'tiny-ps', version: '1.2', viewBox: '0 0 64 64',
    }, [el('title', {}, [text('x')])], null))).diagnostics],
  [true, ['namespace-not-svg']]);

/* ── 4. Security rejections ───────────────────────────────────────────── */
section('4. Security screening');

const REJECTIONS = [
  ['a script element', el('script', {}, [text('alert(1)')]), 'script-element'],
  ['an onload handler', el('rect', { onload: 'alert(1)' }), 'event-handler'],
  ['an onCLICK handler, case-insensitively', el('rect', { onCLICK: 'x' }), 'event-handler'],
  ['a foreignObject', el('foreignObject'), 'foreign-object'],
  ['an image element', el('image', { href: '#a' }), 'external-reference-element'],
  ['a use element', el('use', { href: '#a' }), 'external-reference-element'],
  ['an anchor', el('a', {}), 'link-element'],
  ['an animate element', el('animate'), 'animation'],
  ['an animateTransform element', el('animateTransform'), 'animation'],
  ['a set element', el('set'), 'animation'],
  ['an animateMotion element', el('animateMotion'), 'animation'],
  ['a style with @import', el('style', {}, [text('@import url(x.css);')]), 'external-style'],
  ['a style with url()', el('style', {}, [text('.a{fill:url(https://e.example/x)}')]), 'external-style'],
];

REJECTIONS.forEach(([label, child, token]) => {
  const result = check(conformant({ children: [el('title', {}, [text('t')]), child] }));
  eq(`${label} is refused as ${token}`, result.rejections.includes(token), true);
  eq(`  and the document is not valid`, result.valid, false);
});

section('4b. External references');

const href = (attrs) => check(conformant({
  children: [el('title', {}, [text('t')]), el('path', attrs)],
})).rejections;

eq('a same-document fragment is permitted', href({ href: '#glyph' }), []);
eq('an absolute https href is an external reference',
  href({ href: 'https://evil.example/x.png' }), ['external-reference']);
eq('a relative href is too', href({ href: 'x.png' }), ['external-reference']);
eq('a protocol-relative href is too', href({ href: '//evil.example/x' }), ['external-reference']);
// Measured: the namespaced spelling reports name `xlink:href`, localName `href`.
eq('xlink:href is caught by the same rule',
  href({ 'xlink:href': 'https://evil.example/x#a' }), ['external-reference']);
eq('and an empty href is not a fragment either', href({ href: '' }), ['external-reference']);

section('4c. Everything at once');

const hostile = check(conformant({
  children: [
    el('title', {}, [text('t')]),
    el('script', {}, [text('x')]),
    el('use', { 'xlink:href': 'https://evil.example/x#a' }),
    el('rect', { onload: 'x' }),
    el('a', {}),
  ],
}));
eq('a document with several problems reports all of them, deduplicated',
  hostile.rejections.slice().sort(),
  ['event-handler', 'external-reference', 'external-reference-element',
    'link-element', 'script-element']);
eq('and reports them once each',
  new Set(hostile.rejections).size, hostile.rejections.length);

/* ── 5. Profile diagnostics ───────────────────────────────────────────── */
section('5. SVG P/S diagnostics');

const diag = (attrs, children) => check(conformant({ attrs, children })).diagnostics;

eq('a missing baseProfile is reported',
  diag({ baseProfile: undefined }, null).includes('base-profile-not-tiny-ps'), true);
eq('a wrong baseProfile is reported',
  diag({ baseProfile: 'tiny' }, null), ['base-profile-not-tiny-ps']);
eq('a wrong version is reported', diag({ version: '1.1' }, null), ['version-not-1-2']);
eq('x on the root is reported', diag({ x: '0' }, null), ['root-has-position']);
eq('y on the root is reported', diag({ y: '0' }, null), ['root-has-position']);

eq('a missing viewBox is reported',
  diag({ viewBox: undefined }, null).includes('viewbox-missing'), true);
eq('a non-square viewBox is reported',
  diag({ viewBox: '0 0 64 32' }, null), ['viewbox-not-square']);
eq('a square viewBox with comma separators is accepted',
  diag({ viewBox: '0,0,64,64' }, null), []);
eq('a malformed viewBox is reported as missing rather than mis-measured',
  diag({ viewBox: 'not numbers' }, null), ['viewbox-missing']);

eq('a missing title is reported',
  diag({}, [el('rect')]), ['title-missing']);
eq('an empty title is reported',
  diag({}, [el('title', {}, [text('   ')])]), ['title-missing']);
eq('two direct-child titles are reported',
  diag({}, [el('title', {}, [text('a')]), el('title', {}, [text('b')])]).sort(),
  ['title-not-unique']);
// A title nested in a group is not the document's title.
eq('a title nested inside a group does not count',
  diag({}, [el('g', {}, [el('title', {}, [text('x')])])]), ['title-missing']);
eq('an empty desc is reported',
  diag({}, [el('title', {}, [text('t')]), el('desc', {}, [text('  ')])]), ['desc-empty']);
eq('a non-empty desc is fine',
  diag({}, [el('title', {}, [text('t')]), el('desc', {}, [text('brand')])]), []);

eq('a raster data URI in a fill is a diagnostic, not a rejection',
  check(conformant({ children: [el('title', {}, [text('t')]),
    el('rect', { fill: 'url(data:image/png;base64,iVBOR)' })] })),
  { valid: true, parsed: true, root: 'svg', title: 't',
    rejections: [], diagnostics: ['raster-data-uri'] });
eq('a raster data URI inside a style block is caught too',
  check(conformant({ children: [el('title', {}, [text('t')]),
    el('style', {}, [text('.a{fill:data:image/png;base64,iVBOR}')])] })).diagnostics,
  ['raster-data-uri']);
eq('and a style block with no data URI raises nothing',
  check(conformant({ children: [el('title', {}, [text('t')]),
    el('style', {}, [text('.a{fill:#f00}')])] })).diagnostics, []);
eq('an SVG data URI is not a raster one',
  check(conformant({ children: [el('title', {}, [text('t')]),
    el('rect', { fill: 'data:image/svg+xml,%3Csvg/%3E' })] })).diagnostics, []);

// The spec constrains six attributes to "permitted inert values" without
// enumerating them, so presence alone is the diagnostic until it decides.
['zoomAndPan', 'externalResourcesRequired', 'focusable',
  'snapshotTime', 'playbackOrder', 'timelineBegin'].forEach(name => {
  eq(`${name} present is an unsupported-attribute diagnostic`,
    diag({ [name]: 'x' }, null), ['unsupported-attribute']);
});

section('5b. Diagnostics never make a document invalid');

const diagnosticsOnly = check(conformant({
  attrs: { baseProfile: undefined, version: '1.1', viewBox: '0 0 10 5', x: '1' },
  children: [el('rect')],
}));
eq('a logo that will not display is still not a security refusal',
  [diagnosticsOnly.valid, diagnosticsOnly.rejections], [true, []]);
eq('and every profile problem is listed',
  diagnosticsOnly.diagnostics.slice().sort(),
  ['base-profile-not-tiny-ps', 'root-has-position', 'title-missing',
    'version-not-1-2', 'viewbox-not-square']);

/* ── 6. The module returns no nodes ───────────────────────────────────── */
section('6. Tokens and primitives only');

const shape = check(conformant({ children: [el('title', {}, [text('t')]), el('rect')] }));
eq('the result keys are exactly the published shape',
  Object.keys(shape).sort(),
  ['diagnostics', 'parsed', 'rejections', 'root', 'title', 'valid']);
// The load-bearing rule of the release, asserted structurally: nothing the
// validator returns can be inserted anywhere, because none of it is a node.
eq('no returned value is a node or carries one',
  Object.values(shape).every(v =>
    typeof v === 'boolean' || typeof v === 'string' || v === null ||
    (Array.isArray(v) && v.every(x => typeof x === 'string'))),
  true);
eq('every emitted rejection is a registered member',
  hostile.rejections.filter(t => !BIMI_SVG_REJECTIONS.includes(t)), []);
eq('every emitted diagnostic is a registered member',
  diagnosticsOnly.diagnostics.filter(t => !BIMI_SVG_DIAGNOSTICS.includes(t)), []);

report();
