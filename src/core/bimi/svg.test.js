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
    'raster-data-uri', 'data-uri-reference', 'unsupported-attribute']]);
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
  // Spec 1.10. Attributes were screened for `href` only, so SVG's other ways
  // of naming a document — a paint server, a filter, a mask — reached a valid
  // verdict. Nothing is fetched here, but the tool told an operator that a
  // logo which would beacon from a mail client had passed.
  ['a fill naming another document',
    el('rect', { fill: 'url(https://evil.example/p.svg#g)' }), 'external-reference'],
  ['a style attribute naming another document',
    el('rect', { style: 'fill:url(https://evil.example/p.svg#g)' }), 'external-reference'],
  ['a filter naming another document',
    el('rect', { style: 'filter:url(https://evil.example/f.svg#blur)' }), 'external-reference'],
  ['a stroke naming another document',
    el('rect', { stroke: 'url(//evil.example/p.svg#g)' }), 'external-reference'],
  ['an empty url()', el('rect', { fill: 'url()' }), 'external-reference'],
  ['a local reference beside an external one',
    el('rect', { style: 'fill:url(#a);stroke:url(https://evil.example/b#c)' }), 'external-reference'],
  ['a style element naming another document in a paint server',
    el('style', {}, [text('.a{fill:url("https://evil.example/p.svg#g")}')]), 'external-style'],
];

REJECTIONS.forEach(([label, child, token]) => {
  const result = check(conformant({ children: [el('title', {}, [text('t')]), child] }));
  eq(`${label} is refused as ${token}`, result.rejections.includes(token), true);
  eq(`  and the document is not valid`, result.valid, false);
});

/* The other half of spec 1.10, and the half a fix will silently skip.
 *
 * The 1.9 `<style>` matcher was `/@import|url\s*\(/i`, which rejects EVERY
 * `url(` — so a logo that defines a gradient and paints with it, ordinary
 * conformant SVG, was refused as `external-style`. Widening that regex to
 * every attribute would have spread the false positive across the element
 * tree rather than fixing anything.
 *
 * Every case below must stay VALID. Without them a fix that rejects too much
 * passes the hostile fixtures above and ships a screen that fails good logos.
 */
const LOCAL_REFERENCES = [
  ['a fill naming a local paint server', el('rect', { fill: 'url(#grad)' })],
  ['a style attribute naming a local paint server',
    el('rect', { style: 'fill:url(#grad)' })],
  ['a quoted local reference', el('rect', { fill: 'url("#grad")' })],
  ['a single-quoted local reference', el('rect', { fill: "url('#grad')" })],
  ['a local reference with whitespace', el('rect', { fill: 'url( #grad )' })],
  ['two local references in one value',
    el('rect', { style: 'fill:url(#a);stroke:url(#b)' })],
  ['a style element naming a local paint server',
    el('style', {}, [text('.a{fill:url(#localGradient)}')])],
  ['a style element with two local references',
    el('style', {}, [text('.a{fill:url(#a)}.b{stroke:url( #b )}')])],
];

LOCAL_REFERENCES.forEach(([label, child]) => {
  const result = check(conformant({ children: [el('title', {}, [text('t')]), child] }));
  eq(`${label} stays valid`, [result.valid, result.rejections], [true, []]);
});

/* `data:` is the third case, and it is neither `#fragment` nor external.
 *
 * SVG Tiny 1.2 permits a `fill` or `stroke` to name a local fragment only, so
 * a `data:` paint reference IS non-conformant — and the URI does resolve to a
 * document distinct from the owner document. What it does not do is reach the
 * network: it carries its own bytes, so it requires no fetch and cannot
 * beacon. That is the distinction this file's two vocabularies are built on,
 * and it is why the profile complaint does not become a refusal.
 *
 * It is not unreported. A RASTER `data:` URI in any position is the
 * `raster-data-uri` DIAGNOSTIC — an SVG Tiny PS logo should not embed a
 * bitmap — which is a profile complaint rather than a security one. Making it
 * an `external-reference` instead would turn a shipped diagnostic into an
 * invalid verdict for a self-contained file. Section 5 already pins that for a
 * `fill`; these pin the rule itself, in both positions and for the vector
 * case, which section 5 does not cover.
 */
const dataUri = (child) =>
  check(conformant({ children: [el('title', {}, [text('t')]), child] }));

{
  const raster = dataUri(el('rect', { fill: 'url(data:image/png;base64,iVBOR)' }));
  eq('a raster data URI in a fill diagnoses twice and refuses nothing',
    [raster.valid, raster.rejections, raster.diagnostics],
    [true, [], ['data-uri-reference', 'raster-data-uri']]);

  const inStyleAttr = dataUri(el('rect', { style: 'fill:url(data:image/png;base64,iVBOR)' }));
  eq('and the same in a style attribute',
    [inStyleAttr.valid, inStyleAttr.rejections,
      inStyleAttr.diagnostics.includes('data-uri-reference')], [true, [], true]);

  const inStyleEl = dataUri(el('style', {}, [text('.a{fill:url(data:image/png;base64,iVBOR)}')]));
  eq('and inside a style element, which the 1.9 rule refused outright',
    [inStyleEl.valid, inStyleEl.rejections,
      inStyleEl.diagnostics.includes('data-uri-reference')], [true, [], true]);

  // Vector, so `RASTER_DATA_URI` does not fire. Through 0.8.0 this reached
  // `bimi.svg-valid` with NO signal at all, which is the gap the diagnostic
  // closes: the profile forbids the reference whatever the payload is.
  const vector = dataUri(el('rect', { fill: 'url(data:image/svg+xml,%3Csvg/%3E)' }));
  eq('a vector data URI is diagnosed even though no bitmap is embedded',
    [vector.valid, vector.rejections, vector.diagnostics],
    [true, [], ['data-uri-reference']]);

  // The boundary: `data` as a HOST is an ordinary external reference.
  const host = dataUri(el('rect', { fill: 'url(https://data.example/p.svg#g)' }));
  eq('a host called data is still external',
    [host.valid, host.rejections, host.diagnostics], [false, ['external-reference'], []]);

  // The line the two vocabularies draw. `valid` is a security verdict, bounded
  // by spec 1.0 to refusal rather than profile conformance, which is why
  // `base-profile-not-tiny-ps` and `raster-data-uri` also leave a document
  // valid. A self-contained file fetches nothing, so there is no refusal to
  // make — and the operator is still told the profile forbids the reference.
  eq('data-uri-reference is a diagnostic, never a rejection',
    [BIMI_SVG_DIAGNOSTICS.includes('data-uri-reference'),
      BIMI_SVG_REJECTIONS.includes('data-uri-reference')], [true, false]);
}

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

// Spec 1.10 added `data-uri-reference` beside it: SVG Tiny 1.2 permits a fill
// to name a local fragment only, and `data:` is not one. Two diagnostics, one
// per rule — the bitmap and the reference position are separate complaints —
// and still no rejection, because nothing is fetched.
eq('a raster data URI in a fill raises both diagnostics and no rejection',
  check(conformant({ children: [el('title', {}, [text('t')]),
    el('rect', { fill: 'url(data:image/png;base64,iVBOR)' })] })),
  { valid: true, parsed: true, root: 'svg', title: 't',
    rejections: [], diagnostics: ['data-uri-reference', 'raster-data-uri'],
    sites: [
      { token: 'data-uri-reference', element: '<rect>',
        value: 'fill="url(data:image/png;base64,iVBOR)"' },
      { token: 'raster-data-uri', element: '<rect>',
        value: 'fill="url(data:image/png;base64,iVBOR)"' }] });
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

/* The six constrained attributes and the value each MUST carry when present,
 * quoted from draft-svg-tiny-ps-abrotman-12 §2.3: each "SHOULD NOT be present
 * ... If it is present, it MUST be set to" the value below. An earlier version
 * of this module reported ANY presence as unsupported, which diagnosed the
 * draft's own conformant example. */
const INERT = {
  zoomAndPan: 'disable',
  externalResourcesRequired: 'false',
  focusable: 'false',
  snapshotTime: 'none',
  playbackOrder: 'all',
  timelineBegin: 'onLoad',
};

Object.entries(INERT).forEach(([name, permitted]) => {
  eq(`${name}="${permitted}" is permitted and raises nothing`,
    diag({ [name]: permitted }, null), []);
  eq(`${name} with any other value is unsupported`,
    diag({ [name]: 'nonsense' }, null), ['unsupported-attribute']);
  // XML is case-sensitive, so the folded spelling is not this attribute at all
  // and carries no profile meaning to violate. `focusable` is already
  // lowercase, so it has no folded variant to be a different attribute from.
  if (name !== name.toLowerCase()) {
    eq(`${name.toLowerCase()} is a different attribute and is not constrained`,
      diag({ [name.toLowerCase()]: 'nonsense' }, null), []);
  }
});

eq('the draft\'s own conformant example is not diagnosed',
  diag({ zoomAndPan: 'disable', externalResourcesRequired: 'false' }, null), []);

/* ── XML is case-sensitive, and a conformance check that folds case tells an
 *    operator their nonconformant document conforms ──────────────────────── */
section('5c. Profile names are matched exactly');

eq('baseprofile is not baseProfile',
  diag({ baseProfile: undefined, baseprofile: 'tiny-ps' }, null),
  ['base-profile-not-tiny-ps']);
eq('viewbox is not viewBox',
  diag({ viewBox: undefined, viewbox: '0 0 64 64' }, null), ['viewbox-missing']);
eq('VERSION is not version',
  diag({ version: undefined, VERSION: '1.2' }, null), ['version-not-1-2']);
eq('a wrong-case root is a bad root, not an SVG document',
  validateBimiSvg(OK_TEXT, parserFor(el('SVG', {
    baseProfile: 'tiny-ps', version: '1.2', viewBox: '0 0 64 64',
  }, [el('title', {}, [text('x')])]))),
  { valid: false, parsed: true, root: 'SVG', title: '',
    rejections: ['bad-root'], diagnostics: [],
    sites: [{ token: 'bad-root', element: '<SVG>', value: 'http://www.w3.org/2000/svg' }] });
eq('a wrong-case TITLE does not satisfy the title requirement',
  diag({}, [el('TITLE', {}, [text('x')])]), ['title-missing']);
eq('nor does a wrong-case DESC trip the desc rule',
  diag({}, [el('title', {}, [text('t')]), el('DESC', {}, [text('  ')])]), []);

// The deliberate asymmetry: the SECURITY screen stays case-insensitive,
// because missing `<SCRIPT>` is the dangerous direction there.
eq('but security screening still catches a wrong-case SCRIPT',
  check(conformant({ children: [el('title', {}, [text('t')]), el('SCRIPT', {}, [text('x')])] })).rejections,
  ['script-element']);
eq('and a wrong-case ONLOAD handler',
  check(conformant({ children: [el('title', {}, [text('t')]), el('rect', { ONLOAD: 'x' })] })).rejections,
  ['event-handler']);

/* ── A square that cannot render is not a square ─────────────────────────── */
section('5d. viewBox dimensions must be usable');

eq('a zero-area viewBox is not square, it is unusable',
  diag({ viewBox: '0 0 0 0' }, null), ['viewbox-missing']);
eq('a negative square viewBox is unusable too',
  diag({ viewBox: '0 0 -64 -64' }, null), ['viewbox-missing']);
eq('zero width alone is unusable', diag({ viewBox: '0 0 0 64' }, null), ['viewbox-missing']);
eq('zero height alone is unusable', diag({ viewBox: '0 0 64 0' }, null), ['viewbox-missing']);
eq('negative width alone is unusable', diag({ viewBox: '0 0 -64 64' }, null), ['viewbox-missing']);
eq('a positive square control still passes', diag({ viewBox: '0 0 64 64' }, null), []);
eq('and a positive non-square is still reported as non-square',
  diag({ viewBox: '0 0 64 32' }, null), ['viewbox-not-square']);
eq('a negative origin with positive extent is fine',
  diag({ viewBox: '-32 -32 64 64' }, null), []);

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
  ['diagnostics', 'parsed', 'rejections', 'root', 'sites', 'title', 'valid']);
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

/* ── Located material: the composer must not have to reparse the SVG to
 *    build evidence, so every token records where it came from and what the
 *    offending construct actually was. ─────────────────────────────────── */
section('7. Tree-walk tokens record their site');

const located = check(conformant({ children: [
  el('title', {}, [text('t')]),
  el('rect', { onload: 'alert(1)' }),
  el('use', { 'xlink:href': 'https://evil.example/a#x' }),
] }));
eq('an event handler names the element and the attribute pair',
  located.sites.find(s => s.token === 'event-handler'),
  { token: 'event-handler', element: '<rect>', value: 'onload="alert(1)"' });
eq('an external reference carries the URL that made it one',
  located.sites.find(s => s.token === 'external-reference').value,
  'xlink:href="https://evil.example/a#x"');
eq('and the offending element is named, not the root',
  located.sites.find(s => s.token === 'external-reference-element').element, '<use>');
eq('every site token is a registered member',
  located.sites.filter(s => !BIMI_SVG_REJECTIONS.includes(s.token) &&
    !BIMI_SVG_DIAGNOSTICS.includes(s.token)), []);

// The token arrays are the closed algebras and stay deduplicated; `sites` does
// not, because three external references are three places to fix.
const repeated = check(conformant({ children: [
  el('title', {}, [text('t')]),
  el('image', { href: 'https://a.example/1.png' }),
  el('image', { href: 'https://b.example/2.png' }),
] }));
eq('a repeated rejection is ONE token',
  repeated.rejections.filter(t => t === 'external-reference-element').length, 1);
eq('but every occurrence gets its own site',
  repeated.sites.filter(s => s.token === 'external-reference-element')
    .map(s => s.value),
  ['https://a.example/1.png', 'https://b.example/2.png']);

/* The paths raised BEFORE or AROUND parsing, which have no element to name.
 * An earlier version left these on the token-only helper, so two distinct
 * pre-parse rejections collapsed into one blank evidence entry downstream. */
section('7a. Pre-parse and root rejections record theirs too');

const preParse = validateBimiSvg(
  '<!DOCTYPE x [<!ENTITY a "b"><!ENTITY c "d > e">]><svg/>', () => null);
eq('the complete DOCTYPE and every ENTITY get their own sites',
  preParse.sites,
  [{ token: 'doctype-present', element: '',
    value: '<!DOCTYPE x [<!ENTITY a "b"><!ENTITY c "d > e">]>' },
    { token: 'entity-declaration', element: '', value: '<!ENTITY a "b">' },
    { token: 'entity-declaration', element: '', value: '<!ENTITY c "d > e">' }]);
eq('a bad root names the root that WAS found',
  check(el('html', {}, [], 'http://www.w3.org/1999/xhtml')).sites,
  [{ token: 'bad-root', element: '<html>', value: 'http://www.w3.org/1999/xhtml' }]);
eq('a parser that throws has no supplied position or material to invent',
  validateBimiSvg(OK_TEXT, () => { throw new TypeError('boom'); }).sites,
  [{ token: 'malformed-xml', element: '', value: '' }]);
eq('a parser error node and message are generated, not supplied evidence',
  check(el('svg', {}, [el('parsererror', {}, [text('bad xml')],
    'http://www.w3.org/1999/xhtml')])).sites,
  [{ token: 'malformed-xml', element: '', value: '' }]);
eq('and an empty document is located without inventing an element',
  validateBimiSvg('   ', parserFor(conformant())).sites,
  [{ token: 'malformed-xml', element: '', value: '' }]);

eq('a clean title is bounded in code points, never split mid-character',
  (() => {
    const long = 'y'.repeat(199) + '\u{1F600}';
    const r = check(conformant({ children: [el('title', {}, [text(long)])] }));
    const last = r.title.charCodeAt(r.title.length - 1);
    return last >= 0xD800 && last <= 0xDBFF;
  })(), false);

eq('site material is bounded in code points, never split mid-character',
  (() => {
    const long = 'y'.repeat(199) + '\u{1F600}';
    const r = check(conformant({ children: [el('title', {}, [text('t')]),
      el('rect', { onload: long })] }));
    const v = r.sites.find(s => s.token === 'event-handler').value;
    const last = v.charCodeAt(v.length - 1);
    return last >= 0xD800 && last <= 0xDBFF;
  })(), false);

report();
