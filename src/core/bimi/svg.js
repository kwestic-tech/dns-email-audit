/**
 * User-supplied BIMI indicator SVGs, screened for danger and inspected against
 * the operator-actionable parts of the SVG Portable/Secure profile.
 *
 * Pure protocol logic: no resolver, fetch, storage, DOM or platform import.
 * The parser arrives as an injected `parseSvg` callback — `src/runtime.js`
 * constructs it from the platform's `DOMParser` — so this module reads no
 * ambient browser global and can be exercised with a fixture tree.
 *
 * **This module returns tokens and primitives. It never returns a node.** That
 * is the load-bearing rule of 0.8.0: the parsed document stays detached, and
 * the reason it stays detached is that nothing here can hand a caller anything
 * to insert. `tests/build/local-input-security.test.mjs` asserts the behaviour
 * in a real browser; this file's shape is what makes the assertion easy to keep
 * true.
 *
 * ── Why the DOCTYPE and ENTITY checks happen BEFORE parsing ──────────────
 *
 * Measured, not assumed. Chrome's XML parser **expands internal general
 * entities**: a nine-level billion-laughs document
 * (`<!ENTITY lol9 "&lol8;&lol8;&lol8;">` …) parsed to 59,049 characters of
 * text in 8 ms. Each additional level triples that. So the entity check is not
 * hygiene — it is the only thing standing between a 500-byte upload and an
 * out-of-memory tab, and it MUST run on the source text before `parseSvg` is
 * called. A post-parse check would run after the damage.
 *
 * The same scan rejects any DOCTYPE. An external DTD is not fetched by the
 * browser (also measured), but a document that declares one has no business
 * being a mailbox-provider logo, and `doc.doctype` surviving the parse is not
 * a reason to let the parser see it first.
 *
 * ── What the parser does that the rules have to account for ──────────────
 *
 * | Input | Chrome's result |
 * | --- | --- |
 * | two root elements | parse error — NOT a "multiple roots" diagnostic |
 * | truncated XML | parse error |
 * | HTML in a `.svg` file | parses fine, root is `html` — no parse error at all |
 * | `xlink:href` | `name` is `xlink:href`, `localName` is `href` |
 *
 * The third row is why `bad-root` exists as its own token: nothing about
 * parsing rejects an HTML document, so the root has to be checked by name.
 * The fourth is why href matching is on `localName`, which catches the
 * namespaced and plain spellings with one rule.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Security rejections. A document with any of these is refused outright. */
export const BIMI_SVG_REJECTIONS = Object.freeze([
  'doctype-present', 'entity-declaration', 'malformed-xml', 'bad-root',
  'script-element', 'event-handler', 'foreign-object',
  'external-reference-element', 'external-reference', 'link-element',
  'external-style', 'animation',
]);

/**
 * Profile diagnostics. These describe why a mailbox provider may not display
 * the logo; they are findings, not refusals, and the panel says explicitly that
 * it does not run the full SVG P/S RNC schema.
 *
 * The spec's "single root element" row is deliberately NOT a member: XML makes
 * a second root a parse error, so it is unreachable as a diagnostic and arrives
 * as `malformed-xml` instead. Registering it would be a state no fixture can
 * produce.
 */
export const BIMI_SVG_DIAGNOSTICS = Object.freeze([
  'namespace-not-svg', 'base-profile-not-tiny-ps', 'version-not-1-2',
  'title-missing', 'title-not-unique', 'desc-empty',
  'viewbox-missing', 'viewbox-not-square', 'root-has-position',
  'raster-data-uri', 'unsupported-attribute',
]);

const ANIMATION_ELEMENTS = ['animate', 'animatetransform', 'set', 'animatemotion'];
const EXTERNAL_REF_ELEMENTS = ['image', 'use'];

/**
 * The six attributes SVG Tiny PS constrains, with the value each MUST carry
 * when present. Quoted from draft-svg-tiny-ps-abrotman-12 §2.3, which says of
 * each one that it "SHOULD NOT be present in an SVG Tiny PS document. If it is
 * present, it MUST be set to" the value below.
 *
 * These names are exact. XML is case-sensitive, so `zoomandpan` is not
 * `zoomAndPan` and carries no profile meaning at all.
 */
const CONSTRAINED_ATTRS = Object.freeze({
  zoomAndPan: 'disable',
  externalResourcesRequired: 'false',
  focusable: 'false',
  snapshotTime: 'none',
  playbackOrder: 'all',
  timelineBegin: 'onLoad',
});

const DOCTYPE = /<!DOCTYPE/i;
const ENTITY_DECL = /<!ENTITY/i;
const RASTER_DATA_URI = /data:image\/(?!svg\+xml)/i;
const EXTERNAL_STYLE = /@import|url\s*\(/i;

function emptyResult() {
  return {
    valid: false,
    parsed: false,
    root: null,
    title: '',
    rejections: [],
    diagnostics: [],
  };
}

function add(list, token) {
  if (!list.includes(token)) list.push(token);
}

function elementChildren(node) {
  var out = [];
  var kids = (node && node.childNodes) || [];
  for (var i = 0; i < kids.length; i++) {
    if (kids[i] && kids[i].nodeType === 1) out.push(kids[i]);
  }
  return out;
}

function attributesOf(el) {
  var out = [];
  var attrs = (el && el.attributes) || [];
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i]) out.push(attrs[i]);
  }
  return out;
}

function textOf(node) {
  if (!node) return '';
  if (typeof node.textContent === 'string') return node.textContent;
  return '';
}

function walk(el, visit) {
  visit(el);
  var kids = elementChildren(el);
  for (var i = 0; i < kids.length; i++) walk(kids[i], visit);
}

function lower(value) {
  return String(value == null ? '' : value).toLowerCase();
}

/** The element's name AS WRITTEN. XML is case-sensitive; `<SVG>` is not `<svg>`. */
function nameOf(node) {
  return String((node && (node.localName || node.nodeName)) || '');
}

/**
 * An attribute value by EXACT name.
 *
 * Profile conformance is a question about a schema, and the SVG Tiny PS RNC
 * names `baseProfile` and `viewBox` exactly. Folding case here made
 * `baseprofile="tiny-ps"` satisfy a requirement it does not meet, which is the
 * one failure mode a conformance check must never have: telling an operator
 * their nonconformant document conforms.
 */
function attrValue(el, name) {
  var attrs = attributesOf(el);
  for (var i = 0; i < attrs.length; i++) {
    if (String(attrs[i].name) === name) return String(attrs[i].value == null ? '' : attrs[i].value);
  }
  return null;
}

/**
 * Security rules over the whole tree. Reads names and values, produces tokens.
 *
 * Element and attribute matching here is deliberately CASE-INSENSITIVE, and
 * that is the opposite of the profile rules below. The asymmetry is intended:
 * a conformance check must not call a nonconformant document conformant, while
 * a security screen must not miss `<SCRIPT>` on the grounds that XML says it is
 * a different element. Being wrong in the safe direction is different in each
 * half, so the two halves are written differently.
 */
function screen(root, result) {
  walk(root, function (el) {
    var name = lower(nameOf(el));

    if (name === 'script') add(result.rejections, 'script-element');
    if (name === 'foreignobject') add(result.rejections, 'foreign-object');
    if (EXTERNAL_REF_ELEMENTS.indexOf(name) !== -1) {
      add(result.rejections, 'external-reference-element');
    }
    if (ANIMATION_ELEMENTS.indexOf(name) !== -1) add(result.rejections, 'animation');
    // Any `<a>`, not only one carrying a destination. The spec says "`<a>` with
    // any target"; an anchor with no target is inert but has no business in a
    // logo either, and the safer reading is the one that cannot be argued into
    // permitting a link later.
    if (name === 'a') add(result.rejections, 'link-element');

    if (name === 'style' && EXTERNAL_STYLE.test(textOf(el))) {
      add(result.rejections, 'external-style');
    }

    var attrs = attributesOf(el);
    for (var i = 0; i < attrs.length; i++) {
      var attrName = lower(attrs[i].name);
      var attrLocal = lower(attrs[i].localName || attrs[i].name);
      var value = String(attrs[i].value == null ? '' : attrs[i].value);

      if (/^on/.test(attrName)) add(result.rejections, 'event-handler');

      // `localName` catches `href` and `xlink:href` with one rule — measured:
      // the namespaced spelling reports name `xlink:href`, localName `href`.
      // A same-document fragment is the only permitted destination.
      if (attrLocal === 'href' && value.charAt(0) !== '#') {
        add(result.rejections, 'external-reference');
      }
      if (RASTER_DATA_URI.test(value)) add(result.diagnostics, 'raster-data-uri');
    }

    if (name === 'style' && RASTER_DATA_URI.test(textOf(el))) {
      add(result.diagnostics, 'raster-data-uri');
    }
  });
}

/** SVG P/S diagnostics on the root and its direct children. */
function profile(root, result) {
  if (root.namespaceURI !== SVG_NS) add(result.diagnostics, 'namespace-not-svg');
  if (attrValue(root, 'baseProfile') !== 'tiny-ps') {
    add(result.diagnostics, 'base-profile-not-tiny-ps');
  }
  if (attrValue(root, 'version') !== '1.2') add(result.diagnostics, 'version-not-1-2');
  if (attrValue(root, 'x') !== null || attrValue(root, 'y') !== null) {
    add(result.diagnostics, 'root-has-position');
  }

  // Present is a SHOULD NOT; present with the wrong value is a MUST violation.
  // Only the second is diagnosable without second-guessing the author.
  var names = Object.keys(CONSTRAINED_ATTRS);
  for (var i = 0; i < names.length; i++) {
    var present = attrValue(root, names[i]);
    if (present !== null && present !== CONSTRAINED_ATTRS[names[i]]) {
      add(result.diagnostics, 'unsupported-attribute');
    }
  }

  var viewBox = attrValue(root, 'viewBox');
  if (viewBox === null) {
    add(result.diagnostics, 'viewbox-missing');
  } else {
    var parts = viewBox.trim().split(/[\s,]+/).map(Number);
    var usable = parts.length === 4 && parts.every(function (n) { return isFinite(n); });
    // SVG Tiny 1.2: a negative width or height is an error, and zero disables
    // rendering. Neither is a square logo, and comparing width to height would
    // call `0 0 0 0` and `0 0 -64 -64` square.
    if (!usable || !(parts[2] > 0) || !(parts[3] > 0)) {
      add(result.diagnostics, 'viewbox-missing');
    } else if (parts[2] !== parts[3]) {
      add(result.diagnostics, 'viewbox-not-square');
    }
  }

  // `<title>` must be a DIRECT child, exactly one, non-empty. A title nested
  // inside a group is not the document's title.
  var kids = elementChildren(root);
  var titles = kids.filter(function (el) { return nameOf(el) === 'title'; });
  if (titles.length > 1) add(result.diagnostics, 'title-not-unique');
  if (!titles.length || !textOf(titles[0]).trim()) {
    add(result.diagnostics, 'title-missing');
  } else {
    result.title = textOf(titles[0]).trim().slice(0, 200);
  }

  var descs = kids.filter(function (el) { return nameOf(el) === 'desc'; });
  if (descs.length && !textOf(descs[0]).trim()) add(result.diagnostics, 'desc-empty');
}

/**
 * Screen and inspect one already size-bounded user-supplied SVG.
 *
 * `parseSvg(text)` returns a detached document. The caller enforces the 32 KB
 * UTF-8 limit before this runs; this function enforces that a document
 * declaring a DOCTYPE or an ENTITY never reaches the parser at all.
 */
export function validateBimiSvg(input, parseSvg) {
  var text = typeof input === 'string' ? input : '';
  var result = emptyResult();

  if (!text.trim()) {
    add(result.rejections, 'malformed-xml');
    return result;
  }

  // BEFORE the parser. Chrome expands internal entities; see the header.
  if (DOCTYPE.test(text)) add(result.rejections, 'doctype-present');
  if (ENTITY_DECL.test(text)) add(result.rejections, 'entity-declaration');
  if (result.rejections.length) return result;

  if (typeof parseSvg !== 'function') {
    add(result.rejections, 'malformed-xml');
    return result;
  }

  // Set BEFORE the call, not after. `parsed` is the security guarantee made
  // observable — "did this document reach the parser at all" — and a flag set
  // afterwards answers the different, useless question of whether the parse
  // happened to succeed. A billion-laughs document that reached the parser and
  // then threw has already cost what it was going to cost.
  var doc;
  result.parsed = true;
  try {
    doc = parseSvg(text);
  } catch (e) {
    add(result.rejections, 'malformed-xml');
    return result;
  }

  var root = doc && doc.documentElement;
  if (!root) {
    add(result.rejections, 'malformed-xml');
    return result;
  }

  // A parse error is reported as a `parsererror` element in the XHTML
  // namespace, and it may be the root or nested — measured both ways.
  var sawParserError = false;
  walk(root, function (el) {
    if (lower(nameOf(el)) === 'parsererror') sawParserError = true;
  });
  if (sawParserError) {
    add(result.rejections, 'malformed-xml');
    return result;
  }

  // Exact, not folded. `<SVG>` is a different XML element and is not the SVG
  // element, so it is a bad root rather than a conformant document.
  result.root = nameOf(root);
  if (result.root !== 'svg') {
    // HTML in a `.svg` file parses cleanly, so nothing but this catches it.
    add(result.rejections, 'bad-root');
    return result;
  }

  screen(root, result);
  profile(root, result);
  result.valid = result.rejections.length === 0;
  return result;
}
