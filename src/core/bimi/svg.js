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

const RASTER_DATA_URI = /data:image\/(?!svg\+xml)/i;

/**
 * A `url()` whose argument is not a same-document fragment.
 *
 * One matcher, used in two positions, because through spec 1.9 there were two
 * rules and each was wrong in the opposite direction.
 *
 * `<style>` text was screened by `/@import|url\s*\(/i`, which rejects EVERY
 * `url(` — including a purely local one. A logo that defines a gradient and
 * paints with it, which is ordinary conformant SVG, was refused as
 * `external-style`.
 *
 * Attribute values were screened only for `href` and `xlink:href`. SVG lets a
 * paint server, filter, mask, clip path or marker be named with `url()` in a
 * presentation attribute or inside `style`, and that argument may address
 * another document — so `fill="url(https://evil.example/p.svg#g)"` and
 * `style="filter:url(https://evil.example/f.svg#blur)"` reached a valid
 * verdict. Nothing is fetched, because the parsed document never enters the
 * page and this file returns tokens rather than nodes; what was wrong is the
 * verdict, on a construct SVG Tiny PS forbids and a mail client would beacon
 * from.
 *
 * Widening the old regex to every attribute — the obvious reading of "screen
 * attributes too" — would have propagated the false positive across the whole
 * element tree instead of fixing anything.
 *
 * Written as an extract-then-test rather than one clever regex, for the same
 * reason `attrValue()` in `src/i18n/index.js` parses instead of scanning: a
 * single pattern with optional quoting and optional whitespace backtracks, and
 * the first version of this one passed `url( #local )` — a local reference with
 * a space — as external, because `\s*` matched nothing and the lookahead then
 * saw the space instead of the `#`. Pulling the argument out and trimming it
 * has no such reading.
 *
 * An empty `url()` is external. It addresses nothing, it is not a fragment,
 * and this screen fails closed.
 *
 * `data:` is the one argument that is neither a fragment nor external. It
 * carries its own bytes, so it addresses no other document and cannot beacon,
 * which is the property this rule is about. It is already reported where it
 * matters: a raster `data:` URI in any position is the `raster-data-uri`
 * DIAGNOSTIC, because an SVG Tiny PS logo should not embed a bitmap — that is
 * a profile complaint, not a security one, and folding it into
 * `external-reference` would turn a shipped diagnostic into an invalid verdict
 * for a self-contained file.
 */
const URL_REF = /url\s*\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))/gi;
const IMPORT_RULE = /@import/i;

function hasExternalUrlRef(value) {
  var re = new RegExp(URL_REF.source, 'gi');
  var m;
  while ((m = re.exec(String(value == null ? '' : value)))) {
    var arg = (m[1] !== undefined ? m[1]
      : m[2] !== undefined ? m[2]
        : m[3] || '').trim();
    if (arg.charAt(0) === '#') continue;
    if (/^data:/i.test(arg)) continue;
    return true;
  }
  return false;
}

/**
 * Every declaration beginning with `marker`, without parsing the DTD.
 *
 * This scanner runs before DOMParser by design. It understands only the two
 * boundaries needed to preserve evidence honestly: quoted `>` characters do
 * not close a declaration, and a DOCTYPE's internal subset keeps the outer
 * declaration open until its matching `]` and final `>`. Token arrays remain
 * deduplicated, but sites are per occurrence, so every ENTITY is returned.
 */
function declarations(text, marker, doctype) {
  var folded = text.toLowerCase();
  var needle = marker.toLowerCase();
  var out = [];
  var from = 0;
  var start;

  while ((start = folded.indexOf(needle, from)) !== -1) {
    var quote = '';
    var brackets = 0;
    var end = text.length;
    for (var i = start + needle.length; i < text.length; i++) {
      var ch = text.charAt(i);
      if (quote) {
        if (ch === quote) quote = '';
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if (doctype && ch === '[') { brackets++; continue; }
      if (doctype && ch === ']' && brackets) { brackets--; continue; }
      if (ch === '>' && (!doctype || brackets === 0)) { end = i + 1; break; }
    }
    out.push(text.slice(start, end));
    from = end > start ? end : start + needle.length;
  }
  return out;
}

function emptyResult() {
  return {
    valid: false,
    parsed: false,
    root: null,
    title: '',
    rejections: [],
    diagnostics: [],
    sites: [],
  };
}

/** How much of an offending construct travels with its token. */
const MAX_SITE_TEXT = 200;

function bounded(value) {
  // Code POINTS, not UTF-16 indexes: slicing through an astral character
  // leaves a lone surrogate, and the export path treats that as a defect.
  var points = Array.from(String(value == null ? '' : value));
  return points.length > MAX_SITE_TEXT
    ? points.slice(0, MAX_SITE_TEXT).join('') : points.join('');
}

function add(list, token) {
  if (!list.includes(token)) list.push(token);
}

/**
 * Record a token AND where it came from.
 *
 * The token vocabularies stay deduplicated, because they are the closed
 * algebras. `sites` does not: a document with three external references has
 * three places to fix, and collapsing them to one leaves the operator hunting.
 * `element` is the enclosing element as written; `value` is the bounded
 * offending material — an attribute pair, a URL, a text snippet.
 */
function site(result, bucket, token, element, value) {
  add(result[bucket], token);
  result.sites.push({
    token: token,
    element: element ? '<' + element + '>' : '',
    value: bounded(value),
  });
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
/** For a security screen, which is deliberately case-insensitive. */
function attrValueAnyCase(el, name) {
  var attrs = attributesOf(el);
  for (var i = 0; i < attrs.length; i++) {
    if (lower(attrs[i].localName || attrs[i].name) === name) {
      return String(attrs[i].value == null ? '' : attrs[i].value);
    }
  }
  return '';
}

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

    var written = nameOf(el);
    if (name === 'script') site(result, 'rejections', 'script-element', written, textOf(el));
    if (name === 'foreignobject') site(result, 'rejections', 'foreign-object', written, '');
    if (EXTERNAL_REF_ELEMENTS.indexOf(name) !== -1) {
      site(result, 'rejections', 'external-reference-element', written,
        attrValueAnyCase(el, 'href'));
    }
    if (ANIMATION_ELEMENTS.indexOf(name) !== -1) {
      site(result, 'rejections', 'animation', written, '');
    }
    // Any `<a>`, not only one carrying a destination. The spec says "`<a>` with
    // any target"; an anchor with no target is inert but has no business in a
    // logo either, and the safer reading is the one that cannot be argued into
    // permitting a link later.
    if (name === 'a') {
      site(result, 'rejections', 'link-element', written, attrValueAnyCase(el, 'href'));
    }

    if (name === 'style'
      && (IMPORT_RULE.test(textOf(el)) || hasExternalUrlRef(textOf(el)))) {
      site(result, 'rejections', 'external-style', written, textOf(el));
    }

    var attrs = attributesOf(el);
    for (var i = 0; i < attrs.length; i++) {
      var attrName = lower(attrs[i].name);
      var attrLocal = lower(attrs[i].localName || attrs[i].name);
      var value = String(attrs[i].value == null ? '' : attrs[i].value);

      if (/^on/.test(attrName)) {
        site(result, 'rejections', 'event-handler', written, attrs[i].name + '="' + value + '"');
      }

      // `localName` catches `href` and `xlink:href` with one rule — measured:
      // the namespaced spelling reports name `xlink:href`, localName `href`.
      // A same-document fragment is the only permitted destination.
      if (attrLocal === 'href' && value.charAt(0) !== '#') {
        site(result, 'rejections', 'external-reference', written,
          attrs[i].name + '="' + value + '"');
      }
      // Every attribute, not a list of the ones that take paint. `style` is
      // the obvious one and `fill` the obvious second, but SVG accepts a
      // `url()` in `stroke`, `filter`, `mask`, `clip-path`, `marker-*` and
      // more, and an allowlist of attribute names would have to be revisited
      // for every one of them. The value is what decides.
      if (hasExternalUrlRef(value)) {
        site(result, 'rejections', 'external-reference', written,
          attrs[i].name + '="' + value + '"');
      }
      if (RASTER_DATA_URI.test(value)) {
        site(result, 'diagnostics', 'raster-data-uri', written,
          attrs[i].name + '="' + value + '"');
      }
    }

    if (name === 'style' && RASTER_DATA_URI.test(textOf(el))) {
      site(result, 'diagnostics', 'raster-data-uri', written, textOf(el));
    }
  });
}

/** SVG P/S diagnostics on the root and its direct children. */
function profile(root, result) {
  var written = nameOf(root);
  if (root.namespaceURI !== SVG_NS) {
    site(result, 'diagnostics', 'namespace-not-svg', written, String(root.namespaceURI || ''));
  }
  if (attrValue(root, 'baseProfile') !== 'tiny-ps') {
    site(result, 'diagnostics', 'base-profile-not-tiny-ps', written,
      String(attrValue(root, 'baseProfile') == null ? '' : attrValue(root, 'baseProfile')));
  }
  if (attrValue(root, 'version') !== '1.2') {
    site(result, 'diagnostics', 'version-not-1-2', written,
      String(attrValue(root, 'version') == null ? '' : attrValue(root, 'version')));
  }
  if (attrValue(root, 'x') !== null || attrValue(root, 'y') !== null) {
    site(result, 'diagnostics', 'root-has-position', written,
      'x=' + attrValue(root, 'x') + ' y=' + attrValue(root, 'y'));
  }

  // Present is a SHOULD NOT; present with the wrong value is a MUST violation.
  // Only the second is diagnosable without second-guessing the author.
  var names = Object.keys(CONSTRAINED_ATTRS);
  for (var i = 0; i < names.length; i++) {
    var present = attrValue(root, names[i]);
    if (present !== null && present !== CONSTRAINED_ATTRS[names[i]]) {
      site(result, 'diagnostics', 'unsupported-attribute', written,
        names[i] + '="' + present + '"');
    }
  }

  var viewBox = attrValue(root, 'viewBox');
  if (viewBox === null) {
    site(result, 'diagnostics', 'viewbox-missing', written, '');
  } else {
    var parts = viewBox.trim().split(/[\s,]+/).map(Number);
    var usable = parts.length === 4 && parts.every(function (n) { return isFinite(n); });
    // SVG Tiny 1.2: a negative width or height is an error, and zero disables
    // rendering. Neither is a square logo, and comparing width to height would
    // call `0 0 0 0` and `0 0 -64 -64` square.
    if (!usable || !(parts[2] > 0) || !(parts[3] > 0)) {
      site(result, 'diagnostics', 'viewbox-missing', written, viewBox);
    } else if (parts[2] !== parts[3]) {
      site(result, 'diagnostics', 'viewbox-not-square', written, viewBox);
    }
  }

  // `<title>` must be a DIRECT child, exactly one, non-empty. A title nested
  // inside a group is not the document's title.
  var kids = elementChildren(root);
  var titles = kids.filter(function (el) { return nameOf(el) === 'title'; });
  if (titles.length > 1) {
    site(result, 'diagnostics', 'title-not-unique', 'title', String(titles.length));
  }
  if (!titles.length || !textOf(titles[0]).trim()) {
    site(result, 'diagnostics', 'title-missing', written, '');
  } else {
    result.title = bounded(textOf(titles[0]).trim());
  }

  var descs = kids.filter(function (el) { return nameOf(el) === 'desc'; });
  if (descs.length && !textOf(descs[0]).trim()) {
    site(result, 'diagnostics', 'desc-empty', 'desc', '');
  }
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
    site(result, 'rejections', 'malformed-xml', '', '');
    return result;
  }

  // BEFORE the parser. Chrome expands internal entities; see the header.
  // Each records the DECLARATION ITSELF, so an operator is shown the construct
  // that was refused rather than only the name of the rule that refused it.
  declarations(text, '<!DOCTYPE', true).forEach(function (value) {
    site(result, 'rejections', 'doctype-present', '', value);
  });
  declarations(text, '<!ENTITY', false).forEach(function (value) {
    site(result, 'rejections', 'entity-declaration', '', value);
  });
  if (result.rejections.length) return result;

  if (typeof parseSvg !== 'function') {
    site(result, 'rejections', 'malformed-xml', '', '');
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
    // No source position exists. Spec 1.8 assigns that condition the input
    // variant with an empty value; an exception class is parser-generated
    // metadata, not supplied artifact material.
    site(result, 'rejections', 'malformed-xml', '', '');
    return result;
  }

  var root = doc && doc.documentElement;
  if (!root) {
    site(result, 'rejections', 'malformed-xml', '', '');
    return result;
  }

  // A parse error is reported as a `parsererror` element in the XHTML
  // namespace, and it may be the root or nested — measured both ways.
  var parserError = null;
  walk(root, function (el) {
    if (!parserError && lower(nameOf(el)) === 'parsererror') parserError = el;
  });
  if (parserError) {
    // DOMParser generated this node and its message; neither is a construct
    // from the supplied document. Keep the evidence honest and document-level.
    site(result, 'rejections', 'malformed-xml', '', '');
    return result;
  }

  // Exact, not folded. `<SVG>` is a different XML element and is not the SVG
  // element, so it is a bad root rather than a conformant document.
  result.root = nameOf(root);
  if (result.root !== 'svg') {
    // HTML in a `.svg` file parses cleanly, so nothing but this catches it.
    // Located at the root that WAS found, not at the document.
    site(result, 'rejections', 'bad-root', result.root, String(root.namespaceURI || ''));
    return result;
  }

  screen(root, result);
  profile(root, result);
  result.valid = result.rejections.length === 0;
  return result;
}
