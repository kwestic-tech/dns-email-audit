#!/usr/bin/env node
/**
 * Rendering correctness against hostile and malformed DNS values.
 *
 * The property under test, for every fixture: a DNS-derived value lands in a
 * text node or an allowlisted attribute, and nowhere else. That is a question
 * about which DOM methods the renderer calls, which is why a dependency-free
 * shim answers it — after 0.2.3 the render path never parses a string into
 * markup, so there is no parser for the shim to be wrong about.
 *
 * See tools/lib/dom-shim.mjs for what this does and does not prove.
 */

import {
  loadApp, MarkupSinkError, elements, attributes, locate, hasNoEventHandlers, textOf,
} from './lib/browser-harness.mjs';
import { RICH_TAG_ALLOWLIST, disallowedTags } from './lib/locale-utils.mjs';

const win = loadApp();
const { R, document } = win;
const APP = win.__APP_TEST__;

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
};
const ok = (label, actual) => eq(label, !!actual, true);
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

/* ── Fixtures ─────────────────────────────────────────────────────────
   The table from the spec's Testing section, one row each. */

const FIXTURES = {
  tagInjection: 'v=spf1 <script>alert(1)</script> -all',
  attrBreakout: 'rua=mailto:"><img src=x onerror=alert(1)>@e.com',
  singleQuote: "v=spf1 include:'evil.example' a:'x' -all",
  svgPayload: 'v=DKIM1; k=rsa; p=<svg onload=alert(1)>',
  encodedEntities: '&lt;script&gt; and &#60;script&#62;',
  templateInjection: 'v=spf1 include:{0}.example {1} -all',
  bidiOverride: 'v=spf1 include:‮elpmaxe.evil -all',
  zeroWidthA: 'mail.example.com',
  zeroWidthB: 'mail.exa​mple.com',
  controlChars: 'v=spf1 ' + Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join('') + ' -all',
  oversized: 'v=DKIM1; p=' + 'A'.repeat(64 * 1024),
  loneSurrogate: 'v=DKIM1; p=\uD800BROKEN',
  empty: '',
};

/* ── 1. No fixture escapes a text node or allowlisted attribute ──────── */
section('1. Every DNS-derived value lands in a text node or an attribute');

for (const [name, value] of Object.entries(FIXTURES)) {
  const node = R.value(value);
  const els = elements(node);
  // Every element in the tree is one the renderer created, from its own
  // fixed set — never one named by the input.
  const created = new Set(['span', 'button', 'br']);
  eq(`${name}: only renderer-created elements`,
    els.every(e => created.has(e.localName)), true);
  eq(`${name}: no event-handler attribute`, hasNoEventHandlers(node), true);
}

// The three that actually try to become markup.
eq('tag injection stays text', locate(R.value(FIXTURES.tagInjection), 'script'), 'text');
eq('svg payload stays text', locate(R.value(FIXTURES.svgPayload), 'svg'), 'text');
eq('attribute breakout stays text', locate(R.value(FIXTURES.attrBreakout), 'img'), 'text');
eq('no element is named after an injected tag',
  elements(R.value(FIXTURES.tagInjection)).some(e => e.localName === 'script'), false);

// A single quote needs no special handling once nothing concatenates markup.
eq('single quotes survive verbatim',
  textOf(R.value(FIXTURES.singleQuote)).includes("include:'evil.example'"), true);

// Entities are inert: the renderer never decodes DNS data.
eq('encoded entities are not decoded',
  textOf(R.value(FIXTURES.encodedEntities)), FIXTURES.encodedEntities);

// Template injection is section 2's problem, but the value must also survive
// rendering as literal text.
eq('template braces survive as literal text',
  textOf(R.value(FIXTURES.templateInjection)).includes('{0}'), true);

/* ── 2. Invisible characters get a visible sentinel ──────────────────── */
section('2. Nothing invisible is silently dropped');

const bidi = R.value(FIXTURES.bidiOverride);
eq('the override character is gone from the text run',
  textOf(bidi).includes('‮'), false);
eq('a sentinel stands where it was', textOf(bidi).includes('‹RLO›'), true);
eq('the sentinel is a marker element, not content',
  elements(bidi).some(e => e.classList.contains('rv-sentinel')), true);
eq('the surrounding value is otherwise untouched',
  textOf(bidi).includes('elpmaxe.evil'), true);

const zwA = R.value(FIXTURES.zeroWidthA);
const zwB = R.value(FIXTURES.zeroWidthB);
eq('two hosts differing only by a zero-width character now render differently',
  textOf(zwA) === textOf(zwB), false);
eq('the zero-width character is named', textOf(zwB).includes('‹ZWSP›'), true);

const ctrl = R.value(FIXTURES.controlChars);
eq('a NUL is named by code point', textOf(ctrl).includes('‹U+0000›'), true);
eq('a BEL is named by code point', textOf(ctrl).includes('‹U+0007›'), true);
eq('no raw C0 control survives', /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(textOf(ctrl)), false);
// Tab, newline and carriage return carry meaning in a rendered value.
eq('tab is left alone', textOf(R.value('a\tb')).includes('\t'), true);
eq('newline is left alone', textOf(R.value('a\nb')).includes('\n'), true);

const surrogate = R.value(FIXTURES.loneSurrogate);
eq('a lone surrogate becomes U+FFFD', textOf(surrogate).includes('�'), true);
eq('no lone surrogate survives', /[\uD800-\uDFFF]/.test(textOf(surrogate)), false);

// Script characters are never touched — a domain legitimately publishing
// Hebrew or Arabic reorders correctly on its own.
eq('Hebrew text is not marked', textOf(R.value('v=spf1 include:דוגמה.example')).includes('‹'), false);
eq('Arabic text is not marked', textOf(R.value('مثال.example')).includes('‹'), false);
// The previous assertion used a string containing no format characters at all,
// so it did not actually protect the property it names. These do: every one is
// Cf, and every one is genuine script content rather than an invisible.
eq('an Arabic number sign is not marked',
  textOf(R.value('\u0600123.example')).includes('‹'), false);
eq('an Arabic end of ayah is not marked',
  textOf(R.value('a\u06DDb')).includes('‹'), false);
eq('a Syriac abbreviation mark is not marked',
  textOf(R.value('a\u070Fb')).includes('‹'), false);
eq('script format characters produce no hygiene note',
  R.hygiene('\u0600123 a\u06DDb a\u070Fb'), []);
// …while the invisible members of the same category still are.
eq('a word joiner in the same string IS marked',
  textOf(R.value('\u0600123\u2060x')).includes('‹WJ›'), true);

/* ── 3. Display caps, and the data behind them ───────────────────────── */
section('3. Display caps never reach the data');

const big = R.value(FIXTURES.oversized);
eq('the full value is still in the DOM', textOf(big).length > 64 * 1024, true);
eq('the visible head is capped at 1024 characters',
  elements(big).some(e => e.classList.contains('rv-rest')), true);
eq('a disclosure control is offered',
  elements(big).some(e => e.classList.contains('rv-more')), true);
eq('the remainder starts hidden',
  elements(big).find(e => e.classList.contains('rv-rest')).style.getPropertyValue('display'), 'none');
// 1024 clears a 4096-bit RSA DKIM key (~760 characters with its tags).
const realKey = 'v=DKIM1; k=rsa; p=' + 'B'.repeat(740);
eq('a 4096-bit RSA key is not truncated',
  elements(R.value(realKey)).some(e => e.classList.contains('rv-more')), false);

const many = R.list(Array.from({ length: 400 }, (_, i) => `mx${i}.example.com`));
eq('400 MX records render 20 plus a remainder',
  elements(many).filter(e => e.classList.contains('rv')).length, 20);
eq('the remainder is counted',
  elements(many).some(e => e.classList.contains('rv-remainder')), true);
eq('the remainder count is 380',
  textOf(many).includes('380'), true);
eq('the two caps are independent',
  elements(R.list([FIXTURES.oversized])).some(e => e.classList.contains('rv-more')), true);

// A hostname is at most 253 characters, so a longer one is malformed.
eq('an over-long CNAME target is capped',
  elements(R.host('a'.repeat(400) + '.example')).some(e => e.classList.contains('rv-more')), true);

/* ── 4. Empty and whitespace-only values ─────────────────────────────── */
section('4. An empty record is distinguishable from no lookup');

eq('an empty value renders the none token', textOf(R.value('')), win.t('labels.none'));
eq('a whitespace-only value renders the none token', textOf(R.value('   ')), win.t('labels.none'));
eq('an empty list renders the none token', textOf(R.list([])), win.t('labels.none'));
eq('the none token is marked as such',
  elements(R.value('')).some(e => e.classList.contains('rv-none')), true);

/* ── 5. Record hygiene is observable ─────────────────────────────────── */
section('5. Record hygiene is reported, not scored');

eq('a bidi override is classified', R.hygiene(FIXTURES.bidiOverride), ['bidi-override']);
eq('a zero-width character is classified', R.hygiene(FIXTURES.zeroWidthB), ['zero-width']);
eq('a control character is classified', R.hygiene('a\u0007b'), ['control-char']);
eq('a lone surrogate is classified', R.hygiene(FIXTURES.loneSurrogate), ['lone-surrogate']);
eq('a punycode name is classified', R.hygiene('xn--80ak6aa92e.example'), ['punycode']);
eq('a clean value has no hygiene classes', R.hygiene('v=spf1 -all'), []);
eq('classes are deduplicated across values',
  R.hygieneOf(['a‮b', 'c‮d']), ['bidi-override']);
eq('classes accumulate across values',
  R.hygieneOf(['a‮b', 'c​d']).sort(), ['bidi-override', 'zero-width']);

/* ── 6. The renderer refuses markup sinks ────────────────────────────── */
section('6. The renderer refuses markup sinks');

const threw = (fn) => { try { fn(); return false; } catch (e) { return e; } };

ok('R.el refuses an innerHTML prop',
  threw(() => R.el('div', { innerHTML: '<script>' })));
ok('R.el refuses an outerHTML prop',
  threw(() => R.el('div', { outerHTML: '<script>' })));
ok('R.el refuses an unknown attribute',
  threw(() => R.el('div', { onclick: 'alert(1)' })));
ok('R.el refuses any on* attribute',
  threw(() => R.el('div', { onmouseover: 'alert(1)' })));
eq('the attribute allowlist rejects event handlers', R.attrAllowed('onclick'), false);
eq('the attribute allowlist accepts data-*', R.attrAllowed('data-domain'), true);
eq('the attribute allowlist accepts aria-*', R.attrAllowed('aria-label'), true);
eq('the attribute allowlist rejects srcdoc', R.attrAllowed('srcdoc'), false);

// The shim's setter trap catches what a static pattern would miss.
const el = document.createElement('div');
eq('direct assignment throws',
  threw(() => { el.innerHTML = 'x'; }) instanceof MarkupSinkError, true);
eq('computed assignment throws',
  threw(() => { el['inner' + 'HTML'] = 'x'; }) instanceof MarkupSinkError, true);
eq('Object.assign throws',
  threw(() => Object.assign(el, { innerHTML: 'x' })) instanceof MarkupSinkError, true);
eq('outerHTML assignment throws',
  threw(() => { el.outerHTML = 'x'; }) instanceof MarkupSinkError, true);
eq('reading outerHTML still works', typeof el.outerHTML, 'string');

/* ── 7. href is https-only ───────────────────────────────────────────── */
section('7. Links are https-only');

eq('an https href is kept',
  R.el('a', { href: 'https://example.com/' }).getAttribute('href'), 'https://example.com/');
eq('a javascript: href is dropped',
  R.el('a', { href: 'javascript:alert(1)' }).getAttribute('href'), null);
eq('a data: href is dropped',
  R.el('a', { href: 'data:text/html,<script>alert(1)</script>' }).getAttribute('href'), null);
eq('an http href is dropped',
  R.el('a', { href: 'http://example.com/' }).getAttribute('href'), null);

/* ── 8. Rich text is fail-closed ─────────────────────────────────────── */
section('8. Rich text is tokenized, never parsed into markup');

const rich = (s) => win.i18n.sanitizeFragment(s);

eq('an allowlisted tag becomes an element',
  elements(rich('a <strong>b</strong> c')).map(e => e.localName), ['strong']);
eq('a script tag becomes literal text',
  elements(rich('a <script>alert(1)</script> b')).length, 0);
eq('the refused tag is visible as text',
  textOf(rich('a <script>alert(1)</script> b')), 'a <script>alert(1)</script> b');
eq('an img tag becomes literal text',
  elements(rich('<img src=x onerror=alert(1)>')).length, 0);
eq('an https link keeps href, target and rel',
  attributes(rich('<a href="https://example.com/">x</a>')).map(([n, v]) => `${n}=${v}`),
  ['href=https://example.com/', 'target=_blank', 'rel=noopener noreferrer']);
eq('a javascript: link keeps no href',
  attributes(rich('<a href="javascript:alert(1)">x</a>')).length, 0);
eq('an event handler on an allowlisted tag is discarded',
  attributes(rich('<strong onclick="alert(1)">x</strong>')).length, 0);
eq('a stray close tag is text', textOf(rich('a </strong> b')), 'a </strong> b');
eq('an unclosed tag still nests its content',
  textOf(rich('a <strong>b')), 'a b');
eq('a malformed angle bracket is text', textOf(rich('5 < 6 and 7 > 4')), '5 < 6 and 7 > 4');
eq('entities decode to text, not markup',
  elements(rich('&lt;script&gt;alert(1)&lt;/script&gt;')).length, 0);
eq('a decoded entity stays in a text node',
  textOf(rich('&lt;script&gt;')), '<script>');
eq('a numeric entity decodes', textOf(rich('&#65;&#x42;')), 'AB');
eq('a surrogate entity becomes U+FFFD', textOf(rich('&#xD800;')), '�');
eq('nesting works', textOf(rich('<p>a <em>b <code>c</code></em></p>')), 'a b c');

// The author-time check in tools/check-locales.mjs and the runtime tokenizer
// must agree, or the build would pass a tag the interface then renders as
// literal angle brackets. Assert they cannot drift apart.
for (const tag of RICH_TAG_ALLOWLIST) {
  eq(`check-locales allows <${tag}> and the tokenizer builds it`,
    disallowedTags(`<${tag}>x</${tag}>`).length === 0
      && (tag === 'br' || elements(rich(`<${tag}>x</${tag}>`)).some(e => e.localName === tag)),
    true);
}
for (const tag of ['div', 'span', 'script', 'iframe', 'img', 'style', 'table']) {
  eq(`check-locales rejects <${tag}> and the tokenizer refuses it`,
    disallowedTags(`<${tag}>x</${tag}>`).includes(tag)
      && !elements(rich(`<${tag}>x</${tag}>`)).some(e => e.localName === tag),
    true);
}

/* ── 9. Row rendering end to end ─────────────────────────────────────── */
section('9. A full result row');

const result = {
  domain: 'evil‮.example',
  ns: ['ns1.example.com'],
  mx: ['mx1.example.com', 'mx​2.example.com'],
  spfRecord: FIXTURES.tagInjection,
  dmarcRecord: FIXTURES.attrBreakout,
  dmarcAtDomain: 'evil‮.example',
  verifications: ['google-site-verification=<script>'],
  issues: [{ key: 'spf-missing', sev: 'crit', args: [] }],
  suggestions: [],
  wildcardDkim: false,
  wildcardApex: false,
  spfStatus: { status: 'permerror', cls: 'crit' },
  dmarcStatus: { status: 'missing', cls: 'crit', pct: 100, policy: '', adkim: 'r', aspf: 'r' },
  dkimStatus: {
    found: true,
    selectors: [{ sel: 'sel1', queryName: 'sel1._domainkey.evil.example', value: FIXTURES.svgPayload, cname: '', viaSpf: '' }],
    missingSelectors: [],
  },
  dnsProvider: 'Cloudflare',
  emailProvider: '@none',
  hosting: '@unknown',
  advScore: 5,
  // Populated deliberately: advFullDots is the ONLY path that puts DNS-derived
  // text into a rendered attribute (`data-tip`, painted by
  // `content: attr(data-tip)` in css/style.css). A null here would leave the
  // attribute path — the one place the text-node argument does not apply —
  // completely uncovered.
  advanced: {
    bimi: { present: true, record: 'v=BIMI1; l=<img src=x onerror=alert(1)>‮reversed' },
    mtaSts: { present: true, policyVerified: false },
    tlsRpt: { present: false },
    caa: { found: true, atDomain: 'evil‮.example', records: ['0 issue "ca.exa\u200bmple"'] },
    dnssec: { signed: false },
    spfLookups: { count: 3, warning: false, error: false },
  },
  score: { grade: 'F', pts: 0, max: 100, cls: 'score-f', breakdown: null, unproven: [] },
};

APP.appendRow(result);
const tbody = document.getElementById('tableBody');

eq('the row produced no script element',
  elements(tbody).some(e => e.localName === 'script'), false);
eq('the row produced no img element',
  elements(tbody).some(e => e.localName === 'img'), false);
eq('the row has no event-handler attribute', hasNoEventHandlers(tbody), true);
eq('the injected script tag is text', locate(tbody, 'script'), 'text');
eq('the domain override is sentinelled', textOf(tbody).includes('‹RLO›'), true);
eq('the MX zero-width is sentinelled', textOf(tbody).includes('‹ZWSP›'), true);
eq('a hygiene note is shown',
  elements(tbody).some(e => e.classList.contains('rv-hygiene')), true);
eq('the hygiene note names the override',
  textOf(tbody).includes(win.t('render.hygiene.bidiOverride')), true);

// Every attribute value in the row must be one the renderer chose, or a
// DNS-derived value in an allowlisted slot (title / data-*).
const suspicious = attributes(tbody)
  .filter(([name]) => !/^(class|id|colspan|title|style|type|data-[a-z-]+)$/.test(name));
eq('no unexpected attribute names', suspicious.map(([n]) => n), []);

/* ── 10. DNS data rendered into an attribute ─────────────────────────── */
section('10. Attributes are displayed output too');

// `data-tip` is painted by CSS, so an override inside it reorders exactly as
// it would inside a cell. The text-node argument does not cover this path.
const tips = attributes(tbody).filter(([name]) => name === 'data-tip').map(([, v]) => v);
eq('the advanced strip produced tooltips', tips.length > 0, true);
eq('no raw override survives into an attribute',
  tips.some(v => v.includes('‮')), false);
eq('no raw zero-width survives into an attribute',
  tips.some(v => v.includes('​')), false);
eq('the tooltip is sentinelled instead',
  tips.some(v => v.includes('‹RLO›')), true);
eq('no attribute value in the row carries a raw invisible character',
  attributes(tbody).filter(([, v]) => /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(String(v))).map(([n]) => n),
  []);
eq('a tag in an attribute value is still not an element',
  elements(tbody).some(e => e.localName === 'img'), false);

// The helper the attribute path relies on.
eq('sentinelText substitutes in a plain string',
  R.sentinelText('a‮b'), 'a‹RLO›b');
eq('sentinelText leaves ordinary text alone',
  R.sentinelText('v=spf1 -all'), 'v=spf1 -all');
eq('sentinelText normalizes lone surrogates',
  R.sentinelText('a\uD800b'), 'a\uFFFDb');

/* ── 11. Regressions fixed after review ──────────────────────────────── */
section('11. Regressions fixed after review');

// A consuming lookbehind skipped every second lone low surrogate in a run.
eq('consecutive lone low surrogates are all replaced',
  R.normalize('a\uDC00\uDC00b'), 'a\uFFFD\uFFFDb');
eq('three in a row are all replaced',
  R.normalize('\uDC00\uDC00\uDC00'), '\uFFFD\uFFFD\uFFFD');
eq('a well-formed astral pair is untouched', R.normalize('ok 😀'), 'ok 😀');
eq('an emoji is not classified as invisible', R.hygiene('ok 😀'), []);

// The invisible set is a category test, not a hand-written table.
const INVISIBLE = {
  'U+00AD soft hyphen': '\u00AD',
  'U+2060 word joiner': '\u2060',
  'U+061C arabic letter mark': '\u061C',
  'U+3164 hangul filler': '\u3164',
  'U+FFA0 halfwidth hangul filler': '\uFFA0',
  'U+2028 line separator': '\u2028',
  'U+E0001 language tag': '\u{E0001}',
};
for (const [name, ch] of Object.entries(INVISIBLE)) {
  eq(`${name} gets a sentinel`, R.value('a' + ch + 'b').textContent.includes('‹'), true);
  eq(`${name} is reported as hygiene`, R.hygiene('a' + ch + 'b').length > 0, true);
}

// A record that published U+FFFD itself is not malformed UTF-8.
eq('a published U+FFFD is not reported as a lone surrogate',
  R.hygiene('a\uFFFDb'), []);
eq('an actual lone surrogate still is',
  R.hygiene('a\uD800b'), ['lone-surrogate']);

// Punycode appears mid-value far more often than at the start.
eq('an embedded xn-- label is detected',
  R.hygiene('v=spf1 include:xn--80ak6aa92e.example -all'), ['punycode']);
eq('a leading xn-- label is detected',
  R.hygiene('xn--80ak6aa92e.example'), ['punycode']);
eq('the word "exn--" is not punycode', R.hygiene('exn--nope'), []);

// R.list must honour the caller's empty token, as nameservers do.
eq('R.list forwards its empty token to each value',
  textOf(R.list([''], { none: 'NA-TOKEN' })), 'NA-TOKEN');

// src gets the same scheme test as href.
eq('a javascript: src is dropped',
  R.el('img', { src: 'javascript:alert(1)' }).getAttribute('src'), null);
eq('an https src is kept',
  R.el('img', { src: 'https://example.com/x.png' }).getAttribute('src'), 'https://example.com/x.png');

// The style guard makes the "literals only" comment enforceable.
ok('a style value containing markup is refused',
  threw(() => R.el('div', { style: 'width:1px" onload="alert(1)' })));
ok('a style value containing url() is refused',
  threw(() => R.el('div', { style: 'background:url(https://evil.example/x)' })));
eq('an ordinary style literal is accepted',
  R.el('div', { style: 'width:50%;color:var(--ok);' }).getAttribute('style'),
  'width:50%;color:var(--ok);');

/* ── 12. Codex review 1 — DNS-derived interpolation arguments ────────── */
section('12. DNS-derived interpolation arguments are sentinelled');

// The record itself was already sentinelled, but the issue MESSAGE beside it
// interpolated the same DNS value straight into the translated sentence, so an
// override stayed live in the most important explanatory text on the page.
const hostileIssue = {
  key: 'dmarc-rua-invalid', sev: 'warn',
  args: ['mailto:x@safe.‮evil​z'],
};

const shown = APP.issueMessage(hostileIssue);
eq('the message carries no raw override', shown.includes('‮'), false);
eq('the message carries no raw zero-width', shown.includes('​'), false);
eq('the override is sentinelled', shown.includes('‹RLO›'), true);
eq('the zero-width is sentinelled', shown.includes('‹ZWSP›'), true);
// The translator's own sentence must survive intact — substitution is applied
// to the ARGUMENT before translation, not to the finished string.
eq('the surrounding translation still renders',
  shown.includes('DMARC') && shown.length > 40, true);

// An ordinary argument must be untouched.
eq('an ordinary argument is unchanged',
  APP.issueMessage({ key: 'dmarc-rua-invalid', sev: 'warn', args: ['mailto:ok@example.com'] })
    .includes('mailto:ok@example.com'), true);

// tDns is the boundary helper the other argument-bearing call sites use.
eq('tDns substitutes in an argument',
  APP.tDns('dmarc.inheritedFrom', 'evil‮.example').includes('‹RLO›'), true);
eq('tDns leaves an ordinary argument alone',
  APP.tDns('dmarc.inheritedFrom', 'parent.example').includes('parent.example'), true);

// End to end through a real row.
const hostileRow = {
  domain: 'evil.example', ns: [], mx: ['mx.example'], verifications: [],
  spfRecord: 'v=spf1 -all', dmarcRecord: 'v=DMARC1; p=none',
  issues: [hostileIssue], suggestions: [],
  spfStatus: { status: 'permerror', cls: 'crit' },
  dmarcStatus: { status: 'missing', cls: 'crit', policy: '', pct: 100, adkim: 'r', aspf: 'r', rua: false, ruf: false, testMode: false, sp: '', np: '' },
  dkimStatus: { found: false, confidence: 'checked', selectors: [], missingSelectors: [] },
  dnsProvider: 'Cloudflare', emailProvider: '@none', hosting: '@unknown',
  advScore: 0, advanced: null,
  score: { grade: 'F', pts: 0, max: 100, cls: 'score-f', breakdown: null, unproven: [] },
};
const rowDoc = document.createElement('tbody');
rowDoc.id = 'tableBody';
document.body.appendChild(rowDoc);
APP.appendRow(hostileRow);
const rowText = textOf(document.getElementById('tableBody'));
eq('the rendered row contains no raw override', rowText.includes('‮'), false);
eq('the rendered row shows the sentinel', rowText.includes('‹RLO›'), true);

/* ── 13. Codex review 1 — the display cap splits code points ─────────── */
section('13. The display cap never splits an astral character');

const CAP = R.MAX_VALUE_CHARS;

// The rendered value's own text, without the disclosure control's label —
// `textContent` would otherwise append "Show N more characters" to every
// truncated value and no comparison against the input could ever hold.
const valueText = (node) => {
  elements(node).filter(e => e.classList.contains('rv-more')).forEach(e => e.remove());
  return textOf(node);
};

// A LONE surrogate, not either half of a valid pair. `/[\uD800-\uDFFF]/`
// matches both halves of every emoji, so it cannot express this.
const hasLoneSurrogate = (str) => {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      const n = str.charCodeAt(i + 1);
      if (!(n >= 0xDC00 && n <= 0xDFFF)) return true;
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      return true;
    }
  }
  return false;
};

// Guard the guard: it must accept valid pairs and reject broken ones.
eq('hasLoneSurrogate accepts a valid astral pair', hasLoneSurrogate('a\u{1F600}b'), false);
eq('hasLoneSurrogate rejects a lone high surrogate', hasLoneSurrogate('a\uD800b'), true);
eq('hasLoneSurrogate rejects a lone low surrogate', hasLoneSurrogate('a\uDC00b'), true);
const astralCases = {
  'just before the boundary': 'A'.repeat(CAP - 1) + '\u{1F600}' + 'Z'.repeat(10),
  'straddling the boundary': 'A'.repeat(CAP - 1) + '\u{1F600}' + 'Z',
  'just after the boundary': 'A'.repeat(CAP) + '\u{1F600}' + 'Z',
  'consecutive emoji at the boundary':
    'A'.repeat(CAP - 2) + '\u{1F600}\u{1F601}\u{1F602}' + 'Z',
  'all emoji': '\u{1F600}'.repeat(CAP + 20),
};
for (const [name, input] of Object.entries(astralCases)) {
  const out = valueText(R.value(input));
  eq(`${name}: no U+FFFD appears`, out.includes('�'), false);
  eq(`${name}: no lone surrogate survives`, hasLoneSurrogate(out), false);
  // Disclosure recombines to exactly the input: head + hidden remainder.
  eq(`${name}: head plus remainder is the whole value`, out, input);
}

// The disclosure count is in code points, matching what the label calls
// characters — not UTF-16 units, which would double-count every emoji.
const counted = R.value('\u{1F600}'.repeat(CAP + 7));
const moreBtn = elements(counted).find(e => e.classList.contains('rv-more'));
eq('the disclosure count is in code points', moreBtn.dataset.rvCount, '7');

/* ── 14. Codex review 1 — the invisible-character policy ─────────────── */
section('14. Default_Ignorable is the membership test');

// Previously missed by the \p{Cf} approximation. All render as nothing.
const nowCovered = {
  'U+034F combining grapheme joiner': '͏',
  'U+17B4 khmer vowel inherent aq': '឴',
  'U+17B5 khmer vowel inherent aa': '឵',
  'U+180B mongolian free variation 1': '᠋',
  'U+180D mongolian free variation 3': '᠍',
};
for (const [name, ch] of Object.entries(nowCovered)) {
  eq(`${name} is sentinelled`, textOf(R.value('a' + ch + 'b')).includes('‹'), true);
  eq(`${name} is reported as hygiene`, R.hygiene('a' + ch + 'b'), ['zero-width']);
  eq(`${name} does not survive raw`, textOf(R.value('a' + ch + 'b')).includes(ch), false);
}

// Previously over-marked by \p{Cf}: these are genuine running text in their
// script and must stay unmarked. They are not Default_Ignorable at all.
const scriptContent = {
  'U+0600 arabic number sign': '؀',
  'U+0605 arabic number mark above': '؅',
  'U+06DD arabic end of ayah': '۝',
  'U+070F syriac abbreviation mark': '܏',
  'U+0890 arabic pound mark': '࢐',
  'U+0891 arabic piastre mark': '࢑',
  'U+110BD kaithi number sign': '\u{110BD}',
  'U+13430 egyptian format control': '\u{13430}',
};
for (const [name, ch] of Object.entries(scriptContent)) {
  eq(`${name} is left alone`, textOf(R.value('a' + ch + 'b')).includes('‹'), false);
  eq(`${name} produces no hygiene token`, R.hygiene('a' + ch + 'b'), []);
}

// Exempted by range: default-ignorable, but meaningful content.
const exempted = {
  'U+FE0F variation selector-16': '️',
  'U+FE00 variation selector-1': '︀',
  'U+E0100 variation selector supplement': '\u{E0100}',
  'U+1D173 musical format control': '\u{1D173}',
  'U+1BCA0 shorthand format control': '\u{1BCA0}',
};
for (const [name, ch] of Object.entries(exempted)) {
  eq(`${name} is exempt`, textOf(R.value('a' + ch + 'b')).includes('‹'), false);
  eq(`${name} produces no hygiene token`, R.hygiene('a' + ch + 'b'), []);
}

// An emoji presentation sequence must survive whole — this is why the
// variation selectors are exempt.
eq('an emoji presentation sequence is untouched',
  textOf(R.value('warning ⚠️ here')), 'warning ⚠️ here');
eq('a ZWJ emoji family is still marked, by prior decision',
  textOf(R.value('\u{1F468}‍\u{1F469}‍\u{1F467}')).includes('‹ZWJ›'), true);

// The tag block stays covered.
eq('a language tag character is sentinelled',
  textOf(R.value('a\u{E0001}b')).includes('‹'), true);

/* ── 15. Codex review 1 — object-form styles ─────────────────────────── */
section('15. Object-form styles get the same guard as string form');

ok('object form rejects url()',
  threw(() => R.el('div', { style: { background: 'url(https://evil.example/pixel)' } })));
ok('object form rejects URL() in any case',
  threw(() => R.el('div', { style: { background: 'URL(https://evil.example/x)' } })));
ok('object form rejects expression()',
  threw(() => R.el('div', { style: { width: 'expression(alert(1))' } })));
ok('object form rejects a quote breakout',
  threw(() => R.el('div', { style: { width: '1px" onload="alert(1)' } })));
ok('object form rejects markup characters',
  threw(() => R.el('div', { style: { width: '<script>' } })));
ok('object form rejects a non-plain property name',
  threw(() => R.el('div', { style: { 'background:url(x);color': 'red' } })));
ok('object form rejects a custom property',
  threw(() => R.el('div', { style: { '--x': 'url(https://evil.example)' } })));

// Everything legitimately used today must still work.
eq('display:none still works',
  R.el('span', { style: { display: 'none' } }).style.getPropertyValue('display'), 'none');
eq('a multi-property literal still works',
  R.el('div', { style: { width: '50%', background: 'var(--ok)' } }).style.cssText,
  'width:50%;background:var(--ok)');
eq('the string form still works',
  R.el('div', { style: 'width:50%;color:var(--ok);' }).getAttribute('style'),
  'width:50%;color:var(--ok);');

// The truncated-value remainder uses object form, so this is a live path.
eq('the hidden remainder is still built',
  elements(R.value('A'.repeat(2000))).some(e => e.classList.contains('rv-rest')), true);

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
