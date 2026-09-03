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
  loadUi, MarkupSinkError, elements, attributes, locate, hasNoEventHandlers, textOf,
} from './lib/browser-harness.mjs';
import { RICH_TAG_ALLOWLIST, disallowedTags, LOCALE_CODES, loadLocale } from './lib/locale-utils.mjs';
import { detectDNSProvider } from '../src/providers/detectors.js';

// Task 6.2: a direct ESM path. This used to reach the renderer's internals
// through `window.__APP_TEST__`, a marked adapter that existed for this suite
// and `export.test.mjs` alone. `loadUi()` builds a real runtime and hands back
// what it built — no published name involved, and no adapter left to retire.
const { win, R, document, t, tp, tRaw, i18n, ui: APP } = await loadUi();

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

eq('an empty value renders the none token', textOf(R.value('')), t('labels.none'));
eq('a whitespace-only value renders the none token', textOf(R.value('   ')), t('labels.none'));
eq('an empty list renders the none token', textOf(R.list([])), t('labels.none'));
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

const rich = (s) => i18n.sanitizeFragment(s);

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

// The footer and about panel separate their clauses with `&bull;` in all
// fourteen locales. An entity the table does not know is left as literal text,
// so before this was allowlisted the footer read "Cloudflare &bull; No data
// sent to Kwestic…" on the live site.
eq('the bullet entity decodes', textOf(rich('a &bull; b')), 'a \u2022 b');
eq('the bullet decodes in the shipped footer string',
  [textOf(rich(tRaw('footer.text'))).includes('\u2022'),
    textOf(rich(tRaw('footer.text'))).includes('&bull;')], [true, false]);
eq('an entity outside the allowlist is still literal text',
  textOf(rich('a &dagger; b')), 'a &dagger; b');

// The entity body is matched by `[a-zA-Z]+`, so every Object.prototype member
// name reaches the named-entity lookup. Against an object literal
// `&constructor;` resolved to `Object` and `replace()` stringified it into the
// page. An unknown entity is left as literal text, which is the whole
// requirement.
for (const name of ['constructor', 'toString', 'valueOf', 'hasOwnProperty',
  'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString']) {
  eq(`&${name}; is left as text, not resolved through the prototype`,
    textOf(rich(`&${name};`)), `&${name};`);
}

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
  textOf(tbody).includes(t('render.hygiene.bidiOverride')), true);

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
  // The detail panel renders findings, so the end-to-end sentinel check needs
  // the finding form of the hostile issue — a migrated finding resolves the
  // same issue.<key> message, through the same DNS-argument boundary.
  findings: [{
    id: 'dmarc.rua-invalid', key: 'dmarc-rua-invalid', keyspace: 'issue',
    protocol: 'dmarc', severity: 'medium', confidence: 'confirmed',
    category: 'reporting', effort: 'trivial', args: hostileIssue.args,
    evidence: [], dependsOn: [], blocks: [],
  }],
  remediationPlan: [],
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
/* ── 11. The deep-checks toggle and its auto-disable ─────────────────── */
section('11. Deep protocol checks: the large-run rule');

const deepBox = document.getElementById('optDeepChecks');
const deepNotice = document.getElementById('deepChecksNotice');
const LIMIT = APP.MAX_DEEP_CHECK_DOMAINS;

const runLimit = (count, { reEnabled = false } = {}) => {
  APP.resetDeepCheckMemory();
  // Driven through the same function the checkbox's change handler calls, so
  // the test exercises the real path rather than a hook that exists for it.
  if (reEnabled) APP.rememberDeepCheckChoice(true);
  deepBox.checked = true;
  deepNotice.style.display = 'none';
  APP.applyDeepCheckLimit(count);
  return { checked: deepBox.checked, noticeShown: deepNotice.style.display !== 'none', notice: textOf(deepNotice) };
};

eq('a small run keeps the deep checks on', runLimit(1).checked, true);
eq('and shows no notice',                  runLimit(1).noticeShown, false);
eq('a run exactly at the limit is still on', runLimit(LIMIT).checked, true);
eq('one domain over the limit turns them off', runLimit(LIMIT + 1).checked, false);
eq('and says so',                             runLimit(LIMIT + 1).noticeShown, true);

// The notice has to name both numbers. Someone looking at a checkbox they
// ticked, now clear, needs to know what the rule was and what tripped it.
const notice = runLimit(200).notice;
eq('the notice names the limit',       notice.includes(String(LIMIT)), true);
eq('the notice names the run size',    notice.includes('200'), true);
eq('the notice is not empty prose',    notice.length > 20, true);

// An explicit re-enable is remembered for the tab session and beats the rule.
eq('an explicit re-enable survives a large run', runLimit(200, { reEnabled: true }).checked, true);
eq('and suppresses the notice',                  runLimit(200, { reEnabled: true }).noticeShown, false);
// ...but only for this session. Nothing is persisted, so a fresh page is
// back to the default. `PRIVACY.md` promises exactly one localStorage key and
// this feature must not have added a second.
eq('the memory is not persisted', runLimit(200).checked, false);

/* ── 12. Protocol-depth detail blocks ────────────────────────────────── */
section('12. Detail panel: DKIM key, MX health, CAA policy, TLSA');

const keyOf = over => Object.assign({
  valid: true, version: 'DKIM1', keyType: 'rsa', revoked: false,
  keyBits: 2048, keyBytes: 294, keyEncoding: 'spki', hashAlgorithms: [],
  serviceTypes: [], flags: [], testing: false, strictSubdomain: false,
  notes: '', unknownTags: [], cryptoValidated: null, errors: [],
}, over);

eq('an RSA key shows its size',   textOf(APP.dkimKeyLine(keyOf({}))).includes('RSA 2048-bit'), true);
eq('a 1024-bit key shows 1024',   textOf(APP.dkimKeyLine(keyOf({ keyBits: 1024 }))).includes('RSA 1024-bit'), true);
eq('an ed25519 key names the algorithm',
  textOf(APP.dkimKeyLine(keyOf({ keyType: 'ed25519', keyBits: null, keyBytes: 32 }))).includes('Ed25519'), true);
eq('a revoked key says revoked',
  textOf(APP.dkimKeyLine(keyOf({ revoked: true, keyBits: null }))).includes('revoked'), true);
eq('an unparseable key says so',
  textOf(APP.dkimKeyLine(keyOf({ keyBits: null, errors: ['unparseable-key'] }))).includes('does not decode'), true);
eq('a testing key is flagged',
  textOf(APP.dkimKeyLine(keyOf({ testing: true }))).includes('testing'), true);
// A key Web Crypto never looked at must say nothing about Web Crypto. Silence
// is the record; anything else reads as a verdict we did not reach.
const unvalidated = textOf(APP.dkimKeyLine(keyOf({ cryptoValidated: null })));
eq('an unconfirmed key claims nothing about confirmation',
  /invalid|reject|fail/i.test(unvalidated), false);
// A bare PKCS#1 key is valid and is displayed exactly like an SPKI one.
eq('a bare PKCS#1 key renders as a normal key',
  textOf(APP.dkimKeyLine(keyOf({ keyEncoding: 'pkcs1' }))),
  textOf(APP.dkimKeyLine(keyOf({ keyEncoding: 'spki' }))));
eq('a missing key object renders nothing', APP.dkimKeyLine(null), null);

const mxRow = health => ({ mx: ['10 a.example.', '20 b.example.'], advanced: { mxHealth: health } });
const mxHealth = {
  hosts: [
    { host: 'a.example', preference: 10, addresses: ['203.0.113.1'], v4Count: 1, v6Count: 0, resolves: 'yes', isCname: false, inAudited: false },
    { host: 'b.example', preference: 20, addresses: [], v4Count: 0, v6Count: 0, resolves: 'no', isCname: false, inAudited: false },
    { host: 'c.example', preference: 30, addresses: [], v4Count: 0, v6Count: 0, resolves: 'unknown', isCname: true, inAudited: false },
  ],
  danglingHosts: ['b.example'], cnameHosts: ['c.example'], duplicatePreferences: [],
  singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: true,
};
const mxText = textOf(APP.mxDetail(mxRow(mxHealth)));
eq('a resolving host shows its address', mxText.includes('203.0.113.1'), true);
eq('a dangling host says it does not resolve', mxText.includes('does not resolve'), true);
// The distinction the whole resilience argument rests on: a host we could not
// check must read differently from one that genuinely has no address.
eq('an unchecked host says "not checked" instead', mxText.includes('not checked'), true);
eq('and is not described as unresolvable',
  mxText.split('c.example')[1].includes('does not resolve'), false);
eq('a CNAME target is named', mxText.includes('CNAME'), true);
// With the deep checks off there is no audit to show, so the display is
// exactly what it was before this release.
eq('without an MX audit the plain list is used',
  textOf(APP.mxDetail({ mx: ['10 a.example.'], advanced: null })).includes('10 a.example.'), true);

const caaRow = caa => ({ advanced: { caa: Object.assign({ found: true, atDomain: 'example.com', records: [] }, caa) } });
const openCaa = caaRow({ parsed: [{}], issuers: ['letsencrypt.org'], wildcardIssuers: [], iodef: [], unknownCritical: [], malformed: [], issuanceBlocked: false, wildcardBlocked: false });
eq('the issuer is shown', textOf(APP.caaDetail(openCaa)).includes('letsencrypt.org'), true);
// The semantic that is easiest to invert: an absent issuewild set means the
// issue set governs wildcards, NOT that wildcards are unrestricted.
const wildText = textOf(APP.caaDetail(openCaa));
eq('an absent issuewild set says issue governs', wildText.includes('governed by the issue set'), true);
eq('and never says "none" for wildcards',
  wildText.split('Wildcards')[1].trim().startsWith('none'), false);
eq('a blocked policy says no CA is authorized',
  textOf(APP.caaDetail(caaRow({ parsed: [{}], issuers: [], wildcardIssuers: [], iodef: [], unknownCritical: [], malformed: [], issuanceBlocked: true, wildcardBlocked: false })))
    .includes('No certificate authority is authorized'), true);
eq('a blocked wildcard set is named',
  textOf(APP.caaDetail(caaRow({ parsed: [{}], issuers: ['pki.goog'], wildcardIssuers: [], iodef: [], unknownCritical: [], malformed: [], issuanceBlocked: false, wildcardBlocked: true })))
    .includes('No wildcard certificates'), true);
eq('an unknown critical property is surfaced',
  textOf(APP.caaDetail(caaRow({ parsed: [{}], issuers: ['pki.goog'], wildcardIssuers: [], iodef: [], unknownCritical: ['weirdtag'], malformed: [], issuanceBlocked: false, wildcardBlocked: false })))
    .includes('weirdtag'), true);
eq('no CAA means no block', APP.caaDetail({ advanced: { caa: { found: false } } }), null);
// A result carrying `found` but none of the parsed fields must not throw and
// take the whole row down with it.
eq('a partial CAA shape renders nothing rather than throwing',
  APP.caaDetail({ advanced: { caa: { found: true, records: ['0 issue "x"'], atDomain: 'e.com' } } }), null);

const tlsaRow = hosts => ({ advanced: { tlsa: { hosts, anyPresent: hosts.some(h => h.present) } } });
const tlsaText = textOf(APP.tlsaDetail(tlsaRow([
  { host: 'a.example', queryName: '_25._tcp.a.example', records: [{ valid: true }], present: true, authenticated: true, unknown: false },
  { host: 'b.example', queryName: '_25._tcp.b.example', records: [{ valid: true }], present: true, authenticated: false, unknown: false },
  { host: 'c.example', queryName: '_25._tcp.c.example', records: [], present: false, authenticated: false, unknown: false },
])));
// Acceptance criterion 4, at the surface the user actually reads.
eq('the block says published, not active', tlsaText.includes('Published, not proven active'), true);
eq('nothing claims DANE is active or enabled', /DANE is (active|enabled|protecting)/i.test(tlsaText), false);
// The heading no longer scopes itself to "this release", which stopped being
// true the moment the flag it referred to was retired rather than completed.
eq('the heading makes no promise about a later release',
  /this release|not yet|qualified/i.test(tlsaText), false);
eq('an authenticated host is distinguished', tlsaText.includes('DNSSEC-authenticated'), true);
eq('an unauthenticated host is too', tlsaText.includes('not DNSSEC-authenticated'), true);
eq('a host without TLSA says not published', tlsaText.includes('not published'), true);
eq('no TLSA audit renders no block', APP.tlsaDetail({ advanced: null }), null);

/* ── Conflicting SPF records are shown, not summarized away ─────────── */
const SPF_1 = 'v=spf1 include:_spf.google.com ~all';
const SPF_2 = 'v=spf1 include:mktomail.com ~all';
const meter = R.el('span', { className: 'meter' }, 'meter');

const oneSpfText = textOf(APP.spfDetail({ spfRecord: SPF_1, spfRecords: [SPF_1] }, meter));
eq('a single record renders as before', oneSpfText.includes(SPF_1), true);
eq('and keeps its lookup meter',        oneSpfText.includes('meter'), true);

// The reported defect: the permerror was right and the panel showed one valid
// record, so the finding looked unsupported.
const twoSpfText = textOf(APP.spfDetail({ spfRecord: SPF_1, spfRecords: [SPF_1, SPF_2] }, meter));
eq('the first conflicting record is shown',  twoSpfText.includes(SPF_1), true);
eq('the second conflicting record is too',   twoSpfText.includes(SPF_2), true);
eq('and the set is labelled as conflicting', twoSpfText.includes('conflicting records'), true);
eq('and says none of them applies',          twoSpfText.includes('none of them applies'), true);
eq('and names how many',                     twoSpfText.includes('2'), true);
// The meter is computed from the first record only, so attaching it beside a
// conflicting set would attribute one record's lookup count to all of them.
eq('the lookup meter is withheld from a conflicting set',
  twoSpfText.includes('meter'), false);

// A result from before this field existed must still render.
eq('a result without spfRecords falls back to spfRecord',
  textOf(APP.spfDetail({ spfRecord: SPF_1 }, null)).includes(SPF_1), true);
eq('and no SPF at all renders nothing but the dash the value helper gives',
  textOf(APP.spfDetail({ spfRecord: '', spfRecords: [] }, null)).includes(SPF_1), false);

eq('one key size renders as a number', APP.dkimKeyBitsCell({ minBits: 2048, maxBits: 2048 }), '2048');
eq('mixed key sizes render as a range', APP.dkimKeyBitsCell({ minBits: 1024, maxBits: 2048 }), '1024-2048');
eq('no RSA key renders empty', APP.dkimKeyBitsCell({ minBits: null, maxBits: null }), '');

/* ── DNSSEC chain detail (spec §8) ────────────────────────────────────
   Acceptance criteria 1 and 2, at the surface a user actually reads: no
   `secure` claim assembled from local evidence, and every claim attributed on
   screen rather than only in the data model.
   ──────────────────────────────────────────────────────────────────────── */
section('DNSSEC chain detail');

const dnssecRow = dnssec => ({ advanced: { dnssec } });
const SECURE = {
  signed: true, state: 'secure', resolverValidated: true,
  keys: [
    { keyTag: 2371, algorithm: 13, algorithmName: 'ECDSAP256SHA256', hasSep: true, hasZoneFlag: true, hasRevokeFlag: false },
    { keyTag: 34505, algorithm: 13, algorithmName: 'ECDSAP256SHA256', hasSep: false, hasZoneFlag: true, hasRevokeFlag: false },
  ],
  ds: [{ keyTag: 2371, digestType: 2, digestName: 'SHA-256', match: 'confirmed' }],
  anchorConfirmed: true, orphanDs: [],
  chain: [
    { claim: 'resolver-ad', source: 'resolver', detail: { ad: true } },
    { claim: 'link-checked', source: 'local', detail: { child: 'e.com', link: 'child-dnskey-to-parent-ds' } },
    { claim: 'ds-confirms-dnskey', source: 'local', detail: { keyTag: 2371, digestName: 'SHA-256', anchors: true } },
  ],
};
const secureText = textOf(APP.dnssecDetail(dnssecRow(SECURE)));

eq('the state is named', secureText.includes('validated by the resolver'), true);
eq('both keys are listed', [secureText.includes('2371'), secureText.includes('34505')], [true, true]);
// RFC 6840 §6.2 — the SEP bit is advisory and must not be shown as "KSK".
eq('the SEP bit is named as a flag, not as a role',
  [secureText.includes('SEP'), /\bKSK\b|\bZSK\b/.test(secureText)], [true, false]);
eq('the DS record and its verdict are shown', secureText.includes('SHA-256'), true);

// Criterion 2: attribution is visible, and the two kinds of evidence are
// distinguishable on screen.
eq('the resolver claim is attributed to the resolver', secureText.includes('Resolver'), true);
eq('the local computation is attributed as computed here', secureText.includes('Computed here'), true);
// OQ-SEC9-03: showing one link without naming it implies a completeness the
// tool does not have.
eq('the panel states which single link was checked', secureText.includes('one link checked'), true);

/* ── The states this release exists to expose ────────────────────────── */

const unanchoredText = textOf(APP.dnssecDetail(dnssecRow({
  signed: false, state: 'unanchored', resolverValidated: false,
  keys: SECURE.keys, ds: [], chain: [{ claim: 'resolver-ad', source: 'resolver', detail: { ad: false } }],
})));
eq('an unanchored zone is not described as unsigned',
  [unanchoredText.includes('no DS record'), /Not signed/.test(unanchoredText)], [true, false]);

const mismatchText = textOf(APP.dnssecDetail(dnssecRow({
  signed: false, state: 'mismatch', resolverValidated: false, keys: SECURE.keys,
  ds: [{ keyTag: 34800, digestType: 2, digestName: 'SHA-256', match: 'no-matching-key' }],
  chain: [{ claim: 'ds-no-matching-key', source: 'local', detail: { keyTag: 34800 } }],
})));
eq('a mismatch names the offending DS record', mismatchText.includes('34800'), true);
eq('and reuses the match vocabulary rather than a second wording',
  mismatchText.includes('no published key carries this tag'), true);

// Missing evidence is stated, not inferred from an empty list.
const partialText = textOf(APP.dnssecDetail(dnssecRow({
  signed: false, state: 'insecure', keys: [], ds: [],
  chain: [{ claim: 'lookup-incomplete', source: 'local', detail: { query: 'ds', kind: 'servfail' } }],
})));
eq('an incomplete lookup says which query and why',
  [partialText.includes('ds'), partialText.includes('servfail')], [true, true]);

/* ── Partial shapes render less rather than throwing ─────────────────── */

// 0.4.0 saved only { signed, state }. One thrown render takes down the whole
// table row, so this must degrade rather than fail — the rule from
// dns-protocol-depth's As implemented item 4.
eq('a 0.4.0-shaped result still renders its state',
  textOf(APP.dnssecDetail(dnssecRow({ signed: false, state: 'insecure' }))).includes('Not signed'), true);
eq('a result with no state renders nothing', APP.dnssecDetail(dnssecRow({ signed: false })), null);
eq('no DNSSEC audit renders no block', APP.dnssecDetail({ advanced: null }), null);

/* ── The dot ─────────────────────────────────────────────────────────── */

// Amber covers exactly the two states where real work is not yet protecting
// anything. `bogus` and `indeterminate` stay grey: amber reads as "nearly
// there", and neither of those is.
eq('the dot is amber for unanchored and mismatch only',
  ['secure', 'insecure', 'unanchored', 'mismatch', 'bogus', 'indeterminate']
    .map(state => APP.dnssecDot({ dnssec: { state, signed: state === 'secure' } }).partial),
  [false, false, true, true, false, false]);
eq('only a validated chain counts as configured',
  ['secure', 'unanchored', 'mismatch']
    .map(state => APP.dnssecDot({ dnssec: { state, signed: state === 'secure' } }).ok),
  [true, false, false]);
// "Not configured" is simply false for a signed-but-unanchored zone, and worse
// than false for one whose validation is failing.
eq('every state that needs its own wording gets one',
  ['secure', 'insecure', 'unanchored', 'mismatch', 'bogus', 'indeterminate']
    .map(state => APP.dnssecDot({ dnssec: { state } }).label === null),
  [true, true, false, false, false, false]);
eq('a missing DNSSEC result still yields a dot', APP.dnssecDot({}).ok, false);

/* ── 14. Structured findings render as two views (findings spec §5) ────── */
section('14. The findings block renders both views');

const mkFinding = (id, key, severity, over) => Object.assign({
  id, key, keyspace: key.indexOf('.') === -1 ? 'finding' : 'issue',
  protocol: 'dmarc', severity, confidence: 'confirmed', category: 'policy',
  effort: 'moderate', args: [], evidence: [{ kind: 'txt', queryName: '_dmarc.x.test', value: 'v=DMARC1; p=none' }],
  dependsOn: [], blocks: [],
}, over || {});

const findingsRow = {
  domain: 'find.example', ns: [], mx: [], verifications: [],
  spfRecord: '', dmarcRecord: 'v=DMARC1; p=none', issues: [], suggestions: [],
  findings: [
    mkFinding('dmarc.enforcement-without-auth', 'dmarc-enforcement-without-auth', 'critical', { keyspace: 'finding', dependsOn: ['dkim.weak-with-enforcement'] }),
    mkFinding('dkim.weak-with-enforcement', 'dkim-weak-with-enforcement', 'high', { keyspace: 'finding', blocks: ['dmarc.enforcement-without-auth'] }),
    mkFinding('dkim.mixed-key-strength', 'dkim-key-mixed', 'low'),
    // A second low-tier card is intentional: it proves renderer callbacks do
    // not mistake Array#map's index argument for static-report mode.
    mkFinding('dmarc.no-rua', 'dkim-weak-with-enforcement', 'low', { keyspace: 'finding', confidence: 'unverified' }),
  ],
  remediationPlan: [
    { step: 1, findings: ['dkim.weak-with-enforcement', 'dkim.mixed-key-strength'], rationale: 'foundation', unblocks: ['dmarc.enforcement-without-auth'] },
    { step: 2, findings: ['dmarc.enforcement-without-auth'], rationale: 'afterPrereq', unblocks: [] },
  ],
  spfStatus: { status: 'missing', cls: 'crit' },
  dmarcStatus: { status: 'warn', cls: 'warn', policy: 'none', pct: 100, adkim: 'r', aspf: 'r', rua: false, ruf: false, testMode: false, sp: '', np: '' },
  dkimStatus: { found: false, confidence: 'checked', selectors: [], missingSelectors: [] },
  dnsProvider: 'Cloudflare', emailProvider: '@none', hosting: '@unknown',
  advScore: 0, advanced: null,
  score: { grade: 'F', pts: 0, max: 100, cls: 'score-f', breakdown: null, unproven: [] },
};
const fb = document.createElement('tbody');
fb.id = 'tableBody';
document.body.appendChild(fb);
APP.appendRow(findingsRow);
const fEls = elements(document.getElementById('tableBody'));

// The result↔DOM binding rests on this: exactly one div.finding per finding,
// low/info hidden but present, so the count equals findings.length.
eq('one div.finding per finding, including the collapsed ones',
  fEls.filter(e => e.className === 'finding').length, 4);
eq('the severity view is present', fEls.some(e => e.classList.contains('findings-view-severity')), true);
eq('the remediation view is present but hidden by default',
  fEls.some(e => e.classList.contains('findings-view-remediation') && (e.getAttribute('style') || '').includes('display:none')), true);
eq('low and info collapse behind a disclosure', fEls.some(e => e.classList.contains('finding-collapsed')), true);
eq('both view toggles render', fEls.filter(e => e.classList.contains('findings-view-toggle')).length, 2);
eq('the plan renders one node per step', fEls.filter(e => e.classList.contains('plan-step')).length, 2);
// The remediation view references findings without a second div.finding, so it
// cannot double the binding count.
eq('the plan uses plan-finding, not finding', fEls.some(e => e.classList.contains('plan-finding')), true);
// A blocked finding is marked as waiting, and names what it waits on (spec §5).
eq('a blocked plan finding is marked waiting',
  fEls.some(e => e.classList.contains('plan-finding-waiting')), true);
const blockedNote = fEls.find(e => e.classList.contains('plan-finding-blocked'));
eq('and it carries a "waiting on" note', !!blockedNote, true);
eq('naming the blocking finding\'s message',
  blockedNote && textOf(blockedNote).length > 0, true);
// A finding with no prerequisites is not marked waiting.
eq('an unblocked plan finding is not marked waiting',
  fEls.filter(e => e.classList.contains('plan-finding') && !e.classList.contains('plan-finding-waiting')).length > 0, true);
// Confidence shows only where it is not confirmed.
eq('an unverified finding shows its confidence',
  fEls.some(e => e.classList.contains('finding-conf-unverified')), true);
eq('a confirmed finding shows no confidence marker',
  fEls.some(e => e.classList.contains('finding-conf-confirmed')), false);
// Evidence renders under a finding.
eq('evidence renders under a finding', fEls.some(e => e.classList.contains('finding-evidence')), true);
// `Array#map` passes an index as its second callback argument. When
// findingCard gained a `staticMode` second parameter for HTML reports, passing
// it directly to map made every card after index zero look static in the live
// UI: its disclosure button vanished and its content opened. Pin the live-card
// contract at both observable points.
const findingExplainers = fEls.filter(e => e.classList.contains('showme-wrap'));
eq('every live finding explainer keeps its disclosure button',
  fEls.filter(e => e.classList.contains('showme-btn') && e.parentNode && e.parentNode.classList.contains('showme-wrap')).length,
  findingExplainers.length);
eq('no live finding explainer is forced open by static-report mode',
  fEls.filter(e => e.classList.contains('showme-content') && (e.getAttribute('style') || '').includes('display:block')).length,
  0);
// A domain with no findings renders no findings block — proven able to be empty.
fb.id = '';
const emptyBody = document.createElement('tbody');
emptyBody.id = 'tableBody';
document.body.appendChild(emptyBody);
APP.appendRow(Object.assign({}, findingsRow, { domain: 'clean.example', findings: [], remediationPlan: [] }));
eq('a clean domain renders no div.finding',
  elements(emptyBody).filter(e => e.className === 'finding').length, 0);

/* ── 15. Local artifact limits and evidence are their own branch ─────── */
section('15. Local artifact limits and evidence');

eq('a policy of exactly 64 KiB is accepted before parsing',
  APP.artifactInputProblem('mta-sts-policy', 'a'.repeat(64 * 1024), null), null);
eq('one byte over the policy limit is refused',
  APP.artifactInputProblem('mta-sts-policy', 'a'.repeat(64 * 1024 + 1), null).token, 'too-large');
eq('the paste limit counts UTF-8 bytes rather than UTF-16 units',
  APP.artifactInputProblem('mta-sts-policy', 'é'.repeat(32 * 1024 + 1), null).token, 'too-large');
eq('a file at the SVG limit is accepted before FileReader',
  APP.artifactInputProblem('bimi-svg', '', { size: 32 * 1024, type: 'image/svg+xml' }), null);
eq('a file over the SVG limit is refused before FileReader',
  APP.artifactInputProblem('bimi-svg', '', { size: 32 * 1024 + 1, type: 'image/svg+xml' }).token, 'too-large');
eq('an omitted MIME declaration is advisory and accepted',
  APP.artifactInputProblem('bimi-svg', '', { size: 1, type: '' }), null);
eq('a declared wrong MIME type is refused',
  APP.artifactInputProblem('bimi-svg', '', { size: 1, type: 'text/html' }).token, 'wrong-type');
eq('an unknown artifact kind fails closed',
  APP.artifactInputProblem('vmc', '', null).token, 'unknown-kind');

const suppliedValue = '<use href="https://evil.example/x">';
APP.renderArtifactAnalysis({
  domain: 'artifact.example',
  artifactFindings: [{
    id: 'bimi.svg-rejected', key: 'bimi-svg-rejected', keyspace: 'finding',
    severity: 'high', confidence: 'confirmed', category: 'issuance',
    source: 'user-supplied', args: ['external-reference-element', 'external-reference'],
    evidence: [{ kind: 'element', location: '<use>', value: suppliedValue,
      queryName: 'must-not-be-treated-as-dns.example' }],
  }],
});
const artifactTree = document.getElementById('artifactResults');
const artifactText = textOf(artifactTree);
eq('the aggregate artifact message includes every token',
  artifactText.includes('external-reference-element') && artifactText.includes('external-reference'), true);
eq('each known parser token is rendered with its actionable requirement',
  artifactText.includes(t('artifact.token.external-reference-element')) &&
    artifactText.includes(t('artifact.token.external-reference')), true);
eq('every artifact card renders its user-supplied provenance',
  elements(artifactTree).filter(e => e.classList.contains('artifact-source')).length, 1);
eq('artifact evidence renders its location as text', locate(artifactTree, '<use>'), 'text');
eq('artifact evidence renders the supplied value as text', locate(artifactTree, suppliedValue), 'text');
eq('the artifact branch ignores DNS queryName even if one is smuggled in',
  textOf(artifactTree).includes('must-not-be-treated-as-dns.example'), false);

APP.renderArtifactAnalysis({ domain: 'clean.example', artifactFindings: [] });
eq('a clean supplied policy still produces a visible answer',
  textOf(artifactTree).includes(t('artifact.noFindings')), true);
eq('and the clean answer still names its provenance',
  elements(artifactTree).some(e => e.classList.contains('artifact-source')), true);

/* ── 16. The finding-id sequence is byte-identical across all locales ─── */
section('16. Finding order is identical under every one of the fourteen locales');

// A direct render test (findings spec §6, testing amendment 1.1): render the
// same fixture under each locale by composing a UI whose active bundle IS that
// locale, then compare the data-finding-id sequence the cards and the plan
// carry. The order is set by severity/effort tokens and the pure plan, never by
// translated text, so it must not move — this catches a render path that ever
// sorted by rendered label instead.
async function findingIdSequence(bundle) {
  const { document: doc, ui } = await loadUi({ data: { englishBundle: bundle } });
  ui.appendRow(findingsRow);
  return elements(doc.getElementById('tableBody'))
    .filter(e => e.dataset && e.dataset.findingId)
    .map(e => e.dataset.findingId);
}
const enSequence = await findingIdSequence(loadLocale('en'));
eq('the English render has a finding-id sequence to compare', enSequence.length > 0, true);
// It covers both views (severity cards + plan-findings), so it is a real order.
eq('and it includes the plan as well as the severity view',
  enSequence.length > findingsRow.findings.length, true);
for (const code of LOCALE_CODES) {
  eq(`${code}: byte-identical finding-id sequence`, await findingIdSequence(loadLocale(code)), enSequence);
}
// Proven able to fail: the comparison must reject a REORDERED sequence, not
// merely agree with itself. An earlier version of this control compared German
// against English a second time — which is the assertion above, not a negative
// case, and would have passed even if the comparison were vacuous.
const scrambled = enSequence.slice().reverse();
eq('the scrambled control really differs from the real sequence',
  scrambled.join() === enSequence.join(), false);
eq('and a reordered sequence would be caught',
  JSON.stringify(await findingIdSequence(loadLocale('de'))) === JSON.stringify(scrambled), false);
eq('the fourteen-locale set is complete', LOCALE_CODES.length + 1, 14);

/* ── 17. Derived labels and object-keyed lookups ─────────────────────── */
section('17. Derived labels and object-keyed lookups');

// The suite above feeds hostile bytes into record VALUES. This section feeds
// them into a value the tool DERIVES from a record and then uses as an object
// key. `detectDNSProvider()` falls back to one DNS label of the first NS
// record, capitalised; underscores are legal in owner names and resolvers
// return them verbatim, so the audited domain's operator chooses this string.
//
// Every Object.prototype member name, because guarding the one that was
// reported would leave the class open. `constructor` survives capitalisation
// as `Constructor` and was never the bug; `__proto__` does not, and was.
const derivedRow = (ns) => ({
  ...result,
  domain: 'derived.example',
  ns: [ns],
  dnsProvider: detectDNSProvider([ns], 'derived.example'),
});

for (const name of ['__proto__', 'constructor', 'toString', 'valueOf',
  'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString']) {
  const ns = `ns1.${name}.net`;
  let threw = null;
  try { APP.appendRow(derivedRow(ns)); } catch (e) { threw = e.message; }
  eq(`an NS label of ${name} renders a row instead of throwing`, threw, null);
}

// Re-read the table: section 16 re-renders under fourteen locales, so the
// reference captured in section 9 is not necessarily the live element.
const derivedBody = textOf(document.getElementById('tableBody'));

// The label reaches the badge, so the row is not merely surviving by dropping
// it. `__proto__` is not a token, so it is displayed as the proper name it
// looks like.
eq('the derived label is displayed, not swallowed',
  derivedBody.includes('__proto__'), true);

// A real token still resolves to its translation rather than to the literal.
eq('a genuine token still resolves through the table',
  t('provider.unknown') !== '@unknown' && derivedBody.includes(t('provider.unknown')),
  true);

console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
