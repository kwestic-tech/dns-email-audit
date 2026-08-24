#!/usr/bin/env node
/**
 * The two document builders, and the CSV.
 *
 * These files leave the project's control the moment someone emails one, so
 * they are asserted at the STRING level as well as the tree level. String
 * assertions need no DOM and are where a serializer bug would show up — the
 * shim's model of a tree cannot hide one.
 */

import {
  loadApp, elements, attributes, textOf,
} from './lib/browser-harness.mjs';

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
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

/* ── The scan every exported document must survive ───────────────────── */

// There is deliberately NO whole-string `/<script/i` scan here.
//
// It was the third instance of the same false-positive class this spec has
// been amended for twice. Once `escapeAttr` was corrected to match the HTML
// serialization algorithm — a browser does not escape `<` inside a quoted
// attribute value — a BIMI record whose text contains `<script` puts a raw
// `<script` into the export as inert attribute DATA:
//
//   data-tip="Record: v=BIMI1; l=<script>alert(1)</script>"
//
// A whole-string scan calls that document unsafe when it is not. The
// structural check below covers real elements completely and correctly, by
// tokenizing, so scanning the raw string as well adds nothing but a landmine
// for whoever writes the next fixture.

// An event handler and a javascript: URL are only dangerous as MARKUP — an
// attribute NAME beginning with "on", or a URL-bearing attribute VALUE whose
// scheme is javascript:. A substring scan cannot tell those from the same
// characters appearing as data, and this release has to render both:
//
//   • as text — the spec's attribute-breakout fixture is
//     `rua=mailto:"><img src=x onerror=alert(1)>@e.com`, and escaping it
//     leaves " onerror=" intact inside an inert text node;
//   • as an attribute value — `data-tip` carries DNS-derived text, and a
//     browser does not escape `<` inside a quoted attribute value at all.
//
// So the scan is structural: tokenize the tags, respecting quoting, and
// inspect attribute names and URL values separately. Anything less either
// misses the attribute path or false-positives on a record the tool is
// required to display faithfully.

const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);

/** [{ tag, attrs: [[name, value], …] }] for every tag in the document. */
function parseTags(html) {
  const out = [];
  for (let i = 0; i < html.length; i++) {
    if (html[i] !== '<') continue;
    // Walk to the tag's closing '>', skipping any '>' inside a quoted value.
    let j = i + 1;
    let quote = null;
    while (j < html.length) {
      const c = html[j];
      if (quote) { if (c === quote) quote = null; }
      else if (c === '"' || c === "'") quote = c;
      else if (c === '>') break;
      j++;
    }
    if (j >= html.length) break;
    const body = html.slice(i + 1, j);
    i = j;
    if (!/^\/?[a-zA-Z]/.test(body)) continue;   // comment, doctype, stray '<'
    const m = /^\/?([a-zA-Z][a-zA-Z0-9-]*)([\s\S]*)$/.exec(body);
    if (!m) continue;
    const attrs = [];
    const attrRe = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
    let a;
    while ((a = attrRe.exec(m[2]))) {
      if (a[0] === '') { attrRe.lastIndex++; continue; }
      attrs.push([a[1].toLowerCase(),
        a[2] !== undefined ? a[2] : a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : '']);
    }
    out.push({ tag: m[1].toLowerCase(), attrs });
  }
  return out;
}

// An entity-decoded scheme test: `java&#115;cript:` is the same URL to a
// browser, so comparing the raw bytes would miss it.
function schemeOf(value) {
  const decoded = String(value).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10FFFF
        ? String.fromCodePoint(code) : m;
    }
    return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", colon: ':' }[body.toLowerCase()] ?? m;
  });
  // Leading control characters and whitespace are ignored by URL parsers.
  return decoded.replace(/[\u0000-\u0020]/g, '').toLowerCase();
}

function assertInert(label, html) {
  const tags = parseTags(html);
  eq(`${label}: no event-handler attribute`,
    tags.flatMap(t => t.attrs).filter(([name]) => /^on/.test(name)).map(([n]) => n), []);
  eq(`${label}: no javascript: URL attribute`,
    tags.flatMap(t => t.attrs)
      .filter(([name, value]) => URL_ATTRS.has(name) && /^javascript:/.test(schemeOf(value)))
      .map(([n, v]) => `${n}=${v}`), []);
  eq(`${label}: no script or iframe element`,
    tags.filter(t => ['script', 'iframe', 'object', 'embed'].includes(t.tag)).map(t => t.tag), []);
}

const FIXTURES = {
  tagInjection: 'v=spf1 <script>alert(1)</script> -all',
  attrBreakout: 'rua=mailto:"><img src=x onerror=alert(1)>@e.com',
  singleQuote: "v=spf1 include:'evil.example' -all",
  svgPayload: 'v=DKIM1; k=rsa; p=<svg onload=alert(1)>',
  encodedEntities: '&lt;script&gt; and &#60;script&#62;',
  templateInjection: 'v=spf1 include:{0}.example {1} -all',
  bidiOverride: 'v=spf1 include:‮elpmaxe.evil -all',
  zeroWidth: 'mail.exa​mple.com',
  controlChars: 'v=spf1 \u0000\u0007\u001B -all',
  oversized: 'v=DKIM1; p=' + 'A'.repeat(64 * 1024),
  loneSurrogate: 'v=DKIM1; p=\uD800BROKEN',
  javascriptUrl: 'v=spf1 redirect=javascript:alert(1)',
  empty: '',
};

/* ── 1. Every fixture, rendered then exported ────────────────────────── */
section('1. Every fixture survives export as inert text');

for (const [name, value] of Object.entries(FIXTURES)) {
  const content = document.createDocumentFragment();
  content.appendChild(R.el('div', { className: 'v' }, R.value(value)));

  const html = APP.buildReportDocument({
    lang: 'en',
    css: 'body { color: red; }',
    title: 'Report',
    generated: 'now',
    note: 'note',
    content: content,
  });

  assertInert(name, html);
  // The published record text must still be visible; it is inert because it
  // is a text node, not because it was stripped.
  if (name === 'javascriptUrl') {
    eq(`${name}: the URL is still shown to the reader`, html.includes('javascript:alert(1)'), true);
    eq(`${name}: but never as an href`, /href\s*=\s*"?javascript:/i.test(html), false);
  }
}

// The case that retired the string scan: `<script` as attribute DATA is inert,
// and must not be reported as a script element.
section('1b. A tag name inside an attribute value is data, not an element');

const scriptInAttr = APP.buildReportDocument({
  lang: 'en', css: '', title: 'T', generated: 'g', note: 'n',
  content: (() => {
    const f = document.createDocumentFragment();
    f.appendChild(APP.advFullDots({
      bimi: { present: true, record: 'v=BIMI1; l=<script>alert(1)</script>' },
      mtaSts: { present: false }, tlsRpt: { present: false },
      caa: { found: false }, dnssec: { signed: false },
    }));
    return f;
  })(),
});
assertInert('script text in an attribute', scriptInAttr);
eq('the record text is still shown to the reader',
  scriptInAttr.includes('l=<script>alert(1)'), true);
eq('but it produced no script element',
  parseTags(scriptInAttr).some(t => t.tag === 'script'), false);
eq('a naive whole-string scan would have called this unsafe',
  /<script/i.test(scriptInAttr), true);

/* ── 2. The exported report carries its own policy ───────────────────── */
section('2. The exported report carries its own CSP');

const report = APP.buildReportDocument({
  lang: 'en', css: 'body{color:red}', title: 'Report',
  generated: 'now', note: 'note',
  content: (() => {
    const f = document.createDocumentFragment();
    f.appendChild(R.el('div', null, R.value(FIXTURES.tagInjection)));
    return f;
  })(),
});

eq('the CSP meta tag is present',
  report.includes('http-equiv="Content-Security-Policy"'), true);
eq('the policy is default-src none',
  report.includes("default-src &#039;none&#039;") || report.includes(`default-src 'none'`), true);
eq('style-src unsafe-inline is allowed, and only here',
  /style-src [^"]*unsafe-inline/.test(report), true);
eq('img-src is data: only', /img-src data:/.test(report), true);
eq('the doctype is emitted once',
  (report.match(/<!DOCTYPE html>/gi) || []).length, 1);
eq('the language is set', report.includes('lang="en"'), true);

/* ── 3. The stylesheet survives serialization unchanged ──────────────── */
section('3. The inlined stylesheet is not corrupted');

// css/style.css contains both `&` and a `>` child combinator. <style> is a
// raw-text element, so neither may be entity-escaped — escaping them would
// silently break the exported report's layout.
const trickyCss = '.a > .b { color: red; }\n/* A & B */\n.c::after { content: "x"; }';
const styled = APP.buildReportDocument({
  lang: 'en', css: trickyCss, title: 'T', generated: 'g', note: 'n',
});
eq('the child combinator survives', styled.includes('.a > .b'), true);
eq('the ampersand survives', styled.includes('/* A & B */'), true);
// <style> is raw text, so a literal `</style>` in the CSS would end the
// element early and let everything after it be parsed as markup. The guard
// neutralizes the sequence; the CSS text itself is ours and stays visible.
const hostileCss = APP.buildReportDocument({
  lang: 'en', css: '.x{}</style><script>alert(1)</script>', title: 'T', generated: 'g', note: 'n',
});
eq('the style element is closed exactly once',
  (hostileCss.match(/<\/style>/gi) || []).length, 1);
eq('the injected closing tag was neutralized as a CSS escape',
  hostileCss.includes('\\3c /style>'), true);
eq('nothing after it became a real script element',
  /<script/i.test(hostileCss), false);

/* ── 4. Serialization is idempotent for what the renderer emits ──────── */
section('4. Round trip: text content is preserved');

for (const [name, value] of Object.entries(FIXTURES)) {
  if (name === 'oversized') continue;
  const node = R.value(value);
  const before = textOf(node);
  const wrapper = R.el('div', null, node);
  const serialized = wrapper.outerHTML;
  // Re-decode the entities the serializer introduced and confirm the text is
  // the same run of characters that went in.
  const after = serialized
    .replace(/<[^>]*>/g, '')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&amp;/g, '&');
  eq(`${name}: text content round-trips`, after, before);
}

/* ── 5. The learn-more guide ─────────────────────────────────────────── */
section('5. buildLearnMorePage');

const guide = APP.buildLearnMorePage('dnssec');
eq('a real guide builds', typeof guide, 'string');
assertInert('learn-more guide', guide);
eq('the guide has a doctype', guide.startsWith('<!DOCTYPE html>'), true);
eq('an unknown guide returns null', APP.buildLearnMorePage('nope'), null);

// A locale fixture carrying markup outside the rich-text allowlist.
const bundle = win.__I18N_EN__;
bundle.learnMore.__test__ = {
  title: '<script>alert(1)</script>',
  tagline: '<img src=x onerror=alert(1)>',
  sections: [{
    h: '<iframe src="javascript:alert(1)">',
    body: 'ok <strong>bold</strong> and <script>alert(1)</script>',
    code: 'v=DMARC1; p=reject; rua=mailto:"><script>alert(1)</script>',
    body2: '<a href="javascript:alert(1)">click</a> and <a href="https://ok.example">fine</a>',
  }],
};
const hostile = APP.buildLearnMorePage('__test__');
assertInert('a hostile locale fixture', hostile);
eq('the allowlisted tag survived', hostile.includes('<strong>bold</strong>'), true);
eq('the https link survived', hostile.includes('href="https://ok.example"'), true);
eq('the refused tag is escaped text', hostile.includes('&lt;script&gt;'), true);

/* ── 6. Sentinels reach both exports ─────────────────────────────────── */
section('6. Sentinels survive into a report handed to a third party');

const withOverride = APP.buildReportDocument({
  lang: 'en', css: '', title: 'T', generated: 'g', note: 'n',
  content: (() => {
    const f = document.createDocumentFragment();
    f.appendChild(R.el('div', null, R.value(FIXTURES.bidiOverride)));
    return f;
  })(),
});
eq('the sentinel is in the exported HTML', withOverride.includes('‹RLO›'), true);
eq('the raw override character is not', withOverride.includes('‮'), false);

/* ── 7. The CSV keeps the bytes and names the hygiene ────────────────── */
section('7. CSV: raw data column, separate record_hygiene column (OQ-SEC-11)');

const row = {
  domain: 'evil.example',
  ns: [], mx: [], verifications: [],
  spfRecord: FIXTURES.bidiOverride,
  dmarcRecord: '',
  issues: [], suggestions: [],
  spfStatus: { status: 'permerror' },
  dmarcStatus: { status: 'missing', policy: '', pct: 100, adkim: 'r', aspf: 'r', rua: false, ruf: false, testMode: false, sp: '', np: '' },
  dkimStatus: { found: false, confidence: 'checked', selectors: [], missingSelectors: [] },
  dnsProvider: 'Cloudflare', emailProvider: '@none',
  advanced: null,
  score: { grade: 'F', pts: 0 },
};

const rows = APP.buildCsvRows([row]);
const header = rows[0];
const data = rows[1];

eq('the hygiene column is appended last', header[header.length - 1], 'Record Hygiene');
eq('the header and data rows are the same length', header.length, data.length);
eq('the data column keeps the published bytes exactly',
  data[7], FIXTURES.bidiOverride);
eq('the raw override character is still in the data column',
  data[7].includes('‮'), true);
eq('no sentinel was written into the data column',
  data[7].includes('‹RLO›'), false);
eq('the hygiene column names what was found',
  data[data.length - 1], 'bidi-override');

const clean = APP.buildCsvRows([Object.assign({}, row, { spfRecord: 'v=spf1 -all' })]);
eq('a clean record has an empty hygiene column',
  clean[1][clean[1].length - 1], '');

// The positional-header rule: a locale that predates the column must not
// misalign, which is why it is appended rather than inserted.
eq('every column before the new one is unchanged',
  header.slice(0, -1).join('|'),
  (win.__I18N_EN__.csv.headers.slice(0, -1)).join('|'));

const csvText = APP.toCsvText(rows);
eq('quotes in a value are doubled, not dropped',
  APP.toCsvText([['a"b']]), '"a""b"');
eq('the CSV has one line per row', csvText.split('\n').length, 2);

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
