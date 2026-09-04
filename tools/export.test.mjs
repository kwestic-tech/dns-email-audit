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
  loadUi, elements, attributes, textOf,
} from './lib/browser-harness.mjs';
import { LOCALE_EN } from '../src/data/locales-en.js';
import { createReport } from '../src/ui/report.js';
import { validDkimSelector } from '../src/core/dkim/dkim.js';

// Task 6.2: a direct ESM path, replacing `window.__APP_TEST__`. See
// `loadUi()`'s own note — the adapter existed for this suite and
// `render.test.mjs`, and both import the runtime now.
const { win, R, document, t, i18n, ui: APP } = await loadUi();

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
// The English bundle, imported rather than read off a global — the same
// table `loadUi()` hands the runtime.
const bundle = LOCALE_EN;
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
  findings: [
    { id: 'spf.multiple-records', key: 'spf-multiple-records', keyspace: 'issue', protocol: 'spf', severity: 'critical', confidence: 'confirmed', category: 'authentication', effort: 'trivial', args: [2], evidence: [], dependsOn: [], blocks: [] },
    { id: 'dmarc.missing', key: 'dmarc-missing', keyspace: 'issue', protocol: 'dmarc', severity: 'medium', confidence: 'confirmed', category: 'policy', effort: 'moderate', args: [], evidence: [], dependsOn: [], blocks: [] },
  ],
  remediationPlan: [{ step: 1, findings: ['spf.multiple-records', 'dmarc.missing'], rationale: 'foundation', unblocks: [] }],
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

// 0.3.0 appended three Tree Walk columns after this one, which is the rule
// working as intended: a column's index is fixed for the life of the file, so
// later releases add to the right rather than renumbering what is already
// there. Locate it by name, never by "last".
const hygieneIdx = header.indexOf('Record Hygiene');
eq('the hygiene column is still present', hygieneIdx !== -1, true);
eq('the header and data rows are the same length', header.length, data.length);
// Anchored by index rather than by "last", so the next release appending a
// column moves nothing here. Pinning the tail is what made this assertion fire
// on 0.4.0's eight new columns — which is the rule working, not breaking.
eq('the Tree Walk columns follow the hygiene column',
  header.slice(hygieneIdx, hygieneIdx + 4),
  ['Record Hygiene', 'DMARC Found At', 'DMARC Labels Up', 'DMARC Discovery Terminated']);
// 0.4.0's protocol-depth columns go after those, in their own fixed block.
eq('the protocol-depth columns are appended after the Tree Walk columns',
  header.slice(hygieneIdx + 4, hygieneIdx + 12),
  ['DKIM Key Type', 'DKIM Key Bits', 'DKIM Revoked Selectors', 'CAA Issuers',
    'CAA Wildcard Issuers', 'MX Dangling', 'MX Host Count', 'TLSA Present']);
// The whole point of the positional rule: every column that existed before
// 0.4.0 is still at the index it was at. Checked against English rather than
// against a count, so an inserted column fails loudly here.
eq('no pre-0.4.0 column moved', header.indexOf('Record Hygiene'), hygieneIdx);
// 0.7.0's three structured-finding columns follow the protocol-depth block, in
// their own fixed tail — appended after TLSA Present, never inserted.
eq('the structured-finding columns stay in their original block',
  header.slice(hygieneIdx + 12, hygieneIdx + 15),
  ['Finding IDs', 'Finding Severities', 'Remediation Step 1']);
eq('the three local-artifact columns are appended after every DNS column', header.slice(-3),
  ['Artifact Finding IDs', 'Artifact Severities', 'Artifact Evidence (User Supplied)']);
// The columns carry stable id and severity tokens, not translated prose, and
// the remediation column names what to fix first.
eq('the Finding IDs column joins finding ids',
  data[header.indexOf('Finding IDs')], 'spf.multiple-records | dmarc.missing');
eq('the Finding Severities column joins severity tokens',
  data[header.indexOf('Finding Severities')], 'critical | medium');
eq('the Remediation Step 1 column names the first step\'s findings',
  data[header.indexOf('Remediation Step 1')], 'spf.multiple-records | dmarc.missing');
eq('a row with no local analysis leaves all artifact columns empty', data.slice(-3), ['', '', '']);

APP.getArtifactSessions()['artifact.example'] = {
  domain: 'artifact.example',
  artifactFindings: [{
    id: 'bimi.svg-rejected', key: 'bimi-svg-rejected', keyspace: 'finding',
    severity: 'high', confidence: 'confirmed', category: 'issuance',
    source: 'user-supplied', artifact: 'bimi-svg', args: ['external-reference'],
    evidence: [{ kind: 'element', location: '<use>', value: '<use href="https://evil.example/logo.svg">' }],
  }],
};
const artifactCsvRow = APP.buildCsvRows([Object.assign({}, row, { domain: 'artifact.example' })])[1];
eq('artifact ids stay out of the DNS Finding IDs column',
  artifactCsvRow[header.indexOf('Finding IDs')], 'spf.multiple-records | dmarc.missing');
eq('the artifact id has its own column',
  artifactCsvRow[header.indexOf('Artifact Finding IDs')], 'bimi.svg-rejected');
eq('the artifact severity has its own column',
  artifactCsvRow[header.indexOf('Artifact Severities')], 'high');
const artifactEvidenceCell = artifactCsvRow[header.indexOf('Artifact Evidence (User Supplied)')];
eq('artifact evidence preserves user-supplied provenance',
  artifactEvidenceCell.includes('user-supplied'), true);
eq('artifact evidence preserves its kind and location',
  artifactEvidenceCell.includes('element :: <use>'), true);
eq('artifact evidence preserves the supplied value',
  artifactEvidenceCell.includes('https://evil.example/logo.svg'), true);
const artifactReport = APP.buildArtifactReportContent();
eq('the static artifact section is present when this session has analysis', !!artifactReport, true);
eq('the static artifact section names the domain and provenance',
  textOf(artifactReport).includes('artifact.example') && textOf(artifactReport).includes(t('artifact.userSupplied')), true);
eq('the static artifact section carries the evidence as text',
  textOf(artifactReport).includes('<use href="https://evil.example/logo.svg">'), true);
eq('the supplied use element never becomes a use node in the report',
  elements(artifactReport).some(el => el.localName === 'use'), false);
eq('the static artifact section contains no interactive control',
  elements(artifactReport).some(el => el.localName === 'button' || el.localName === 'input' || el.localName === 'textarea'), false);
eq('the first data column is still the domain', header[0], 'Domain');
eq('the data column keeps the published bytes exactly',
  data[7], FIXTURES.bidiOverride);
eq('the raw override character is still in the data column',
  data[7].includes('‮'), true);
eq('no sentinel was written into the data column',
  data[7].includes('‹RLO›'), false);
eq('the hygiene column names what was found',
  data[hygieneIdx], 'bidi-override');
// A row with no discovery object leaves the appended columns empty rather
// than shifting anything.
eq('a row without a Tree Walk leaves those columns empty',
  data.slice(hygieneIdx + 1, hygieneIdx + 4), ['', '', '']);
// `advanced` is null on this fixture, so the deep-check columns must say
// "Unknown" rather than "No". A domain whose MX hosts were never resolved has
// no dangling hosts *reported*, which is not the same as having none.
eq('unchecked protocol-depth columns say unknown, never no',
  data.slice(hygieneIdx + 4, hygieneIdx + 12),
  ['', '', '', '', '', 'Unknown', 'Unknown', 'Unknown']);

/* ── The SPF Record column carries the whole conflicting set ─────────── */
// A count in `Issues` says how many records conflict; the records are the
// evidence. Exporting only the first reproduced outside the UI the same
// misleading presentation the detail panel was fixed for.
const spfIdx = header.indexOf('SPF Record');
eq('the SPF Record column is still present', spfIdx !== -1, true);

const SPF_ONE = 'v=spf1 include:_spf.google.com ~all';
const SPF_TWO = 'v=spf1 include:mktomail.com ~all';
const spfRow = extra => APP.buildCsvRows([Object.assign({}, row, { spfRecord: SPF_ONE }, extra)])[1];

// Single record: byte-for-byte identical whether or not the new field exists,
// which is every domain that is not in permerror.
eq('a single record is unchanged by the new field',
  spfRow({ spfRecords: [SPF_ONE] })[spfIdx], spfRow({})[spfIdx]);
eq('and is exactly the record itself', spfRow({ spfRecords: [SPF_ONE] })[spfIdx], SPF_ONE);
eq('a result predating spfRecords still exports', spfRow({})[spfIdx], SPF_ONE);
eq('no SPF at all is still an empty cell',
  APP.buildCsvRows([Object.assign({}, row, { spfRecord: '', spfRecords: [] })])[1][spfIdx], '');
// The whole serialized line is identical too, not just the one cell.
eq('the serialized row is byte-for-byte unchanged',
  APP.toCsvText([spfRow({ spfRecords: [SPF_ONE] })]), APP.toCsvText([spfRow({})]));

// Multiple records: joined with newlines, in resolver order.
eq('both records reach the cell', spfRow({ spfRecords: [SPF_ONE, SPF_TWO] })[spfIdx],
  SPF_ONE + '\n' + SPF_TWO);
eq('resolver order is preserved, not sorted',
  spfRow({ spfRecords: [SPF_TWO, SPF_ONE] })[spfIdx], SPF_TWO + '\n' + SPF_ONE);
eq('three records join too',
  spfRow({ spfRecords: [SPF_ONE, SPF_TWO, 'v=spf1 -all'] })[spfIdx],
  SPF_ONE + '\n' + SPF_TWO + '\n' + 'v=spf1 -all');
// Only the column moved; the row is still aligned with the header.
eq('the joined row is still the header length',
  spfRow({ spfRecords: [SPF_ONE, SPF_TWO] }).length, header.length);

// A newline inside a field is RFC 4180 §2.6 only while the field is quoted.
const joinedCsv = APP.toCsvText([spfRow({ spfRecords: [SPF_ONE, SPF_TWO] })]);
eq('the joined cell is quoted, so its newline stays inside the field',
  joinedCsv.includes('"' + SPF_ONE + '\n' + SPF_TWO + '"'), true);

// CSV-special characters inside a record must survive the join and the quoting.
// DNS TXT can carry commas and quotes, and a record is published by the domain.
const SPF_COMMA = 'v=spf1 include:a.example,b.example ~all';
const SPF_QUOTE = 'v=spf1 include:say"hi".example ~all';
const SPF_CRLF  = 'v=spf1 include:a.example\r\nb ~all';
const special = spfRow({ spfRecords: [SPF_COMMA, SPF_QUOTE, SPF_CRLF] });
eq('a comma inside a record does not split the cell',
  special[spfIdx], SPF_COMMA + '\n' + SPF_QUOTE + '\n' + SPF_CRLF);
const specialCsv = APP.toCsvText([special]);
eq('embedded quotes are doubled, not dropped',
  specialCsv.includes('say""hi"".example'), true);
eq('the raw single quote never survives undoubled',
  specialCsv.includes('say"hi".example'), false);
// Round-trip through a minimal RFC 4180 reader: the cell must come back
// identical, commas, quotes, newlines and all.
const parseCsv = text => {
  const rows = [[]]; let cell = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') inQ = false;
      else cell += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { rows[rows.length - 1].push(cell); cell = ''; }
    else if (c === '\n') { rows[rows.length - 1].push(cell); cell = ''; rows.push([]); }
    else cell += c;
  }
  rows[rows.length - 1].push(cell);
  return rows;
};
eq('the cell round-trips through an RFC 4180 reader',
  parseCsv(specialCsv)[0][spfIdx], SPF_COMMA + '\n' + SPF_QUOTE + '\n' + SPF_CRLF);
eq('and the round-tripped row still has every column',
  parseCsv(specialCsv)[0].length, header.length);
eq('a two-record cell round-trips as one field, not two rows',
  parseCsv(joinedCsv).length, 1);

// Record hygiene must cover every record the export now carries. A marker in
// the SECOND conflicting record reached the raw cell with nothing in the
// Record Hygiene column naming it, because only the first was scanned.
const hygieneIdx2 = header.indexOf('Record Hygiene');
const secondDirty = APP.buildCsvRows([Object.assign({}, row, {
  spfRecord: SPF_ONE,
  spfRecords: [SPF_ONE, FIXTURES.bidiOverride],
})])[1];
eq('a marker in a non-first SPF record is still exported raw',
  secondDirty[spfIdx].includes('‮'), true);
eq('and the hygiene column names it',
  secondDirty[hygieneIdx2].includes('bidi-override'), true);
// A clean first record must not mask a dirty later one, and vice versa.
eq('a marker in the first record is still caught',
  APP.buildCsvRows([Object.assign({}, row, {
    spfRecord: FIXTURES.bidiOverride, spfRecords: [FIXTURES.bidiOverride, SPF_ONE],
  })])[1][hygieneIdx2].includes('bidi-override'), true);
eq('two clean conflicting records report no hygiene marker',
  APP.buildCsvRows([Object.assign({}, row, {
    spfRecord: SPF_ONE, spfRecords: [SPF_ONE, SPF_TWO],
  })])[1][hygieneIdx2], '');
// The fallback for a result that predates spfRecords still scans spfRecord.
eq('a result without spfRecords still has its record scanned',
  APP.buildCsvRows([Object.assign({}, row, { spfRecord: FIXTURES.bidiOverride })])[1][hygieneIdx2]
    .includes('bidi-override'), true);

const clean = APP.buildCsvRows([Object.assign({}, row, { spfRecord: 'v=spf1 -all' })]);
eq('a clean record has an empty hygiene column',
  clean[1][hygieneIdx], '');

// Tree Walk provenance is exported as TOKENS, not translated prose, so a
// script consuming the file does not have to parse a sentence in whichever
// language the export happened to be made in.
const walked = APP.buildCsvRows([Object.assign({}, row, {
  spfRecord: 'v=spf1 -all',
  dmarcDiscovery: {
    applied: { record: 'v=DMARC1; p=reject', foundAt: 'example.com', labelsUp: 2, inherited: true },
    terminated: 'root', queries: 4, steps: [], observed: [],
  },
})])[1];
eq('the found-at column carries the name', walked[hygieneIdx + 1], 'example.com');
eq('the labels-up column carries the count', walked[hygieneIdx + 2], 2);
eq('the terminated column carries the token', walked[hygieneIdx + 3], 'root');

// The positional-header rule: a locale that predates the column must not
// misalign, which is why it is appended rather than inserted.
eq('every column before the new ones is unchanged',
  header.slice(0, hygieneIdx).join('|'),
  (LOCALE_EN.csv.headers.slice(0, hygieneIdx)).join('|'));

const csvText = APP.toCsvText(rows);
eq('quotes in a value are doubled, not dropped',
  APP.toCsvText([['a"b']]), '"a""b"');
eq('the CSV has one line per row', csvText.split('\n').length, 2);

/* ── 8. Codex review 1 — CSV formula injection ───────────────────────── */
section('8. Formula-leading cells are neutralized in the CSV');

// RFC 4180 quoting does not stop this: the quotes are stripped before the cell
// is evaluated, so a domain that publishes `=cmd|...` gets a live formula in
// anyone's spreadsheet. The .csv extension and the "Export CSV" button invite
// exactly that, so spreadsheet safety wins over byte fidelity here.
const cellOf = (value) => {
  const line = APP.toCsvText([[value]]);
  return line.slice(1, -1).replace(/""/g, '"');
};

const FORMULA_LEADS = {
  'equals': '=1+1',
  'plus': '+1+1',
  'minus': '-1+1',
  'at': '@SUM(A1)',
  'tab': '\t=1+1',
  'carriage return': '\r=1+1',
  'line feed': '\n=1+1',
  'leading space then equals': '   =1+1',
  'leading quote then equals': '"=1+1',
  'full-width equals': '＝1+1',
  'full-width plus': '＋1',
  'full-width at': '＠1',
  'the DDE payload': '=cmd|\' /C calc\'!A0',
};
for (const [name, value] of Object.entries(FORMULA_LEADS)) {
  const cell = cellOf(value);
  eq(`${name}: is neutralized`, cell.charAt(0), "'");
  eq(`${name}: the original value is still readable`, cell.slice(1), value);
  // Assert the property directly. An earlier form of this checked
  // `R.isFormulaLeading(...) && !cell.startsWith("'")`, which is necessarily
  // false once the prefix is applied and so passed no matter what the code did.
  eq(`${name}: the serialized cell does not open with a formula character`,
    /^[=+\-@\t\r\n\uFF1D\uFF0B\uFF0D\uFF20]/.test(cell), false);
}

// Ordinary cells — including ones with embedded formula characters — must be
// byte-identical. Over-neutralizing would corrupt every SPF record.
const UNTOUCHED = [
  'v=spf1 include:_spf.example.com -all',
  'v=DMARC1; p=reject; rua=mailto:a@b.example',
  'example.com', 'A++', '0', '10 mx.example.com',
  '0 issue "ca.example"', 'a=b', 'x+y', 'name@example.com',
  'Yes', 'No', '—', 'Ärger', '日本語のテキスト',
];
for (const value of UNTOUCHED) {
  eq(`unchanged: ${JSON.stringify(value)}`, cellOf(value), value);
}

// RFC 4180 transport still works after neutralization.
eq('a quote is still doubled', APP.toCsvText([['a"b']]), '"a""b"');
eq('a comma still round-trips', cellOf('a,b'), 'a,b');
eq('an embedded newline still round-trips', cellOf('a\nb'), 'a\nb');
eq('a neutralized cell is still quoted',
  APP.toCsvText([['=1']]).charAt(0), '"');

// Column alignment must survive the new column and the neutralization.
const formulaRow = {
  domain: 'evil.example', ns: [], mx: [], verifications: [],
  spfRecord: '=cmd|\' /C calc\'!A0', dmarcRecord: '',
  issues: [], suggestions: [],
  spfStatus: { status: 'permerror' },
  dmarcStatus: { status: 'missing', policy: '', pct: 100, adkim: 'r', aspf: 'r', rua: false, ruf: false, testMode: false, sp: '', np: '' },
  dkimStatus: { found: false, confidence: 'checked', selectors: [], missingSelectors: [] },
  dnsProvider: 'Cloudflare', emailProvider: '@none', advanced: null,
  score: { grade: 'F', pts: 0 },
};
const fRows = APP.buildCsvRows([formulaRow]);
const fText = APP.toCsvText(fRows);
const fLines = fText.split('\n');
eq('header and data column counts match',
  fLines[0].split('","').length, fLines[1].split('","').length);
eq('the row array still holds the published bytes',
  fRows[1][7], '=cmd|\' /C calc\'!A0');
eq('the serialized cell is neutralized',
  fLines[1].split('","')[7].charAt(0), "'");
eq('the hygiene column reports it',
  fRows[1][hygieneIdx].includes('formula-leading'), true);
eq('a clean row reports no formula hygiene',
  APP.buildCsvRows([Object.assign({}, formulaRow, { spfRecord: 'v=spf1 -all' })])[1][hygieneIdx],
  '');

/* ── 9. Codex review 1 — issue messages in the exported report ───────── */
section('9. Sentinelled issue messages survive into the HTML report');

const issueRow = {
  domain: 'evil.example', ns: [], mx: ['mx.example'], verifications: [],
  spfRecord: 'v=spf1 -all', dmarcRecord: 'v=DMARC1; p=none',
  issues: [{ key: 'dmarc-rua-invalid', sev: 'warn', args: ['mailto:x@safe.‮evil​z'] }],
  // The detail panel renders findings; the migrated finding resolves the same
  // issue.<key> message through the same DNS-argument boundary.
  findings: [{
    id: 'dmarc.rua-invalid', key: 'dmarc-rua-invalid', keyspace: 'issue',
    protocol: 'dmarc', severity: 'medium', confidence: 'confirmed',
    category: 'reporting', effort: 'trivial', args: ['mailto:x@safe.‮evil​z'],
    evidence: [], dependsOn: [], blocks: [],
  }],
  remediationPlan: [],
  suggestions: [],
  spfStatus: { status: 'permerror', cls: 'crit' },
  dmarcStatus: { status: 'missing', cls: 'crit', policy: '', pct: 100, adkim: 'r', aspf: 'r', rua: false, ruf: false, testMode: false, sp: '', np: '' },
  dkimStatus: { found: false, confidence: 'checked', selectors: [], missingSelectors: [] },
  dnsProvider: 'Cloudflare', emailProvider: '@none', hosting: '@unknown',
  advScore: 0, advanced: null,
  score: { grade: 'F', pts: 0, max: 100, cls: 'score-f', breakdown: null, unproven: [] },
};
const tbody = document.createElement('tbody');
tbody.id = 'tableBody';
document.body.appendChild(tbody);
APP.appendRow(issueRow);

const issueContent = document.createDocumentFragment();
Array.from(document.getElementById('tableBody').childNodes).forEach(n => issueContent.appendChild(n));
const issueReport = APP.buildReportDocument({
  lang: 'en', css: '', title: 'T', generated: 'g', note: 'n', content: issueContent,
});
assertInert('a report carrying a hostile issue message', issueReport);
eq('the exported report carries no raw override', issueReport.includes('‮'), false);
eq('the exported report carries no raw zero-width', issueReport.includes('​'), false);
eq('the exported report shows the sentinel', issueReport.includes('‹RLO›'), true);

/* ── 10. Codex review 1 — astral characters through the export ───────── */
section('10. An astral character at the display cap survives export');

const astral = 'A'.repeat(R.MAX_VALUE_CHARS - 1) + '\u{1F600}' + 'Z';
const astralReport = APP.buildReportDocument({
  lang: 'en', css: '', title: 'T', generated: 'g', note: 'n',
  content: (() => {
    const f = document.createDocumentFragment();
    f.appendChild(R.el('div', null, R.value(astral)));
    return f;
  })(),
});
eq('the emoji survives serialization', astralReport.includes('\u{1F600}'), true);
eq('no replacement character was introduced', astralReport.includes('�'), false);
assertInert('a report containing an astral boundary value', astralReport);

/* ── The JSON export (report-comparison 1.9 §3) ──────────────────────── */
section('The JSON export');

/**
 * Two harnesses, and a limit worth stating.
 *
 * The composed UI below proves that three capabilities ARRIVE -- `versions`
 * and `resolver` from the composition root, `validSelector` from
 * `src/core/dkim/`. It proves nothing about the fourth: no audit has run here,
 * so `getRunContext()` is `null` and `generatedAt` is empty. An earlier version
 * of this comment claimed otherwise, and the timestamp path was consequently
 * untested -- stubbing `nowIso()` left this suite green.
 *
 * **The production timestamp path is covered in `tools/audit-run.test.mjs` §4**,
 * which drives a completed run through the click path with a pinned clock. That
 * is where it belongs: `runContext` is run-loop state.
 *
 * The captured-download harness then drives the bytes with a supplied run
 * context, because `dl()` is the only part that needs a document. It formats;
 * it does not establish where the instant came from.
 */
const composed = (await loadUi()).ui.buildReportJson();
eq('the composed UI produces a schema-identified report',
  [composed.schema, composed.schemaVersion], ['dns-email-audit/report', 1]);
eq('the resolver reached the export from its owner',
  composed.resolver, 'https://cloudflare-dns.com/dns-query');
eq('and so did a real release version, not a placeholder',
  /^\d+\.\d+\.\d+$/.test(composed.generator.version), true);
eq('and a positive analysis version',
  Number.isInteger(composed.generator.analysisVersion) && composed.generator.analysisVersion > 0, true);
// The capability that has already been undefined once in this release: if it
// were missing, `projectReport` would throw rather than reach this line.
eq('the selector capability was composed, or this would have thrown',
  Array.isArray(composed.options.selectors), true);
// Stated rather than left to be inferred: with no run, there is no stamp.
eq('and with no run there is no timestamp to prove here',
  composed.generatedAt, '');

const RUN_AT = '2026-09-03T12:34:56.789Z';
const captured = [];
function reportWithRun(runAt, results, sessions) {
  const anchors = [];
  const fakePlatform = {
    Blob: function (parts) { this.parts = parts; },
    URL: { createObjectURL(blob) { captured.push(blob); return 'blob:' + captured.length; },
      revokeObjectURL() {} },
    setTimeout() {}, fetch() { return Promise.reject(new Error('no network')); },
    formatDateTime() { return ''; },
  };
  // `dl()` sets `download` and `href` on the anchor before clicking, so the
  // name and the body are both observable without a real DOM.
  const fakeDocument = { createElement() {
    const a = {
      set download(v) { a._name = v; }, get download() { return a._name; },
      set href(v) { a._href = v; }, get href() { return a._href; },
      click() { anchors.push({ name: a._name, blob: captured[captured.length - 1] }); },
    };
    return a;
  } };
  const api = createReport({
    document: fakeDocument, platform: fakePlatform, i18n, renderer: R,
    englishBundle: LOCALE_EN,
    label: x => String(x), issueMessage: () => '', spfRecordCell: () => '',
    dkimKeyBitsCell: () => '', rowHygieneValues: () => [],
    showToast() {}, $: () => null,
    getResults: () => results,
    getArtifactSessions: () => sessions || {},
    buildArtifactReportContent: () => null,
    versions: { app: '0.9.0', analysis: 1 },
    resolver: 'https://cloudflare-dns.com/dns-query',
    validSelector: validDkimSelector,
    getRunContext: () => ({
      options: { dkim: true, dkimComprehensive: false, www: true, wildcard: true,
        advanced: true, deepChecks: true, selectors: ['selector1'] },
      generatedAt: runAt,
    }),
  });
  api.exportJSON();
  const last = anchors[anchors.length - 1];
  return { api, name: last.name, text: last.blob.parts[0] };
}

const jsonRun = reportWithRun(RUN_AT, [row]);

// The filename is DERIVED, proven by changing the input rather than by
// restating the expected string.
eq('the download name carries the run date', jsonRun.name, 'dns-email-audit-2026-09-03.json');
eq('and it moves with the run, not with a second clock read',
  reportWithRun('2024-01-02T00:00:00.000Z', [row]).name, 'dns-email-audit-2024-01-02.json');

const jsonBody = JSON.parse(jsonRun.text);
eq('the downloaded bytes are the report', jsonBody.generatedAt, RUN_AT);
eq('the audited domain is present', jsonBody.domains.map(d => d.domain), ['evil.example']);

// Acceptance criterion 4 reduces to this: `generatedAt` comes from the RUN, so
// two exports of one audit cannot differ however far apart they are taken.
eq('two exports of one run are byte-identical',
  reportWithRun(RUN_AT, [row]).text, jsonRun.text);

/**
 * The provenance boundary 0.8.0 established, asserted in BOTH directions.
 *
 * The CSV carries artifact findings in three dedicated columns; the JSON must
 * carry none (RQ-CMP-07). Asserting only the absence would pass on a fixture
 * that never had one, so the same session is shown reaching the CSV.
 */
const artifactSession = {
  'evil.example': { artifactFindings: [{
    id: 'artifact.mta-sts.mode-testing', severity: 'medium', source: 'user-supplied',
    artifact: 'mta-sts', evidence: [{ kind: 'policy', location: 'mode', value: 'testing' }],
  }] },
};
const withArtifacts = reportWithRun(RUN_AT, [row], artifactSession);
eq('no user-supplied provenance reaches the JSON export',
  withArtifacts.text.includes('user-supplied'), false);
eq('and no artifact finding id does either',
  withArtifacts.text.includes('artifact.mta-sts.mode-testing'), false);
eq('while the same session does reach the CSV, which is the boundary', (() => {
  const csvRow = withArtifacts.api.buildCsvRows([row])[1];
  return csvRow.some(cell => String(cell).includes('artifact.mta-sts.mode-testing'));
})(), true);

// The vendor tokens section 1 excludes. The fixture row carries `verifications`,
// so this is an assertion about the projection rather than about the input.
eq('the fixture really does carry a vendor token', (() => {
  const withToken = Object.assign({}, row, { verifications: ['google-site-verification=SECRET'] });
  return withToken.verifications.length;
})(), 1);
eq('and it does not reach the exported JSON',
  reportWithRun(RUN_AT, [Object.assign({}, row,
    { verifications: ['google-site-verification=SECRET'] })]).text.includes('SECRET'), false);

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
