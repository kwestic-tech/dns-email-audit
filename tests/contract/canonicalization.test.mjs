#!/usr/bin/env node
/**
 * Proves the canonicalization rules, and proves each one can fail.
 *
 * Framework §1.3: a green check nobody has watched fail is not evidence. The
 * canonicalizer is the instrument the whole release is measured with, so every
 * rule here is asserted twice — once that it preserves what it must, and once
 * that a difference of exactly the kind it exists to catch produces a
 * different canonical form.
 *
 * Rules: tests/fixtures/equivalence/canonicalization.md
 * Implementation: tests/lib/canonical.mjs
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import {
  encode, serialize, canonicalResult, canonicalQueryTrace, orderedSubsequence,
  canonicalCsv, canonicalDom, reportByteRegions, applyExclusions,
} from '../lib/canonical.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, throws, section, report } = createSuite();

const differs = (a, b) => canonicalResult(a) !== canonicalResult(b);

/* ── 1. Determinism ───────────────────────────────────────────────────── */
section('1. Determinism');

const sample = { b: 1, a: { d: [3, 1, 2], c: 'x' } };
eq('the same input twice is byte-identical', canonicalResult(sample), canonicalResult(sample));
eq('key order in the input does not matter',
  canonicalResult({ a: 1, b: 2 }), canonicalResult({ b: 2, a: 1 }));
eq('nested key order does not matter either',
  canonicalResult({ x: { p: 1, q: 2 } }), canonicalResult({ x: { q: 2, p: 1 } }));
eq('output is sorted', Object.keys(encode({ z: 1, a: 2, m: 3 })), ['a', 'm', 'z']);

/* ── 2. Array order is behaviour ──────────────────────────────────────── */
section('2. Array order is preserved');

eq('a reordered array is a different result', differs({ chain: ['a', 'b'] }, { chain: ['b', 'a'] }), true);
eq('a truncated array is a different result', differs({ steps: [1, 2, 3] }, { steps: [1, 2] }), true);
eq('a duplicate is not collapsed', differs({ issues: ['x'] }, { issues: ['x', 'x'] }), true);
eq('order survives encoding', encode(['c', 'a', 'b']), ['c', 'a', 'b']);

/* ── 3. Absent is not undefined ───────────────────────────────────────── */
section('3. Absence and undefined');

const present = { error: undefined };
const absent = {};
eq('present-with-undefined encodes to a tag', encode(present), { error: { $undefined: true } });
eq('absent encodes to nothing', encode(absent), {});
eq('the two are different results', differs(present, absent), true);
// The real pair this rule exists for.
eq('a determinate DNSSEC result and one missing the key differ',
  differs({ state: 'insecure', error: undefined }, { state: 'insecure' }), true);
eq('and undefined is not null', differs({ error: undefined }, { error: null }), true);

/* ── 4. Non-JSON primitives are tagged, never coerced ─────────────────── */
section('4. Non-JSON primitives');

eq('BigInt is tagged', encode(255n), { $bigint: '255' });
eq('a large BigInt keeps every digit',
  encode(340282366920938463463374607431768211455n).$bigint,
  '340282366920938463463374607431768211455');
eq('two different BigInts differ', differs({ v: 1n }, { v: 2n }), true);
eq('NaN is tagged, not nulled', encode(NaN), { $number: 'NaN' });
eq('NaN is not null', differs({ v: NaN }, { v: null }), true);
eq('Infinity is tagged', encode(Infinity), { $number: 'Infinity' });
eq('-Infinity is distinct from Infinity', differs({ v: Infinity }, { v: -Infinity }), true);
eq('-0 is tagged', encode(-0), { $number: '-0' });
eq('-0 is not 0', differs({ v: -0 }, { v: 0 }), true);
eq('an ordinary number is left alone', encode(1.5), 1.5);
eq('no rounding: two close floats differ', differs({ v: 0.1 + 0.2 }, { v: 0.3 }), true);

eq('a Map is tagged rather than emptied', encode(new Map([['a', 1]])), { $map: [['a', 1]] });
eq('an empty Map is not an empty object', differs({ v: new Map() }, { v: {} }), true);
eq('a Set is tagged', encode(new Set([1, 2])), { $set: [1, 2] });
eq('a Date is tagged', encode(new Date(0)), { $date: '1970-01-01T00:00:00.000Z' });
eq('an Error keeps its kind', encode(Object.assign(new Error('m'), { name: 'DnsQueryError', kind: 'servfail' })),
  { $error: { name: 'DnsQueryError', message: 'm', kind: 'servfail' } });
eq('a typed array is tagged', encode(new Uint8Array([1, 2, 3])), { $bytes: '1,2,3' });

/* ── 5. Refusals ──────────────────────────────────────────────────────── */
section('5. Values that must not reach the result surface');

throws('a function is refused, with its path', () => encode({ a: { fn() {} } }),
  e => /a function reached the result surface at \$\.a\.fn/.test(e.message));
throws('a symbol is refused', () => encode({ s: Symbol('x') }),
  e => /a symbol reached the result surface/.test(e.message));
const cyclic = { name: 'x' };
cyclic.self = cyclic;
throws('a cycle is refused, with its path', () => encode(cyclic),
  e => /circular reference at \$\.self/.test(e.message));
// A repeated (but acyclic) reference is not a cycle and must still encode.
const shared = { v: 1 };
eq('a shared reference is not a cycle', encode({ a: shared, b: shared }), { a: { v: 1 }, b: { v: 1 } });

/* ── 6. Nothing empty is dropped ──────────────────────────────────────── */
section('6. Empty values are preserved and distinct');

eq('an empty array survives', encode({ issuers: [] }), { issuers: [] });
eq('an empty array is not absence', differs({ issuers: [] }, {}), true);
eq('an empty string is not null', differs({ note: '' }, { note: null }), true);
eq('false is not absence', differs({ found: false }, {}), true);
eq('0 is not null', differs({ pts: 0 }, { pts: null }), true);
// The real pair. caa.issuers === [] means "this policy authorizes nobody".
eq('a blocking CAA policy and an absent one differ',
  differs({ issuers: [], issuanceBlocked: true }, { issuers: [], issuanceBlocked: false }), true);

/* ── 7. Query trace ───────────────────────────────────────────────────── */
section('7. Query trace');

const call = (name, type, opts = {}) => ({ name, type, ...opts });
const traceA = [call('a.test', 'NS'), call('b.test', 'TXT'), call('a.test', 'NS')];
const traceB = [call('a.test', 'NS'), call('a.test', 'NS'), call('b.test', 'TXT')];

eq('interleaving of independent branches is tolerated',
  JSON.stringify(canonicalQueryTrace(traceA)), JSON.stringify(canonicalQueryTrace(traceB)));
// Whitespace-collapsed: the phrase wraps in the document and an assertion that
// depended on where it wrapped would be about the line width, not the rule.
const rulesText = readFileSync(join(REPO, 'tests/fixtures/equivalence/canonicalization.md'), 'utf8');
const rulesFlat = rulesText.replace(/\s+/g, ' ');
eq('and the tolerance is stated in the rules, not implicit',
  rulesFlat.includes('the relative order of concurrent, independent branches'), true);

// The counts are what the tolerance must not cost.
eq('a lost query is caught',
  JSON.stringify(canonicalQueryTrace(traceA)) ===
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS'), call('b.test', 'TXT')])), false);
eq('an EXTRA query is caught — this is the lost-cache-hit case',
  JSON.stringify(canonicalQueryTrace(traceA)) ===
  JSON.stringify(canonicalQueryTrace([...traceA, call('b.test', 'TXT')])), false);
eq('a different query name is caught',
  JSON.stringify(canonicalQueryTrace(traceA)) ===
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS'), call('c.test', 'TXT'), call('a.test', 'NS')])), false);
eq('a do=1 flag change is caught',
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS')])) ===
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS', { dnssec: true })])), false);
eq('a cd=1 flag change is caught',
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS')])) ===
  JSON.stringify(canonicalQueryTrace([call('a.test', 'NS', { checkingDisabled: true })])), false);
eq('counts are reported', canonicalQueryTrace(traceA).total, 3);
eq('distinct is reported', canonicalQueryTrace(traceA).distinct, 2);
eq('concurrency is carried when observed',
  canonicalQueryTrace(traceA, { maxConcurrency: 16, maxBatchSize: 24 }).maxConcurrency, 16);

// Order IS asserted for the two order-bearing algorithms.
const walk = [call('_dmarc.a.b.com', 'TXT'), call('mx.other', 'A'), call('_dmarc.b.com', 'TXT'), call('_dmarc.com', 'TXT')];
const isWalk = c => c.name.startsWith('_dmarc.');
eq('the tree walk subsequence keeps its order',
  orderedSubsequence(walk, isWalk),
  ['_dmarc.a.b.com TXT', '_dmarc.b.com TXT', '_dmarc.com TXT']);
eq('a reversed walk is a different subsequence',
  JSON.stringify(orderedSubsequence(walk, isWalk)) ===
  JSON.stringify(orderedSubsequence([...walk].reverse(), isWalk)), false);
eq('unrelated concurrent queries do not enter the subsequence',
  orderedSubsequence(walk, isWalk).some(q => q.includes('mx.other')), false);

/* ── 8. CSV is bytes ──────────────────────────────────────────────────── */
section('8. CSV');

const csv = '﻿Domain,Grade\r\n"a.test","A+"\r\n';
eq('the text is returned unchanged', canonicalCsv(csv), csv);
eq('the BOM is not stripped', canonicalCsv(csv).charCodeAt(0), 0xFEFF);
eq('CRLF is not normalized', canonicalCsv(csv).includes('\r\n'), true);
eq('a reordered column is a different file',
  canonicalCsv('Domain,Grade\r\n') === canonicalCsv('Grade,Domain\r\n'), false);
eq('a whitespace change is a different file',
  canonicalCsv('a,b\r\n') === canonicalCsv('a, b\r\n'), false);
throws('a non-string is refused', () => canonicalCsv(['a', 'b']),
  e => /must be compared as text/.test(e.message));

/* ── 9. DOM ───────────────────────────────────────────────────────────── */
section('9. DOM');

const { createDocument } = await import(join(REPO, 'tools/lib/dom-shim.mjs'));
const doc = createDocument();
const build = (text, attrs = {}) => {
  const el = doc.createElement('div');
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.appendChild(doc.createTextNode(text));
  return el;
};

const json = v => JSON.stringify(canonicalDom(v));
eq('attribute order does not matter',
  json(build('x', { a: '1', b: '2' })), json(build('x', { b: '2', a: '1' })));
eq('an attribute VALUE change is caught',
  json(build('x', { a: '1' })) === json(build('x', { a: '2' })), false);
eq('a text change is caught', json(build('x')) === json(build('y')), false);
eq('leading whitespace is NOT trimmed', json(build(' x')) === json(build('x')), false);
eq('a whitespace-only text node is not dropped', json(build('  ')) === json(build('')), false);
eq('the hygiene sentinel survives exactly',
  canonicalDom(build('​ZWSP')).children[0].data, '​ZWSP');
eq('an astral character survives exactly',
  canonicalDom(build('\u{1F600}')).children[0].data, '\u{1F600}');

// Child order is behaviour.
const two = (a, b) => {
  const el = doc.createElement('ul');
  el.appendChild(build(a));
  el.appendChild(build(b));
  return el;
};
eq('child order is caught', json(two('a', 'b')) === json(two('b', 'a')), false);

// The live property this rule exists for.
const box = doc.createElement('input');
box.id = 'optDeepChecks';
box.type = 'checkbox';
box.checked = true;
const canonicalBox = canonicalDom(box);
eq('a checkbox reports its checked state', canonicalBox.properties.checked, true);
eq('and that state is not in the markup', 'checked' in canonicalBox.attributes, false);
box.checked = false;
eq('unchecking is caught', canonicalDom(box).properties.checked, false);

/* ── 10. Report byte regions ──────────────────────────────────────────── */
section('10. Report byte regions');

const html = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:"><style>.a{color:red}</style>';
const regions = reportByteRegions(html);
eq('the policy is extracted byte for byte',
  regions.csp, "default-src 'none'; style-src 'unsafe-inline'; img-src data:");
eq('the stylesheet is extracted byte for byte', regions.stylesheet, '.a{color:red}');
eq('and measured', regions.stylesheetBytes, 13);
eq('a policy change is caught',
  reportByteRegions(html.replace("img-src data:", "img-src *")).csp === regions.csp, false);
eq('a one-byte stylesheet change is caught',
  reportByteRegions(html.replace('color:red', 'color:blue')).stylesheet === regions.stylesheet, false);

/* ── 11. Exclusions ───────────────────────────────────────────────────── */
section('11. Exclusions');

eq('the manifest is empty by default', applyExclusions({ a: 1 }, []), { a: 1 });
throws('a wildcard class is refused',
  () => applyExclusions({ a: 1 }, [{ path: 'a.*.timestamp', reason: 'noisy' }]),
  e => /wildcard exclusion refused/.test(e.message));
throws('an exclusion without a reason is refused',
  () => applyExclusions({ a: 1 }, [{ path: 'a' }]),
  e => /stated reason/.test(e.message));
throws('an empty reason is refused',
  () => applyExclusions({ a: 1 }, [{ path: 'a', reason: '   ' }]),
  e => /stated reason/.test(e.message));
eq('a well-formed exclusion records its reason in place',
  applyExclusions({ a: { b: 1 } }, [{ path: 'a.b', reason: 'stated' }]),
  { a: { b: { $excluded: 'stated' } } });
eq('and the original is not mutated', (() => {
  const original = { a: { b: 1 } };
  applyExclusions(original, [{ path: 'a.b', reason: 'stated' }]);
  return original.a.b;
})(), 1);

/* ── 12. The document and the code agree ──────────────────────────────── */
section('12. Rules document');

eq('the rules document exists',
  existsSync(join(REPO, 'tests/fixtures/equivalence/canonicalization.md')), true);
const text = rulesFlat;
for (const fn of ['encode()', 'canonicalQueryTrace()', 'orderedSubsequence()',
  'canonicalCsv()', 'canonicalDom()', 'reportByteRegions()', 'applyExclusions()']) {
  eq(`it names the function carrying each rule: ${fn}`, text.includes(fn), true);
}
eq('it forbids a timestamp wildcard', text.includes('There is no timestamp wildcard'), true);
eq('it states no wildcard field classes', text.includes('**No wildcard field classes**'), true);
eq('serialization ends in a newline', serialize({ a: 1 }).endsWith('\n'), true);

report();
