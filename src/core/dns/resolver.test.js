#!/usr/bin/env node
/**
 * The usability gate and the normalized layer.
 * Spec Design §3 layers 2 and 3, implementation Task 3.4.
 *
 * The property under test is the boundary: three kinds pass, seven throw, and
 * what comes out of layer 3 carries no kind at all. A protocol module consuming
 * a normalized array must not be able to tell — or need to tell — a `servfail`
 * from a `nodata`, because layer 2 already refused to hand it one.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { createResolver, requireUsable, cleanAnswerData, USABLE_KINDS } from './resolver.js';
import { TRANSPORT_KINDS } from './doh.js';

const { eq, rejects, throws, section, report } = createSuite();

const raw = (kind, answers = [], extra = {}) => ({ kind, answers, ad: false, status: 0, ...extra });
const resolverOver = answersByCall => {
  const calls = [];
  const dohFetch = async (name, type, opts) => {
    calls.push({ name, type, opts });
    return typeof answersByCall === 'function' ? answersByCall(name, type, opts) : answersByCall;
  };
  return { ...createResolver({ dohFetch }), calls };
};

/* ── 1. Three pass, seven throw ───────────────────────────────────────── */
section('1. The usability gate');

eq('three kinds are usable', [...USABLE_KINDS].sort(), ['nodata', 'nxdomain', 'success']);
eq('and the set is frozen', Object.isFrozen(USABLE_KINDS), true);

for (const kind of USABLE_KINDS) {
  const result = raw(kind);
  eq(`${kind} passes through unchanged`, requireUsable(result, 'n', 'A') === result, true);
}

const rejected = TRANSPORT_KINDS.filter(k => !USABLE_KINDS.includes(k));
eq('which leaves seven that do not', rejected.length, 7);
for (const kind of rejected) {
  throws(`${kind} throws rather than passing`,
    () => requireUsable(raw(kind), 'example.test', 'TXT'),
    error => error.kind === kind && /example\.test TXT/.test(error.message));
}

/**
 * `nxdomain` is the one worth stating: it is a REAL ANSWER meaning the name does
 * not exist, not a failure to obtain one. A gate that rejected it would make
 * "no such domain" indistinguishable from "the resolver would not say".
 */
eq('nxdomain is an answer, not a failure', requireUsable(raw('nxdomain'), 'n', 'NS').kind, 'nxdomain');

// An http-error carries its status into the message, which is the only place
// the HTTP layer's detail survives.
throws('an http-error names the status it got',
  () => requireUsable(raw('http-error', [], { httpStatus: 502 }), 'example.test', 'A'),
  error => /HTTP 502/.test(error.message));

/* ── 2. Layer 3 drops the kind ────────────────────────────────────────── */
section('2. Normalized records carry no kind');

const answers = [
  { type: 16, data: '"v=spf1 -all"' },
  { type: 5, data: 'alias.example.test' },
  { type: 16, data: '"part one" "part two"' },
];
const normal = resolverOver(raw('success', answers));

const txt = await normal.dohQuery('example.test', 'TXT');
eq('dohQuery returns an array of strings', Array.isArray(txt) && txt.every(v => typeof v === 'string'), true);
eq('nothing on it carries a kind', txt.some(v => TRANSPORT_KINDS.includes(v)), false);
eq('it filters to the requested type', txt, ['v=spf1 -all', 'part onepart two']);

const all = await normal.dohAll('example.test', 'TXT');
eq('dohAll returns every answer, not only the requested type', all.length, 3);
eq('and cleans a non-TXT answer as its own type',
  all.includes('alias.example.test'), true);

const empty = resolverOver(raw('nodata', []));
eq('a nodata answer normalizes to an empty array', await empty.dohQuery('example.test', 'MX'), []);
const gone = resolverOver(raw('nxdomain', []));
eq('and so does nxdomain — the caller sees records, not existence',
  await gone.dohQuery('example.test', 'MX'), []);

/**
 * The distinction layer 3 hides on purpose. A protocol module cannot tell these
 * two apart, and must not have to: that is why `domainExists()` is a named
 * exception edge rather than something every caller re-derives.
 */
eq('nodata and nxdomain are indistinguishable after normalization',
  JSON.stringify(await empty.dohQuery('example.test', 'MX')) ===
  JSON.stringify(await gone.dohQuery('example.test', 'MX')), true);

for (const kind of rejected) {
  const failing = resolverOver(raw(kind));
  await rejects(`dohQuery propagates the ${kind} throw rather than returning []`,
    () => failing.dohQuery('example.test', 'TXT'),
    error => error.kind === kind);
  await rejects(`and so does dohAll for ${kind}`,
    () => failing.dohAll('example.test', 'TXT'),
    error => error.kind === kind);
}

/* ── 3. Answer cleaning ───────────────────────────────────────────────── */
section('3. cleanAnswerData');

eq('a non-TXT value loses its surrounding quotes', cleanAnswerData('"host.example."', 'CNAME'), 'host.example.');
eq('and is trimmed', cleanAnswerData('  10 mail.example.  ', 'MX'), '10 mail.example.');
eq('a single TXT chunk is unwrapped', cleanAnswerData('"v=spf1 -all"', 'TXT'), 'v=spf1 -all');
eq('several chunks are joined with nothing between them',
  cleanAnswerData('"v=DMARC1; " "p=reject"', 'TXT'), 'v=DMARC1; p=reject');
eq('an escape is decoded', cleanAnswerData('"a\\u0041b"', 'TXT'), 'aAb');
eq('an unquoted TXT value falls back to the raw text', cleanAnswerData('bare', 'TXT'), 'bare');
eq('and an empty one to the empty string', cleanAnswerData('', 'TXT'), '');

/**
 * A confirmed divergence, kept: a malformed escape renders as its literal
 * source text rather than as a decoded character. That is the honest reading of
 * an undecodable chunk, and changing it would change parsed record values.
 */
eq('a malformed escape keeps its source text verbatim',
  cleanAnswerData('"a\\uZZZZb"', 'TXT'), 'a\\uZZZZb');

/* ── 4. checkConnectivity — a named exception edge ────────────────────── */
section('4. The connectivity probe');

/**
 * It reads `.kind` directly, which layer 3 forbids, and that is why spec §3
 * names it an exception edge rather than leaving it to look like an oversight.
 */
for (const [kind, expected] of [['success', true], ['nodata', true], ['nxdomain', false],
  ['servfail', false], ['refused', false], ['dns-error', false], ['http-error', false],
  ['cancelled', false], ['timeout', false], ['network-error', false]]) {
  const probe = resolverOver(raw(kind));
  eq(`${kind} means reachable=${expected}`, await probe.checkConnectivity(), expected);
}

const probed = resolverOver(raw('success', [{ type: 1, data: '93.184.216.34' }]));
await probed.checkConnectivity();
eq('it asks for one fixed name, independent of any audit', probed.calls[0].name, 'example.com');
eq('as an A record', probed.calls[0].type, 'A');
// noCache is why a page-load probe and a per-run probe are two real queries
// rather than one and a cache hit — PRIVACY.md distinguishes them.
eq('it never caches, so each probe is a real query', probed.calls[0].opts.noCache, true);
eq('it does not retry', probed.calls[0].opts.retries, 0);
eq('and it uses a shorter timeout than an audit query', probed.calls[0].opts.timeoutMs, 5000);
eq('exactly one query per probe', probed.calls.length, 1);

report();
