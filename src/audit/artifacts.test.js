#!/usr/bin/env node
/**
 * The user-supplied artifact composer.
 *
 *   node src/audit/artifacts.test.js
 *
 * This is where the two protocol validators meet, and the whole point of the
 * file is the three boundaries it must not cross: artifact findings stay out
 * of the DNS findings array, nothing fetches, nothing scores. Those are
 * asserted structurally here rather than left to review.
 *
 * The `deliveryCandidates()` half is the release's headline check finally
 * connected to real audit data. Every one of its four cases is exercised from
 * the shape the audit actually holds — raw MX presentation strings, not the
 * deep-check audit objects that caused the `[object Object]` round.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import {
  analyzeArtifacts, deliveryCandidates, mtaStsPolicyFindings, bimiSvgFindings,
  artifactEvidence, ARTIFACT_KINDS, ARTIFACT_SOURCES, ARTIFACT_EVIDENCE_KINDS,
  ARTIFACT_FINDING_IDS, MAX_EVIDENCE_CHARS,
} from './artifacts.js';
import { SEVERITIES, CONFIDENCES, CATEGORIES, EFFORTS, EVIDENCE_KINDS } from './findings.js';

const { eq, section, report } = createSuite();

/* ── 1. The published vocabularies ────────────────────────────────────── */
section('1. State constants');

eq('the artifact kinds are frozen, and VMC is not one',
  [Object.isFrozen(ARTIFACT_KINDS), [...ARTIFACT_KINDS]],
  [true, ['mta-sts-policy', 'bimi-svg']]);
eq('provenance is a closed vocabulary, not a boolean',
  [Object.isFrozen(ARTIFACT_SOURCES), [...ARTIFACT_SOURCES]], [true, ['user-supplied']]);
eq('and artifact evidence kinds are frozen',
  [Object.isFrozen(ARTIFACT_EVIDENCE_KINDS), [...ARTIFACT_EVIDENCE_KINDS]],
  [true, ['line', 'element', 'input']]);

/* The finding identity itself is a closed algebra, like every other published
 * vocabulary here. `audit.finding.id` stays the DNS contract; this is its
 * artifact counterpart, and the catalog is pinned against it so a thirteenth
 * id cannot appear without the registry moving too. */
eq('the artifact finding ids are frozen', Object.isFrozen(ARTIFACT_FINDING_IDS), true);
eq('and every id the composer can emit is a registered member',
  [...new Set([
    ...mtaStsPolicyFindings('nonsense', { hosts: [], unknown: true }).findings,
    ...mtaStsPolicyFindings('version: STSv1\nmode: none\nmax_age: 1', { hosts: ['a.example.com'] }).findings,
    ...mtaStsPolicyFindings('version: STSv1\nmode: testing\nmax_age: 1\nmx: x.example.com',
      { hosts: ['a.example.com'] }).findings,
    ...mtaStsPolicyFindings('version: STSv1\nmode: enforce\nmax_age: 1\nmx: a.example.com',
      { hosts: [], nullMx: true }).findings,
  ].map(f => f.id))].filter(id => !ARTIFACT_FINDING_IDS.includes(id)), []);

/**
 * The boundary that matters most. If these two vocabularies ever overlap, an
 * artifact evidence entry could be rendered by the DNS evidence path, which
 * presents its location as a queried name.
 */
eq('artifact evidence kinds share NOTHING with the DNS evidence algebra',
  ARTIFACT_EVIDENCE_KINDS.filter(k => EVIDENCE_KINDS.includes(k)), []);

eq('an unregistered kind is coerced rather than thrown on',
  artifactEvidence('queryName', 'x', 'y').kind, 'input');
eq('and supplied material is bounded at the source',
  artifactEvidence('input', 'x'.repeat(500), 'y'.repeat(500)).value.length,
  MAX_EVIDENCE_CHARS);

/* ── 2. Delivery candidates: the four cases, from real audit shapes ───── */
section('2. deliveryCandidates');

eq('explicit MX records become their parsed exchange hostnames',
  deliveryCandidates({ mx: ['10 mail.example.com.', '20 backup.example.com'], domain: 'example.com' }),
  { hosts: ['mail.example.com', 'backup.example.com'], unknown: false });
eq('duplicate exchanges at different preferences are one candidate',
  deliveryCandidates({ mx: ['10 mail.example.com', '20 mail.example.com'], domain: 'example.com' }).hosts,
  ['mail.example.com']);

// RFC 7505. A domain that accepts no mail has no delivery candidate, and that
// is a different answer from "we could not find out".
eq('a null MX is its own state',
  deliveryCandidates({ mx: ['0 .'], domain: 'example.com' }),
  { hosts: [], nullMx: true });

// RFC 5321 §5.1. No MX plus a usable address record means one candidate: the
// domain itself. A policy naming it is correct, not stale.
eq('no MX with an address record is the implicit MX',
  deliveryCandidates({ mx: [], addresses: ['192.0.2.1'], domain: 'Example.com' }),
  { hosts: ['example.com'], unknown: false, implicit: true });
eq('no MX and no address record establishes nothing',
  deliveryCandidates({ mx: [], addresses: [], domain: 'example.com' }),
  { hosts: [], unknown: true });
eq('a failed lookup is unknown even with records in hand',
  deliveryCandidates({ mx: ['10 mail.example.com'], domain: 'example.com', unknown: true }),
  { hosts: [], unknown: true });

// Fail closed: half an MX set read is worse than none, because it would be
// compared with confidence.
eq('ONE unparseable record fails the whole set',
  deliveryCandidates({ mx: ['10 mail.example.com', 'garbage'], domain: 'example.com' }),
  { hosts: [], unknown: true });
eq('and an absent input is unknown, not empty',
  deliveryCandidates(), { hosts: [], unknown: true });

/* ── 3. MTA-STS policy composition ────────────────────────────────────── */
section('3. mtaStsPolicyFindings');

const HOSTS = { hosts: ['mail.example.com'], unknown: false };
const ENFORCE = 'version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com';
const ids = r => r.findings.map(f => f.id).sort();

eq('a conforming policy that matches DNS produces nothing',
  ids(mtaStsPolicyFindings(ENFORCE, HOSTS)), []);

eq('an MX host no pattern covers is a mismatch',
  ids(mtaStsPolicyFindings(
    'version: STSv1\nmode: enforce\nmax_age: 604800\nmx: other.example.com', HOSTS)),
  ['mta-sts.policy-mx-mismatch', 'mta-sts.policy-mx-unused']);

eq('an unestablished MX fact says so rather than claiming a stale policy',
  ids(mtaStsPolicyFindings(ENFORCE, { hosts: [], unknown: true })),
  ['mta-sts.policy-mx-unknown']);
eq('and a null-MX domain gets its own finding',
  ids(mtaStsPolicyFindings(ENFORCE, { hosts: [], nullMx: true })),
  ['mta-sts.policy-on-null-mx']);

section('3a. The scope matrix decides what may be said');

/* RFC 8461 §8.3's removal procedure is "mode: none with a small max_age". The
 * scope must suppress max-age-short there, or the tool advises an operator to
 * break the protocol's own opt-out. */
const WITHDRAWAL = 'version: STSv1\nmode: none\nmax_age: 3600';
eq('a withdrawal policy yields its mode finding and nothing else',
  ids(mtaStsPolicyFindings(WITHDRAWAL, HOSTS)), ['mta-sts.mode-none']);
eq('specifically, no max-age-short on the RFC 8.3 document',
  mtaStsPolicyFindings(WITHDRAWAL, HOSTS).findings
    .some(f => f.id === 'mta-sts.max-age-short'), false);
eq('and no MX comparison, though the DNS fact was available',
  mtaStsPolicyFindings(WITHDRAWAL, HOSTS).findings
    .some(f => f.id.startsWith('mta-sts.policy-mx')), false);

eq('the same short max_age under enforce IS reported',
  ids(mtaStsPolicyFindings(
    'version: STSv1\nmode: enforce\nmax_age: 3600\nmx: mail.example.com', HOSTS)),
  ['mta-sts.max-age-short']);
eq('testing reports its mode and still compares',
  ids(mtaStsPolicyFindings(
    'version: STSv1\nmode: testing\nmax_age: 604800\nmx: other.example.com', HOSTS)),
  ['mta-sts.mode-testing', 'mta-sts.policy-mx-mismatch', 'mta-sts.policy-mx-unused']);

// An invalid policy still exposes whichever mx lines parsed. Comparing them
// would report mismatches derived from a document no sender will honour.
const INVALID = 'version: STSv1\nmode: enforce\nmax_age: 604800\nmx: bad_host';
eq('an invalid policy yields only the parser diagnostic',
  ids(mtaStsPolicyFindings(INVALID, HOSTS)), ['mta-sts.policy-invalid']);
eq('and no semantic interpretation of the fields that survived',
  mtaStsPolicyFindings(INVALID, HOSTS).findings
    .some(f => f.id !== 'mta-sts.policy-invalid'), false);

section('3b. Diagnostics carry the line they were seen on');

const BLANK = 'version: STSv1\n\nmode: enforce\nmax_age: 604800\nmx: mail.example.com';
const blank = mtaStsPolicyFindings(BLANK, HOSTS).findings[0];
eq('a blank line is located by line number',
  [blank.id, blank.evidence[0].kind, blank.evidence[0].location],
  ['mta-sts.policy-invalid', 'line', 'line 2']);

// A missing field is raised against the document, not a line, so it takes the
// `input` variant rather than inventing a line number.
const missing = mtaStsPolicyFindings('version: STSv1\nmode: enforce\nmx: mail.example.com', HOSTS);
eq('a document-level error is located by the artifact, not a line',
  [missing.findings[0].evidence[0].kind, missing.findings[0].evidence[0].location],
  ['input', 'policy']);

const bom = mtaStsPolicyFindings('﻿' + ENFORCE, HOSTS);
eq('a BOM is hygiene, not invalidity',
  ids(bom), ['mta-sts.policy-hygiene']);

/* ── 4. BIMI SVG composition ──────────────────────────────────────────── */
section('4. bimiSvgFindings');

const SVG_NS = 'http://www.w3.org/2000/svg';
const el = (localName, attrs = {}, children = [], ns = SVG_NS) => ({
  nodeType: 1, localName, nodeName: localName, namespaceURI: ns,
  attributes: Object.entries(attrs).map(([name, value]) => ({
    name, localName: name.includes(':') ? name.split(':')[1] : name, value: String(value),
  })),
  childNodes: children,
  get textContent() { return children.map(c => (c.nodeType === 3 ? c.data : c.textContent)).join(''); },
});
const text = d => ({ nodeType: 3, data: d, textContent: d });
const parserFor = root => () => ({ documentElement: root });
const OK_TEXT = `<svg xmlns="${SVG_NS}"/>`;
const conformant = children => el('svg', {
  baseProfile: 'tiny-ps', version: '1.2', viewBox: '0 0 64 64',
}, children || [el('title', {}, [text('Brand')])]);

eq('a conformant logo reports that it is conformant',
  bimiSvgFindings(OK_TEXT, parserFor(conformant())).findings.map(f => f.id),
  ['bimi.svg-valid']);
eq('a security rejection outranks profile diagnostics',
  bimiSvgFindings(OK_TEXT, parserFor(conformant([
    el('title', {}, [text('t')]), el('script', {}, [text('x')]),
  ]))).findings.map(f => f.id), ['bimi.svg-rejected']);
eq('a profile problem alone is a profile finding',
  bimiSvgFindings(OK_TEXT, parserFor(el('svg', { version: '1.2', viewBox: '0 0 64 64' },
    [el('title', {}, [text('t')])]))).findings.map(f => f.id), ['bimi.svg-profile']);
eq('and a profile finding is never a security refusal',
  bimiSvgFindings(OK_TEXT, parserFor(el('svg', { version: '1.2', viewBox: '0 0 64 64' },
    [el('title', {}, [text('t')])]))).findings[0].severity !== 'critical', true);

// The entity guard, through the composer: the parser must not be reached.
let parserCalls = 0;
bimiSvgFindings('<!DOCTYPE x [<!ENTITY a "b">]><svg/>', () => { parserCalls++; return null; });
eq('an entity-declaring document never reaches the parser through the composer',
  parserCalls, 0);

/* ── 5. The boundaries, asserted structurally ─────────────────────────── */
section('5. Boundaries');

const both = analyzeArtifacts({
  domain: 'example.com',
  mx: ['10 mail.example.com'],
  aRec: [], aaaaRec: [],
  mtaStsPolicyText: 'version: STSv1\nmode: enforce\nmax_age: 3600\nmx: other.example.com',
  bimiSvgText: OK_TEXT,
  parseSvg: parserFor(conformant()),
});

eq('both artifacts compose into ONE separate array',
  both.artifactFindings.length > 0, true);
eq('the result exposes no `findings` key that could be merged by habit',
  Object.keys(both).sort(),
  ['artifactFindings', 'bimiSvg', 'domain', 'mtaStsPolicy', 'mxFact']);

eq('EVERY finding carries user-supplied provenance',
  both.artifactFindings.every(f => f.source === 'user-supplied'), true);
eq('and names the artifact it came from',
  both.artifactFindings.every(f => ARTIFACT_KINDS.includes(f.artifact)), true);
eq('every evidence entry uses the artifact kinds, never the DNS ones',
  both.artifactFindings.flatMap(f => f.evidence)
    .filter(e => !ARTIFACT_EVIDENCE_KINDS.includes(e.kind)), []);
eq('and no evidence entry carries a queryName, which is the DNS contract',
  both.artifactFindings.flatMap(f => f.evidence)
    .filter(e => 'queryName' in e), []);

// The shared metadata shape: these have to be presentable by the 0.7.0
// renderer, so their vocabularies must be the ones it already knows.
eq('severity, confidence, category and effort are all 0.7.0 members',
  both.artifactFindings.filter(f =>
    !SEVERITIES.includes(f.severity) || !CONFIDENCES.includes(f.confidence) ||
    !CATEGORIES.includes(f.category) || !EFFORTS.includes(f.effort)), []);
eq('and keyspace stays `finding`',
  both.artifactFindings.every(f => f.keyspace === 'finding'), true);

eq('nothing is returned that is not a token, a primitive or a plain finding',
  both.artifactFindings.flatMap(f => f.evidence)
    .every(e => typeof e.kind === 'string' && typeof e.location === 'string' &&
      typeof e.value === 'string'), true);

section('5a. Supplying nothing composes nothing');

const empty = analyzeArtifacts({ domain: 'example.com' });
eq('no artifact means no findings', empty.artifactFindings, []);
eq('and no validator result is invented',
  [empty.mtaStsPolicy, empty.bimiSvg], [null, null]);
eq('an absent input does not throw', analyzeArtifacts().artifactFindings, []);

section('5b. One artifact does not imply the other');

const policyOnly = analyzeArtifacts({
  domain: 'example.com', mx: ['10 mail.example.com'], mtaStsPolicyText: ENFORCE,
});
eq('a policy alone leaves the SVG result null', policyOnly.bimiSvg, null);
eq('and reports the policy it validated',
  policyOnly.mtaStsPolicy.result.mode, 'enforce');

/* ── 6. The public entry point, over the fields the audit really holds ──
 *
 * `deliveryCandidates()` had unit tests and `mtaStsPolicyFindings()` had unit
 * tests, and the composer still reported `policy-mx-unknown` for a domain
 * whose MX matched perfectly — because `analyzeArtifacts()` never called the
 * derivation. Two green halves proving nothing about the join. These fixtures
 * drive the PUBLIC entry with `mx`/`aRec`/`aaaaRec`, which is what
 * `audit-domain.js` actually has. ─────────────────────────────────────── */
section('6. analyzeArtifacts derives the fact from audit fields');

const MATCHING = 'version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mail.example.com';
const entry = (fields) => analyzeArtifacts(Object.assign(
  { domain: 'example.com', mtaStsPolicyText: MATCHING }, fields))
  .artifactFindings.map(f => f.id);

eq('explicit MX that the policy covers produces nothing',
  entry({ mx: ['10 mail.example.com'], aRec: [], aaaaRec: [] }), []);
eq('explicit MX the policy misses is a mismatch',
  entry({ mx: ['10 other.example.com'], aRec: [], aaaaRec: [] }),
  ['mta-sts.policy-mx-mismatch', 'mta-sts.policy-mx-unused']);
eq('a null MX reaches its own finding through the public entry',
  entry({ mx: ['0 .'], aRec: [], aaaaRec: [] }), ['mta-sts.policy-on-null-mx']);
eq('an implicit MX is covered by a policy naming the domain',
  analyzeArtifacts({
    domain: 'mail.example.com', mx: [], aRec: ['192.0.2.1'], aaaaRec: [],
    mtaStsPolicyText: MATCHING,
  }).artifactFindings.map(f => f.id), []);
eq('an AAAA-only domain still has an implicit candidate',
  analyzeArtifacts({
    domain: 'mail.example.com', mx: [], aRec: [], aaaaRec: ['2001:db8::1'],
    mtaStsPolicyText: MATCHING,
  }).artifactFindings.map(f => f.id), []);
eq('a failed MX lookup says the check did not run',
  entry({ mx: ['10 mail.example.com'], mxUnknown: true }),
  ['mta-sts.policy-mx-unknown']);
eq('and the derived fact is exposed for the panel to explain itself',
  analyzeArtifacts({ domain: 'example.com', mx: ['0 .'] }).mxFact,
  { hosts: [], nullMx: true });

section('6a. Evidence carries the supplied material, per occurrence');

const invalidMode = analyzeArtifacts({
  domain: 'example.com', mx: ['10 mail.example.com'],
  mtaStsPolicyText: 'version: STSv1\nmode: bogus\nmax_age: 604800\nmx: mail.example.com',
}).artifactFindings[0];
eq('the value is the offending LINE, not the diagnostic token',
  invalidMode.evidence, [{ kind: 'line', location: 'line 2', value: 'mode: bogus' }]);
eq('and the token is carried by args, where it belongs',
  invalidMode.args, ['invalid-mode']);

const twoBlanks = analyzeArtifacts({
  domain: 'example.com', mx: ['10 mail.example.com'],
  mtaStsPolicyText: 'version: STSv1\n\n\nmode: enforce\nmax_age: 604800\nmx: mail.example.com',
}).artifactFindings[0];
eq('two occurrences of one token get two evidence entries, at their own lines',
  twoBlanks.evidence.map(e => e.location), ['line 2', 'line 3']);

const hostile = analyzeArtifacts({
  domain: 'example.com', bimiSvgText: OK_TEXT,
  parseSvg: parserFor(conformant([
    el('title', {}, [text('t')]),
    el('use', { 'xlink:href': 'https://evil.example/a#x' }),
  ])),
}).artifactFindings[0];
eq('an SVG rejection names the OFFENDING element, not the root',
  hostile.evidence.map(e => e.location).includes('<use>'), true);
eq('and carries the material that made it a rejection',
  hostile.evidence.some(e => e.value.includes('evil.example')), true);

eq('a bounded value is cut on code points, never mid-character',
  (() => {
    const v = artifactEvidence('input', 'x', 'y'.repeat(199) + '\u{1F600}').value;
    const last = v.charCodeAt(v.length - 1);
    return last >= 0xD800 && last <= 0xDBFF;
  })(), false);

report();
