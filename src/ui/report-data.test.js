#!/usr/bin/env node
/**
 * The 0.9.0 report schema, importer and comparison.
 * Spec: report-comparison 1.6 (Final), sections 1, 4 and 5.
 *
 * Section 1 is the load-bearing one and it is proven in BOTH directions. A test
 * that only checked the wanted fields were present would pass on a dump of the
 * whole result object -- which is exactly the defect the 1.0 review found in the
 * draft, and the reason the excluded fields are named individually below.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createSuite } from '../../tests/lib/assert.mjs';
import { normalizeSource } from '../../tests/lib/source.mjs';
// The selector grammar's OWNER. Imported here, in the test, precisely to prove
// the schema layer judges selectors by the owner's rule rather than a copy:
// `src/ui/` may not import this module, so the predicate reaches the schema as
// a composed capability and this assertion pins the two together.
import { validDkimSelector } from '../core/dkim/dkim.js';
import {
  SCHEMA_ID, SCHEMA_VERSION, MAX_DOMAINS, LIMITS, REPORT_PATHS,
  PROTOCOL_TOKENS, OPTION_PROTOCOLS, DOMAIN_STATUSES,
  projectReport, parseReport, compareReports, normalizeRecords, pathsIn,
} from './report-data.js';

const { eq, section, report } = createSuite();

// Comments stripped, per the framework rule: the module's own docstring
// EXPLAINS why it avoids one of these names, and a raw-text search cannot tell
// an explanation from a use.
const SOURCE = normalizeSource(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'report-data.js'), 'utf8'));

/* -- Fixtures --------------------------------------------------------- */

const OBSERVED = PROTOCOL_TOKENS.reduce((m, p) => { m[p] = 'observed'; return m; }, {});
const observability = over => Object.assign({}, OBSERVED, over || {});

/**
 * A result that reaches EVERY registered path. Every array is non-empty on
 * purpose: an empty one never produces its `[]` path, so a fixture with empty
 * arrays would silently fail to cover half the registry.
 */
const richResult = (over) => Object.assign({
  domain: 'alpha.test',
  organizationalDomain: 'alpha.test',
  observability: observability(),
  ns: ['ns1.alpha.test', 'ns2.alpha.test'],
  mx: ['10 mail.alpha.test'],
  spfRecords: ['v=spf1 -all'],
  dmarcRecord: 'v=DMARC1; p=reject',
  dmarcAtDomain: '_dmarc.alpha.test',
  dmarcDiscovery: {
    applied: { foundAt: 'alpha.test', labelsUp: 0 },
    terminated: 'root', organizationalDomain: 'alpha.test',
    policyDomain: 'alpha.test', psdBoundary: 'test',
    queries: ['THIS MUST NOT BE EXPORTED'], steps: ['NOR THIS'],
  },
  dkimStatus: {
    confidence: 'observed',
    selectors: [{
      sel: 's1', queryName: 's1._domainkey.alpha.test', value: 'v=DKIM1; p=AAA',
      key: { keyType: 'rsa', keyBits: 2048 },
    }],
  },
  advanced: {
    bimi: { record: 'v=BIMI1; l=https://alpha.test/logo.svg' },
    mtaSts: { record: 'v=STSv1; id=1' },
    tlsRpt: { record: 'v=TLSRPTv1; rua=mailto:t@alpha.test' },
    caa: { atDomain: 'alpha.test', records: ['0 issue "le.org"'] },
    dnssec: {
      keys: [{ flags: 257, protocol: 3, algorithm: 8, publicKey: 'AAAA' }],
      ds: [{ keyTag: 1, algorithm: 8, digestType: 2, digest: 'abcd' }],
    },
    tlsa: {
      hosts: [{
        host: 'mail.alpha.test', queryName: '_25._tcp.mail.alpha.test', authenticated: true,
        records: [{ usage: 3, selector: 1, matchingType: 1, data: 'beef' }],
      }],
    },
  },
  score: {
    pts: 72, max: 100, grade: 'A', parked: false, cls: 'score-a', unproven: ['dkim'],
    breakdown: { pillars: [{ key: 'dmarc', pts: 25, max: 30 }], dmarc: { policy: 12 } },
  },
  findings: [{
    id: 'dmarc.policy-none', protocol: 'dmarc', severity: 'high', confidence: 'confirmed',
    category: 'policy', effort: 'moderate', args: ['none'], dependsOn: ['spf.missing'],
    blocks: ['SHOULD NOT BE EXPORTED'], key: 'dmarc-none', keyspace: 'issue',
    noteKey: 'n', noteArgs: { a: 1 },
    evidence: [{ kind: 'txt', queryName: '_dmarc.alpha.test', value: 'v=DMARC1; p=none' }],
  }],
  remediationPlan: [{ step: 1, rationale: 'foundation', findings: ['dmarc.policy-none'], unblocks: ['spf.missing'] }],
  // Everything below is excluded by section 1 and must not survive projection.
  txt: ['v=spf1 -all', 'google-site-verification=SECRET'],
  verifications: ['google-site-verification=SECRET'],
  issues: [{ key: 'x' }], suggestions: [{ key: 'y' }], advScore: 5,
  dnsProvider: 'cloudflare', emailProvider: 'google', hosting: 'x',
  aRec: ['198.51.100.1'], aaaaRec: ['2001:db8::1'],
  dmarcStatus: { cls: 'ok', policy: 'reject' },
}, over || {});

const OPTIONS = {
  dkim: true, dkimComprehensive: false, www: true, wildcard: true,
  advanced: true, deepChecks: true, selectors: ['s2', 's1', 's1'],
};

const CAPS = { validSelector: validDkimSelector };

const build = (results, over) => projectReport(Object.assign({
  results, options: OPTIONS, resolver: 'https://cloudflare-dns.com/dns-query',
  versions: { app: '0.9.0', analysis: 1 }, generatedAt: '2026-09-03T00:00:00.000Z',
  validSelector: validDkimSelector,
}, over || {}));

// `unproven` must be empty for the score to be comparable at all, so the
// score-tiebreak fixtures use a fully proven pillar set.
const provenScore = pts => ({ pts, max: 100, grade: 'A', parked: false, unproven: [],
  breakdown: { pillars: [{ key: 'dmarc', pts: 25, max: 30 }] } });

const roundTrip = (rep) => {
  const parsed = parseReport(JSON.stringify(rep), CAPS);
  if (!parsed.ok) throw new Error('fixture did not round-trip: ' + parsed.errors.join('; '));
  return parsed.report;
};

/* -- 1. The closed path set, proven in both directions ---------------- */
section('1. The projection is closed, both ways');

const full = build([richResult(), { domain: 'gone.test', unregistered: true }, { domain: 'bad.test', error: true }]);
const emitted = pathsIn(full);
const registered = REPORT_PATHS.slice().sort();

eq('every emitted path is registered',
  [...new Set(emitted)].filter(p => REPORT_PATHS.indexOf(p) === -1).sort(), []);
eq('every registered path is reached by the fixture',
  registered.filter(p => emitted.indexOf(p) === -1), []);
eq('the registry has no duplicate members',
  registered.length - new Set(registered).size, 0);
// A one-way test would pass on a dump, so section 1's exclusions are named as
// PATHS rather than as substrings. A substring search is the wrong instrument
// here and quietly gives a false positive: `score.pillars[].key` is a legitimate
// field named `key`, and `"txt"` appears as an evidence KIND value.
const EXCLUDED_PATHS = [
  'domains[].score.cls', 'domains[].score.breakdown.dmarc.policy',
  'domains[].findings[].key', 'domains[].findings[].keyspace',
  'domains[].findings[].noteKey',
  // `noteArgs` is an object, so its leaf path carries the member name.
  'domains[].findings[].noteArgs.a',
  'domains[].findings[].blocks[]',
  'domains[].txt[]', 'domains[].verifications[]',
  'domains[].issues[].key', 'domains[].suggestions[].key', 'domains[].advScore',
  'domains[].dnsProvider', 'domains[].emailProvider', 'domains[].hosting',
  'domains[].aRec[]', 'domains[].aaaaRec[]',
  'domains[].dmarcDiscovery.queries[]', 'domains[].dmarcDiscovery.steps[]',
  'domains[].dmarcStatus.cls',
];
eq('no excluded path survives the projection',
  EXCLUDED_PATHS.filter(p => emitted.indexOf(p) !== -1), []);
// ...and the fixture really did supply every one of them, so the check above is
// not passing because the input was already clean.
eq('the fixture supplied every excluded path in the first place',
  EXCLUDED_PATHS.filter(p => pathsIn({ domains: [richResult()] }).indexOf(p) === -1), []);
eq('and the vendor verification token is nowhere in the file',
  JSON.stringify(full).includes('google-site-verification'), false);
// The negative control on the closed-path check itself.
eq('an extra field would be caught',
  pathsIn({ domains: [{ smuggled: 1 }] }).filter(p => REPORT_PATHS.indexOf(p) === -1),
  ['domains[].smuggled']);

eq('an unregistered domain carries only its name and state',
  Object.keys(full.domains[1]).sort(), ['domain', 'state']);
eq('and so does an errored one',
  [Object.keys(full.domains[2]).sort().join(','), full.domains[2].state],
  ['domain,state', 'error']);

/* -- 2. Producer / importer round-trip -------------------------------- */
section('2. Round-trip: what is exported is what is imported');

const reimported = roundTrip(full);
eq('the parsed report equals the exported one, field for field',
  JSON.stringify(reimported), JSON.stringify(full));
eq('schema identity and version survive',
  [reimported.schema, reimported.schemaVersion], [SCHEMA_ID, SCHEMA_VERSION]);
eq('the generator block survives', reimported.generator, { version: '0.9.0', analysisVersion: 1 });
eq('selectors are sorted and deduplicated on the way out',
  full.options.selectors, ['s1', 's2']);
eq('a second round-trip is stable',
  JSON.stringify(roundTrip(reimported)), JSON.stringify(reimported));
// Cross-language byte-identity (acceptance criterion 4) reduces to this: the
// projection reads no locale, so two exports of one run cannot differ.
eq('two projections of the same run are byte-identical',
  JSON.stringify(build([richResult()])), JSON.stringify(build([richResult()])));

/* -- 3. Canonical record ordering ------------------------------------- */
section('3. Resolver answer order cannot fabricate a change');

const shuffled = richResult({ ns: ['ns2.alpha.test', 'ns1.alpha.test'] });
eq('a reordered answer set projects identically',
  JSON.stringify(build([shuffled]).domains[0].records.ns),
  JSON.stringify(build([richResult()]).domains[0].records.ns));
eq('duplicates collapse',
  normalizeRecords('ns', [{ queryName: 'a', value: 'x' }, { queryName: 'a', value: 'x' }]).length, 1);
eq('entries sort by the complete tuple',
  normalizeRecords('ns', [{ queryName: 'a', value: 'z' }, { queryName: 'a', value: 'b' }])
    .map(e => e.value), ['b', 'z']);
// The tuple is per-kind: two TLSA entries differing only in `authenticated` are
// different records, so a dedupe on queryName+value alone would lose one.
eq('the tlsa tuple includes authenticated',
  normalizeRecords('tlsa', [
    { queryName: 'q', value: 'v', authenticated: true },
    { queryName: 'q', value: 'v', authenticated: false },
  ]).length, 2);
eq('the dkim tuple includes selector, keyType and keyBits',
  normalizeRecords('dkim', [
    { queryName: 'q', value: 'v', selector: 'a', keyType: 'rsa', keyBits: 2048 },
    { queryName: 'q', value: 'v', selector: 'b', keyType: 'rsa', keyBits: 2048 },
  ]).length, 2);
eq('a record change is still reported when the value really moves',
  compareReports(roundTrip(build([richResult()])),
    roundTrip(build([richResult({ spfRecords: ['v=spf1 ~all'] })])))
    .domains[0].recordChanges.map(c => c.path), ['records.spf']);

/* -- 4. Hostile input ------------------------------------------------- */
section('4. Hostile input fails closed');

const ok = t => parseReport(t, CAPS).ok;

/**
 * A minimally valid report envelope. Every hostile fixture below varies exactly
 * ONE thing against this, so a rejection is attributable: a fixture that also
 * omitted `generator` would be rejected for the wrong reason and prove nothing
 * about the property it names.
 */
const envelope = (over) => Object.assign({
  schema: SCHEMA_ID, schemaVersion: SCHEMA_VERSION,
  generatedAt: '2026-09-03T00:00:00.000Z',
  generator: { version: '0.9.0', analysisVersion: 1 },
  resolver: 'https://cloudflare-dns.com/dns-query',
  options: { dkim: true, dkimComprehensive: false, www: true, wildcard: true,
    advanced: true, deepChecks: true, selectors: [] },
  domains: [],
}, over || {});
const okEnv = over => ok(JSON.stringify(envelope(over)));
eq('the envelope itself is valid, so a rejection below is attributable', okEnv(), true);

eq('a __proto__ key is rejected', ok('{"__proto__":{"polluted":true}}'), false);
eq('and nothing was polluted', ({}).polluted, undefined);
eq('a constructor key is rejected', ok('{"constructor":{"x":1}}'), false);
eq('a prototype key is rejected', ok('{"prototype":{"x":1}}'), false);
// Nested, not just at the root -- the reviver sees every key.
eq('a nested __proto__ is rejected too',
  ok(JSON.stringify({ schema: SCHEMA_ID, schemaVersion: 1, domains: [] })
    .replace('"domains"', '"__proto__"')), false);
eq('a finding id of __proto__ does not resolve through the chain', (() => {
  const rep = build([richResult({
    findings: [{ id: '__proto__', protocol: 'dmarc', severity: 'info', confidence: 'confirmed',
      category: 'policy', effort: 'trivial', args: [], dependsOn: [], evidence: [] }],
  })]);
  // It cannot reach the importer (the reviver rejects it), so the guarantee that
  // matters is that comparison over such an id neither throws nor resolves.
  const cmp = compareReports(rep, rep);
  return [cmp.domains[0].findings.unchanged, typeof cmp.domains[0].status];
})(), [['__proto__'], 'string']);

eq('a file over the byte limit is rejected before anything else',
  ok('x'.repeat(LIMITS.bytes + 1)), false);
const manyDomains = n => new Array(n).fill(0).map((_, i) => ({ domain: 'd' + i + '.test', state: 'unregistered' }));
eq('more than MAX_DOMAINS domains is rejected', okEnv({ domains: manyDomains(MAX_DOMAINS + 1) }), false);
eq('exactly MAX_DOMAINS is accepted', okEnv({ domains: manyDomains(MAX_DOMAINS) }), true);
eq('the domain cap is the run cap, not a round number', [LIMITS.domains, MAX_DOMAINS], [200, 200]);

eq('deep nesting is rejected', (() => {
  let deep = 'x';
  for (let i = 0; i < 50; i++) deep = { n: deep };
  return okEnv({ deep });
})(), false);
eq('and the limit is not so tight it rejects a real report', parseReport(JSON.stringify(full), CAPS).ok, true);

// A real audited domain, so a findings/evidence rejection is about the count.
const audited = over => Object.assign({}, build([richResult()]).domains[0], over || {});
const withDomain = over => okEnv({ domains: [audited(over)] });
eq('a real audited domain passes, so the fixtures below isolate one thing',
  withDomain(), true);
eq('too many findings on one domain is rejected',
  withDomain({ findings: new Array(LIMITS.findings + 1).fill(build([richResult()]).domains[0].findings[0]) }), false);
eq('too much evidence on one finding is rejected', (() => {
  const f = JSON.parse(JSON.stringify(build([richResult()]).domains[0].findings[0]));
  f.evidence = new Array(LIMITS.evidence + 1).fill(f.evidence[0]);
  return withDomain({ findings: [f] });
})(), false);

eq('a foreign schema is rejected with its own message',
  parseReport(JSON.stringify(envelope({ schema: 'something-else' })), CAPS).errors,
  ['not a report from this tool']);
eq('a newer schemaVersion is rejected with a different message',
  parseReport(JSON.stringify(envelope({ schemaVersion: SCHEMA_VERSION + 1 })), CAPS).errors,
  ['this report was made by a newer version of the tool']);
eq('truncated JSON is rejected with no partial state',
  parseReport('{"schema":"dns-email-audit/report",', CAPS).ok, false);
eq('an HTML file renamed .json is rejected', ok('<!doctype html><html></html>'), false);
eq('valid JSON of the wrong shape is rejected', ok('[1,2,3]'), false);
eq('a non-string input is rejected', parseReport(null, CAPS).ok, false);

// A hostile string is DATA. It must survive as text rather than be dropped, so
// the renderer can put it in a text node -- dropping it would hide the attack.
/**
 * Domain identity is grammar-bounded; a record value is not.
 *
 * Section 1 requires `domain` to be a normalized ASCII domain string, so a
 * `<img ...>` in that field is a report this tool never wrote and is rejected.
 * The rendering-safety guarantee belongs where hostile bytes legitimately
 * arrive -- record and evidence values, which carry whatever the resolver
 * returned and are bounded only by the file.
 */
eq('a script-like domain identity is rejected, not carried', okEnv({
  domains: [{ domain: '<img src=x onerror=alert(1)>', state: 'unregistered' }],
}), false);
eq('and so is a script-like organizationalDomain',
  withDomain({ organizationalDomain: '<img src=x onerror=alert(1)>' }), false);
eq('a domain with an underscore or a leading hyphen is rejected',
  [okEnv({ domains: [{ domain: 'a_b.test', state: 'unregistered' }] }),
    okEnv({ domains: [{ domain: '-a.test', state: 'unregistered' }] })], [false, false]);
eq('while a real subdomain is accepted',
  okEnv({ domains: [{ domain: 'sub.delta.test', state: 'unregistered' }] }), true);

// ...and the value side, which is where the assertion actually belongs.
const hostileValue = '<img src=x onerror=alert(1)>';
eq('a script-like RECORD value survives as text', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  rec.spf[0].value = hostileValue;
  const parsed = parseReport(JSON.stringify(envelope({ domains: [audited({ records: rec })] })), CAPS);
  return parsed.ok && parsed.report.domains[0].records.spf[0].value;
})(), hostileValue);
eq('and so does a script-like EVIDENCE value', (() => {
  const f = JSON.parse(JSON.stringify(build([richResult()]).domains[0].findings[0]));
  f.evidence[0].value = hostileValue;
  const parsed = parseReport(JSON.stringify(envelope({ domains: [audited({ findings: [f] })] })), CAPS);
  return parsed.ok && parsed.report.domains[0].findings[0].evidence[0].value;
})(), hostileValue);
eq('a bidirectional override in a record value survives too', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  rec.spf[0].value = 'v=spf1 include:\u202Esafe.example -all';
  const parsed = parseReport(JSON.stringify(envelope({ domains: [audited({ records: rec })] })), CAPS);
  return parsed.ok && parsed.report.domains[0].records.spf[0].value.indexOf('\u202E') !== -1;
})(), true);
eq('unknown fields are dropped rather than carried', (() => {
  const parsed = parseReport(JSON.stringify(envelope({
    smuggled: 'x', domains: [{ domain: 'a.test', state: 'unregistered', alsoSmuggled: 'y' }],
  })), CAPS);
  return parsed.ok && JSON.stringify(parsed.report).includes('muggled');
})(), false);
eq('a duplicate domain is rejected rather than silently deduplicated',
  okEnv({ domains: [{ domain: 'a.test', state: 'unregistered' }, { domain: 'a.test', state: 'error' }] }), false);
// Section 4 removed the per-string ceiling: the producer has no such bound, so
// an importer with one would reject a file this build wrote.
eq('a long record value is not rejected on its own length', (() => {
  const long = 'v=spf1 ' + 'include:a.test '.repeat(2000) + '-all';
  return parseReport(JSON.stringify(build([richResult({ spfRecords: [long] })])), CAPS).ok;
})(), true);

/* -- 4b. Strict shape: known fields are rejected, not repaired ---------- */
section('4b. A malformed known field is rejected, never coerced');

/**
 * The failure this section exists to prevent: an importer that REPAIRS a
 * malformed report produces a comparable-looking artefact out of values nobody
 * wrote, and then reports confident differences derived from them. Section 4
 * says every field is checked for type and range.
 */
const rejects = (label, over) => eq(label, okEnv(over), false);

rejects('a missing generator', { generator: undefined });
rejects('a generator with no version', { generator: { analysisVersion: 1 } });
rejects('a non-semver generator version', { generator: { version: 'dev', analysisVersion: 1 } });
rejects('a zero analysisVersion', { generator: { version: '0.9.0', analysisVersion: 0 } });
rejects('a non-integer analysisVersion', { generator: { version: '0.9.0', analysisVersion: 1.5 } });
rejects('a missing generatedAt', { generatedAt: undefined });
rejects('a non-canonical timestamp', { generatedAt: '2026-09-03T00:00:00Z' });
rejects('a missing resolver', { resolver: undefined });
rejects('a non-HTTPS resolver', { resolver: 'http://example.test/dns-query' });
rejects('a missing options block', { options: undefined });
rejects('an options block missing deepChecks', {
  options: { dkim: true, dkimComprehensive: false, www: true, wildcard: true, advanced: true, selectors: [] } });
rejects('a non-boolean option', {
  options: { dkim: 'yes', dkimComprehensive: false, www: true, wildcard: true, advanced: true, deepChecks: true, selectors: [] } });
rejects('non-string selectors', {
  options: { dkim: true, dkimComprehensive: false, www: true, wildcard: true, advanced: true, deepChecks: true, selectors: [1] } });

// Shape is not validity. Each of these has the RIGHT SHAPE and is still not a
// value this tool could have written.
const selectorsWith = v => ({ options: { dkim: true, dkimComprehensive: false, www: true,
  wildcard: true, advanced: true, deepChecks: true, selectors: [v] } });
rejects('a timestamp that matches the pattern but is not a date',
  { generatedAt: '2026-99-99T99:99:99.999Z' });
rejects('a timestamp with the wrong day for its month', { generatedAt: '2026-02-30T00:00:00.000Z' });
rejects('a 29 February in a non-leap year', { generatedAt: '2026-02-29T00:00:00.000Z' });
rejects('a leap second', { generatedAt: '2026-06-30T23:59:60.000Z' });
rejects('a 25th hour', { generatedAt: '2026-06-30T24:00:00.000Z' });
rejects('a zeroth month', { generatedAt: '2026-00-10T00:00:00.000Z' });
eq('while 29 February in a leap year is accepted',
  okEnv({ generatedAt: '2024-02-29T12:00:00.000Z' }), true);
eq('and the last day of a 31-day month is', okEnv({ generatedAt: '2026-01-31T23:59:59.999Z' }), true);

// Section 1: the four discovery fields are domain identities, three nullable.
const disc = over => Object.assign({}, build([richResult()]).domains[0].dmarcDiscovery, over);
eq('each dmarcDiscovery domain field rejects a malformed name',
  ['foundAt', 'organizationalDomain', 'policyDomain', 'psdBoundary']
    .filter(f => withDomain({ dmarcDiscovery: disc({ [f]: '<bad>' }) }) !== false), []);
eq('the three nullable ones still accept null',
  ['foundAt', 'policyDomain', 'psdBoundary']
    .filter(f => withDomain({ dmarcDiscovery: disc({ [f]: null }) }) !== true), []);
eq('but organizationalDomain is required', withDomain({ dmarcDiscovery: disc({ organizationalDomain: null }) }), false);
rejects('a version with a leading zero component', { generator: { version: '00.9.0', analysisVersion: 1 } });
rejects('a four-component version', { generator: { version: '0.9.0.1', analysisVersion: 1 } });
rejects('an HTTPS scheme with no host', { resolver: 'https://' });
rejects('an HTTPS URL with a hostile host', { resolver: 'https://<script>' });
// The bound is an UPPER one only. Port 0 is inside the URL port range -- an
// earlier fix rejected it while fixing `:99999`, trading one wrong answer for
// another -- so both ends of the range are pinned here.
eq('a resolver port above the range is rejected, despite the right shape',
  okEnv({ resolver: 'https://example.test:99999/' }), false);
eq('while both ends of the real range are accepted',
  [okEnv({ resolver: 'https://example.test:0/' }),
    okEnv({ resolver: 'https://example.test:65535/' })], [true, true]);
eq('and one past the top is not', okEnv({ resolver: 'https://example.test:65536/' }), false);
eq('a real port is accepted', okEnv({ resolver: 'https://example.test:8443/dns-query' }), true);
eq('and a plain resolver URL is accepted',
  okEnv({ resolver: 'https://cloudflare-dns.com/dns-query' }), true);

/* -- The selector grammar belongs to core/dkim, not to this module -- */
const okSel = okEnv;
// The two probes that show a local copy would have been WRONG: the owner allows
// an underscore and forbids a dot, which is the opposite of a domain grammar.
eq('the owner accepts an underscore and rejects a dot',
  [validDkimSelector('a_b'), validDkimSelector('a.b')], [true, false]);
eq('and the importer agrees, because it uses the owner rather than a copy',
  [okSel(selectorsWith('a_b')), okSel(selectorsWith('a.b'))], [true, false]);
eq('a selector with a leading hyphen is rejected', okSel(selectorsWith('-BAD')), false);
eq('a selector with a space is rejected', okSel(selectorsWith('bad selector')), false);
eq('a real selector is accepted', okSel(selectorsWith('selector1')), true);
// ...and the producer FILTERS with the same predicate, so the rejected forms
// never reach a file this build wrote. This is the round-trip that closes the
// self-rejection: user input the audit would not query is discarded at export.
eq('the producer discards user selectors the importer would reject', (() => {
  const emitted = build([richResult()], {
    options: Object.assign({}, OPTIONS, { selectors: ['selector1', '-bad', 'a.b', 's_2'] }),
  }).options.selectors;
  return emitted;
})(), ['s_2', 'selector1']);
eq('and what it does emit round-trips under the same predicate', (() => {
  const rep = build([richResult()], {
    options: Object.assign({}, OPTIONS, { selectors: ['selector1', '-bad', 'a.b', 's_2'] }),
  });
  const parsed = parseReport(JSON.stringify(rep), CAPS);
  return parsed.ok && JSON.stringify(parsed.report.options.selectors);
})(), JSON.stringify(['s_2', 'selector1']));
// The capability is REQUIRED, and the control proves a forgotten wiring call
// fails loudly rather than quietly skipping the check. An absent predicate is a
// build defect, not a bad file, so it throws instead of returning an error.
eq('a missing selector capability throws rather than failing open', (() => {
  const calls = [
    () => parseReport(JSON.stringify(envelope()), {}),
    () => parseReport(JSON.stringify(envelope())),
    () => projectReport({ results: [], options: OPTIONS, versions: {}, generatedAt: '' }),
  ];
  return calls.map((call) => {
    try { call(); return 'no throw'; } catch (e) { return e instanceof TypeError; }
  });
})(), [true, true, true]);

// Section 1 specifies these four as closed NON-NULL enums.
const nullEnum = (label, over) => eq(label, withDomain(over), false);
nullEnum('a null grade', { score: Object.assign({}, build([richResult()]).domains[0].score, { grade: null }) });
nullEnum('a null pillar key', (() => {
  const sc = JSON.parse(JSON.stringify(build([richResult()]).domains[0].score));
  sc.pillars[0].key = null;
  return { score: sc };
})());
nullEnum('a null terminated token', {
  dmarcDiscovery: Object.assign({}, build([richResult()]).domains[0].dmarcDiscovery, { terminated: null }) });
nullEnum('a null finding protocol', (() => {
  const f = Object.assign({}, build([richResult()]).domains[0].findings[0], { protocol: null });
  return { findings: [f] };
})());

// The byte counter, which decides whether a file is even parsed.
eq('the byte counter sits exactly on the limit for both surrogate cases', (() => {
  // Each probe is built to land ON the limit or one byte past it, so the pair
  // proves the count rather than merely exercising it. The lone-surrogate probe
  // is the one that catches an undercount: reading the following character as a
  // low surrogate would score six bytes as four and let an oversized file in.
  const over = t => parseReport(t, CAPS).errors[0] === 'file is larger than ' + LIMITS.bytes + ' bytes';
  const a = n => 'a'.repeat(n);
  const PAIR = '\u{1F600}';        // one code point, four UTF-8 bytes
  const LONE = '\uD800\u0800';    // lone high surrogate + a 3-byte BMP char = six
  return [
    over(a(LIMITS.bytes - 4) + PAIR),  // exactly the limit
    over(a(LIMITS.bytes - 3) + PAIR),  // one byte over
    over(a(LIMITS.bytes - 6) + LONE),  // exactly the limit
    over(a(LIMITS.bytes - 5) + LONE),  // one byte over -- false if the lone
  ];                                   // surrogate were miscounted as a pair
})(), [false, true, false, true]);

const rejectsDomain = (label, over) => eq(label, withDomain(over), false);
rejectsDomain('an unknown domain state', { state: 'maybe' });
rejectsDomain('a missing observability map', { observability: undefined });
rejectsDomain('an observability map missing a protocol', (() => {
  const o = Object.assign({}, build([richResult()]).domains[0].observability);
  delete o.dane;
  return { observability: o };
})());
rejectsDomain('an unknown observability state', (() => {
  const o = Object.assign({}, build([richResult()]).domains[0].observability, { dns: 'probably' });
  return { observability: o };
})());
rejectsDomain('a negative score', { score: Object.assign({}, build([richResult()]).domains[0].score, { pts: -1 }) });
rejectsDomain('a negative max', { score: Object.assign({}, build([richResult()]).domains[0].score, { max: -1 }) });
rejectsDomain('an unknown grade', { score: Object.assign({}, build([richResult()]).domains[0].score, { grade: 'S' }) });
rejectsDomain('a non-boolean parked', { score: Object.assign({}, build([richResult()]).domains[0].score, { parked: 'no' }) });
rejectsDomain('an unknown pillar in unproven', { score: Object.assign({}, build([richResult()]).domains[0].score, { unproven: ['nope'] }) });
rejectsDomain('an unknown severity', (() => {
  const f = Object.assign({}, build([richResult()]).domains[0].findings[0], { severity: 'catastrophic' });
  return { findings: [f] };
})());
rejectsDomain('an unknown evidence kind', (() => {
  const f = JSON.parse(JSON.stringify(build([richResult()]).domains[0].findings[0]));
  f.evidence[0].kind = 'rumour';
  return { findings: [f] };
})());
rejectsDomain('a duplicate finding id', (() => {
  const f = build([richResult()]).domains[0].findings[0];
  return { findings: [f, f] };
})());
rejectsDomain('a record entry with a numeric value', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  rec.ns[0].value = 42;
  return { records: rec };
})());
rejectsDomain('a tlsa entry with no authenticated flag', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  delete rec.tlsa[0].authenticated;
  return { records: rec };
})());
rejectsDomain('a dkim entry with a zero keyBits', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  rec.dkim[0].keyBits = 0;
  return { records: rec };
})());
rejectsDomain('a missing record kind', (() => {
  const rec = JSON.parse(JSON.stringify(build([richResult()]).domains[0].records));
  delete rec.ds;
  return { records: rec };
})());
rejectsDomain('a non-contiguous remediation step', {
  remediationPlan: [{ step: 2, rationale: 'foundation', findings: [], unblocks: [] }] });
rejectsDomain('an unknown rationale', {
  remediationPlan: [{ step: 1, rationale: 'someday', findings: [], unblocks: [] }] });
rejectsDomain('a missing dmarcDiscovery', { dmarcDiscovery: undefined });
rejectsDomain('an unknown termination token', {
  dmarcDiscovery: Object.assign({}, build([richResult()]).domains[0].dmarcDiscovery, { terminated: 'gave-up' }) });
rejectsDomain('a negative labelsUp', {
  dmarcDiscovery: Object.assign({}, build([richResult()]).domains[0].dmarcDiscovery, { labelsUp: -1 }) });

/**
 * The self-rejection guard, and the reason the whole size measurement exists.
 * Every case in the committed corpus is projected and re-imported: an importer
 * strict enough to reject a file this build wrote is the defect the 1.0 review
 * found in the draft's byte limit, arriving through the type checks instead.
 */
eq('every domain in the committed corpus round-trips through the importer', (() => {
  const corpus = JSON.parse(readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', '..',
      'tests', 'fixtures', 'equivalence', 'baseline-v0.8.0.json'), 'utf8'));
  const results = [];
  for (const c of corpus.cases) {
    for (const d of c.result) if (d.result) results.push(d.result);
  }
  // The corpus predates observability, so supply the audit's own default for
  // the field this release adds; everything else is real v0.8.1 output.
  const withObs = results.map(r => Object.assign({}, r, { observability: observability() }));
  const chunks = [];
  for (let i = 0; i < withObs.length; i += MAX_DOMAINS) chunks.push(withObs.slice(i, i + MAX_DOMAINS));
  const failures = [];
  chunks.forEach(function (chunk, n) {
    // Domain names repeat across corpus cases; the importer rejects duplicates,
    // so make each unique while keeping every other byte of real output.
    const unique = chunk.map((r, i) => Object.assign({}, r, { domain: 'c' + n + 'd' + i + '.' + r.domain }));
    const parsed = parseReport(JSON.stringify(build(unique)), CAPS);
    if (!parsed.ok) failures.push(parsed.errors[0]);
  });
  return failures;
})(), []);

/* -- 5. Per-protocol comparability and the option mapping ------------- */
section('5. Option mapping and per-protocol comparability (spec 1.6)');

eq('advanced maps to the five advanced protocols plus spf, dmarc and reporting',
  OPTION_PROTOCOLS.advanced.slice().sort(),
  ['bimi', 'caa', 'dmarc', 'dnssec', 'mta-sts', 'reporting', 'spf', 'tls-rpt']);
eq('deepChecks maps to mx and dane', OPTION_PROTOCOLS.deepChecks, ['mx', 'dane']);
eq('wildcard maps to dns and dkim', OPTION_PROTOCOLS.wildcard, ['dns', 'dkim']);
eq('www maps to dns', OPTION_PROTOCOLS.www, ['dns']);
eq('every mapped protocol is a real protocol token',
  Object.keys(OPTION_PROTOCOLS).reduce((bad, k) =>
    bad.concat(OPTION_PROTOCOLS[k].filter(p => PROTOCOL_TOKENS.indexOf(p) === -1)), []), []);

const base = roundTrip(build([richResult()]));
// The same run with the DMARC finding gone -- normally `resolved`.
const fixed = roundTrip(build([richResult({ findings: [] })]));

eq('with both sides observed, a vanished finding is resolved',
  compareReports(base, fixed).domains[0].findings.resolved, ['dmarc.policy-none']);

const dmarcUnproven = roundTrip(build([richResult({
  findings: [], observability: observability({ dmarc: 'unproven' }),
})]));
eq('but an unproven protocol makes it unknown, never resolved',
  [compareReports(base, dmarcUnproven).domains[0].findings.resolved,
    compareReports(base, dmarcUnproven).domains[0].findings.unknown],
  [[], ['dmarc.policy-none']]);
eq('and the side is recorded',
  compareReports(base, dmarcUnproven).domains[0].incomparableProtocols
    .filter(e => e.protocol === 'dmarc').map(e => e.side + ':' + e.reason), ['current:unproven']);
eq('not-run does the same as unproven',
  compareReports(base, roundTrip(build([richResult({
    findings: [], observability: observability({ dmarc: 'not-run' }),
  })]))).domains[0].findings.unknown, ['dmarc.policy-none']);

// The 1.2 correction, end to end: an `advanced` mismatch must not let the eight
// advanced-gated SPF findings read as resolved.
const advancedOff = roundTrip(build([richResult({
  findings: [], observability: observability({ spf: 'unproven', dmarc: 'unproven' }),
})], { options: Object.assign({}, OPTIONS, { advanced: false }) }));
const advCmp = compareReports(base, advancedOff).domains[0];
eq('an advanced mismatch reports its option difference',
  compareReports(base, advancedOff).meta.optionDifferences, ['advanced']);
eq('and blocks spf and dmarc, not just the five advanced protocols',
  ['spf', 'dmarc', 'reporting', 'dnssec', 'caa', 'mta-sts', 'tls-rpt', 'bimi']
    .filter(p => advCmp.incomparableProtocols.some(e => e.protocol === p)).sort(),
  ['bimi', 'caa', 'dmarc', 'dnssec', 'mta-sts', 'reporting', 'spf', 'tls-rpt']);
eq('so the DMARC finding is unknown rather than resolved',
  [advCmp.findings.resolved, advCmp.findings.unknown], [[], ['dmarc.policy-none']]);

// One failed protocol must not blank the others.
const dkimOnlyUnproven = roundTrip(build([richResult({
  observability: observability({ dkim: 'unproven' }),
  spfRecords: ['v=spf1 ~all'],
})]));
const partial = compareReports(base, dkimOnlyUnproven).domains[0];
eq('a failed DKIM lookup leaves the SPF record diff intact',
  partial.recordChanges.map(c => c.path), ['records.spf']);
eq('and the dkim record path is omitted rather than shown as a change',
  partial.recordChanges.some(c => c.path === 'records.dkim'), false);
eq('the domain is still comparable overall', partial.status !== 'incomparable', true);

// Section 5: "a domain is incomparable when every observed change belongs to an
// incomparable protocol". A TLSA-only change with deepChecks off is exactly
// that -- and omitting it from `recordChanges` without counting it would leave
// the domain reading `unchanged`, which is the same lie one level down.
const daneOnly = (over) => roundTrip(build([richResult(Object.assign({
  observability: observability({ mx: 'not-run', dane: 'not-run' }),
}, over || {}))], { options: Object.assign({}, OPTIONS, { deepChecks: false }) }));
const daneBefore = daneOnly();
const daneAfter = daneOnly({
  advanced: Object.assign({}, richResult().advanced, {
    tlsa: { hosts: [{ host: 'mail.alpha.test', queryName: '_25._tcp.mail.alpha.test',
      authenticated: false, records: [{ usage: 3, selector: 1, matchingType: 1, data: 'cafe' }] }] },
  }),
});
const daneCmp = compareReports(daneBefore, daneAfter).domains[0];
eq('a TLSA-only change under an unobservable DANE is not reported as a change',
  daneCmp.recordChanges.map(c => c.path), []);
eq('but it is not silently unchanged either',
  [daneCmp.status, daneCmp.incomparableReasons.includes('only-incomparable-movement')],
  ['incomparable', true]);
// The control: the same record move with DANE observed IS a reported change.
const daneObserved = (data) => roundTrip(build([richResult({
  advanced: Object.assign({}, richResult().advanced, {
    tlsa: { hosts: [{ host: 'mail.alpha.test', queryName: '_25._tcp.mail.alpha.test',
      authenticated: true, records: [{ usage: 3, selector: 1, matchingType: 1, data }] }] },
  }),
})]));
eq('with DANE observed the same move is a reported record change',
  compareReports(daneObserved('beef'), daneObserved('cafe')).domains[0].recordChanges.map(c => c.path),
  ['records.tlsa']);

// ...but "only incomparable movement" must mean ONLY. A blocked TLSA change
// alongside a real comparable score delta is not a wholly incomparable domain,
// and calling it one would throw away a verdict both reports support.
const daneBlockedScored = (data, pts) => roundTrip(build([richResult({
  observability: observability({ mx: 'not-run', dane: 'not-run' }),
  score: provenScore(pts),
  advanced: Object.assign({}, richResult().advanced, {
    tlsa: { hosts: [{ host: 'mail.alpha.test', queryName: '_25._tcp.mail.alpha.test',
      authenticated: true, records: [{ usage: 3, selector: 1, matchingType: 1, data }] }] },
  }),
})], { options: Object.assign({}, OPTIONS, { deepChecks: false }) }));
const mixed = compareReports(daneBlockedScored('beef', 70), daneBlockedScored('cafe', 80)).domains[0];
eq('a blocked record change alongside a comparable score delta is not incomparable',
  mixed.status, 'improved');
eq('the score delta is still reported', mixed.scoreDelta, 10);
eq('and the blocked change is still withheld from recordChanges',
  mixed.recordChanges.map(c => c.path), []);
// The control: same blocked change, no score movement, IS incomparable.
eq('with no comparable movement at all it is incomparable',
  compareReports(daneBlockedScored('beef', 70), daneBlockedScored('cafe', 70)).domains[0].status,
  'incomparable');

/* -- 6. Deterministic status precedence ------------------------------- */
section('6. Status precedence, in the order section 5 fixes');

const withFindings = (list, over) => roundTrip(build([richResult(
  Object.assign({ findings: list }, over || {}))]));
const finding = (id, severity, protocol) => ({
  id, protocol: protocol || 'dmarc', severity, confidence: 'confirmed',
  category: 'policy', effort: 'moderate', args: ['a'], dependsOn: ['x'],
  evidence: [{ kind: 'txt', queryName: 'q', value: 'v' }],
});
const statusOf = (b, c) => compareReports(b, c).domains[0].status;

const critical = withFindings([finding('a.crit', 'critical')]);
const low = withFindings([finding('b.low', 'low')]);
const both = withFindings([finding('a.crit', 'critical'), finding('b.low', 'low')]);
const none = withFindings([]);

eq('a domain only in the current report is added',
  compareReports(build([]), base).domains[0].status, 'added');
eq('a domain only in the baseline is removed',
  compareReports(base, build([])).domains[0].status, 'removed');
eq('identical reports are unchanged', statusOf(base, base), 'unchanged');

// Step 4, the headline case: severity decides, not counts.
eq('resolving a critical while gaining a low is improved',
  statusOf(critical, low), 'improved');
eq('and the reverse is regressed', statusOf(low, critical), 'regressed');
eq('resolving one critical beats gaining two lows',
  statusOf(both, withFindings([finding('b.low', 'low'), finding('c.low', 'low')])), 'improved');
eq('a severity increase is a regression',
  statusOf(withFindings([finding('a.x', 'low')]), withFindings([finding('a.x', 'critical')])), 'regressed');
eq('a severity decrease is an improvement',
  statusOf(withFindings([finding('a.x', 'critical')]), withFindings([finding('a.x', 'low')])), 'improved');
eq('a severity change is reported with both ends',
  compareReports(withFindings([finding('a.x', 'low')]), withFindings([finding('a.x', 'high')]))
    .domains[0].findings.severityChanged, [{ id: 'a.x', from: 'low', to: 'high' }]);

// Step 5: score only breaks a finding tie.
const scored = pts => withFindings([], { score: provenScore(pts) });
eq('with no finding movement, a positive score delta is improved',
  statusOf(scored(70), scored(80)), 'improved');
eq('and a negative one is regressed', statusOf(scored(80), scored(70)), 'regressed');
eq('the delta is reported', compareReports(scored(70), scored(80)).domains[0].scoreDelta, 10);
eq('finding movement outranks the score', (() => {
  const worseScoreBetterFindings = withFindings([finding('b.low', 'low')], { score: provenScore(10) });
  const betterScoreWorseFindings = withFindings([finding('a.crit', 'critical')], { score: provenScore(99) });
  return statusOf(betterScoreWorseFindings, worseScoreBetterFindings);
})(), 'improved');

// Step 3: different generator versions cannot claim improvement.
const v1 = roundTrip(build([richResult({ findings: [finding('a.crit', 'critical')] })]));
const v2 = roundTrip(build([richResult({ findings: [] })], { versions: { app: '1.0.0', analysis: 1 } }));
eq('a cross-version diff is changed, never improved', statusOf(v1, v2), 'changed');
eq('findingSemanticsMatch says why', compareReports(v1, v2).meta.findingSemanticsMatch, false);
eq('but the raw id diff is still produced',
  compareReports(v1, v2).domains[0].findings.resolved, ['a.crit']);
// The hole this closes: two releases can share an analysisVersion, so the score
// stays comparable while the finding semantics do not. A score-only move must
// still not read as improvement.
const crossVersionScore = (pts, app) => roundTrip(build([richResult({ findings: [], score: provenScore(pts) })],
  { versions: { app, analysis: 1 } }));
eq('a score-only move across generator versions is changed, not improved',
  statusOf(crossVersionScore(70, '0.9.0'), crossVersionScore(80, '0.9.1')), 'changed');
eq('and downward it is changed, not regressed',
  statusOf(crossVersionScore(80, '0.9.0'), crossVersionScore(70, '0.9.1')), 'changed');
eq('while the same move within one version is improved',
  statusOf(crossVersionScore(70, '0.9.0'), crossVersionScore(80, '0.9.0')), 'improved');

// Section 2 gates score AND grade on the analysis version.
const gradeAt = (grade, analysis) => roundTrip(build([richResult({
  findings: [], score: Object.assign(provenScore(70), { grade }),
})], { versions: { app: '0.9.0', analysis } }));
eq('a grade change across analysis versions is not reported',
  compareReports(gradeAt('B', 1), gradeAt('A', 2)).domains[0].gradeChange, null);
eq('and neither is the delta',
  compareReports(gradeAt('B', 1), gradeAt('A', 2)).domains[0].scoreDelta, null);
eq('while within one analysis version the grade change is reported',
  compareReports(gradeAt('B', 1), gradeAt('A', 1)).domains[0].gradeChange, { from: 'B', to: 'A' });

// Score comparability is separate from finding comparability.
const otherAnalysis = roundTrip(build([richResult({ findings: [] })], { versions: { app: '0.9.0', analysis: 2 } }));
eq('a different analysisVersion nulls the score delta',
  [compareReports(none, otherAnalysis).domains[0].scoreComparable,
    compareReports(none, otherAnalysis).domains[0].scoreDelta],
  [false, null]);
eq('an unproven scored pillar also nulls it',
  compareReports(base, base).domains[0].scoreComparable, false);
eq('while a fully proven pair is comparable',
  compareReports(scored(70), scored(70)).domains[0].scoreComparable, true);

// Step 2: state mismatch and total incomparability.
eq('a state mismatch is incomparable', (() => {
  const cmp = compareReports(build([richResult()]), build([{ domain: 'alpha.test', unregistered: true }]));
  return [cmp.domains[0].status, cmp.domains[0].incomparableReasons];
})(), ['incomparable', ['state']]);
eq('two unregistered sides are unchanged, not incomparable',
  compareReports(build([{ domain: 'a.test', unregistered: true }]),
    build([{ domain: 'a.test', unregistered: true }])).domains[0].status, 'unchanged');
eq('no comparable protocol at all is incomparable', (() => {
  const blind = PROTOCOL_TOKENS.reduce((m, p) => { m[p] = 'not-run'; return m; }, {});
  const b = roundTrip(build([richResult({ observability: blind })]));
  const c = roundTrip(build([richResult({ observability: blind, findings: [] })]));
  const d = compareReports(b, c).domains[0];
  return [d.status, d.incomparableReasons.includes('no-comparable-protocol')];
})(), ['incomparable', true]);

eq('the summary counts every domain exactly once', (() => {
  const cmp = compareReports(build([richResult()]), build([richResult(), richResult({ domain: 'new.test' })]));
  const total = DOMAIN_STATUSES.reduce((n, s) => n + cmp.summary[s], 0);
  return [total, cmp.domains.length];
})(), [2, 2]);
eq('domains come back in a deterministic order',
  compareReports(build([richResult({ domain: 'z.test' }), richResult({ domain: 'a.test' })]),
    build([richResult({ domain: 'a.test' }), richResult({ domain: 'z.test' })]))
    .domains.map(d => d.domain), ['a.test', 'z.test']);
eq('every status the comparison emits is a registered one', (() => {
  const cmp = compareReports(base, advancedOff);
  return cmp.domains.filter(d => DOMAIN_STATUSES.indexOf(d.status) === -1);
})(), []);

/* -- 7. Nothing here touches the DOM or persists ---------------------- */
section('7. Pure by construction');

eq('the module reaches no storage or DOM API', (() => {
  // The module is pure data code, so a reference to any of these would be a
  // boundary violation rather than a feature. Read from source, because the
  // absence of a call is not observable by calling it.
  //
  // The names are ASSEMBLED rather than written out: `platform.test.mjs` scans
  // every file under `src/` for ambient primitives, this one included, so a
  // literal `document` here would make the test that forbids it look like the
  // violation. TextEncoder is on the list for the same reason it was removed
  // from the module -- it is an ambient the platform does not name.
  const banned = ['local|Storage', 'indexed|DB', 'session|Storage',
    'docu|ment.', 'wind|ow.', 'fet|ch(', 'TextEn|coder',
    // `Date` and `isNaN` joined the list at I7: the timestamp check briefly
    // validated the calendar by round-tripping through `Date`, which is a
    // browser primitive the platform contract owns. It escaped the lexical
    // ambient scan only because that catalog does not list the name.
    'new Da|te', 'isNa|N(']
    .map(name => name.replace('|', ''));
  return banned.filter(b => SOURCE.includes(b));
})(), []);
// Proven able to see one. Stripping comments is what makes the check honest;
// it must not also make it blind.
eq('and the same check catches a real ambient use', (() => {
  const withUse = normalizeSource('function f() {\n  // a remark\n  return docu' + 'ment.querySelector("x");\n}');
  return ['docu|ment.', 'fet|ch('].map(n => n.replace('|', '')).filter(b => withUse.includes(b));
})(), ['docu' + 'ment.']);
eq('while a comment mentioning one is not a use', (() => {
  const mentionOnly = normalizeSource('function f() {\n  // avoids docu' + 'ment on purpose\n  return 1;\n}');
  return mentionOnly.includes('docu' + 'ment');
})(), false);

report();
