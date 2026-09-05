#!/usr/bin/env node
/**
 * Measurement-only spike for 0.9.2's divergence procedure. NOT an implementation.
 *
 *   node docs/specs/fixtures/ptr-fan-out-spike-0.9.2.mjs
 *
 * `OQ-MXV-03` asked what 0.9.2's PTR fan-out costs, and required query traces
 * rather than an argument. Counting addresses in the v0.9.1 oracle answers only
 * how many PTR calls the algorithm would REQUEST; it cannot answer what the
 * forward-confirm step costs, because v0.9.1 holds no PTR answers from which a
 * candidate name could be selected. So this executes §4 literally against a
 * recording resolver and reports the queries it actually issued.
 *
 * The qualifying hosts and their addresses are read from the committed
 * `baseline-v0.9.1.json`, so the input is the real corpus and not invented. The
 * PTR and forward answers are a fixture, because no such answers exist yet;
 * each one is chosen to exercise a different branch of §4, and they are listed
 * in the capture beside this file.
 *
 * Nothing here is imported by `src/`. It is evidence, and it is reproducible.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const baseline = JSON.parse(
  readFileSync(join(REPO, 'tests/fixtures/equivalence/baseline-v0.9.1.json'), 'utf8'));

/* ── The fixture, one branch of §4 per domain ─────────────────────────── */

const SERVFAIL = Symbol('servfail');
const PTR_ANSWERS = {
  // Divergent: provider publishes an address the customer's copy does not.
  '100.2.0.20': ['mailfilter.provider.test'],
  '2a01:100::20': ['mailfilter.provider.test'],
  // Self-hosted: the reverse name is inside the audited domain, so there is no
  // separate provider name to compare against and step 2 selects no candidate.
  '100.51.100.5': ['mail.bravo.test'],
  // No PTR published at all — an answer, and therefore a claim of absence.
  '100.0.113.5': [],
  // The lookup did not return. Not a claim either way.
  '100.0.113.9': SERVFAIL,
  // A reverse name that does not forward-confirm: step 3 must stop.
  '100.0.113.11': ['unconfirmed.provider.test'],
  // Equal address sets: confirmed, compared, and correctly reports nothing.
  '100.0.113.13': ['equal.provider.test'],
  // Divergent again, on a second domain.
  '100.51.100.10': ['mailfilter.provider.test'],
};
const FORWARD_ANSWERS = {
  'mailfilter.provider.test': { A: ['100.2.0.20', '100.51.100.10', '100.9.9.9'], AAAA: ['2a01:100::20'] },
  // Resolves, but to nothing the audited domain published — fails confirmation.
  'unconfirmed.provider.test': { A: ['203.0.113.200'], AAAA: [] },
  'equal.provider.test': { A: ['100.0.113.13'], AAAA: [] },
};

/* ── A resolver that records every question asked ─────────────────────── */

function recordingResolver() {
  const asked = [];
  return {
    asked,
    query(name, type) {
      asked.push(`${name}/${type}`);
      if (type === 'PTR') {
        const answer = PTR_ANSWERS[name];
        if (answer === SERVFAIL) return null;      // did not return
        return answer || [];
      }
      const entry = FORWARD_ANSWERS[name];
      return entry ? (entry[type] || []) : [];
    },
  };
}

/* ── §4, executed literally ───────────────────────────────────────────── */

const MAX_HOSTS = 2;          // §4, added by the 0.14 privacy review
const MAX_ADDRESSES = 4;
const MAX_CANDIDATES = 2;

function divergenceForDomain(domain, hosts, resolver) {
  const qualifying = hosts
    .filter(h => h.inAudited && h.resolves === 'yes' && h.reachability !== 'none')
    .sort((a, b) => a.preference - b.preference)
    .slice(0, MAX_HOSTS);

  const findings = [];
  const candidates = [];
  for (const host of qualifying) {
    const names = [];
    let anyReturned = false;
    for (const address of (host.addresses || []).slice(0, MAX_ADDRESSES)) {
      const answer = resolver.query(address, 'PTR');
      if (answer === null) continue;              // per-address, never per-host
      anyReturned = true;
      names.push(...answer);
    }
    if (!anyReturned) continue;                   // reverseNames null: no claim
    if (!names.length) { findings.push({ domain, host: host.host, finding: 'mx.no-reverse-dns' }); continue; }

    const candidate = names.find(n =>
      n !== host.host && n !== domain && !n.endsWith('.' + domain));
    if (!candidate) continue;                     // self-hosted
    if (!candidates.includes(candidate)) {
      if (candidates.length >= MAX_CANDIDATES) continue;
      candidates.push(candidate);
    }

    const providerA = resolver.query(candidate, 'A');
    const providerAAAA = resolver.query(candidate, 'AAAA');
    const provider = [...providerA, ...providerAAAA];
    const confirmed = (host.addresses || []).some(a => provider.includes(a));
    if (!confirmed) continue;                     // step 3 stops

    const missing = provider.filter(a => !(host.addresses || []).includes(a));
    const strictSuperset = missing.length > 0
      && (host.addresses || []).every(a => provider.includes(a));
    if (strictSuperset) findings.push({ domain, host: host.host, finding: 'mx.vanity-divergent', missing });
  }
  return findings;
}

/* ── Run it over the real corpus ──────────────────────────────────────── */

function run({ deepChecks }) {
  const resolver = recordingResolver();
  const findings = [];
  let audited = 0;
  let qualifyingHosts = 0;
  for (const testCase of baseline.cases) {
    for (const entry of testCase.result) {
      const result = entry.result;
      if (!result) continue;
      audited++;
      const mxHealth = deepChecks && result.advanced && result.advanced.mxHealth;
      if (!mxHealth) continue;
      const hosts = mxHealth.hosts || [];
      qualifyingHosts += hosts.filter(h =>
        h.inAudited && h.resolves === 'yes' && h.reachability !== 'none').length;
      findings.push(...divergenceForDomain(result.domain, hosts, resolver));
    }
  }
  const ptr = resolver.asked.filter(q => q.endsWith('/PTR'));
  const forward = resolver.asked.filter(q => !q.endsWith('/PTR'));
  return { audited, qualifyingHosts, ptr, forward, findings, asked: resolver.asked };
}

const on = run({ deepChecks: true });
console.log('OBSERVED, deep checks on');
console.log(`  domains audited                 : ${on.audited}`);
console.log(`  qualifying hosts                : ${on.qualifyingHosts}`);
console.log(`  PTR queries ISSUED              : ${on.ptr.length}`);
console.log(`  forward-confirm queries ISSUED  : ${on.forward.length}`);
console.log(`  TOTAL additional queries        : ${on.asked.length}`);
console.log(`  per audited domain              : ${(on.asked.length / on.audited).toFixed(3)}`);
console.log('  findings produced:');
for (const f of on.findings) console.log(`    ${f.finding.padEnd(22)} ${f.domain} (${f.host})${f.missing ? ' missing ' + JSON.stringify(f.missing) : ''}`);
console.log('  every question asked:');
for (const q of on.asked) console.log(`    ${q}`);

// The negative control. With the gate off there is no mxHealth to read, so the
// procedure must issue nothing at all — otherwise the measurement above would
// be counting queries the gate was supposed to prevent.
const off = run({ deepChecks: false });
console.log('\nNEGATIVE CONTROL, deep checks off');
console.log(`  queries issued                  : ${off.asked.length}  (must be 0)`);
console.log(`  findings produced               : ${off.findings.length}  (must be 0)`);
if (off.asked.length !== 0 || off.findings.length !== 0) {
  console.error('CONTROL FAILED');
  process.exit(1);
}
