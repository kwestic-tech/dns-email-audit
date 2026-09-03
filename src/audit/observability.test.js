#!/usr/bin/env node
/**
 * Per-protocol observability. Spec: report-comparison 1.7 (Final), §1 and §5.
 *
 * Section 4 is the reason this module exists. The two cases there are the ones
 * that made the 1.0 draft's derivation — `score.unproven` plus the protocol of
 * any `confidence: 'unverified'` finding — wrong in BOTH directions, and they
 * are asserted against the real finding metadata rather than described.
 */
import { createSuite } from '../../tests/lib/assert.mjs';
import { PROTOCOLS, FINDING_META } from './findings.js';
import { OBSERVABILITY_STATES, buildObservability } from './observability.js';

const { eq, section, report } = createSuite();

const ALL_ON = { advanced: true, dkim: true, www: true, wildcard: true, deepChecks: true };

// A run where every check ran and every one completed.
const clean = (over) => buildObservability({
  options: { ...ALL_ON, ...((over && over.options) || {}) },
  dkimStatus: { confidence: 'observed', ...((over && over.dkimStatus) || {}) },
  dmarcDiscovery: { error: null, ...((over && over.dmarcDiscovery) || {}) },
  advanced: {
    spfLookups: { unknown: false }, spfSubnets: { unknown: false },
    dnssec: { state: 'secure' }, caa: { unknown: false },
    mtaSts: { unknown: false }, tlsRpt: { unknown: false }, bimi: { unknown: false },
    mxHealth: { unknown: false }, tlsa: { unknown: false }, reportAuth: [],
    ...((over && over.advanced) || {}),
  },
});

/* ── 1. The map is total and closed ───────────────────────────────────── */
section('1. Total over PROTOCOLS, closed over three states');

const full = clean();
eq('every protocol has a verdict', PROTOCOLS.filter(p => !(p in full)), []);
eq('and no protocol outside PROTOCOLS appears',
  Object.keys(full).filter(k => PROTOCOLS.indexOf(k) === -1), []);
eq('the map is exactly as wide as PROTOCOLS', Object.keys(full).length, PROTOCOLS.length);
eq('every value is a registered state',
  Object.values(full).filter(v => OBSERVABILITY_STATES.indexOf(v) === -1), []);
eq('a fully successful run observes everything',
  Object.values(full).filter(v => v !== 'observed'), []);

/* ── 2. `not-run`: the option gating the checks was off ───────────────── */
section('2. not-run follows the option gate');

eq('advanced off makes every advanced protocol not-run',
  ['dnssec', 'caa', 'mta-sts', 'tls-rpt', 'bimi'].map(p => clean({ options: { advanced: false } })[p]),
  ['not-run', 'not-run', 'not-run', 'not-run', 'not-run']);
eq('advanced off also stops the deep checks',
  [clean({ options: { advanced: false } }).mx, clean({ options: { advanced: false } }).dane],
  ['not-run', 'not-run']);
eq('deepChecks off makes mx and dane not-run',
  [clean({ options: { deepChecks: false } }).mx, clean({ options: { deepChecks: false } }).dane],
  ['not-run', 'not-run']);
eq('dkim off makes dkim not-run', clean({ options: { dkim: false } }).dkim, 'not-run');
// A wildcard TXT answers every _domainkey probe, so without the wildcard probe
// the audit cannot prove a selector is absent (spec §5's mapping).
eq('wildcard off makes dkim not-run too', clean({ options: { wildcard: false } }).dkim, 'not-run');
eq('www or wildcard off makes dns not-run',
  [clean({ options: { www: false } }).dns, clean({ options: { wildcard: false } }).dns],
  ['not-run', 'not-run']);
// Core records are always retrieved, so neither can ever be `not-run`...
eq('spf and dmarc are never not-run',
  [clean({ options: { advanced: false } }).spf, clean({ options: { advanced: false } }).dmarc]
    .filter(v => v === 'not-run'), []);
// ...but with `advanced` off their sub-audits did not run, so neither is
// `observed` either. Reporting `observed` here would let a comparison across an
// `advanced` mismatch call all eight advanced-gated SPF findings `resolved`.
// `advanced` defaults spfLookups/spfSubnets/reportAuth to null in
// audit-domain.js and fills them only inside the gate.
eq('advanced off leaves spf and dmarc unproven, not observed',
  [clean({ options: { advanced: false }, advanced: { spfLookups: null, spfSubnets: null, reportAuth: null } }).spf,
    clean({ options: { advanced: false }, advanced: { spfLookups: null, spfSubnets: null, reportAuth: null } }).dmarc],
  ['unproven', 'unproven']);

/* ── 3. `unproven`: the checks ran and did not conclude ───────────────── */
section('3. unproven follows the facts');

eq('a failed SPF lookup audit leaves spf unproven',
  clean({ advanced: { spfLookups: { unknown: true } } }).spf, 'unproven');
eq('a failed SPF subnet audit does too',
  clean({ advanced: { spfSubnets: { unknown: true } } }).spf, 'unproven');
eq('a Tree Walk error leaves dmarc unproven',
  clean({ dmarcDiscovery: { error: 'servfail' } }).dmarc, 'unproven');
eq('a sampled DKIM scan is unproven, not observed',
  clean({ dkimStatus: { confidence: 'sampled' } }).dkim, 'unproven');
eq('an indeterminate chain leaves dnssec unproven',
  clean({ advanced: { dnssec: { state: 'indeterminate' } } }).dnssec, 'unproven');
eq('a bogus chain is still an observation',
  clean({ advanced: { dnssec: { state: 'bogus' } } }).dnssec, 'observed');
eq('each advanced summary reports its own failed lookup',
  ['caa', 'mtaSts', 'tlsRpt', 'bimi'].map(key => {
    const state = clean({ advanced: { [key]: { unknown: true } } });
    return state[key === 'mtaSts' ? 'mta-sts' : key === 'tlsRpt' ? 'tls-rpt' : key];
  }),
  ['unproven', 'unproven', 'unproven', 'unproven']);
eq('a failed MX-health audit leaves mx unproven',
  clean({ advanced: { mxHealth: { unknown: true } } }).mx, 'unproven');
eq('a failed TLSA lookup leaves dane unproven',
  clean({ advanced: { tlsa: { unknown: true } } }).dane, 'unproven');
// A parked domain's null MX leaves both facts null even with deep checks on:
// there is no host to resolve. `unproven` rather than `not-run` because the
// option WAS on — the run simply has no MX observation to offer. The two are
// interchangeable to §5, which makes anything other than `observed`
// incomparable, so this picks the one that describes what happened.
eq('a null MX leaves mx and dane unproven, never observed',
  [clean({ advanced: { mxHealth: null, tlsa: null } }).mx,
    clean({ advanced: { mxHealth: null, tlsa: null } }).dane],
  ['unproven', 'unproven']);

/* ── 4. The two derivations RQ-CMP-08 rejected ────────────────────────── */
section('4. Finding confidence is not a proxy, and here is why');

// The 1.0 draft would have read the protocol off the unverified finding.
eq('dns.checks-unverified is protocol `dns`, so reading it marks the wrong control',
  [FINDING_META['checks-unverified'].id, FINDING_META['checks-unverified'].protocol,
    FINDING_META['checks-unverified'].confidence],
  ['dns.checks-unverified', 'dns', 'unverified']);
// ...which is why the MX/TLSA failure has to come from the FACTS instead.
const mxFailed = clean({ advanced: { mxHealth: { unknown: true }, tlsa: { unknown: true } } });
eq('an MX and TLSA failure marks mx and dane, not dns',
  [mxFailed.mx, mxFailed.dane, mxFailed.dns], ['unproven', 'unproven', 'observed']);

// The converse: an unverified DMARC finding that must NOT blank the DMARC diff.
eq('dmarc.external-unverifiable is an unverified finding on protocol `dmarc`',
  [FINDING_META['dmarc-external-unverifiable'].id,
    FINDING_META['dmarc-external-unverifiable'].protocol,
    FINDING_META['dmarc-external-unverifiable'].confidence],
  ['dmarc.external-unverifiable', 'dmarc', 'unverified']);
eq('a successful Tree Walk still reports dmarc observed', clean().dmarc, 'observed');
// The distinction that makes both halves work: DMARC goes unproven when the
// external-auth check did not RUN, never because the finding it produced was
// uncertain. A populated result with no `unknown` flag is an observation.
eq('an external-auth result that ran keeps dmarc observed, however uncertain',
  clean({ advanced: { reportAuth: [{ authorized: false, unverifiable: true }] } }).dmarc,
  'observed');
eq('but an external-auth check that never ran does not',
  clean({ advanced: { reportAuth: null } }).dmarc, 'unproven');
eq('the nine advanced-gated ids that make this load-bearing are still spf and dmarc',
  ['spf-over-limit', 'spf-near-limit', 'spf-cycle', 'spf-large-subnet',
    'spf-medium-subnet', 'spf-redundant-mechanism', 'spf-partial-coverage',
    'spf-indeterminate', 'dmarc-external-unverifiable']
    .map(k => FINDING_META[k].protocol),
  ['spf', 'spf', 'spf', 'spf', 'spf', 'spf', 'spf', 'spf', 'dmarc']);

/* ── 5. Cross-protocol tokens are conservative ────────────────────────── */
section('5. Cross-protocol tokens take the worst component');

eq('defensive follows mx and spf',
  [clean().defensive,
    clean({ advanced: { mxHealth: { unknown: true } } }).defensive,
    clean({ options: { deepChecks: false } }).defensive],
  ['observed', 'unproven', 'not-run']);
eq('reporting follows dmarc and tls-rpt',
  [clean().reporting,
    clean({ advanced: { tlsRpt: { unknown: true } } }).reporting,
    clean({ options: { advanced: false } }).reporting],
  ['observed', 'unproven', 'not-run']);
// not-run outranks unproven: never having looked is a stronger statement of
// ignorance than having looked and failed.
eq('not-run outranks unproven when the components disagree',
  clean({ options: { deepChecks: false }, dmarcDiscovery: { error: 'servfail' } }).defensive,
  'not-run');

/* ── 6. Missing input never reads as success ──────────────────────────── */
section('6. Absent facts fail closed');

const empty = buildObservability({});
eq('no options and no facts observes nothing at all',
  Object.entries(empty).filter(([, v]) => v === 'observed').map(([k]) => k).sort(), []);
eq('and it is still a total map', PROTOCOLS.filter(p => !(p in empty)), []);
eq('a call with no argument at all does not throw',
  Object.keys(buildObservability()).length, PROTOCOLS.length);

report();
