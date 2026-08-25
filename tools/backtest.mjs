#!/usr/bin/env node
/**
 * Grade-distribution back-test.
 *
 * Loads the real scoring code from js/dns.js and runs it against live domains
 * over Cloudflare DNS-over-HTTPS, then prints the resulting letter-grade
 * histogram and score percentiles. Use it to sanity-check GRADE_THRESHOLDS
 * before shipping a scoring change — a rubric that lands 80% of the internet
 * on F is measuring the wrong thing.
 *
 *   node tools/backtest.mjs domains.txt
 *   node tools/backtest.mjs domains.txt --json > before.json
 *   node tools/backtest.mjs --sample              # built-in 40-domain sample
 *   node tools/backtest.mjs domains.txt --comprehensive-dkim # max 5 domains
 *   node tools/backtest.mjs --sample --deep      # with MX health + TLSA
 *
 * Every run also reports the DNS query fan-out — the number of DoH requests
 * actually issued, per domain. `PRIVACY.md` states that number publicly, so it
 * is measured here rather than estimated, and re-measured whenever a release
 * changes how many lookups an audit makes.
 *
 * Requires outbound network access, so run it locally rather than in CI.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const asJson = args.includes('--json');
const useSample = args.includes('--sample');
const comprehensiveDkim = args.includes('--comprehensive-dkim');
// The deep protocol checks (MX health, TLSA) are the only part of an audit
// whose cost scales with the audited domain's own configuration, so their
// fan-out has to be measured rather than reasoned about. PRIVACY.md states the
// number with and without them; this flag is how both halves are obtained.
const deepChecks = args.includes('--deep');
const fileArg = args.find(a => !a.startsWith('--'));

// A spread of well-known domains across sectors and maturity levels. Not a
// statistical sample — a smoke test. For real validation feed a top-1000 list.
const SAMPLE = [
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
  'github.com', 'gitlab.com', 'cloudflare.com', 'netflix.com', 'spotify.com',
  'paypal.com', 'stripe.com', 'square.com', 'chase.com', 'wellsfargo.com',
  'irs.gov', 'nasa.gov', 'nih.gov', 'gov.uk', 'europa.eu',
  'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk',
  'wikipedia.org', 'mozilla.org', 'eff.org', 'archive.org',
  'shopify.com', 'salesforce.com', 'oracle.com', 'ibm.com', 'sap.com',
  'slack.com', 'notion.so', 'figma.com', 'atlassian.com', 'zoom.us',
  'nytimes.com', 'bbc.co.uk',
];

const domains = useSample
  ? SAMPLE
  : readFileSync(fileArg || join(ROOT, 'domains.txt'), 'utf8')
    .split(/\r?\n/).map(s => s.trim().toLowerCase())
    .filter(s => s && !s.startsWith('#'));

if (comprehensiveDkim && domains.length > 5) {
  throw new Error('Comprehensive DKIM scanning is limited to 5 domains per run.');
}

// ── Load the production scoring code, unmodified ────────────────────────
// Counted, not merely passed through: the fan-out figure in PRIVACY.md is a
// promise to the reader about what Cloudflare gets to see, and an estimate is
// not good enough for it. This counts requests that actually reach the
// network, so the cache's effect on a multi-domain run is included — which is
// the honest number, since that is what a real audit sends.
let networkQueries = 0;
const countingFetch = (...args) => { networkQueries++; return fetch(...args); };

const sandbox = {
  window: {},
  fetch: countingFetch,
  AbortController,
  console,
  URLSearchParams,
  setTimeout,
  clearTimeout,
  Promise,
  Math,
  JSON,
  Set,
  Array,
  String,
  Number,
  isNaN,
  parseInt,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(readFileSync(join(ROOT, 'js', 'public-suffixes.js'), 'utf8'), sandbox);
vm.runInContext(readFileSync(join(ROOT, 'js', 'dkim-selectors.js'), 'utf8'), sandbox);
vm.runInContext(readFileSync(join(ROOT, 'js', 'dns.js'), 'utf8'), sandbox);
const D = sandbox.window.DnsAudit;

const OPTS = { dkim: true, dkimComprehensive: comprehensiveDkim, www: false, advanced: true, wildcard: false, deepChecks };
const CONCURRENCY = 6;

const results = [];
let done = 0;

async function worker(queue) {
  while (queue.length) {
    const domain = queue.shift();
    try {
      const r = await D.analyzeDomain(domain, OPTS);
      results.push(r);
    } catch (e) {
      results.push({ domain, error: true, message: e.message });
    }
    done++;
    if (!asJson) process.stderr.write(`\r  ${done}/${domains.length} …`);
  }
}

const queue = [...domains];
await Promise.all(
  Array.from({ length: Math.min(CONCURRENCY, domains.length) }, () => worker(queue))
);
if (!asJson) process.stderr.write('\r' + ' '.repeat(40) + '\r');

// ── Report ──────────────────────────────────────────────────────────────
const scored = results.filter(r => !r.error && !r.unregistered && r.score);
const BASE_ORDER = ['A++', 'A+', 'A', 'B', 'C', 'D', 'F'];

function gradeSort(a, b) {
  return BASE_ORDER.indexOf(a) - BASE_ORDER.indexOf(b);
}

const fanOut = {
  networkQueries,
  domains: results.length,
  perDomain: results.length ? Number((networkQueries / results.length).toFixed(1)) : 0,
};

if (asJson) {
  console.log(JSON.stringify({
    weights: D.WEIGHTS,
    thresholds: D.GRADE_THRESHOLDS,
    fanOut,
    domains: scored.map(r => ({
      domain: r.domain, grade: r.score.grade, pts: r.score.pts,
      dmarc: r.dmarcStatus.policy, sp: r.dmarcStatus.effectiveSp,
      np: r.dmarcStatus.effectiveNp, pct: r.dmarcStatus.pct,
      // Tree Walk provenance, so a diff between two runs can explain a grade
      // move by naming the record that moved rather than just the number.
      dmarcFoundAt: r.dmarcDiscovery?.applied?.foundAt ?? null,
      dmarcLabelsUp: r.dmarcDiscovery?.applied?.labelsUp ?? null,
      dmarcTerminated: r.dmarcDiscovery?.terminated ?? null,
      dmarcQueries: r.dmarcDiscovery?.queries ?? null,
      dmarcObserved: (r.dmarcDiscovery?.observed ?? []).map(o => o.why),
      organizationalDomain: r.organizationalDomain ?? null,
      dmarcStatus: r.dmarcStatus.status,
      dnssec: !!r.advanced?.dnssec?.signed,
      dkim: {
        found: r.dkimStatus.found,
        scanMode: r.dkimStatus.scanMode,
        selectors: r.dkimStatus.selectors,
        missingSelectors: r.dkimStatus.missingSelectors,
        failedSelectors: r.dkimStatus.failedSelectors,
      },
      pillars: r.score.breakdown?.pillars,
    })),
  }, null, 2));
  process.exit(0);
}

const displayedGrades = Array.from(new Set([
  ...BASE_ORDER,
  ...scored.map(r => r.score.grade),
])).sort(gradeSort);
const counts = Object.fromEntries(displayedGrades.map(g => [g, 0]));
scored.forEach(r => { counts[r.score.grade]++; });

const counted = Object.values(counts).reduce((sum, count) => sum + count, 0);
if (counted !== scored.length) {
  throw new Error(`Grade histogram counted ${counted} of ${scored.length} scored domains.`);
}

console.log(`\nGRADE DISTRIBUTION  (${scored.length} scored, ${results.length - scored.length} skipped)\n`);
const widest = Math.max(...Object.values(counts), 1);
const gradeWidth = Math.max(4, ...displayedGrades.map(g => g.length));
for (const g of displayedGrades) {
  const n = counts[g];
  const pct = scored.length ? (n / scored.length * 100) : 0;
  const bar = '█'.repeat(Math.round(n / widest * 40));
  console.log(`  ${g.padEnd(gradeWidth)} ${String(n).padStart(3)}  ${pct.toFixed(1).padStart(5)}%  ${bar}`);
}

const pts = scored.map(r => r.score.pts).sort((a, b) => a - b);
const pctl = p => pts.length ? pts[Math.min(pts.length - 1, Math.floor(p / 100 * pts.length))] : 0;
console.log(`\nSCORE PERCENTILES`);
console.log(`  min ${pts[0]}   p25 ${pctl(25)}   median ${pctl(50)}   p75 ${pctl(75)}   p90 ${pctl(90)}   max ${pts[pts.length - 1]}`);
console.log(`  mean ${(pts.reduce((a, b) => a + b, 0) / (pts.length || 1)).toFixed(1)}`);

// Per-pillar adoption tells you whether a weight is doing any work at all.
console.log(`\nPILLAR ADOPTION  (% of scored domains earning full marks)`);
const pillarKeys = scored[0]?.score.breakdown?.pillars.map(p => p.key) || [];
for (const key of pillarKeys) {
  const full = scored.filter(r => {
    const p = r.score.breakdown.pillars.find(x => x.key === key);
    return p && p.max && p.pts >= p.max;
  }).length;
  const zero = scored.filter(r => {
    const p = r.score.breakdown.pillars.find(x => x.key === key);
    return p && p.pts === 0;
  }).length;
  console.log(`  ${key.padEnd(8)} full ${String(Math.round(full / scored.length * 100)).padStart(3)}%   zero ${String(Math.round(zero / scored.length * 100)).padStart(3)}%`);
}

console.log(`\nWORST 10`);
scored.slice().sort((a, b) => a.score.pts - b.score.pts).slice(0, 10)
  .forEach(r => console.log(`  ${r.score.grade.padEnd(4)} ${String(r.score.pts).padStart(3)}  ${r.domain}`));
console.log(`\nBEST 10`);
scored.slice().sort((a, b) => b.score.pts - a.score.pts).slice(0, 10)
  .forEach(r => console.log(`  ${r.score.grade.padEnd(4)} ${String(r.score.pts).padStart(3)}  ${r.domain}`));

console.log(`\nDNS QUERY FAN-OUT`);
console.log(`  ${fanOut.networkQueries} network queries across ${fanOut.domains} domains`);
console.log(`  ${fanOut.perDomain} per domain (cache shared across the run, as in a real audit)`);
const dmarcQueries = results.filter(r => r.dmarcDiscovery).map(r => r.dmarcDiscovery.queries);
if (dmarcQueries.length) {
  console.log(`  Tree Walk: ${(dmarcQueries.reduce((a, b) => a + b, 0) / dmarcQueries.length).toFixed(1)} steps per domain, max ${Math.max(...dmarcQueries)}`);
}

const skipped = results.filter(r => r.error);
if (skipped.length) {
  console.log(`\nERRORS (${skipped.length})`);
  skipped.slice(0, 10).forEach(r => console.log(`  ${r.domain}: ${r.message}`));
}
console.log('');
