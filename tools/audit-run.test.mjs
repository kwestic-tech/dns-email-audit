#!/usr/bin/env node
/**
 * The audit run loop: how a run starts, and what stops a second one.
 *
 *   node tools/audit-run.test.mjs
 *
 * ── Why this suite exists separately from tools/render.test.mjs ──────────
 *
 * `render.test.mjs` calls one renderer at a time against a prepared result.
 * The defects this file covers are not in a renderer — they are in the order
 * of operations inside `startAudit()`, which is only reachable by booting the
 * application and clicking the button. So this suite builds the page from the
 * shipped `index.html` (via the equivalence runner's own skeleton builder, so
 * the ids are the subject's facts and not a hand-maintained copy), hands the
 * platform a `fetch` it controls, dispatches `DOMContentLoaded`, and drives
 * the controls.
 *
 * No seam was added to `src/`. `startAudit()` is not exported and is not
 * called directly here; the entry point is the click listener the application
 * registers on its own.
 *
 * ── The defect ──────────────────────────────────────────────────────────
 *
 * `startAudit()` read `auditController` as its re-entry guard and did not
 * write it until after `await checkConnectivity()`. A second click inside that
 * probe window passed the guard and started a second run. Both replaced
 * `results`, both reset the progress log and the table, and whichever finished
 * first set `auditController` to null and re-enabled the button while the
 * other was still querying — so Cancel no longer reached it. The published
 * per-run DNS fan-out doubled.
 *
 * The second half is the one a fix breaks: releasing the guard on every early
 * return. A run that assigns the controller and then bails on a failed
 * connectivity probe without clearing it locks the button for the rest of the
 * page's life, and because the button was never disabled nothing looks wrong.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadUi } from './lib/browser-harness.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX_HTML = readFileSync(join(repo, 'index.html'), 'utf8');

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
};
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

const click = (el) => el.dispatchEvent({ type: 'click', target: el });
const settle = (turns = 60) =>
  new Promise(resolve => { let n = turns; (function spin() { n-- ? setTimeout(spin, 5) : resolve(); })(); });

/**
 * Boot the application against a fetch this suite owns.
 *
 * `connectivity` decides what the pre-flight probe sees. Every DoH query is
 * counted and answered with an empty NOERROR after a turn of the event loop,
 * which is the shape that matters: the probe has to still be in flight when
 * the second click arrives, or there is no window to test.
 */
async function boot({ connectivity = true } = {}) {
  const calls = { probe: 0, dns: 0 };
  const fetch = async (url) => {
    const name = new URL(String(url), 'https://cloudflare-dns.com').searchParams.get('name') || '';
    const isProbe = name === 'example.com';
    if (isProbe) calls.probe++; else calls.dns++;
    await new Promise(resolve => setTimeout(resolve, 5));
    if (isProbe && !connectivity) return { ok: false, status: 502, headers: { get: () => null } };
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/dns-json' },
      json: async () => ({ Status: 0, Answer: [] }),
    };
  };
  const ui = await loadUi({ page: INDEX_HTML, fetch });
  ui.document.dispatchEvent({ type: 'DOMContentLoaded' });
  // Boot fires its own connectivity probe — `PRIVACY.md` publishes it as "once
  // per page load and once per run" — so let it finish and then zero the
  // counters. What every case below measures is the RUN's fan-out.
  await settle(20);
  calls.probe = 0;
  calls.dns = 0;
  return { ...ui, calls };
}

/* ── 1. One double click starts one run ──────────────────────────────── */
section('1. One double click starts one run');

{
  const { document, calls } = await boot();
  document.getElementById('domainInput').value = 'a.example\nb.example';

  const btn = document.getElementById('auditBtn');
  // Both clicks in the same tick, which is what a double click is. The first
  // suspends at `await checkConnectivity()`; the second arrives before its
  // continuation runs.
  click(btn);
  click(btn);
  await settle();

  // The probe is the measure the privacy documentation publishes: "once per
  // run, however many domains". Counting DNS queries instead would work too,
  // and is noisier — the run's own fan-out varies with the options.
  eq('the connectivity probe ran once, not twice', calls.probe, 1);
  eq('the run issued DNS queries at all', calls.dns > 0, true);
}

/* ── 2. A failed probe does not lock the interface ───────────────────── */
section('2. A failed probe does not lock the interface');

{
  const { document, calls } = await boot({ connectivity: false });
  document.getElementById('domainInput').value = 'a.example';
  const btn = document.getElementById('auditBtn');

  click(btn);
  await settle();
  eq('the offline banner is shown', document.getElementById('netBanner').style.display, 'block');
  eq('no DNS query was issued', calls.dns, 0);

  // The guard is now assigned before the probe, so a fix that forgets to
  // release it on this path leaves every later click returning in silence.
  click(btn);
  await settle();
  eq('a second attempt still reaches the probe', calls.probe, 2);
}

/* ── 3. An input the run refuses also releases the guard ─────────────── */
section('3. An input the run refuses also releases the guard');

{
  const { document, calls } = await boot();
  const btn = document.getElementById('auditBtn');

  // Empty input: refused before the probe, on a path that returns early.
  document.getElementById('domainInput').value = '';
  click(btn);
  await settle(5);
  eq('an empty input runs nothing', calls.probe, 0);

  document.getElementById('domainInput').value = 'a.example';
  click(btn);
  await settle();
  eq('and the next real run still starts', calls.probe, 1);
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
