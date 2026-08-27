#!/usr/bin/env node
/**
 * `file://` still works. Acceptance criterion, and Task 1.6's biggest risk.
 *
 *   node tests/build/file-url.test.mjs
 *
 * `js/locales-en.js` states in its own generated header that English is inlined
 * "so the app works when index.html is opened directly from disk (file://),
 * where fetching locales/*.json is blocked by the browser". That file is
 * 125,172 bytes — about 18% of the payload — bought and paid for exactly this.
 * `OQ-ARCH-06` chose an IIFE bundle over an ES module for the same reason: a
 * module script is fetched with CORS, which `file://` refuses outright.
 *
 * **Structural reasoning is not evidence here.** "It is a classic script and
 * the English is inlined, therefore file:// works" is the shape of argument
 * this project has been wrong with before. So this drives a real browser engine
 * at a real `file://` URL and asks the page what happened.
 *
 * Headless Chrome over the DevTools Protocol, with Node's built-in WebSocket —
 * no dependency is added for it, and none may be: the release ships exactly one
 * devDependency. If no Chrome is installed the suite REFUSES rather than
 * skipping: a `file://` check that quietly passes when it did not run is worth
 * less than none.
 */

import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const CHROME_CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  process.env.CHROME_PATH,
].filter(Boolean);

const chrome = CHROME_CANDIDATES.find(existsSync);

/* ── 0. The instrument ────────────────────────────────────────────────── */
section('0. A real browser engine');

eq('a Chromium-family browser is available to test with', Boolean(chrome), true);
if (!chrome) {
  console.log('\n  No Chrome, Chromium or Edge found, and this check refuses to skip.');
  console.log('  Set CHROME_PATH, or install one. `file://` is an acceptance criterion');
  console.log('  and structural reasoning is not evidence for it.');
  report();
  process.exit(1);
}

/* ── 1. Drive it ──────────────────────────────────────────────────────── */

const profile = mkdtempSync(join(tmpdir(), 'file-url-'));
const port = 9222 + (process.pid % 400);
const child = spawn(chrome, [
  '--headless=new',
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-gpu',
  // Deliberately NOT --allow-file-access-from-files. The point is that the app
  // works under a browser's ordinary file:// restrictions, not that it works
  // when those restrictions are lifted.
  'about:blank',
], { stdio: ['ignore', 'ignore', 'ignore'] });

// Tolerant on purpose. The browser holds its profile open for a moment after
// SIGKILL, and a temp directory that outlives the run is not a test result —
// letting it throw would turn a green check into a red one for no reason.
const cleanup = () => {
  try { child.kill('SIGKILL'); } catch { /* already gone */ }
  try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  catch { /* the OS will reap it */ }
};
process.on('exit', cleanup);

async function targets() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      const list = await response.json();
      if (list.length) return list;
    } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error('file-url: headless browser did not start');
}

/** One CDP round trip per call. Enough for navigate-then-evaluate. */
function connect(wsUrl) {
  const socket = new WebSocket(wsUrl);
  const pending = new Map();
  let nextId = 1;
  const ready = new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  });
  return {
    ready,
    send(method, params = {}) {
      const id = nextId++;
      return new Promise(resolve => {
        pending.set(id, resolve);
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close: () => socket.close(),
  };
}

const list = await targets();
const page = list.find(t => t.type === 'page') || list[0];
const cdp = connect(page.webSocketDebuggerUrl);
await cdp.ready;

const fileUrl = pathToFileURL(join(REPO, 'index.html')).href;
await cdp.send('Page.enable');
await cdp.send('Runtime.enable');
await cdp.send('Page.navigate', { url: fileUrl });

// Wait for the document to finish and the script to have run.
for (let attempt = 0; attempt < 80; attempt++) {
  const state = await cdp.send('Runtime.evaluate', {
    expression: 'document.readyState === "complete" && typeof window.DnsAudit',
    returnByValue: true,
  });
  if (state.result?.result?.value === 'object') break;
  await new Promise(resolve => setTimeout(resolve, 250));
}

const evaluate = async expression => {
  const response = await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (response.result?.exceptionDetails) {
    return { error: response.result.exceptionDetails.text || 'threw' };
  }
  return response.result?.result?.value;
};

/* ── 2. What the page reports about itself ────────────────────────────── */
section('1. The page loaded from file://');

const facts = await evaluate(`JSON.stringify({
  protocol: location.protocol,
  scripts: [...document.querySelectorAll('script[src]')].map(s => s.getAttribute('src')),
  moduleScripts: document.querySelectorAll('script[type=module]').length,
  globals: ['DnsAudit','R','i18n','t','tp','tRaw','startAudit','cancelAudit','__APP_TEST__',
            '__PUBLIC_SUFFIX_RULES__','__I18N_EN__','__DKIM_SELECTOR_CATALOG__']
           .filter(n => typeof window[n] !== 'undefined'),
  dnsAuditMembers: Object.keys(DnsAudit).length,
  pslRules: __PUBLIC_SUFFIX_RULES__.length,
  weights: DnsAudit.WEIGHTS,
  lang: i18n.lang,
  title: t('doc.title'),
  documentTitle: document.title,
  auditButton: document.getElementById('auditBtn') ? document.getElementById('auditBtn').textContent.trim() : null,
  translatedNodes: document.querySelectorAll('[data-i18n]').length
})`);
const page1 = typeof facts === 'string' ? JSON.parse(facts) : facts;

eq('the page really is on file://', page1?.protocol, 'file:');
eq('it loads exactly one script', page1?.scripts?.length, 1);
eq('and it is the built artifact', page1?.scripts?.[0], 'dist/app.min.js');
eq('no script is a module — a module would be blocked by CORS here', page1?.moduleScripts, 0);

section('2. The application initialised');

eq('all twelve probed globals exist', page1?.globals?.length, 12);
eq('DnsAudit has its full surface', page1?.dnsAuditMembers, 95);
eq('the whole public suffix list is present', page1?.pslRules, 10239);
eq('the scoring weights are intact',
  JSON.stringify(page1?.weights),
  JSON.stringify({ dmarc: 30, spf: 15, dkim: 15, dnssec: 15, caa: 10, mtaSts: 8, bimi: 4, tlsRpt: 3 }));

section('3. i18n resolved with no network');

// The point of the inlined English bundle. Under file:// a fetch of
// locales/en.json is blocked, so if the app is showing real text it can only
// have come from __I18N_EN__.
eq('the i18n layer selected English', page1?.lang, 'en');
eq('t() returns real text, not the key',
  page1?.title, 'DNS & Email Security Auditor — Free SPF, DKIM, DMARC & DNSSEC Checker');
eq('the document title was translated in place', page1?.documentTitle, page1?.title);
eq('the audit button carries translated text, not a placeholder',
  /Run Audit/i.test(page1?.auditButton || ''), true);
eq('and the page has translatable nodes to have done it to', page1?.translatedNodes > 20, true);

section('4. The engine ran real work');

// Not a smoke test: this reads the bundled PSL and runs the DER key walk, both
// of which would fail quietly if bundling had damaged the generated data.
const computed = await evaluate(`JSON.stringify({
  org: DnsAudit.getOrganizationalDomain('foo.blogspot.com'),
  ck: DnsAudit.getOrganizationalDomain('a.b.ck'),
  grade: DnsAudit.gradeFor(94, true),
  key: (() => { const k = DnsAudit.analyzeDkimKey('v=DKIM1; k=rsa; p=' + ${JSON.stringify(
    (await import('../fixtures/equivalence/keys.mjs')).RSA_2048_SPKI)});
    return { bits: k.keyBits, encoding: k.keyEncoding, valid: k.valid }; })()
})`);
const page2 = typeof computed === 'string' ? JSON.parse(computed) : computed;

eq('the org-domain walk reads the real bundled PSL', page2?.org, 'foo.blogspot.com');
eq('and resolves a wildcard rule', page2?.ck, 'a.b.ck');
eq('the grader works', JSON.stringify(page2?.grade), JSON.stringify({ grade: 'A++', cls: 'score-aplusplus' }));
eq('the DER key walk read a 2048-bit modulus', page2?.key?.bits, 2048);
eq('from an SPKI envelope', page2?.key?.encoding, 'spki');

section('5. Nothing failed silently');

const errors = await evaluate(`JSON.stringify(window.__fileUrlErrors || [])`);
eq('no uncaught error was recorded', JSON.parse(errors || '[]'), []);
// The negative control: the harness can see a failure when there is one.
const control = await evaluate(`typeof window.__definitely_not_defined__`);
eq('the harness reports an absent global as absent', control, 'undefined');

cdp.close();
cleanup();
report();
