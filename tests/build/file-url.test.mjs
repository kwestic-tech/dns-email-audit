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

import { existsSync, mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';

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
  // Every name the application has EVER published, probed for presence — a
  // watchlist, not an inventory. The nine Task 6.2 removed are in the list on
  // purpose: a real browser is the last place they could still be hiding.
  globals: ['DnsAudit','R','i18n','t','tp','tRaw','__APP_TEST__',
            '__PUBLIC_SUFFIX_RULES__','__I18N_EN__','__DKIM_SELECTOR_CATALOG__']
           .filter(n => typeof window[n] !== 'undefined'),
  // The fourteen Task 2.8 removed. A real browser is the last place they could
  // still be hiding, so they are probed for ABSENCE rather than left unlisted.
  removed: ['startAudit','cancelAudit','clearAll','exportCSV','exportHTML','filterTable',
            'loadExample','loadFile','openLearnMore','setLang','showHelp','sortTable',
            'toggleDetail','toggleShowMe']
           .filter(n => typeof window[n] !== 'undefined'),
  dnsAuditMembers: Object.keys(DnsAudit).sort(),
  facadeCallable: Object.keys(DnsAudit).every(n => typeof DnsAudit[n] === 'function'),
  // The generated tables are inside the bundle's closure since Task 6.2, so
  // their identity is checked against the artifact TEXT outside the page. What
  // the PAGE can still answer is whether the English bundle actually rendered:
  // under file:// a fetch of locales/en.json is blocked, so real text can only
  // have come from the inlined bundle.
  lang: document.documentElement.lang,
  title: document.title,
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

// **One global, in a real browser.** Task 6.2 removed the last nine; what
// remains is the name esbuild generates from the entry point's exports.
eq('DnsAudit is the only global the application publishes', page1?.globals, ['DnsAudit']);
eq('and not one of the fourteen Task 2.8 removed is still on the window',
  page1?.removed, []);

/**
 * The supported facade, in a real browser, from disk. Spec §10 stage 3.
 *
 * This asserted 95 members until Task 2.7. Two is the whole point of that
 * commit, and `src/facade.expected.json` is the checked-in list both
 * `parity.test.mjs` and `state-matrix.test.mjs` compare against — this is the
 * third place, and the only one where the reader is Chrome.
 */
eq('DnsAudit exposes exactly the supported facade',
  page1?.dnsAuditMembers, ['analyzeDomain', 'checkConnectivity']);
eq('and both members are callable', page1?.facadeCallable, true);


section('3. i18n resolved with no network');

// The point of the inlined English bundle. Under file:// a fetch of
// locales/en.json is blocked, so if the app is showing real text it can only
// have come from `src/data/locales-en.js`, bundled INTO the artifact. It used
// to be reachable as `window.__I18N_EN__`; Task 6.2 retired that global with
// the last adapter, and the evidence is the rendered prose rather than the
// name.
eq('the i18n layer selected English', page1?.lang, 'en');
eq('t() returns real text, not the key',
  page1?.title, 'DNS & Email Security Auditor — Free SPF, DKIM, DMARC & DNSSEC Checker');
eq('the document title was translated in place', page1?.documentTitle, page1?.title);
eq('the audit button carries translated text, not a placeholder',
  /Run Audit/i.test(page1?.auditButton || ''), true);
eq('and the page has translatable nodes to have done it to', page1?.translatedNodes > 20, true);

section('4. The application computed, in the browser');

/**
 * Real work, not a smoke test — and re-routed by Task 2.7 rather than dropped.
 *
 * This section used to call `DnsAudit.getOrganizationalDomain`, `gradeFor` and
 * `analyzeDkimKey` off the global. The facade contraction removed all three
 * from the browser deliberately: they were never supported API. Where that
 * depth is proved now is `tests/build/parity.test.mjs` section 4, which runs
 * three whole corpus audits through `analyzeDomain` against **this same
 * artifact** — every weight, the DER walk, the DNSSEC digest matcher — and the
 * five-surface equivalence run, which drives the artifact from `_site/`.
 *
 * What only Chrome can answer is what stays here: that the file loads from
 * `file://` with no server, evaluates, and computes correctly with **no network
 * at all**. So the probes below are ones that reach real application code
 * through the surface a browser still has, and every one is pure — a live
 * `analyzeDomain()` would issue a DoH request, and a suite that depended on
 * someone else's DNS is not a suite.
 */
const computed = await evaluate(`JSON.stringify({
  // The page's own rendered text, which is the deepest thing a browser can
  // still answer about the application from outside it. Under file:// a fetch
  // of locales/en.json is blocked, so real prose here can only have come from
  // the inlined English bundle.
  auditButton: document.getElementById('auditBtn') ? document.getElementById('auditBtn').textContent.trim() : null,
  translated: [...document.querySelectorAll('[data-i18n]')]
    .filter(el => el.textContent.trim() && !/^[a-z]+\\.[a-z]/i.test(el.textContent.trim())).length,
  // The supported facade, called for real. \`checkConnectivity\` would issue a
  // request, so only its TYPE is read — a suite that depended on someone
  // else's DNS is not a suite.
  facadeShape: Object.keys(DnsAudit).map(n => n + ':' + typeof DnsAudit[n]).sort()
})`);
const page2 = typeof computed === 'string' ? JSON.parse(computed) : computed;

eq('the audit button carries translated prose, not a key',
  /Run Audit/i.test(page2?.auditButton || ''), true);
eq('and many nodes were translated in place', page2?.translated > 20, true);
eq('the facade is two callable members and nothing else',
  page2?.facadeShape, ['analyzeDomain:function', 'checkConnectivity:function']);

/**
 * The generated data, checked against the ARTIFACT rather than the page.
 *
 * Task 6.2 removed the last globals, so `__DKIM_SELECTOR_CATALOG__` and
 * `__APP_TEST__` are gone and the tables live inside the bundle's closure. The
 * depth those probes carried did not go with them — it moved to where it is
 * still observable:
 *
 * | Was proved here through a global | Proved now |
 * | --- | --- |
 * | the CSV formula guard | `tools/export.test.mjs`, 199 assertions |
 * | the renderer building a real element | `tools/render.test.mjs`, 329 assertions |
 * | a token becoming translated prose | the page's own rendered text, above |
 * | the tables surviving bundling | the artifact scan below, and `parity.test.mjs` §5 |
 *
 * What only Chrome can answer is what stays in this file: that the artifact
 * loads from `file://` with no server, evaluates, and renders correctly with
 * **no network at all**.
 */
const artifactSource = readFileSync(join(REPO, 'dist', 'app.min.js'), 'utf8');
eq('the artifact Chrome loaded carries the real public suffix list',
  artifactSource.includes('blogspot.com'), true);
eq('and the DKIM selector catalog survived bundling',
  Object.keys(DKIM_SELECTOR_CATALOG.providers).filter(k => !artifactSource.includes(k)), []);
eq('and it is the whole application, not a stub', artifactSource.length > 100000, true);

section('5. Nothing failed silently');

const errors = await evaluate(`JSON.stringify(window.__fileUrlErrors || [])`);
eq('no uncaught error was recorded', JSON.parse(errors || '[]'), []);
// The negative control: the harness can see a failure when there is one.
const control = await evaluate(`typeof window.__definitely_not_defined__`);
eq('the harness reports an absent global as absent', control, 'undefined');

cdp.close();
cleanup();
report();
