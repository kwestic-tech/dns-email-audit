#!/usr/bin/env node
/**
 * The instrument for 0.8.0's local artifact analysis — built and PROVED before
 * the SVG validator it exists to measure.
 *
 *   node tests/build/local-input-security.test.mjs   (npm run test:local-input-security)
 *
 * 0.8.0 parses hostile SVG that a stranger supplied. The whole safety argument
 * is that the parsed document is detached and no node from it ever reaches the
 * application document, which is a rule enforced by convention, a file
 * boundary, and this suite. `OQ-ART-08` resolved that the suite runs in a real
 * Chromium-family engine over the DevTools Protocol, because the fixtures that
 * matter — entity expansion, DTD handling, malformed-XML recovery — are
 * properties of the parser the browser actually ships, not of a Node shim.
 *
 * **This file is deliberately written before the validator.** AGENTS rule 3:
 * every check ships with the negative case that proves it works. Writing the
 * riskiest code in the release first and the instrument afterwards would mean
 * the instrument's first green run is also the first time anyone trusted it.
 * So the three detectors are built here, against a fixture that deliberately
 * commits all three violations, and each detector is then switched off in turn
 * to prove it — and only it — stops seeing its own violation.
 *
 * That negative control is MECHANICAL rather than a manual source edit someone
 * has to remember to redo. `probe({ enabled })` runs the same hostile fixture
 * with any subset of the detectors installed, so "prove it fails when removed"
 * is an assertion in this file rather than a note in a review document.
 *
 * ── The three detectors ──────────────────────────────────────────────────
 *
 * | Detector | Mechanism | Defeatable by page code? |
 * | --- | --- | --- |
 * | network | CDP `Network.requestWillBeSent` | no — it is outside the page |
 * | storage | wrapped `setItem`/`indexedDB.open`/cookie setter | in principle; installed before the app's own script runs |
 * | insertion | wrapped `appendChild`/`insertBefore`/… , comparing `ownerDocument` BEFORE delegating | same |
 *
 * `ownerDocument` is read before the native call on purpose: the DOM adopts a
 * foreign node on insertion, so afterwards it always looks like it belonged.
 *
 * ── What this does NOT yet cover ─────────────────────────────────────────
 *
 * There is no artifact panel and no SVG validator to drive. When they land,
 * the hostile-SVG fixtures from the spec's table attach to `probe()` and the
 * assertion becomes "analysing this fixture produced no network request, no
 * storage write and no foreign-node insertion". The instrument is what is
 * under test here, not the feature.
 */

import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, resolve, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

/* ── 0. The instrument needs a real engine, and refuses to skip ───────── */
section('0. A real browser engine');

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
eq('a Chromium-family browser is available to test with', Boolean(chrome), true);
if (!chrome) {
  console.log('\n  No Chrome, Chromium or Edge found, and this check refuses to skip.');
  console.log('  Set CHROME_PATH, or install one. A security instrument that quietly');
  console.log('  passes when it did not run is worth less than none.');
  report();
  process.exit(1);
}

/* ── The page is served over http, not file:// ─────────────────────────
 *
 * `file://` is already covered by `file-url.test.mjs`, and it is the wrong
 * origin for this instrument: a same-origin `fetch` is blocked there, so the
 * hostile fixture could not make the one request the network detector has to
 * be shown catching. http also matches how the deployed site actually runs,
 * where `localStorage` and `indexedDB` behave normally. ──────────────── */

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8',
};

const root = resolve(REPO);
const server = createServer(async (req, res) => {
  try {
    const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    let file = resolve(root, '.' + pathname);
    if (file !== root && !file.startsWith(root + sep)) throw new Error('traversal');
    if ((await stat(file)).isDirectory()) file = resolve(file, 'index.html');
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const APP_URL = `${origin}/index.html`;

const profile = mkdtempSync(join(tmpdir(), 'local-input-'));
const port = 9700 + (process.pid % 300);
const child = spawn(chrome, [
  '--headless=new',
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-gpu',
  'about:blank',
], { stdio: ['ignore', 'ignore', 'ignore'] });

const cleanup = () => {
  try { child.kill('SIGKILL'); } catch { /* already gone */ }
  try { server.close(); } catch { /* already closed */ }
  try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  catch { /* the OS will reap it */ }
};
process.on('exit', cleanup);

async function targets() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      if (list.length) return list;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('local-input-security: headless browser did not start');
}

/** CDP with EVENT buffering — `file-url.test.mjs` only needs replies. */
function connect(wsUrl) {
  const socket = new WebSocket(wsUrl);
  const pending = new Map();
  let events = [];
  let nextId = 1;
  const ready = new Promise((res, rej) => {
    socket.addEventListener('open', res, { once: true });
    socket.addEventListener('error', rej, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    } else if (message.method) {
      events.push(message);
    }
  });
  return {
    ready,
    send(method, params = {}) {
      const id = nextId++;
      return new Promise(res => {
        pending.set(id, res);
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    drain(method) {
      const matched = events.filter(e => e.method === method);
      return matched;
    },
    clearEvents() { events = []; },
    close: () => socket.close(),
  };
}

const list = await targets();
const target = list.find(t => t.type === 'page') || list[0];
const cdp = connect(target.webSocketDebuggerUrl);
await cdp.ready;
await cdp.send('Page.enable');
await cdp.send('Runtime.enable');

/* ── The in-page half of the instrument ────────────────────────────────
 *
 * Installed with `Page.addScriptToEvaluateOnNewDocument` so the wrappers are
 * in place BEFORE the application's own script runs. Instrumenting after load
 * would miss everything that happens during boot, and — more to the point —
 * would not be in place when artifact code eventually runs during boot paths.
 * `enabled` is what makes the negative control mechanical. ─────────────── */
const detectorSource = enabled => `
(() => {
  const probe = { storage: [], insertion: [], bootStorage: [], phase: 'boot' };
  window.__probe = probe;
  const on = ${JSON.stringify(enabled)};

  const record = (bucket, entry) => {
    probe[probe.phase === 'boot' && bucket === 'storage' ? 'bootStorage' : bucket].push(entry);
  };

  if (on.includes('storage')) {
    for (const store of ['localStorage', 'sessionStorage']) {
      const target = window[store];
      const native = target.setItem.bind(target);
      Object.defineProperty(target, 'setItem', {
        configurable: true,
        value: (k, v) => { record('storage', store + ':' + k); return native(k, v); },
      });
    }
    if (window.indexedDB) {
      const nativeOpen = indexedDB.open.bind(indexedDB);
      indexedDB.open = (...args) => { record('storage', 'indexedDB:' + args[0]); return nativeOpen(...args); };
    }
    const cookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cookie && cookie.set) {
      Object.defineProperty(document, 'cookie', {
        configurable: true,
        get: () => cookie.get.call(document),
        set: v => { record('storage', 'cookie:' + String(v).split('=')[0]); return cookie.set.call(document, v); },
      });
    }
  }

  if (on.includes('insertion')) {
    // ownerDocument is read BEFORE delegating: the DOM adopts a foreign node
    // on insertion, so afterwards every node looks like it always belonged.
    const guard = (proto, name) => {
      const native = proto[name];
      if (typeof native !== 'function') return;
      proto[name] = function (...args) {
        for (const arg of args) {
          if (arg && arg.nodeType && arg.ownerDocument && arg.ownerDocument !== document) {
            record('insertion', name + ':' + (arg.nodeName || '?').toLowerCase());
          }
        }
        return native.apply(this, args);
      };
    };
    for (const name of ['appendChild', 'insertBefore', 'replaceChild']) guard(Node.prototype, name);
    for (const name of ['append', 'prepend', 'replaceChildren', 'before', 'after']) guard(Element.prototype, name);
    for (const name of ['adoptNode', 'importNode']) guard(Document.prototype, name);
  }

  window.__probeArmed = () => { probe.phase = 'analysis'; };

  /* ─────────────────────────────────────────────────────────────────────
   * THE DELIBERATELY UNSAFE FIXTURE.
   *
   * This is not production code and must never resemble any. It exists only
   * so the detectors above can be shown catching something, and it commits
   * exactly the three violations 0.8.0 forbids: one network request, one
   * storage write, one foreign-document node insertion.
   *
   * The request is SAME-ORIGIN on purpose. \`connect-src 'self'\` permits it,
   * and the point here is that the detector sees a request that really
   * reached the network layer — not that the CSP blocked a cross-origin one.
   * CSP is independent defence in depth and has its own source test.
   * ───────────────────────────────────────────────────────────────────── */
  window.__unsafeFixture = async () => {
    const attempted = [];
    try { await fetch(location.pathname + '?probe=1', { cache: 'no-store' }); attempted.push('network'); }
    catch (e) { attempted.push('network-threw:' + e.name); }
    try { localStorage.setItem('__unsafe_probe__', '1'); attempted.push('storage'); }
    catch (e) { attempted.push('storage-threw:' + e.name); }
    try {
      const foreign = new DOMParser().parseFromString(
        '<svg xmlns="http://www.w3.org/2000/svg"><title>probe</title></svg>', 'image/svg+xml');
      document.body.appendChild(foreign.documentElement);
      attempted.push('insertion');
    } catch (e) { attempted.push('insertion-threw:' + e.name); }
    return attempted;
  };
})();
`;

const evaluate = async expression => {
  const response = await cdp.send('Runtime.evaluate', {
    expression, returnByValue: true, awaitPromise: true,
  });
  if (response.result?.exceptionDetails) return { error: response.result.exceptionDetails.text || 'threw' };
  return response.result?.result?.value;
};

let installedScript = null;

/**
 * One scenario: load the app with `enabled` detectors, optionally run the
 * hostile fixture, and report what each detector saw DURING the analysis
 * phase. Requests made to load the page itself are drained first — the real
 * question is always "did analysing an artifact cause a request", never "did
 * the page load".
 */
async function probe({ enabled, unsafe }) {
  if (installedScript) {
    await cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier: installedScript });
  }
  const added = await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: detectorSource(enabled),
  });
  installedScript = added.result?.identifier;

  // The network detector IS the Network domain. Removing it means not enabling
  // it, which is a faithful removal rather than a simulated one.
  await cdp.send(enabled.includes('network') ? 'Network.enable' : 'Network.disable');

  await cdp.send('Page.navigate', { url: APP_URL });
  for (let attempt = 0; attempt < 80; attempt++) {
    const state = await evaluate('document.readyState === "complete" && typeof window.DnsAudit');
    if (state === 'object') break;
    await new Promise(r => setTimeout(r, 250));
  }

  const bootStorage = await evaluate('JSON.stringify(window.__probe.bootStorage)');
  // Everything above this line is page load. Everything below is analysis.
  cdp.clearEvents();
  await evaluate('window.__probeArmed()');

  const attempted = unsafe
    ? await evaluate('window.__unsafeFixture().then(a => JSON.stringify(a))')
    : '[]';

  // Give the request a moment to be reported before draining.
  await new Promise(r => setTimeout(r, 400));
  const requests = cdp.drain('Network.requestWillBeSent')
    .map(e => e.params?.request?.url || '')
    .filter(url => url.includes('probe=1'));

  const seen = await evaluate('JSON.stringify({ storage: window.__probe.storage, insertion: window.__probe.insertion })');
  const parsed = typeof seen === 'string' ? JSON.parse(seen) : { storage: [], insertion: [] };
  return {
    attempted: JSON.parse(typeof attempted === 'string' ? attempted : '[]'),
    bootStorage: JSON.parse(typeof bootStorage === 'string' ? bootStorage : '[]'),
    network: requests,
    storage: parsed.storage,
    insertion: parsed.insertion,
  };
}

const ALL = ['network', 'storage', 'insertion'];

/* ── 1. A clean load trips nothing ────────────────────────────────────── */
section('1. The baseline: loading the app violates nothing');

const clean = await probe({ enabled: ALL, unsafe: false });
eq('no network request is attributed to analysis', clean.network, []);
eq('no storage write happens during the analysis phase', clean.storage, []);
eq('and no foreign node is inserted', clean.insertion, []);

/**
 * The one documented write, asserted rather than assumed. `PRIVACY.md` says
 * the app writes "exactly one value" — `dns-email-audit-lang` — and only when
 * a language is chosen. A boot that writes anything else is a privacy claim
 * going stale, and this is the only suite positioned to notice.
 */
eq('boot writes nothing beyond the one key PRIVACY.md documents',
  clean.bootStorage.filter(k => k !== 'localStorage:dns-email-audit-lang'), []);

/* ── 2. The instrument catches a fixture that violates all three ──────── */
section('2. The deliberately unsafe fixture is caught');

const caught = await probe({ enabled: ALL, unsafe: true });
eq('the fixture really did all three things it claims',
  caught.attempted, ['network', 'storage', 'insertion']);
eq('the network detector saw the request', caught.network.length, 1);
eq('the storage detector saw the write', caught.storage, ['localStorage:__unsafe_probe__']);
eq('the insertion detector saw the foreign node', caught.insertion, ['appendChild:svg']);

/* ── 3. Each detector, removed, stops seeing its own violation ─────────
 *
 * The half that makes the other three assertions worth anything. A detector
 * nobody has watched fail is not evidence, and "the suite is green" is
 * indistinguishable from "the suite measures nothing" without this. Each run
 * also asserts the OTHER two still fire, so a removal cannot pass by
 * accidentally blinding everything at once. ──────────────────────────── */
section('3. Negative control: each detector proven to fail when removed');

for (const removed of ALL) {
  const enabled = ALL.filter(d => d !== removed);
  const blind = await probe({ enabled, unsafe: true });

  eq(`without the ${removed} detector, the fixture still commits all three`,
    blind.attempted, ['network', 'storage', 'insertion']);
  eq(`without the ${removed} detector, that violation goes unseen`,
    blind[removed].length, 0);

  for (const other of enabled) {
    eq(`  but the ${other} detector still reports it`, blind[other].length > 0, true);
  }
}

/* ── 4. The instrument survives its own removal being undone ──────────── */
section('4. And it works again once restored');

const restored = await probe({ enabled: ALL, unsafe: true });
eq('all three detectors report again after the negative runs',
  [restored.network.length > 0, restored.storage.length > 0, restored.insertion.length > 0],
  [true, true, true]);

cdp.close();
cleanup();
report();
