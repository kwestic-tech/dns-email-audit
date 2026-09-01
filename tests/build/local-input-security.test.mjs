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
 * ── The three detectors, and why none of them enumerates an API ──────────
 *
 * | Detector | Mechanism | Defeatable by page code? |
 * | --- | --- | --- |
 * | network | CDP `Network.requestWillBeSent` | no — outside the page |
 * | storage | before/after snapshot of every storage surface, plus CDP `DOMStorage` events | no — it compares state, not calls |
 * | insertion | every node the instrumented `DOMParser` produces is tagged, and a `MutationObserver` on the application document reports any tagged node that arrives | no — it observes the document, not the call |
 *
 * **The first version of this file wrapped a list of methods, and that was
 * wrong.** Two bypasses were executed against it in real Chrome:
 *
 *   Range.insertNode(foreign.documentElement)
 *   → wrapper count 0; the application document contained the inserted <svg>
 *
 *   localStorage.__direct_probe__ = '1'
 *   → wrapper count 0; the value was stored
 *
 * `Range.insertNode` does not route through a JavaScript replacement of
 * `Node.prototype.appendChild`, and a named-property write does not route
 * through a replaced `setItem`. The suite stayed green because its own unsafe
 * fixture used exactly the two methods the wrappers watched. Removing a wrapper
 * proved the wrapper worked; it proved nothing about the promised behaviour.
 *
 * The acceptance criterion is behavioural — *no request, no storage write, no
 * inserted node* — so the detectors are now behavioural too. Enumerating
 * insertion surfaces would have meant chasing `Range.surroundContents`,
 * `ShadowRoot`, `DocumentFragment`, `outerHTML` and whatever ships next; a
 * `MutationObserver` on the document sees all of them because it watches the
 * outcome instead of the route.
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

import { readFileSync } from 'node:fs';

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

  /* ── insertion: tag at the parser, observe at the document ──────────────
   *
   * Every node the page parses out of untrusted text is tagged, and a
   * MutationObserver reports any tagged node that turns up in the application
   * document. This is why Range.insertNode, innerHTML, adoptNode and anything
   * else all report: the observer watches the outcome, not the route. */
  const foreignNodes = new WeakSet();
  if (on.includes('insertion')) {
    const nativeParse = DOMParser.prototype.parseFromString;
    DOMParser.prototype.parseFromString = function (...args) {
      const doc = nativeParse.apply(this, args);
      try {
        const walker = doc.createTreeWalker(doc, 0xFFFFFFFF);
        foreignNodes.add(doc);
        let n = walker.currentNode;
        while (n) { foreignNodes.add(n); n = walker.nextNode(); }
      } catch (e) { /* a document too broken to walk cannot be inserted either */ }
      return doc;
    };

    /* A CLONE of a tagged node is a different object and inherits no tag, so
     * appendChild(parsed.cloneNode(true)) walked straight past the observer.
     * Found by mutating this file's own fixture to leak a clone; the network
     * detector still caught the consequence -- Chrome fetched the external
     * references the moment the copy entered the document -- which is the
     * layering doing its job. The tag is now propagated across the three
     * copying calls so the insertion detector does not depend on that rescue. */
    const propagate = (proto, name) => {
      const native = proto[name];
      if (typeof native !== 'function') return;
      proto[name] = function (...args) {
        const source = name === 'cloneNode' ? this : args[0];
        const copy = native.apply(this, args);
        if (foreignNodes.has(source) && copy) {
          try {
            const walker = document.createTreeWalker(copy, 0xFFFFFFFF);
            foreignNodes.add(copy);
            let n = walker.currentNode;
            while (n) { foreignNodes.add(n); n = walker.nextNode(); }
          } catch (e) { foreignNodes.add(copy); }
        }
        return copy;
      };
    };
    propagate(Node.prototype, 'cloneNode');
    propagate(Document.prototype, 'importNode');
    propagate(Document.prototype, 'adoptNode');

    const seen = node => {
      if (foreignNodes.has(node)) {
        probe.insertion.push((node.nodeName || '?').toLowerCase());
        return;
      }
      const kids = node.childNodes || [];
      for (const kid of kids) seen(kid);
    };
    const observer = new MutationObserver(records => {
      for (const record of records) for (const node of record.addedNodes) seen(node);
    });
    observer.observe(document, { childList: true, subtree: true });
    // takeRecords() flushes synchronously, so collection is deterministic
    // rather than dependent on when the microtask queue happens to drain.
    window.__probeFlush = () => {
      const pending = observer.takeRecords();
      for (const record of pending) for (const node of record.addedNodes) seen(node);
    };
  } else {
    window.__probeFlush = () => {};
  }

  /* ── storage: compare state, do not watch calls ─────────────────────────
   *
   * A snapshot diff catches a named-property write, a setItem, a cookie and an
   * IndexedDB database alike, because it never asks how the change was made. */
  const snapshot = () => {
    const out = {};
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); out['localStorage:' + k] = localStorage.getItem(k); } } catch (e) {}
    try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); out['sessionStorage:' + k] = sessionStorage.getItem(k); } } catch (e) {}
    try { if (document.cookie) for (const pair of document.cookie.split(';')) out['cookie:' + pair.split('=')[0].trim()] = 1; } catch (e) {}
    return out;
  };
  const diff = (before, after) => Object.keys(after)
    .filter(k => !(k in before) || before[k] !== after[k]).sort();

  let bootBefore = snapshot();
  let phaseBefore = null;

  window.__probeArmed = () => {
    if (probe.phase === 'boot') {
      probe.bootStorage = on.includes('storage') ? diff(bootBefore, snapshot()) : [];
    }
    // Arming begins a fresh analysis phase, so anything a PREVIOUS phase
    // recorded is cleared with it. Otherwise a later phase inherits an earlier
    // phase's violations and reports them as its own.
    probe.storage = [];
    probe.insertion = [];
    if (window.__probeFlush) window.__probeFlush();
    probe.insertion = [];
    phaseBefore = snapshot();
    probe.phase = 'analysis';
  };
  window.__probeCollect = () => {
    if (on.includes('storage') && phaseBefore) {
      probe.storage = diff(phaseBefore, snapshot());
    }
    window.__probeFlush();
    return JSON.stringify({ storage: probe.storage, insertion: probe.insertion });
  };

  /* ─────────────────────────────────────────────────────────────────────
   * THE DELIBERATELY UNSAFE FIXTURE.
   *
   * Not production code and must never resemble any. It commits the three
   * violations 0.8.0 forbids, and it now commits each of them by MORE THAN ONE
   * route — including the two that bypassed the previous wrappers — so a
   * detector that only covers the obvious path cannot pass.
   *
   * The request is SAME-ORIGIN on purpose. \`connect-src 'self'\` permits it,
   * and the point is that the detector sees a request that really reached the
   * network layer, not that the CSP blocked a cross-origin one.
   * ───────────────────────────────────────────────────────────────────── */
  window.__unsafeFixture = async (nonce) => {
    const attempted = [];
    try { await fetch(location.pathname + '?probe=1', { cache: 'no-store' }); attempted.push('network'); }
    catch (e) { attempted.push('network-threw:' + e.name); }

    // Storage, by both routes.
    try { localStorage.setItem('__unsafe_probe__', String(nonce)); attempted.push('storage-setItem'); }
    catch (e) { attempted.push('storage-threw:' + e.name); }
    try { localStorage.__direct_probe__ = String(nonce); attempted.push('storage-property'); }
    catch (e) { attempted.push('storage-property-threw:' + e.name); }

    // Insertion, by both routes.
    const parse = t => new DOMParser().parseFromString(t, 'image/svg+xml');
    try {
      document.body.appendChild(parse('<svg xmlns="http://www.w3.org/2000/svg"><title>a</title></svg>').documentElement);
      attempted.push('insertion-appendChild');
    } catch (e) { attempted.push('insertion-threw:' + e.name); }
    try {
      const range = document.createRange();
      range.selectNodeContents(document.body);
      range.insertNode(parse('<svg xmlns="http://www.w3.org/2000/svg"><title>b</title></svg>').documentElement);
      attempted.push('insertion-range');
    } catch (e) { attempted.push('insertion-range-threw:' + e.name); }

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
// localStorage survives navigation inside one browser profile, so each run
// writes a distinct value. Otherwise the second run's snapshot comparison
// correctly reports "nothing changed" and the detector looks broken.
let runNonce = 1;

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
  // it, which is a faithful removal rather than a simulated one. The same holds
  // for DOMStorage, the external half of the storage detector.
  await cdp.send(enabled.includes('network') ? 'Network.enable' : 'Network.disable');
  await cdp.send(enabled.includes('storage') ? 'DOMStorage.enable' : 'DOMStorage.disable');

  await cdp.send('Page.navigate', { url: APP_URL });
  for (let attempt = 0; attempt < 80; attempt++) {
    const state = await evaluate('document.readyState === "complete" && typeof window.DnsAudit');
    if (state === 'object') break;
    await new Promise(r => setTimeout(r, 250));
  }

  // Everything above this line is page load. Everything below is analysis.
  await evaluate('window.__probeArmed()');
  const bootStorage = await evaluate('JSON.stringify(window.__probe.bootStorage)');
  cdp.clearEvents();

  const attempted = unsafe
    ? await evaluate(`window.__unsafeFixture(${runNonce++}).then(a => JSON.stringify(a))`)
    : '[]';

  // Give the request and the observer a moment before collecting.
  await new Promise(r => setTimeout(r, 400));
  const requests = cdp.drain('Network.requestWillBeSent')
    .map(e => e.params?.request?.url || '')
    .filter(url => url.includes('probe=1'));
  // The external corroborator for storage: page code cannot suppress a CDP
  // event the way it could shadow a wrapped method.
  const storageEvents = cdp.drain('DOMStorage.domStorageItemAdded')
    .concat(cdp.drain('DOMStorage.domStorageItemUpdated'))
    .map(e => e.params?.key || '')
    .filter(Boolean);

  const seen = await evaluate('window.__probeCollect()');
  const parsed = typeof seen === 'string' ? JSON.parse(seen) : { storage: [], insertion: [] };
  return {
    attempted: JSON.parse(typeof attempted === 'string' ? attempted : '[]'),
    bootStorage: JSON.parse(typeof bootStorage === 'string' ? bootStorage : '[]'),
    network: requests,
    storage: parsed.storage,
    storageEvents,
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
eq('the fixture committed every violation by every route it claims',
  caught.attempted,
  ['network', 'storage-setItem', 'storage-property',
    'insertion-appendChild', 'insertion-range']);
eq('the network detector saw the request', caught.network.length, 1);

// Both storage routes, including the named-property write that walked past the
// previous wrapper entirely.
eq('the storage detector saw BOTH writes, including the property assignment',
  caught.storage, ['localStorage:__direct_probe__', 'localStorage:__unsafe_probe__']);
eq('and the external CDP corroborator saw them too',
  caught.storageEvents.slice().sort(), ['__direct_probe__', '__unsafe_probe__']);

// Both insertion routes, including Range.insertNode, which does not dispatch
// through Node.prototype.appendChild at all.
eq('the insertion detector saw BOTH foreign nodes, including the Range one',
  caught.insertion.length, 2);
eq('and identified them as the parsed svg roots',
  caught.insertion, ['svg', 'svg']);

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

  eq(`without the ${removed} detector, the fixture still commits every violation`,
    blind.attempted,
    ['network', 'storage-setItem', 'storage-property',
      'insertion-appendChild', 'insertion-range']);
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

/* ── 5. The validator, against the parser it will actually meet ────────
 *
 * `src/core/bimi/svg.test.js` proves the RULES against a hand-built fixture
 * tree, and says plainly that the tree is not a parser. This is the other
 * half: the same module, driven by the real `DOMParser`, on documents whose
 * behaviour is a property of the engine rather than of the rules.
 *
 * The module is injected as source rather than imported, because nothing in
 * `src/core/bimi/` is in `dist/app.min.js` yet — the composer that will import
 * it does not exist. When it does, this section drives it through the panel
 * instead and the injection goes away. ────────────────────────────────── */
section('5. The SVG validator against the real DOMParser');

const validatorSource = readFileSync(join(REPO, 'src', 'core', 'bimi', 'svg.js'), 'utf8')
  .replace(/^export /gm, '');

await evaluate(`
  window.__svg = (() => {
    ${validatorSource}
    return { validateBimiSvg, BIMI_SVG_REJECTIONS, BIMI_SVG_DIAGNOSTICS };
  })();
  window.__check = text => JSON.stringify(
    window.__svg.validateBimiSvg(text, t => new DOMParser().parseFromString(t, 'image/svg+xml')));
`);

const checkSvg = async text => {
  const raw = await evaluate(`window.__check(${JSON.stringify(text)})`);
  return typeof raw === 'string' ? JSON.parse(raw) : { error: raw };
};

const NS = 'http://www.w3.org/2000/svg';
const conformantSvg =
  `<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 64 64"><title>Brand</title></svg>`;

const cleanSvg = await checkSvg(conformantSvg);
eq('a conformant tiny-ps logo passes through the real parser',
  [cleanSvg.valid, cleanSvg.rejections, cleanSvg.diagnostics, cleanSvg.title],
  [true, [], [], 'Brand']);

/* A fresh analysis phase: section 4 left its own deliberate violations on this
 * page, and they are not this section's to report. */
await evaluate('window.__probeArmed()');
cdp.clearEvents();

section('5a. Hostile fixtures, parsed by the engine that ships');

const HOSTILE = [
  ['<script> inside the SVG', `<svg xmlns="${NS}"><script>alert(1)</script><title>t</title></svg>`, 'script-element'],
  ['onload on the root', `<svg xmlns="${NS}" onload="alert(1)"><title>t</title></svg>`, 'event-handler'],
  ['billion laughs', '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;">]>' +
    `<svg xmlns="${NS}"><title>&lol1;</title></svg>`, 'entity-declaration'],
  ['external DTD reference', `<!DOCTYPE svg SYSTEM "https://evil.example/x.dtd"><svg xmlns="${NS}"/>`, 'doctype-present'],
  ['<image> with an absolute href', `<svg xmlns="${NS}"><image href="https://evil.example/x.png"/><title>t</title></svg>`, 'external-reference-element'],
  ['<use> with an xlink href', `<svg xmlns="${NS}" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.example/x#a"/><title>t</title></svg>`, 'external-reference'],
  ['@import in a style block', `<svg xmlns="${NS}"><style>@import url(https://evil.example/x.css);</style><title>t</title></svg>`, 'external-style'],
  ['<foreignObject> with an iframe', `<svg xmlns="${NS}"><foreignObject><iframe xmlns="http://www.w3.org/1999/xhtml"/></foreignObject><title>t</title></svg>`, 'foreign-object'],
  ['HTML content in an .svg file', '<html><body><p>hi</p></body></html>', 'bad-root'],
  ['truncated XML', `<svg xmlns="${NS}"><title>t</title>`, 'malformed-xml'],
  ['two root elements', `<svg xmlns="${NS}"/><svg xmlns="${NS}"/>`, 'malformed-xml'],
  ['an animate element', `<svg xmlns="${NS}"><animate attributeName="x"/><title>t</title></svg>`, 'animation'],
  ['an anchor', `<svg xmlns="${NS}"><a href="#x"><title>t</title></a></svg>`, 'link-element'],
];

for (const [label, source, token] of HOSTILE) {
  const result = await checkSvg(source);
  eq(`${label} is rejected as ${token}`, result.rejections.includes(token), true);
  eq(`  and the document is not valid`, result.valid, false);
}

/* The reason the entity rule is ordered before the parser, asserted against
 * the engine that does the expanding. */
const bomb = await checkSvg('<!DOCTYPE lolz [<!ENTITY lol "lol">]>' + `<svg xmlns="${NS}"/>`);
eq('an entity-declaring document never reached the parser', bomb.parsed, false);

section('5b. Wrong-case names, which XML does not fold');

eq('a wrong-case <SVG> root is a bad root in the real parser',
  (await checkSvg(`<SVG xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 64 64"><title>t</title></SVG>`)).rejections,
  ['bad-root']);
eq('baseprofile does not satisfy baseProfile',
  (await checkSvg(`<svg xmlns="${NS}" baseprofile="tiny-ps" version="1.2" viewBox="0 0 64 64"><title>t</title></svg>`)).diagnostics,
  ['base-profile-not-tiny-ps']);
eq('viewbox does not satisfy viewBox',
  (await checkSvg(`<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewbox="0 0 64 64"><title>t</title></svg>`)).diagnostics,
  ['viewbox-missing']);
eq('a wrong-case <TITLE> does not satisfy the title requirement',
  (await checkSvg(`<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 64 64"><TITLE>t</TITLE></svg>`)).diagnostics,
  ['title-missing']);
// The deliberate asymmetry, in the real engine: security screening stays broad.
eq('but a wrong-case <SCRIPT> is still screened out',
  (await checkSvg(`<svg xmlns="${NS}"><SCRIPT>alert(1)</SCRIPT><title>t</title></svg>`)).rejections,
  ['script-element']);

section('5c. SVG Tiny PS permitted values, in the real parser');

eq('the draft\'s own conformant attribute example raises nothing',
  (await checkSvg(`<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 64 64" zoomAndPan="disable" externalResourcesRequired="false"><title>t</title></svg>`)).diagnostics,
  []);
eq('but a value outside the permitted table is unsupported',
  (await checkSvg(`<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 64 64" zoomAndPan="magnify"><title>t</title></svg>`)).diagnostics,
  ['unsupported-attribute']);
eq('a zero-area viewBox is unusable rather than square',
  (await checkSvg(`<svg xmlns="${NS}" baseProfile="tiny-ps" version="1.2" viewBox="0 0 0 0"><title>t</title></svg>`)).diagnostics,
  ['viewbox-missing']);

section('5d. Analysing all of that caused no violation');

/* The point of the whole file: the instrument was watching the entire time the
 * validator ran, including on every hostile fixture above. */
await evaluate('window.__probeFlush()');
const afterAnalysis = await evaluate('window.__probeCollect()');
const analysisSeen = typeof afterAnalysis === 'string'
  ? JSON.parse(afterAnalysis) : { storage: [], insertion: [] };
const analysisRequests = cdp.drain('Network.requestWillBeSent')
  .map(e => e.params?.request?.url || '')
  .filter(url => !url.includes('probe=1'));

eq('no foreign node from any hostile fixture entered the document',
  analysisSeen.insertion, []);
eq('no storage write happened while analysing them', analysisSeen.storage, []);
eq('and no fixture caused a network request',
  analysisRequests.filter(u => !u.startsWith(origin)), []);

cdp.close();
cleanup();
report();
