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
 * | storage | CDP mutation events for Web Storage, IndexedDB and Cache Storage, plus a before/after content snapshot and cookies | no — the authoritative signals are outside the page |
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
 * A later round found the same mistake one level down: the snapshot named
 * "every storage surface" while reading only Web Storage and cookie NAMES, so
 * analysis could create an IndexedDB database, write a Cache Storage entry,
 * delete a key or change a cookie's value with the gate still green. The round
 * after THAT found the same shortcut one level deeper: the new snapshot read
 * database names, versions and cached request URLs — catalogs — so a record
 * put into an object store that already existed, or a response body replaced
 * for a URL already cached, changed nothing it looked at. And the round after
 * THAT found the representation itself lossy: `JSON.stringify` turns a Blob
 * into `{}`, and `.text()` decodes two different invalid bytes to the same
 * character, so replacing either value looked like replacing nothing.
 *
 * A detector is only as behavioural as the surfaces it enumerates, as deep as
 * it reads them, and as faithful as the representation it compares. Four
 * rounds found the same mistake at four levels. The content snapshots remain
 * useful corroboration, but CDP's browser-external content-mutation events are
 * now authoritative for IndexedDB and Cache Storage: they observe the write,
 * not a hand-written approximation of the value before and after it.
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
   * A state comparison never asks HOW a change was made, so a named-property
   * write, a setItem, a cookie and a database all report the same way.
   *
   * It has to enumerate every surface it claims, though, and an earlier version
   * of this file did not: it read Web Storage and cookie NAMES only, while its
   * own comment promised IndexedDB. A negative control created a database
   * during the analysis phase and the gate stayed green. Two narrower bugs came
   * from the same shortcut — the diff walked only the after-snapshot's keys, so
   * a REMOVAL was invisible, and cookies were stored as name-only, so changing
   * an existing cookie's value was invisible too.
   *
   * Asynchronous because IndexedDB and Cache Storage are. */
  const snapshot = async () => {
    const out = {};
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        out['localStorage:' + k] = localStorage.getItem(k);
      }
    } catch (e) { out['localStorage:<unreadable>'] = String(e && e.name); }
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        out['sessionStorage:' + k] = sessionStorage.getItem(k);
      }
    } catch (e) { out['sessionStorage:<unreadable>'] = String(e && e.name); }
    try {
      if (document.cookie) for (const pair of document.cookie.split(';')) {
        const at = pair.indexOf('=');
        const name = (at < 0 ? pair : pair.slice(0, at)).trim();
        // The VALUE, not just the name: replacing a cookie's contents is a
        // storage write and a name-only snapshot cannot see it.
        if (name) out['cookie:' + name] = at < 0 ? '' : pair.slice(at + 1).trim();
      }
    } catch (e) { out['cookie:<unreadable>'] = String(e && e.name); }
    /* CONTENTS, not catalogs. Recording a database name and version detects a
     * new database; it does not detect a record put into an object store that
     * already existed, which needs no version change. The same shortcut in
     * Cache Storage recorded request URLs, so replacing the stored response for
     * a URL already present was invisible. Both are exactly the persistence the
     * spec forbids, so both are read through. */
    try {
      if (indexedDB && indexedDB.databases) {
        for (const info of await indexedDB.databases()) {
          out['indexedDB:' + info.name] = String(info.version);
          let db = null;
          try {
            db = await new Promise((resolve, reject) => {
              // No version argument: opening at the current version cannot
              // trigger an upgrade, so reading state never changes it.
              const request = indexedDB.open(info.name);
              request.onsuccess = () => resolve(request.result);
              request.onerror = () => reject(request.error);
              request.onblocked = () => reject(new Error('blocked'));
            });
            for (const store of Array.from(db.objectStoreNames)) {
              const rows = await new Promise(resolve => {
                try {
                  const tx = db.transaction(store, 'readonly');
                  const target = tx.objectStore(store);
                  const keys = target.getAllKeys();
                  const values = target.getAll();
                  tx.oncomplete = () => resolve([keys.result, values.result]);
                  tx.onerror = () => resolve('<unreadable>');
                  tx.onabort = () => resolve('<unreadable>');
                } catch (e) { resolve('<unreadable>'); }
              });
              out['indexedDB:' + info.name + '/' + store] = await encode(rows);
            }
          } catch (e) {
            out['indexedDB:' + info.name + '/<unreadable>'] = String(e && e.name);
          } finally {
            try { if (db) db.close(); } catch (e) {}
          }
        }
      }
    } catch (e) { out['indexedDB:<unreadable>'] = String(e && e.name); }
    try {
      if (window.caches) {
        for (const key of await caches.keys()) {
          const cache = await caches.open(key);
          const entries = await cache.keys();
          out['cache:' + key] = entries.map(r => r.url).sort().join(' ');
          for (const request of entries) {
            let body = '<none>';
            try {
              const response = await cache.match(request);
              if (response) {
                // Bytes, plus the status and headers that are also persisted
                // state. .text() decoded them and lost the distinction.
                body = response.status + ' ' + response.statusText + ' ' +
                  [...response.headers].map(([k, v]) => k + '=' + v).sort().join('&') +
                  ' ' + hex(await response.arrayBuffer());
              }
            } catch (e) { body = '<unreadable:' + (e && e.name) + '>'; }
            out['cache:' + key + '|' + request.url] = body;
          }
        }
      }
    } catch (e) { out['cache:<unreadable>'] = String(e && e.name); }
    return out;
  };

  /* ── A byte-preserving snapshot corroborator ────────────────────────────
   *
   * JSON.stringify was the wrong tool twice over. IndexedDB stores structured
   * clones, and a Blob serialises to {}, so replacing one Blob with another
   * produced identical snapshots. Cache Storage persists BYTES, and reading a
   * body with .text() decodes them, so 0x80 and 0x81 both became U+FFFD and a
   * changed body looked unchanged.
   *
   * This is deliberately corroboration, not the authoritative write detector.
   * Structured-clone values include graphs and platform objects whose identity
   * cannot be made injective by a small custom encoder. CDP content-update
   * events supply that authority outside the page; this encoder keeps the
   * before/after evidence human-readable for the common stored shapes. */
  const hex = buffer => Array.from(new Uint8Array(buffer),
    b => b.toString(16).padStart(2, '0')).join('');

  const encode = async (value, depth) => {
    const d = depth || 0;
    if (d > 8) return '<deep>';
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    const type = typeof value;
    if (type === 'string') return 's:' + value;
    if (type === 'number' || type === 'boolean') return type[0] + ':' + String(value);
    if (type === 'bigint') return 'n:' + value.toString();
    try {
      if (value instanceof Date) return 'date:' + value.getTime();
      if (value instanceof RegExp) return 're:' + String(value);
      if (value instanceof Blob) {
        return 'blob:' + value.type + ':' + value.size + ':' + hex(await value.arrayBuffer());
      }
      if (ArrayBuffer.isView(value)) {
        return 'view:' + value.constructor.name + ':' +
          hex(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
      }
      if (value instanceof ArrayBuffer) return 'buf:' + hex(value);
      if (value instanceof Map) {
        const parts = [];
        for (const [k, v] of value) parts.push(await encode(k, d + 1) + '=>' + await encode(v, d + 1));
        return 'map:[' + parts.sort().join(',') + ']';
      }
      if (value instanceof Set) {
        const parts = [];
        for (const v of value) parts.push(await encode(v, d + 1));
        return 'set:[' + parts.sort().join(',') + ']';
      }
      if (Array.isArray(value)) {
        const parts = [];
        for (const v of value) parts.push(await encode(v, d + 1));
        return '[' + parts.join(',') + ']';
      }
      if (type === 'object') {
        const parts = [];
        for (const k of Object.keys(value).sort()) parts.push(k + ':' + await encode(value[k], d + 1));
        return '{' + parts.join(',') + '}';
      }
    } catch (e) { return '<unencodable:' + (e && e.name) + '>'; }
    return type + ':' + String(value);
  };

  const openSeedDb = () => new Promise((resolve, reject) => {
    const request = indexedDB.open('__seed_db__', 2);
    request.onupgradeneeded = () => {
      // Two stores on purpose. With the Blob beside the string record, a
      // change to the string alone made the whole store's serialisation
      // differ, so a Blob assertion passed without the Blob being seen.
      if (!request.result.objectStoreNames.contains('items')) {
        request.result.createObjectStore('items');
      }
      if (!request.result.objectStoreNames.contains('blobs')) {
        request.result.createObjectStore('blobs');
      }
      if (!request.result.objectStoreNames.contains('deep')) {
        request.result.createObjectStore('deep');
      }
      if (!request.result.objectStoreNames.contains('files')) {
        request.result.createObjectStore('files');
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('blocked'));
  });

  const putRecord = (db, value, key, store) => new Promise(resolve => {
    try {
      const tx = db.transaction(store || 'items', 'readwrite');
      tx.objectStore(store || 'items').put(value, key || 'k');
      tx.oncomplete = resolve;
      tx.onerror = resolve;
      tx.onabort = resolve;
    } catch (e) { resolve(); }
  });

  const nestedValue = leaf => {
    let value = leaf;
    for (let i = 0; i < 12; i++) value = { next: value };
    return value;
  };

  // The UNION of both key sets, so a removal is a difference too. Walking only
  // the after-snapshot made deleting a key indistinguishable from never having
  // written one.
  const diff = (before, after) => {
    const keys = new Set(Object.keys(before).concat(Object.keys(after)));
    return [...keys].filter(k => before[k] !== after[k]).sort();
  };

  let bootBefore = null;
  let phaseBefore = null;
  const booted = snapshot().then(v => { bootBefore = v; });

  window.__probeArmed = async (seedNonce) => {
    await booted;
    if (probe.phase === 'boot') {
      probe.bootStorage = on.includes('storage') ? diff(bootBefore, await snapshot()) : [];
    }
    // Seeded AFTER the boot diff and BEFORE the phase snapshot, so the values
    // the fixture will remove or overwrite exist without counting as boot
    // writes. Nonced because storage survives navigation within one profile.
    if (seedNonce !== undefined) {
      try { localStorage.setItem('__seed_remove__', 'seeded' + seedNonce); } catch (e) {}
      try { document.cookie = '__seed_cookie__=old' + seedNonce + '; path=/'; } catch (e) {}
      // An IndexedDB database and a cache that ALREADY EXIST when the phase
      // opens. Creating a container is easy to notice; writing inside one that
      // was already there is the case a catalog-shaped snapshot cannot see.
      try {
        const db = await openSeedDb();
        await putRecord(db, 'old' + seedNonce, 'k');
        // A Blob-valued record. IndexedDB stores structured clones, and a Blob
        // is one of the shapes a pasted artifact would most naturally take.
        await putRecord(db, new Blob(['before' + seedNonce]), 'blob', 'blobs');
        // Two values the snapshot encoder deliberately does not claim to
        // represent injectively. CDP must still report their writes.
        await putRecord(db, nestedValue('before' + seedNonce), 'deep', 'deep');
        await putRecord(db, new File(['same'], 'before.svg',
          { type: 'image/svg+xml', lastModified: seedNonce }), 'file', 'files');
        db.close();
      } catch (e) {}
      try {
        const cache = await caches.open('__seed_cache__');
        await cache.put(new Request(location.pathname + '?seed=1'),
          new Response('old' + seedNonce));
        // A response whose body is not valid UTF-8. Decoding it to text throws
        // away the distinction between one invalid byte and another.
        await cache.put(new Request(location.pathname + '?bytes=1'),
          new Response(new Uint8Array([0x80])));
      } catch (e) {}
    }
    // Arming begins a fresh analysis phase, so anything a PREVIOUS phase
    // recorded is cleared with it. Otherwise a later phase inherits an earlier
    // phase's violations and reports them as its own.
    probe.storage = [];
    probe.insertion = [];
    if (window.__probeFlush) window.__probeFlush();
    probe.insertion = [];
    phaseBefore = await snapshot();
    probe.phase = 'analysis';
  };
  window.__probeCollect = async () => {
    if (on.includes('storage') && phaseBefore) {
      probe.storage = diff(phaseBefore, await snapshot());
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
   * The request is SAME-ORIGIN on purpose. The connect-src 'self' policy permits it,
   * and the point is that the detector sees a request that really reached the
   * network layer, not that the CSP blocked a cross-origin one.
   * ───────────────────────────────────────────────────────────────────── */
  window.__unsafeFixture = async (nonce) => {
    const attempted = [];
    try { await fetch(location.pathname + '?probe=1', { cache: 'no-store' }); attempted.push('network'); }
    catch (e) { attempted.push('network-threw:' + e.name); }

    // Storage, across every surface the snapshot claims and by every route:
    // a method call, a named-property write, a REMOVAL, a value REPLACEMENT,
    // a database and a cache entry.
    try { localStorage.setItem('__unsafe_probe__', String(nonce)); attempted.push('storage-setItem'); }
    catch (e) { attempted.push('storage-threw:' + e.name); }
    try { localStorage.__direct_probe__ = String(nonce); attempted.push('storage-property'); }
    catch (e) { attempted.push('storage-property-threw:' + e.name); }
    try { localStorage.removeItem('__seed_remove__'); attempted.push('storage-remove'); }
    catch (e) { attempted.push('storage-remove-threw:' + e.name); }
    try { document.cookie = '__seed_cookie__=new' + nonce + '; path=/'; attempted.push('storage-cookie'); }
    catch (e) { attempted.push('storage-cookie-threw:' + e.name); }
    try {
      await new Promise(resolve => {
        const request = indexedDB.open('__unsafe_db__' + nonce);
        request.onsuccess = () => { try { request.result.close(); } catch (e) {} resolve(); };
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      attempted.push('storage-indexeddb');
    } catch (e) { attempted.push('storage-indexeddb-threw:' + e.name); }
    try {
      const cache = await caches.open('__unsafe_cache__' + nonce);
      await cache.put(new Request(location.pathname + '?cached=' + nonce), new Response('x'));
      attempted.push('storage-cache');
    } catch (e) { attempted.push('storage-cache-threw:' + e.name); }

    // Writes INSIDE containers that already existed when the phase opened.
    // Neither changes a database name, a database version, or a cached request
    // URL, so a snapshot of container metadata alone reports nothing.
    try {
      const db = await openSeedDb();
      await putRecord(db, 'new' + nonce, 'k');
      db.close();
      attempted.push('storage-idb-record');
    } catch (e) { attempted.push('storage-idb-record-threw:' + e.name); }
    try {
      const cache = await caches.open('__seed_cache__');
      await cache.put(new Request(location.pathname + '?seed=1'),
        new Response('new' + nonce));
      attempted.push('storage-cache-body');
    } catch (e) { attempted.push('storage-cache-body-threw:' + e.name); }

    /* The two representation cases. Neither changes anything a JSON- or
     * text-coercing snapshot can see: a Blob serialises as {} under
     * JSON.stringify, and 0x80 and 0x81 both decode to the same replacement
     * character. Both are still the persistence the spec forbids. */
    try {
      const db = await openSeedDb();
      await putRecord(db, new Blob(['after' + nonce]), 'blob', 'blobs');
      db.close();
      attempted.push('storage-idb-blob');
    } catch (e) { attempted.push('storage-idb-blob-threw:' + e.name); }
    try {
      const cache = await caches.open('__seed_cache__');
      await cache.put(new Request(location.pathname + '?bytes=1'),
        new Response(new Uint8Array([0x81])));
      attempted.push('storage-cache-bytes');
    } catch (e) { attempted.push('storage-cache-bytes-threw:' + e.name); }

    // Values the corroborating encoder collapses. The authoritative CDP event
    // must report both writes without understanding either representation.
    try {
      const db = await openSeedDb();
      await putRecord(db, nestedValue('after' + nonce), 'deep', 'deep');
      db.close();
      attempted.push('storage-idb-deep');
    } catch (e) { attempted.push('storage-idb-deep-threw:' + e.name); }
    try {
      const db = await openSeedDb();
      await putRecord(db, new File(['same'], 'after.svg',
        { type: 'image/svg+xml', lastModified: nonce + 1000 }), 'file', 'files');
      db.close();
      attempted.push('storage-idb-file');
    } catch (e) { attempted.push('storage-idb-file-threw:' + e.name); }

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

const requireCdp = async (method, params = {}) => {
  const response = await cdp.send(method, params);
  if (response.error) {
    throw new Error(`${method}: ${response.error.message || 'unsupported'}`);
  }
  return response;
};

/* IndexedDB and Cache Storage can persist arbitrary structured-clone values
 * and response bytes. A before/after serializer is inevitably an
 * approximation; these browser-external events are the authoritative signal
 * that content changed. The snapshot remains useful independent evidence. */
const storageMutationEvents = () => [
  ...cdp.drain('DOMStorage.domStorageItemAdded').map(e =>
    `cdp:webStorage-added:${e.params?.key || '?'}`),
  ...cdp.drain('DOMStorage.domStorageItemUpdated').map(e =>
    `cdp:webStorage-updated:${e.params?.key || '?'}`),
  ...cdp.drain('DOMStorage.domStorageItemRemoved').map(e =>
    `cdp:webStorage-removed:${e.params?.key || '?'}`),
  ...cdp.drain('DOMStorage.domStorageItemsCleared').map(() => 'cdp:webStorage-cleared'),
  ...cdp.drain('Storage.indexedDBContentUpdated').map(e =>
    `cdp:indexedDB-content:${e.params?.databaseName || '?'}:${e.params?.objectStoreName || '?'}`),
  ...cdp.drain('Storage.indexedDBListUpdated').map(() => 'cdp:indexedDB-list'),
  ...cdp.drain('Storage.cacheStorageContentUpdated').map(e =>
    `cdp:cache-content:${e.params?.cacheName || '?'}`),
  ...cdp.drain('Storage.cacheStorageListUpdated').map(() => 'cdp:cache-list'),
].sort();

let installedScript = null;
let storageTracking = false;
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
  if (storageTracking) {
    await requireCdp('Storage.untrackIndexedDBForOrigin', { origin });
    await requireCdp('Storage.untrackCacheStorageForOrigin', { origin });
    storageTracking = false;
  }
  if (enabled.includes('storage')) {
    await requireCdp('Storage.trackIndexedDBForOrigin', { origin });
    await requireCdp('Storage.trackCacheStorageForOrigin', { origin });
    storageTracking = true;
  }

  await cdp.send('Page.navigate', { url: APP_URL });
  for (let attempt = 0; attempt < 80; attempt++) {
    const state = await evaluate('document.readyState === "complete" && typeof window.DnsAudit');
    if (state === 'object') break;
    await new Promise(r => setTimeout(r, 250));
  }

  // Everything above this line is page load. Everything below is analysis.
  await evaluate(`window.__probeArmed(${runNonce})`);
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
  const contentEvents = storageMutationEvents();

  const seen = await evaluate('window.__probeCollect()');
  const parsed = typeof seen === 'string' ? JSON.parse(seen) : { storage: [], insertion: [] };
  return {
    attempted: JSON.parse(typeof attempted === 'string' ? attempted : '[]'),
    bootStorage: JSON.parse(typeof bootStorage === 'string' ? bootStorage : '[]'),
    network: requests,
    storage: [...new Set(parsed.storage.concat(contentEvents))].sort(),
    storageEvents,
    contentEvents,
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
const EVERY_ROUTE = ['network', 'storage-setItem', 'storage-property',
  'storage-remove', 'storage-cookie', 'storage-indexeddb', 'storage-cache',
  'storage-idb-record', 'storage-cache-body',
  'storage-idb-blob', 'storage-cache-bytes',
  'storage-idb-deep', 'storage-idb-file',
  'insertion-appendChild', 'insertion-range'];
eq('the fixture committed every violation by every route it claims',
  caught.attempted, EVERY_ROUTE);
eq('the network detector saw the request', caught.network.length, 1);

// Both storage routes, including the named-property write that walked past the
// previous wrapper entirely.
/* Every surface the snapshot claims, and the three change KINDS: an addition,
 * a removal, and a replacement of an existing value. */
eq('the storage detector saw a write by method call and by property assignment',
  caught.storage.filter(k => k.startsWith('localStorage:__')).sort(),
  ['localStorage:__direct_probe__', 'localStorage:__seed_remove__',
    'localStorage:__unsafe_probe__']);
eq('a REMOVAL is a difference, not an absence',
  caught.storage.includes('localStorage:__seed_remove__'), true);
eq('a cookie whose VALUE changed is a difference',
  caught.storage.includes('cookie:__seed_cookie__'), true);
eq('an IndexedDB database is seen',
  caught.storage.some(k => k.startsWith('indexedDB:__unsafe_db__')), true);
eq('and a Cache Storage entry is seen',
  caught.storage.some(k => k.startsWith('cache:__unsafe_cache__')), true);

/* Container metadata is the easy half. These two write INSIDE containers that
 * already existed, changing no database name, no version and no cached request
 * URL — the case a catalog-shaped snapshot reports as nothing at all. */
eq('a record written into an EXISTING object store is seen',
  caught.storage.some(k => k.startsWith('indexedDB:__seed_db__/')), true);
eq('and a replaced response body for an EXISTING cached URL is seen',
  caught.storage.some(k => k.startsWith('cache:__seed_cache__|')), true);

/* Representation, not just location. A snapshot that coerces to JSON or to
 * text collapses values the storage APIs really do persist: a Blob becomes
 * {}, and two different invalid UTF-8 bytes become the same character. */
eq('a replaced Blob-valued record is seen',
  caught.storage.includes('indexedDB:__seed_db__/blobs'), true);
eq('and a cached body whose BYTES changed but whose text did not is seen',
  caught.storage.some(k => k.endsWith('?bytes=1')), true);
eq('a deep value change is seen without serialising its leaf',
  caught.contentEvents.includes('cdp:indexedDB-content:__seed_db__:deep'), true);
eq('and a File metadata change is seen without serialising its metadata',
  caught.contentEvents.includes('cdp:indexedDB-content:__seed_db__:files'), true);
eq('Cache Storage writes also reach the browser-external content signal',
  caught.contentEvents.includes('cdp:cache-content:__seed_cache__'), true);
eq('the external CDP corroborator saw the Web Storage writes',
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
    blind.attempted, EVERY_ROUTE);
  eq(`without the ${removed} detector, that violation goes unseen`,
    blind[removed].length, 0);
  if (removed === 'storage') {
    eq('  and the browser-external content signal is genuinely absent',
      blind.contentEvents, []);
  }

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

/* A fresh analysis phase, opened BEFORE the first validator call. Section 4
 * left its own deliberate violations on this page and they are not this
 * section's to report — but the window must also cover every call below,
 * including this one. Arming after the first call left an idempotent leak
 * outside the measured window entirely, which is how an early version of this
 * section reported "no storage write" while analysis created a database. */
await evaluate('window.__probeArmed()');
cdp.clearEvents();

const cleanSvg = await checkSvg(conformantSvg);
eq('a conformant tiny-ps logo passes through the real parser',
  [cleanSvg.valid, cleanSvg.rejections, cleanSvg.diagnostics, cleanSvg.title],
  [true, [], [], 'Brand']);

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
// A collector that throws must FAIL the gate. Defaulting to an empty result
// would turn a broken instrument into a clean bill of health, which is the
// one outcome a security suite must never produce.
eq('the collector returned a result rather than erroring',
  typeof afterAnalysis === 'string', true);
const analysisSeen = typeof afterAnalysis === 'string'
  ? JSON.parse(afterAnalysis) : { storage: ['<collector-failed>'], insertion: ['<collector-failed>'] };
const analysisStorage = [...new Set(
  analysisSeen.storage.concat(storageMutationEvents()))].sort();
// NO filter. The criterion is "analysis caused no request", not "no
// cross-origin request": a same-origin call can still exfiltrate the supplied
// artifact to a route `connect-src 'self'` permits. The validator source and
// its fixtures are installed before the events are cleared, so nothing
// legitimate is expected here at all.
const analysisRequests = cdp.drain('Network.requestWillBeSent')
  .map(e => e.params?.request?.url || '');

eq('no foreign node from any hostile fixture entered the document',
  analysisSeen.insertion, []);
eq('no storage write happened while analysing them', analysisStorage, []);
eq('and no fixture caused ANY network request, same-origin included',
  analysisRequests, []);

cdp.close();
cleanup();
report();
