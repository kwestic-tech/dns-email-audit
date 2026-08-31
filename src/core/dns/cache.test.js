#!/usr/bin/env node
/**
 * The DoH cache. Spec Design §5, implementation Task 3.2.
 *
 * Two properties matter here and they are different in kind. One is mechanical
 * — the eviction really is least-recently-used and the ceiling really holds.
 * The other is a **privacy invariant**: two runtimes share no cache, and one
 * runtime keeps its cache for the whole page. `PRIVACY.md` publishes the
 * fan-out that lifetime produces, so a change to it is a change to a published
 * figure rather than an optimisation.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { createDohCache, MAX_DOH_CACHE_ENTRIES } from './cache.js';

const { eq, section, report } = createSuite();

/* ── 1. Storage ───────────────────────────────────────────────────────── */
section('1. It stores and returns what it was given');

const cache = createDohCache();
eq('a miss is undefined', cache.get('absent'), undefined);
cache.set('a', { kind: 'success', answers: [] });
eq('a hit returns the stored value', cache.get('a').kind, 'success');
eq('and the same object, not a copy — the transport returns it directly',
  cache.get('a') === cache.get('a'), true);
eq('size reflects what is held', cache.size, 1);

cache.set('a', { kind: 'nodata', answers: [] });
eq('re-setting a key replaces its value', cache.get('a').kind, 'nodata');
eq('and does not grow the map', cache.size, 1);

/* ── 2. Least-recently-used, not first-in-first-out ───────────────────── */
section('2. Eviction order');

/**
 * The distinction this asserts is the whole reason `get` re-inserts. Under
 * FIFO, the oldest WRITE is evicted; under LRU it is the oldest USE. A DMARC
 * tree walk re-reads the same organizational domain across siblings, so an
 * entry can be old and hot at once — evicting it would re-issue a query the
 * fan-out figures assume is cached.
 */
const lru = createDohCache({ maxEntries: 3 });
lru.set('one', 1);
lru.set('two', 2);
lru.set('three', 3);
eq('the ceiling is not yet exceeded', lru.size, 3);

lru.get('one');              // 'one' is now the most recently used
lru.set('four', 4);          // evicts the least recently used, which is 'two'

eq('the ceiling holds', lru.size, 3);
eq('the least recently USED entry was evicted', lru.get('two'), undefined);
eq('the oldest entry survived because it was read', lru.get('one'), 1);
eq('and the newest is present', lru.get('four'), 4);
eq('as is the untouched middle one', lru.get('three'), 3);

// The negative control: without the re-insertion this would be FIFO, and
// 'one' — the oldest write — would be the one that went.
const fifoWouldHaveEvicted = 'one';
eq('an LRU cache did NOT evict the oldest write', lru.get(fifoWouldHaveEvicted) !== undefined, true);

/* ── 3. The ceiling ───────────────────────────────────────────────────── */
section('3. The bound is a bound');

eq('the shipped ceiling is 4096', MAX_DOH_CACHE_ENTRIES, 4096);

const bounded = createDohCache({ maxEntries: 10 });
for (let i = 0; i < 500; i++) bounded.set(`k${i}`, i);
eq('500 writes into a 10-entry cache leave 10', bounded.size, 10);
eq('and they are the last 10', bounded.get('k499'), 499);
eq('the earliest are gone', bounded.get('k0'), undefined);

const shipped = createDohCache();
for (let i = 0; i < MAX_DOH_CACHE_ENTRIES + 50; i++) shipped.set(`k${i}`, i);
eq('the default ceiling holds too', shipped.size, MAX_DOH_CACHE_ENTRIES);

/* ── 4. One cache per runtime — the privacy invariant ─────────────────── */
section('4. Two caches share nothing');

/**
 * Risk R10, and round 1's finding F4. The cache's lifetime is a published
 * figure: one per runtime produces the sibling reuse
 * `tools/scoring.test.mjs:1888-1891` asserts, and `PRIVACY.md` states the
 * fan-out that reuse yields. This asserts the isolation half; the reuse half is
 * asserted through the engine, where a real DMARC walk can be counted.
 */
const first = createDohCache();
const second = createDohCache();
first.set('shared-key', 'from first');
eq('a second cache does not see the first\'s entry', second.get('shared-key'), undefined);
second.set('shared-key', 'from second');
eq('and writing it does not disturb the first', first.get('shared-key'), 'from first');
eq('nor the second', second.get('shared-key'), 'from second');
eq('the factory returns a new object each call', first === second, false);

/**
 * The module holds no state of its own. If it did, importing it twice — or
 * once, in a process running two runtimes — would leak between them, which is
 * exactly what "Node's ESM cache is not a dependency-injection mechanism"
 * means in practice.
 */
const third = createDohCache();
eq('a cache built after two others is still empty', third.size, 0);
eq('and sees nothing either of them wrote', third.get('shared-key'), undefined);

report();
