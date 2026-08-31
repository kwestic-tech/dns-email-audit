/**
 * The DoH response cache. Spec Design §5, implementation Task 3.2.
 *
 * Bounded, least-recently-used, and **one per runtime**. That lifetime is the
 * whole point of this module having a factory rather than a singleton, and it
 * is not an implementation preference:
 *
 * > `tools/scoring.test.mjs:1888-1891` asserts a first DMARC walk issues three
 * > queries and a sibling issues one. `PRIVACY.md` publishes the fan-out that
 * > reuse produces — roughly 41 queries for a typical domain, 61 for
 * > `cloudflare.com`. **Narrowing this cache changes a published privacy
 * > figure.** Spec correction 3, Risk R10, round 1 finding F4.
 *
 * So: `createAuditRuntime()` calls this once, `src/main.js` builds one runtime
 * per page, and two runtimes share nothing. Node's ES module cache is not a
 * dependency-injection mechanism and this module does not rely on it — test
 * isolation comes from calling the factory again.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `dohCacheGet`/`dohCacheSet` closure, with the `Map` and the
 * ceiling that were beside it. Same eviction, same re-insertion, same ceiling.
 *
 * ── What is cached, and what decides ────────────────────────────────────
 *
 * Nothing here. This module stores what it is given under the key it is given.
 * The rule that only `success`, `nodata` and `nxdomain` are admitted — and that
 * `cancelled`, though retry-terminal, never is — belongs to `doh.js`, which is
 * where the kind is known. A cache that also decided admission would hold the
 * same rule twice, and two copies of one rule is how they drift apart.
 */

/**
 * The ceiling.
 *
 * The `Map` previously grew for the lifetime of the page, so a long session
 * auditing several batches retained every answer it had ever seen. 4096
 * comfortably holds a full 200-domain run — comprehensive DKIM included —
 * while staying a fixed ceiling rather than a leak.
 */
export const MAX_DOH_CACHE_ENTRIES = 4096;

/**
 * Build one cache.
 *
 * `get` returns `undefined` for a miss, which is what `doh.js` tests against.
 * A stored value is never `undefined` — only a whole DoH result object is ever
 * written — so the two cannot be confused.
 */
export function createDohCache({ maxEntries = MAX_DOH_CACHE_ENTRIES } = {}) {
  const entries = new Map();

  return {
    get(key) {
      if (!entries.has(key)) return undefined;
      // Re-insert to move the entry to the most-recently-used end. Map
      // preserves insertion order, so the oldest key is always the first one.
      const value = entries.get(key);
      entries.delete(key);
      entries.set(key, value);
      return value;
    },

    set(key, value) {
      if (entries.has(key)) entries.delete(key);
      entries.set(key, value);
      while (entries.size > maxEntries) {
        entries.delete(entries.keys().next().value);
      }
    },

    /** Observable for tests and for reasoning about the ceiling. Never a gate. */
    get size() { return entries.size; },
  };
}
