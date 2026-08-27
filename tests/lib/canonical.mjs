/**
 * The executable half of `tests/fixtures/equivalence/canonicalization.md`.
 *
 * Every rule in that document names a function here. The document is the
 * argument; this file is the behaviour, and the two are checked against each
 * other by `tests/contract/canonicalization.test.mjs` — including the negative
 * cases that prove each rule can fail.
 *
 * The governing constraint, spec Design §8: a canonicalizer loose enough never
 * to cry wolf is loose enough to absorb a real regression. Nothing here rounds,
 * trims, sorts an array, or drops an empty value.
 */

/* ── Value encoding ───────────────────────────────────────────────────── */

/**
 * Encode one value into a JSON-representable form that loses nothing.
 *
 * The four things plain `JSON.stringify` destroys, and what happens instead:
 *
 *   | input        | JSON.stringify | here                  |
 *   | ---          | ---            | ---                   |
 *   | `undefined`  | key vanishes   | `{"$undefined":true}` |
 *   | `NaN`        | `null`         | `{"$number":"NaN"}`   |
 *   | `-0`         | `0`            | `{"$number":"-0"}`    |
 *   | `123n`       | throws         | `{"$bigint":"123"}`   |
 *
 * `undefined` is the load-bearing one. `checkDNSSEC()` sets `error` to
 * `undefined` on a determinate result (js/dns.js:4128) while the not-checked
 * DKIM shape omits six properties outright — present-with-undefined and absent
 * are different facts about the code, and a canonicalizer that folded them
 * together would hide a refactor turning one into the other.
 *
 * `-0` is here because the SPF and scoring arithmetic is numeric and `-0`
 * survives `Math.min` and multiplication. It has never been observed in a
 * result; it is tagged so that if it ever appears it appears, rather than
 * being silently equal to `0`.
 */
export function encode(value, path = '$', seen = new Set()) {
  if (value === null) return null;

  const type = typeof value;

  if (type === 'bigint') return { $bigint: value.toString() };
  if (type === 'undefined') return { $undefined: true };
  if (type === 'function') {
    throw new Error(`canonical: a function reached the result surface at ${path}`);
  }
  if (type === 'symbol') {
    throw new Error(`canonical: a symbol reached the result surface at ${path}`);
  }
  if (type === 'number') {
    if (Number.isNaN(value)) return { $number: 'NaN' };
    if (value === Infinity) return { $number: 'Infinity' };
    if (value === -Infinity) return { $number: '-Infinity' };
    if (value === 0 && Object.is(value, -0)) return { $number: '-0' };
    // No rounding. A float that changed is a change.
    return value;
  }
  if (type === 'string' || type === 'boolean') return value;

  if (seen.has(value)) throw new Error(`canonical: circular reference at ${path}`);
  seen.add(value);
  try {
    // Array ORDER IS PRESERVED. Several are semantically ordered — the DMARC
    // walk steps, the DNSSEC chain claims, the scoring pillars, the issue
    // list — and sorting them would erase the behaviour under test.
    if (Array.isArray(value)) {
      return value.map((entry, i) => encode(entry, `${path}[${i}]`, seen));
    }
    // Map and Set are tagged rather than serialized to `{}`. Nothing in the
    // v0.5.0 result carries one, and this is what makes that a fact the runner
    // reports rather than an assumption it relies on.
    if (value instanceof Map) {
      return { $map: [...value.entries()].map(([k, v], i) => [encode(k, `${path}<key ${i}>`, seen), encode(v, `${path}<${String(k)}>`, seen)]) };
    }
    if (value instanceof Set) {
      return { $set: [...value].map((v, i) => encode(v, `${path}<${i}>`, seen)) };
    }
    if (value instanceof Date) return { $date: value.toISOString() };
    if (value instanceof Error) {
      return { $error: { name: value.name, message: value.message, kind: encode(value.kind, `${path}.kind`, seen) } };
    }
    if (ArrayBuffer.isView(value)) {
      return { $bytes: Array.from(value).join(',') };
    }

    // Objects: OWN enumerable keys only, and the key list is taken before
    // encoding so a property that is present with an undefined value keeps its
    // place. Recursively sorted — the ONLY sort this file performs.
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = encode(value[key], `${path}.${key}`, seen);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

/**
 * Serialize an encoded value deterministically.
 *
 * `encode` has already sorted every object's keys, so insertion order is the
 * canonical order and `JSON.stringify` is stable over it. Two spaces, trailing
 * newline: the committed baseline is a file humans have to diff.
 */
export function serialize(encoded) {
  return JSON.stringify(encoded, null, 2) + '\n';
}

/** encode + serialize, the pair used for the result surface. */
export function canonicalResult(value) {
  return serialize(encode(value));
}

/* ── Query trace ──────────────────────────────────────────────────────── */

/**
 * Canonicalize a DNS query trace.
 *
 * Gated on the MULTISET of `(name, type, do, cd)` with occurrence counts, plus
 * the maximum observed concurrency and batch size. NOT on global chronology:
 * independent `Promise.all` branches may interleave differently between two
 * runs of identical code, and gating on that produces failures that mean
 * nothing — which is the fastest way to teach a team to ignore this surface.
 *
 * Order IS asserted, separately and explicitly, for the two algorithms where
 * the sequence is the behaviour: the DMARC tree walk and SPF recursive
 * evaluation. `orderedSubsequence()` below is what does that.
 *
 * The count is the reason this surface exists at all. `PRIVACY.md:30-33`
 * publishes "roughly 41 queries for a typical domain" and 61 for
 * `cloudflare.com`; a lost cache hit changes that figure and is invisible in
 * the result surface.
 */
export function canonicalQueryTrace(calls, observed = {}) {
  const counts = new Map();
  for (const call of calls) {
    const key = `${call.name} ${call.type} do=${call.dnssec ? 1 : 0} cd=${call.checkingDisabled ? 1 : 0}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return {
    // Sorted, because a multiset has no order. This is a sort of a set, not of
    // a sequence, and it is the one place a sort is correct here.
    queries: [...counts.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([key, count]) => ({ query: key, count })),
    total: calls.length,
    distinct: counts.size,
    maxConcurrency: observed.maxConcurrency ?? null,
    maxBatchSize: observed.maxBatchSize ?? null,
  };
}

/**
 * The ordered subsequence of a trace matching a predicate.
 *
 * Used for the two order-bearing algorithms. A tree walk that queried
 * `_dmarc.a.b.com` after `_dmarc.com` is a different algorithm from one that
 * queried them the other way round, and the multiset above cannot tell them
 * apart.
 */
export function orderedSubsequence(calls, predicate) {
  return calls.filter(predicate).map(call => `${call.name} ${call.type}`);
}

/* ── CSV ──────────────────────────────────────────────────────────────── */

/**
 * CSV is compared as EXACT BYTES, so there is no canonicalization to do — this
 * function exists to state that and to pin the one convention the comparison
 * depends on.
 *
 * The columns are positional (js/app.js:1452 backfills a short translated
 * header from English by index), so a reordered column silently breaks anyone
 * parsing the file while every value in it stays correct. Nothing here may
 * normalize line endings, strip the BOM, or trim a field.
 */
export function canonicalCsv(text) {
  if (typeof text !== 'string') throw new Error('canonical: CSV must be compared as text');
  return text;
}

/* ── DOM and HTML ─────────────────────────────────────────────────────── */

/**
 * Non-attribute properties that are part of the observable state of an
 * element and are invisible in its markup.
 *
 * `checked` is the reason this list exists: `#optDeepChecks` is a real
 * checkbox whose `.checked` the code reads and writes, and its state never
 * appears as an attribute.
 */
const LIVE_PROPERTIES = ['value', 'checked', 'disabled', 'hidden', 'selected'];

/**
 * Canonicalize a DOM subtree.
 *
 * Ordered node and child structure with EXACT text. Whitespace text nodes are
 * NOT normalized away and text is not trimmed: the hygiene sentinels the
 * renderer emits (`‹RLO›`, `‹ZWSP›`) are exact text, and so is the astral
 * character at the display cap that `export.test.mjs` pins.
 *
 * Attributes are compared as a sorted name/value map, because attribute order
 * is not observable behaviour and a DOM shim need not preserve it.
 */
export function canonicalDom(node) {
  if (!node) return null;
  // Text, comment and other character-data nodes.
  if (node.nodeType !== 1) {
    return { type: node.nodeType, data: node.data === undefined ? null : node.data };
  }

  const attributes = {};
  if (node.attributes && typeof node.attributes.forEach === 'function') {
    node.attributes.forEach(({ name, value }) => { attributes[name] = value; });
  }
  if (node.dataset) {
    for (const key of Object.keys(node.dataset)) {
      attributes['data-' + key.replace(/[A-Z]/g, m => '-' + m.toLowerCase())] = String(node.dataset[key]);
    }
  }

  const properties = {};
  for (const name of LIVE_PROPERTIES) {
    if (node[name] !== undefined) properties[name] = node[name];
  }

  return {
    tag: node.localName,
    // Sorted: attribute order is not behaviour.
    attributes: Object.fromEntries(Object.keys(attributes).sort().map(k => [k, attributes[k]])),
    properties: Object.fromEntries(Object.keys(properties).sort().map(k => [k, properties[k]])),
    // NOT sorted: child order is behaviour.
    children: (node.childNodes || []).map(canonicalDom),
  };
}

/**
 * The two byte-exact regions of the exported HTML report.
 *
 * The report carries its own Content-Security-Policy and its own inlined
 * stylesheet, and `tools/csp.test.mjs` §5 asserts the policy. Those are
 * precisely the parts a tree canonicalizer must not be allowed to normalize
 * away, so they are pulled out and compared as bytes beside the tree.
 */
export function reportByteRegions(html) {
  // The attribute delimiter is captured and back-referenced: the policy itself
  // contains single quotes (`'none'`, `'unsafe-inline'`), so a character class
  // excluding both quote characters stops at the first one and silently
  // returns a truncated policy that still looks plausible.
  const policy = /content=(["'])((?:(?!\1).)*default-src(?:(?!\1).)*)\1/.exec(html);
  const style = /<style[^>]*>([\s\S]*?)<\/style>/.exec(html);
  return {
    csp: policy ? policy[2] : null,
    stylesheet: style ? style[1] : null,
    stylesheetBytes: style ? Buffer.byteLength(style[1], 'utf8') : 0,
  };
}

/* ── Exclusions ───────────────────────────────────────────────────────── */

/**
 * Apply the excluded-field manifest.
 *
 * One entry per excluded field, each naming a path and a reason. NO WILDCARD
 * CLASSES: an exclusion nobody can enumerate is a hole nobody can review, so
 * a path containing `*` is rejected rather than expanded.
 *
 * The manifest is expected to stay empty. Time and locale are controlled
 * INPUTS through the platform binding — `now()` and `formatDateTime()` — not
 * excluded outputs, so `report.generated` carries the same formatted timestamp
 * in the baseline, source and bundle runs and needs no exclusion.
 */
export function applyExclusions(encoded, manifest = []) {
  for (const entry of manifest) {
    if (!entry || typeof entry.path !== 'string' || typeof entry.reason !== 'string' || !entry.reason.trim()) {
      throw new Error('canonical: every exclusion needs a path and a stated reason');
    }
    if (entry.path.includes('*')) {
      throw new Error(`canonical: wildcard exclusion refused — ${entry.path}`);
    }
  }
  if (!manifest.length) return encoded;

  const clone = JSON.parse(JSON.stringify(encoded));
  for (const entry of manifest) {
    const segments = entry.path.split('.');
    let cursor = clone;
    for (let i = 0; i < segments.length - 1 && cursor; i++) cursor = cursor[segments[i]];
    if (cursor && typeof cursor === 'object') {
      cursor[segments[segments.length - 1]] = { $excluded: entry.reason };
    }
  }
  return clone;
}
