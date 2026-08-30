/**
 * Per-audit state. Spec Design §5, implementation Task 5.1.
 *
 * One audit of one domain has three pieces of state that belong to it and to
 * nothing else: the options it was started with, the query options those
 * produce, and the result it is accumulating. This module owns those three and
 * refuses everything else.
 *
 * ── What this deliberately does NOT own ─────────────────────────────────
 *
 * | Not here | Where it lives, and why |
 * | --- | --- |
 * | The DoH cache | [`core/dns/cache.js`](../core/dns/cache.js), at runtime/page lifetime. Spec correction 3 and Risk R10: the cache is reused across sibling audits, and narrowing it to one audit changes the DNS fan-out `PRIVACY.md` publishes. A context that held it would make that a per-audit decision. |
 * | Parsing | `core/<protocol>/`. Nothing here reads a record. |
 * | Scoring and issues | `audit/scoring.js` and `audit/issues.js`, Tasks 5.3 and 5.4. |
 * | Concurrency | The coordinator's `Promise.all` structure, unchanged in this release. |
 * | The cancellation POLICY | [`core/dns/optional.js`](../core/dns/optional.js). This module carries the signal; it does not decide what an abort means. |
 *
 * ── Cancellation ────────────────────────────────────────────────────────
 *
 * The `AbortSignal` enters the audit here and reaches every query as
 * `queryOptions.signal`. That is the whole of this module's part in it: the two
 * cancellation shapes — an already-aborted signal throwing before a request,
 * and an in-flight abort returning transport kind `cancelled` — are the
 * transport's and `optionalCheck()`'s, and are unchanged. Nothing here inspects
 * `signal.aborted`, so an audit started with an already-aborted signal is
 * constructed exactly like any other and fails at its first query.
 *
 * ── The options are carried, not reinterpreted ──────────────────────────
 *
 * `options` is the object the caller supplied, exposed as given. No defaulting,
 * no coercion, no narrowing — two of the flags (`selectors`,
 * `dkimComprehensive`) are passed onward as VALUES rather than read as
 * booleans, and `retries` is observably not forwarded into the query options
 * today. Resolving any of that would be a behaviour change wearing a
 * boundary's clothes. `context.test.js` pins the query options to the one key
 * they actually carry.
 *
 * ── The result is isolated at the TOP LEVEL, and only there ─────────────
 *
 * `result()` returns a fresh outer object, so replacing one of its properties
 * cannot reach the accumulator. It does **not** copy what those properties
 * hold: `result().score` is the same object the audit recorded, and mutating
 * THROUGH a result changes what a later `result()` returns.
 *
 * That is deliberate and must stay. Deep-cloning here would change legacy
 * identities and value types — the result carries `BigInt`s from the SPF
 * subnet helpers among other things — and a structural copy is a behaviour
 * change, not a stronger boundary. Both halves are asserted in
 * `context.test.js` so nobody later "hardens" this into serialization.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `analyzeDomain()`'s first three lines and its two return statements, and
 * nothing else. The coordinator still holds every check, every fallback and
 * the `Promise.all` structure until Task 5.2.
 */

/**
 * Build the context for one audit of one domain.
 *
 * `domain` is normalized the way `analyzeDomain()` has always normalized it —
 * lowercased and trimmed, and a value with no `toLowerCase` throws here for the
 * same reason it threw there.
 */
export function createAuditContext({ domain, options }) {
  const name = domain.toLowerCase().trim();
  /**
   * The options every query is issued under.
   *
   * Exactly one key. `analyzeDomain()` has always built this as `{ signal }`,
   * so anything else on the caller's options — `retries` among them — does not
   * reach the transport, and widening it here would change the fan-out.
   */
  let queryOptions = { signal: options.signal };
  const accumulated = {};

  return {
    /** The audited name, normalized. */
    domain: name,
    /** The options in force, as supplied. */
    options,
    get queryOptions() { return queryOptions; },

    /**
     * Re-issue subsequent queries with DNSSEC checking disabled.
     *
     * The one derived query option this audit has. A validating resolver
     * answers SERVFAIL for a bogus chain, and once that verdict is established
     * the remaining diagnostic records are retrieved with `cd=1` so the
     * operator can see the failure and its data. The DNSSEC verdict itself
     * still comes from the validating query.
     *
     * A new object each time, exactly as the coordinator built it: the options
     * already handed to an in-flight query are never mutated underneath it.
     */
    disableDnssecChecking() {
      queryOptions = Object.assign({}, queryOptions, { checkingDisabled: true });
      return queryOptions;
    },

    /**
     * Accumulate fields into the result this audit is building.
     *
     * `domain` is not a recordable field. The audited name is normalized once,
     * at construction, and it is the context's — an accumulated field must not
     * be able to replace it and make `result().domain` disagree with
     * `ctx.domain`. Every other field in the same call still lands.
     */
    record(fields) {
      for (const key of Object.keys(fields)) {
        if (key === 'domain') continue;
        accumulated[key] = fields[key];
      }
    },

    /**
     * The accumulated result, with the audited name in front.
     *
     * A fresh OUTER object per call, and only that: what the properties hold is
     * shared by identity with the audit, deliberately. See the note above.
     */
    result() {
      return Object.assign({ domain: name }, accumulated);
    },
  };
}
