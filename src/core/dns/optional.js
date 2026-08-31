/**
 * The error and cancellation policy. Spec Design §3 layer 4, Task 3.5.
 *
 * One function, and it decides the difference between a degraded check and a
 * discarded audit.
 *
 * ── What it is for ──────────────────────────────────────────────────────
 *
 * Everything behind `opts.www` / `opts.wildcard` / `opts.advanced` is
 * enrichment: the domain's actual email-security posture is already established
 * by the core NS/MX/TXT lookups. Before this existed, a transient SERVFAIL on
 * any one of them threw, and the throw discarded the entire audit — SPF, DKIM,
 * DMARC and all — for a domain whose real records had resolved perfectly.
 * Across a 200-domain run that is close to guaranteed to happen to someone.
 *
 * A resolver hiccup must degrade one check, never delete the result. What it
 * must NOT do is quietly become a passing or failing verdict, so every fallback
 * marks itself unknown and the scorer treats it as unscored rather than as zero.
 *
 * ── The two names it re-throws, and why each ────────────────────────────
 *
 * | Name | Why it is not an "unknown" |
 * | --- | --- |
 * | `AbortError` | An aborted audit is not an unknown result. The user stopped it; reporting a stated "unknown" would claim a check ran. |
 * | `DnsTypeError` | A query for a record type the transport does not know is a defect in this repository, not a resolver hiccup. Degrading it would restore the failure `dnsTypeNum()` throws to prevent — the check silently never runs, and the interface says so in the calm voice it uses for a domain the resolver was merely slow about. |
 *
 * It re-throws by **name**, not by kind, which is why `dnsError()` names a
 * cancelled query `AbortError` while leaving its kind `cancelled`.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `optionalCheck`, unchanged. Pure with respect to the module —
 * it closes over nothing — so it needs no factory.
 */

/** The thrown names that are never degraded to a stated unknown. */
export const RETHROWN_ERROR_NAMES = Object.freeze(['AbortError', 'DnsTypeError']);

/**
 * Run an optional enrichment check, turning a DNS failure into a stated
 * "unknown" instead of an exception.
 *
 * `fallback` may be a value or a function of the error, so a caller can record
 * what went wrong alongside its declared unknown.
 */
export async function optionalCheck(run, fallback) {
  try {
    return await run();
  } catch (error) {
    if (error && (error.name === 'AbortError' || error.name === 'DnsTypeError')) throw error;
    return typeof fallback === 'function' ? fallback(error) : fallback;
  }
}
