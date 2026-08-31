/**
 * Name existence. Spec Design §3, a named exception edge. Task 3.5.
 *
 * `yes` / `no` / `unknown`, mapped from a raw transport kind — which means this
 * module deliberately **bypasses layer 3**. It has to: after normalization
 * `nodata` and `nxdomain` both come back as an empty array, and the whole
 * question here is which of the two it was.
 *
 * | Kind | Existence | Reading |
 * | --- | --- | --- |
 * | `nxdomain` | `no` | The resolver says this name does not exist. |
 * | `success`, `nodata` | `yes` | The name exists; it may simply publish no NS record. |
 * | the other seven | `unknown` | The resolver would not say. Not the same as "no". |
 *
 * **`nxdomain` ≠ `nodata` is the whole point** (spec §3), and the third value
 * is what keeps a resolver failure from being reported as a missing domain.
 * An audit that collapsed `unknown` into `no` would tell someone their domain
 * is unregistered because a query timed out.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `existenceFromResponse` and `domainExists`, unchanged.
 */

import { dnsError } from './errors.js';

/** The closed set this module maps to. */
export const EXISTENCE_STATES = Object.freeze(['yes', 'no', 'unknown']);

/**
 * A raw transport result to an existence verdict.
 *
 * Pure, and total: a missing response is `unknown`, not a throw, because a
 * caller that got here without a response has already been through the
 * optional-check policy.
 */
export function existenceFromResponse(response) {
  if (!response) return 'unknown';
  if (response.kind === 'nxdomain') return 'no';
  if (response.kind === 'success' || response.kind === 'nodata') return 'yes';
  return 'unknown';
}

/**
 * Ask whether a name exists, over one transport.
 *
 * Cancellation is re-thrown rather than reported as `unknown`: an aborted audit
 * has no verdict about the domain, and `unknown` is a claim that the resolver
 * was asked and would not say.
 */
export function createExistence({ dohFetch }) {
  return async function domainExists(name, queryOpts) {
    var response = await dohFetch(name, 'NS', queryOpts);
    if (response.kind === 'cancelled') throw dnsError('cancelled', name, 'NS');
    return existenceFromResponse(response);
  };
}
