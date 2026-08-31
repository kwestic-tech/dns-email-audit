/**
 * The usability gate and the normalized record layer.
 * Spec Design §3 layers 2 and 3, implementation Task 3.4.
 *
 * Two layers, and the boundary between them is the point of the module:
 *
 * | Layer | Function | In | Out |
 * | --- | --- | --- | --- |
 * | 2 — usability | `requireUsable()` | a raw result with a `kind` | the same raw result, or a **throw** |
 * | 3 — normalized | `dohQuery()`, `dohAll()` | a name and a type | arrays of cleaned strings, **with no kind** |
 *
 * **Three kinds pass and seven throw.** `success`, `nodata` and `nxdomain` are
 * usable answers — including `nxdomain`, which is a real answer meaning the name
 * does not exist. The other seven are failures to obtain an answer at all, and
 * a caller that received an empty array for one could not tell "no records" from
 * "could not ask".
 *
 * **Layer 3 drops the kind deliberately.** That is what makes it safe for a
 * protocol module to consume: it can reason about records without having to
 * decide what a `servfail` means. Anything that genuinely needs the kind is a
 * named exception edge (§3) and reads `dohFetch` directly instead.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `requireUsable`, `cleanAnswerData`, `dohQuery`, `dohAll` and
 * `checkConnectivity`, with `dohFetch` becoming a factory argument.
 */

import { dnsError, dnsTypeNum } from './errors.js';

/** The three kinds that are answers rather than failures to obtain one. */
export const USABLE_KINDS = Object.freeze(['success', 'nodata', 'nxdomain']);

/**
 * Pass a usable raw result through, or throw for the seven that are not.
 *
 * Pure, and exported on its own because the exception edges call it directly
 * after inspecting a kind the normalized layer would have dropped.
 */
export function requireUsable(result, name, type) {
  if (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain') return result;
  throw dnsError(result.kind, name, type, result.httpStatus ? 'HTTP ' + result.httpStatus : '');
}

/**
 * One answer's `data` field, cleaned to the value a protocol module reads.
 *
 * TXT is the special case: the wire format is a sequence of quoted chunks that
 * must be concatenated, and a long record arrives split.
 */
export function cleanAnswerData(data, type) {
  var value = String(data || '').trim();
  if (type !== 'TXT') return value.replace(/^"|"$/g, '').trim();
  var chunks = [];
  var re = /"((?:\\.|[^"\\])*)"/g;
  var match;
  while ((match = re.exec(value))) {
    // Confirmed divergence (spec 0.2.3 §4): the success path decodes \uXXXX
    // escapes, the fallback keeps the chunk verbatim, so a malformed escape
    // renders as its literal source text rather than as a decoded character.
    // That is the honest reading of an undecodable chunk and it is left
    // alone deliberately — changing it would change parsed record values.
    // Any lone surrogate JSON.parse does emit is normalized to U+FFFD at
    // display time by src/ui/render.js, not here, so grades are unaffected.
    try { chunks.push(JSON.parse('"' + match[1] + '"')); }
    catch (e) { chunks.push(match[1]); }
  }
  return chunks.length ? chunks.join('') : value.replace(/^"|"$/g, '');
}

/**
 * Build the normalized layer over one transport.
 *
 * `checkConnectivity()` is here rather than in `doh.js` because it is a
 * resolver-level probe, and it is a **named exception edge** (§3): it reads
 * `.kind` directly, which layer 3 forbids. Naming it is what keeps the
 * exception from looking like an oversight — see `API.md`.
 */
export function createResolver({ dohFetch }) {
  /**
   * Answers of the requested type, cleaned.
   *
   * The type filter is why `dnsTypeNum()` must be partial: a query that fell
   * back to TXT would filter for type 16, match nothing, and return `[]` — the
   * shape of "no records published" for a type never asked for.
   */
  async function dohQuery(name, type, opts) {
    const { answers } = requireUsable(await dohFetch(name, type, opts), name, type);
    const num = dnsTypeNum(type);
    return answers.filter(a => a.type === num).map(a => cleanAnswerData(a.data, type));
  }

  /**
   * Every answer, cleaned, regardless of type.
   *
   * Used where the chain matters and not only the endpoint — a CNAME sitting in
   * front of the record being read. TXT answers are cleaned as TXT even when
   * the query was for something else, because the chunk-joining is a property
   * of the record, not of the question.
   */
  async function dohAll(name, type, opts) {
    const { answers } = requireUsable(await dohFetch(name, type, opts), name, type);
    return answers.map(a => cleanAnswerData(a.data, a.type === 16 ? 'TXT' : type));
  }

  /** Pre-flight: can we reach the resolver at all? A named exception edge. */
  async function checkConnectivity() {
    const result = await dohFetch('example.com', 'A', { noCache: true, retries: 0, timeoutMs: 5000 });
    return result.kind === 'success' || result.kind === 'nodata';
  }

  return { requireUsable, dohQuery, dohAll, checkConnectivity, cleanAnswerData };
}
