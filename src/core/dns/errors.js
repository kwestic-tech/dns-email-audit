/**
 * DNS transport errors. Spec Design §3, implementation Task 3.3.
 *
 * Two things leave this layer as a **throw** rather than as a kind, and keeping
 * them distinct from the ten-kind algebra is the point of the module:
 *
 * | | Thrown by | Name | Caught by `optionalCheck()`? |
 * | --- | --- | --- | --- |
 * | `DnsTypeError` | `dnsTypeNum()` | `DnsTypeError` | **No — re-thrown** |
 * | `DnsError` | `dnsError()`, `requireUsable()` | `DnsQueryError`, or `AbortError` when the kind is `cancelled` | Yes, except `AbortError` |
 *
 * `DnsTypeError` is **not a transport kind and must not become one** (spec §3).
 * A query for a record type the transport does not know is a defect in this
 * repository, not a resolver hiccup.
 *
 * ── Why `dnsTypeNum` throws rather than defaulting ──────────────────────
 *
 * It used to end in `?? 16`, which made the function total by answering every
 * unknown type with the TXT number. The cost of that totality was the worst
 * failure this codebase can produce: a caller asking for `DS` issued a TXT
 * query, filtered the answers for type 16, found none, and received a
 * plausible-looking empty array. No error, no warning, and a confident "no
 * records published" about a type that was never asked for.
 *
 * Every call site passes a supported literal, so throwing is behaviour-
 * preserving for the code that exists and fail-fast for the code that comes
 * next. `hasOwnProperty` rather than a bare lookup, so a type name colliding
 * with `Object.prototype` — `"constructor"`, `"toString"` — throws instead of
 * returning a function.
 *
 * ── Why a cancelled query is named `AbortError` ─────────────────────────
 *
 * Because `optionalCheck()` re-throws by NAME, and an aborted audit must not
 * degrade to a stated "unknown" the way a resolver hiccup does. The `kind` is
 * still `cancelled`; only the `name` differs, and the two carry different
 * information: the kind says what happened at the transport, the name says how
 * the policy layer must treat it.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `DNS_TYPES`, `dnsTypeNum()` and `dnsError()`, unchanged. Both
 * functions are pure and neither closes over anything, which is why they need
 * no factory.
 */

/** The record types this transport supports. A type absent here throws. */
export const DNS_TYPES = Object.freeze({
  A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  DS: 43, DNSKEY: 48, TLSA: 52, CAA: 257,
});

/**
 * A record type name to its IANA number.
 *
 * @throws {Error} named `DnsTypeError` for any unsupported type.
 */
export function dnsTypeNum(type) {
  if (!Object.prototype.hasOwnProperty.call(DNS_TYPES, type)) {
    var error = new Error('unsupported DNS type: ' + type);
    // Named so optionalCheck() re-throws it. An unsupported type is a
    // programming error, not a resolver hiccup, and degrading it to a stated
    // "unknown" would hide exactly what the throw exists to surface.
    error.name = 'DnsTypeError';
    throw error;
  }
  return DNS_TYPES[type];
}

/**
 * Build — not throw — the error for a transport kind the caller cannot use.
 *
 * Returned rather than thrown so the call site reads as the throw it is:
 * `throw dnsError(...)`. `requireUsable()` is the main caller.
 */
export function dnsError(kind, name, type, detail) {
  var e = new Error(kind + ' while querying ' + name + ' ' + type + (detail ? ': ' + detail : ''));
  e.name = kind === 'cancelled' ? 'AbortError' : 'DnsQueryError';
  e.kind = kind;
  e.queryName = name;
  e.queryType = type;
  return e;
}
