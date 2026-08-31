/**
 * Selecting a protocol's records out of a TXT set. Spec §12, Task 5.2a.
 *
 * Three helpers, one question: **which of these strings announce themselves as
 * this protocol's record?** Selection is not validation and deliberately comes
 * before it — a record has to be recognizable as a candidate before it can be
 * diagnosed as a malformed one, and a selector that was strict enough to be a
 * validator would make the malformed record vanish instead of reporting it.
 *
 * ── Why these are shared, when Task 4.0 ruled they were not ─────────────
 *
 * Task 4.0 rejected all three, and for a reason that was true at the time:
 * their only readers were `analyzeDomain()` and, for `startsWithCI`, one
 * protocol owner — and §12 gives `src/audit/` no edge to `core/shared/`, so
 * admitting them would have been building a shared home for one owner and one
 * module that could not reach it.
 *
 * Phase 5 removed the premise. The audit coordinator may hold no parsing rule
 * (Gate 5), so the selection its owners need moved to those owners, and each
 * of these now has two or more protocol readers:
 *
 * | Helper | Readers |
 * | --- | --- |
 * | `startsWithCI` | `core/spf/`, `providers/` |
 * | `versionCandidates` | `core/bimi/`, `core/transport/` (MTA-STS and TLS-RPT) |
 * | `leadingVersionMatches` | `core/bimi/`, `core/transport/` |
 *
 * That is the admission test in [`API.md`](API.md) met on its own terms, not
 * an exception carved for a refactor. `core/spf/`'s private copy of
 * `startsWithCI` — kept duplicated at Task 4.8 precisely because the second
 * reader was unreachable — is retired into this module by the same move.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s three helpers by way of `src/audit/audit-domain.js`, byte for
 * byte apart from the dedent and the `export` keywords. Same patterns, same
 * case sensitivity, same tolerance for whitespace before a delimiter.
 */

/**
 * Case-insensitive prefix match, for record SELECTION only.
 *
 * RFC 7489 and RFC 7208 tag names are case-insensitive, so `V=DMARC1` and
 * `V=SPF1` are valid records that a case-sensitive `startsWith()` would
 * silently discard — reporting a protected domain as having no policy at all.
 * False negatives are the worse error for a security tool, so match liberally
 * here and validate the contents later.
 */
export function startsWithCI(value, prefix) {
  return String(value || '').slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
}

/**
 * Records at a protocol's dedicated owner name that MENTION its version field.
 *
 * Recognition is case-insensitive and order-independent on purpose, while
 * validation stays exact. That is the point: a record has to be recognizable
 * as a candidate before it can be diagnosed as a malformed one.
 */
export function versionCandidates(records, token) {
  var pattern = new RegExp('(^|;)\\s*v\\s*=\\s*' + token + '\\s*(;|$)', 'i');
  return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
}

/** Records a conforming sender keeps before applying the full validator. */
export function leadingVersionMatches(records, token) {
  // The version literal itself is exact and case-sensitive. The delimiter,
  // however, is `*WSP ";" *WSP` in MTA-STS/TLS-RPT (and tolerated by the
  // BIMI parser), so valid whitespace before the semicolon must not make a
  // sender-compatible record disappear from the effective set.
  var pattern = new RegExp('^v=' + token + '[ \\t]*(?:;|$)');
  return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
}
