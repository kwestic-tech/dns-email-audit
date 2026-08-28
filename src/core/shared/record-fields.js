/**
 * Ordered record-field parsing, shared by two protocol owners. Spec §12,
 * Task 4.0.
 *
 * `parseOrderedFields()` is read by `core/transport/`'s MTA-STS and TLS-RPT
 * validators and by `core/bimi/`'s. Three call sites, two owning directories,
 * one grammar: `field *( field-delim field )`, where order is part of the
 * contract because RFC 8461 §3.1 and RFC 8460 §3 both put the version field
 * first — a fact an unordered tag map cannot express.
 *
 * **Not `parseTagList()`.** DMARC's permissive tag-bag reader looks like a
 * near-duplicate of this and is deliberately left in `core/dmarc/`: it lowercases
 * names, trims values unconditionally, drops fields that carry no `=`, and
 * reports duplicates — four behavioural differences, each of which some caller
 * depends on. Merging them would be a redesign wearing a de-duplication costume.
 *
 * The `strictFieldSyntax` option is the same arrangement as `uri.js`'s: the
 * grammar is shared, the per-protocol tightening is the caller's. `EXT_NAME`
 * is here for the same reason and `RECORD_EXT_VALUE` is not: the extension
 * NAME grammar is one production all three validators share, while the
 * extension VALUE class differs — BIMI's pinned draft does not carry
 * MTA-STS's `=` exclusion — so each owner keeps its own.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `parseOrderedFields` and `EXT_NAME`, unchanged apart from the
 * two-space dedent and the `export` keywords. `EXT_NAME` should have moved at
 * Task 4.0 and did not: that sweep analysed FUNCTION callers mechanically and
 * read the constant list by eye, and a constant used directly by three
 * validators rather than through a moved helper fell between the two. Found at
 * Task 4.3, when BIMI needed it.
 */

/**
 * `sts-ext-name = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")`.
 *
 * RFC 8461 §3.1's production, reused verbatim by RFC 8460 §3 and by the BIMI
 * draft. Exported as the regex rather than as a predicate so the three call
 * sites stay byte-identical through the move; it carries no `g` flag, so
 * `.test()` retains nothing between calls and the directory's no-state rule
 * holds.
 */
export const EXT_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;

/**
 * Split a record into ordered `{ name, value }` fields, or null if any field
 * is not `name=value`.
 *
 * Ordered, because RFC 8461 §3.1 and RFC 8460 §3 both require the version
 * field FIRST — a fact an unordered tag map cannot express, which is why
 * `id=abc; v=STSv1` validated. A single trailing delimiter is permitted by
 * both ABNFs.
 */
export function parseOrderedFields(record, opts) {
  var options = opts || {};
  var parts = String(record === undefined || record === null ? '' : record).split(';');
  if (parts.length > 1 && parts[parts.length - 1].trim() === '') parts.pop();
  var fields = [];
  for (var i = 0; i < parts.length; i++) {
    // `field-delim = *WSP ";" *WSP`, so whitespace belongs to the delimiter.
    var field = parts[i].trim();
    var equals = field.indexOf('=');
    if (equals === -1) return null;
    var name = field.slice(0, equals);
    var value = field.slice(equals + 1);
    // MTA-STS and TLS-RPT write their fields as single literals —
    // `%s"v=STSv1"`, `%s"id="`, `%s"rua="` — and their extensions as
    // `name "=" value`. None of those admits whitespace around the `=`, so
    // trimming it accepted `v = STSv1`. BIMI's grammar is looser, hence an
    // option rather than a blanket rule.
    if (!options.strictFieldSyntax) { name = name.trim(); value = value.trim(); }
    fields.push({ name: name, value: value });
  }
  return fields;
}
