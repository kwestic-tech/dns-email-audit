/**
 * The extension VALUE class MTA-STS and TLS-RPT share. Task 4.4.
 *
 * Internal to `core/transport/`: a sibling import, which §12 permits inside a
 * directory. It is **not** in `core/shared/` and must not move there, even
 * though it sits one line from `EXT_NAME`, which is.
 *
 * The two look interchangeable and are not:
 *
 * | Production | Shared? | Why |
 * | --- | --- | --- |
 * | `EXT_NAME` | yes, `core/shared/record-fields.js` | RFC 8461 §3.1's name grammar, reused verbatim by RFC 8460 §3 and by the BIMI draft. One production, three readers. |
 * | `RECORD_EXT_VALUE` | no, here | RFC 8461 and RFC 8460 agree; the BIMI draft does **not** — it omits the `=` exclusion. Three readers, two grammars. |
 *
 * `bimi.test.js` asserts `ext=a=b` is valid in BIMI and `mta-sts.test.js`
 * asserts it is not here, so the split is executable rather than a claim.
 */

// sts-ext-value / tlsrpt-ext-value = 1*(%x21-3A / %x3C / %x3E-7E) — VCHAR
// excluding ';' (0x3B), '=' (0x3D), SP and controls. The earlier range
// included 0x3D, so `ext=a=b` validated in both protocols.
export const RECORD_EXT_VALUE = /^[\x21-\x3A\x3C\x3E-\x7E]+$/;
