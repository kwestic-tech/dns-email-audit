/**
 * Base64 decoding, shared by two protocol owners. Spec §12, Task 4.0.
 *
 * `base64ToBytes()` is read by `core/dkim/`'s key analysis — `analyzeDkimKey()`
 * and `validateDkimKeyStructure()` — and by `core/dnssec/`'s `dnskeyRdata()`
 * and `parseDnskey()`. Two owning directories, one RFC 4648 decoder, and the
 * reason it is hand-written rather than `atob` applies identically to both.
 *
 * Value-only and total: it returns `null` for input that is not base64 rather
 * than throwing, so a caller reads "this key does not decode" instead of
 * catching. `bytesToHex()` is NOT here — DNSSEC is its only reader.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `BASE64_ALPHABET` and `base64ToBytes`, unchanged apart from the
 * two-space dedent and the `export` keyword. The alphabet stays private.
 */

var BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decode base64, tolerating the folding whitespace RFC 6376 §3.2 allows in p=.
 *
 * Decoded here rather than with `atob` on purpose. `atob` throws when it is
 * absent, and this function's caller reads a throw as "this key does not
 * decode" — so in any environment without it, every DKIM key on every domain
 * would be reported unparseable. That is precisely the failure this release
 * exists to prevent: a confident verdict about the operator's records that is
 * really a statement about our own environment. Twelve lines of arithmetic
 * buys an answer that cannot depend on what the host happens to provide.
 *
 * Returns null only for input that genuinely is not base64.
 */
export function base64ToBytes(value) {
  var source = String(value || '');
  // base64string permits FWS, not every character JavaScript classifies as
  // whitespace. A bare LF, vertical tab or form feed makes the key record
  // malformed and must not disappear during decoding.
  source = source.replace(/\r\n(?=[ \t])/g, '');
  if (/[\r\n]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(source)) return null;
  var text = source.replace(/[ \t]+/g, '');
  if (!text) return new Uint8Array(0);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  var padding = /==$/.test(text) ? 2 : /=$/.test(text) ? 1 : 0;
  // RFC 4648 canonical encoding requires unused pad bits to be zero. Without
  // this, several different strings decode to the same DER value.
  if (padding === 2 && (BASE64_ALPHABET.indexOf(text[text.length - 3]) & 0x0f) !== 0) return null;
  if (padding === 1 && (BASE64_ALPHABET.indexOf(text[text.length - 2]) & 0x03) !== 0) return null;
  var bytes = new Uint8Array((text.length / 4) * 3 - padding);
  var out = 0;
  for (var i = 0; i < text.length; i += 4) {
    // The '=' padding characters index to -1; masking with 63 folds them to
    // zero bits, and the output length computed above stops them being
    // written. Padding can only appear in the last two positions, which the
    // pattern above already guarantees.
    var group = (BASE64_ALPHABET.indexOf(text[i]) << 18) |
      (BASE64_ALPHABET.indexOf(text[i + 1]) << 12) |
      ((BASE64_ALPHABET.indexOf(text[i + 2]) & 63) << 6) |
      (BASE64_ALPHABET.indexOf(text[i + 3]) & 63);
    if (out < bytes.length) bytes[out++] = (group >> 16) & 0xff;
    if (out < bytes.length) bytes[out++] = (group >> 8) & 0xff;
    if (out < bytes.length) bytes[out++] = group & 0xff;
  }
  return bytes;
}
