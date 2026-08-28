/**
 * URI grammars, shared by three protocol owners. Spec §12, Task 4.0.
 *
 * `isHttpUri()` and `isMailtoUri()` are read by CAA's `iodef` tag, TLS-RPT's
 * `rua` field and BIMI's `l=` / `a=` — three separate protocol directories
 * validating the same two productions of RFC 3986 and RFC 6068. That is the
 * whole test Task 4.0 applies: used by two or more protocol owners, pure, and
 * value-only. Nothing else in `js/dns.js` reached these.
 *
 * **The protocol-specific part stays with the protocol.** `opts.httpsOnly` and
 * `opts.requireFqdn` exist because BIMI requires both and TLS-RPT and CAA
 * require neither; applying either everywhere rejected conforming records.
 * A shared grammar with per-caller options is not the same thing as a shared
 * policy, and this module owns only the first.
 *
 * ── Imports nothing ─────────────────────────────────────────────────────
 *
 * Spec §12's allowed-edge matrix gives `src/core/shared/` no outgoing edges at
 * all — not to a sibling here either. So the IP-literal predicates below are
 * this module's own, and `ip.js`'s BigInt parsers are that module's own: they
 * answer different questions (is this text a host, versus what number is this
 * address) and were already two separate implementations before the move.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s "Shared value grammars" block, unchanged apart from the
 * two-space dedent and the two `export` keywords. Only `isHttpUri` and
 * `isMailtoUri` are exported; the eleven helpers they are built from stay
 * private, and are covered through them.
 */

/* ── Shared value grammars ────────────────────────────────────────────
   A recognized field name is a promise about its value. Several validators
   here checked the name and took the value on trust, which is how CAA came
   to report `%%%%%` as a certificate authority. These are the value checks
   those promises need — deliberately structural, never proving that a
   mailbox receives mail or that a URL resolves.
   ───────────────────────────────────────────────────────────────────── */

// A dotted LDH host. This is a BIMI requirement, NOT a URI one — RFC 3986
// is happy with `localhost`. Keep the DNS size limits here too: a regex that
// checks only characters calls a 64-octet label an FQDN even though no DNS
// implementation can resolve it.
function isFqdn(host) {
  var text = String(host || '');
  if (text.charAt(text.length - 1) === '.') text = text.slice(0, -1);
  if (!text || text.length > 253) return false;
  var labels = text.split('.');
  if (labels.length < 2) return false;
  return labels.every(function (label) {
    return label.length >= 1 && label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label);
  });
}

/** RFC 3986 §2.1: every '%' must introduce two hex digits. */
function hasValidPercentEncoding(text) {
  var value = String(text || '');
  for (var i = value.indexOf('%'); i !== -1; i = value.indexOf('%', i + 1)) {
    if (!/^[0-9a-f]{2}$/i.test(value.substr(i + 1, 2))) return false;
  }
  return true;
}

/**
 * RFC 3986 §3.2.2: host = IP-literal / IPv4address / reg-name.
 *
 * An FQDN is one of those shapes and not the definition of one. Requiring a
 * dotted name here refused `https://[2001:db8::1]/r`, which is a perfectly
 * good TLS-RPT destination — the FQDN rule belongs to BIMI, which adds it,
 * and is applied there rather than to every URI this file reads.
 */
function isIpv4Address(value) {
  var parts = String(value || '').split('.');
  return parts.length === 4 && parts.every(function (part) {
    return /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255;
  });
}

/** RFC 3986 §3.2.2 IPv6address, including an embedded final IPv4 address. */
function isIpv6Address(value) {
  var text = String(value || '');
  if (!text || text.indexOf(':::') !== -1) return false;
  var halves = text.split('::');
  if (halves.length > 2) return false;
  var compressed = halves.length === 2;
  var parseHalf = function (half, allowIpv4) {
    if (!half) return { valid: true, units: 0 };
    var pieces = half.split(':');
    var units = 0;
    for (var i = 0; i < pieces.length; i++) {
      if (!pieces[i]) return { valid: false, units: 0 };
      if (pieces[i].indexOf('.') !== -1) {
        if (!allowIpv4 || i !== pieces.length - 1 || !isIpv4Address(pieces[i])) {
          return { valid: false, units: 0 };
        }
        units += 2;
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(pieces[i])) return { valid: false, units: 0 };
        units++;
      }
    }
    return { valid: true, units: units };
  };
  // An embedded IPv4 address supplies the FINAL 32 bits. With compression
  // present that means it can occur only in the right half: accepting
  // `192.0.2.1::` put the IPv4 address before the elided zero groups.
  var left = parseHalf(halves[0], !compressed);
  var right = parseHalf(compressed ? halves[1] : '', true);
  if (!left.valid || !right.valid) return false;
  var total = left.units + right.units;
  return compressed ? total < 8 : total === 8;
}

function isIpLiteral(value) {
  var inner = String(value || '').slice(1, -1);
  if (/^v[0-9a-f]+\.(?:[a-z0-9._~!$&'()*+,;=:-])+$/i.test(inner)) return true;
  return isIpv6Address(inner);
}

function isUriHost(host) {
  var text = String(host || '');
  if (!text) return false;
  if (text.charAt(0) === '[' && text.charAt(text.length - 1) === ']') return isIpLiteral(text);
  return /^(?:[a-z0-9\-._~!$&'()*+,;=]|%[0-9a-f]{2})+$/i.test(text); // reg-name / IPv4
}

/** Split an authority into host and port, keeping an IP-literal intact. */
function hasOnlyUriChars(text, rawPattern) {
  var value = String(text || '');
  for (var i = 0; i < value.length; i++) {
    if (value.charAt(i) === '%') {
      if (!/^[0-9a-f]{2}$/i.test(value.slice(i + 1, i + 3))) return false;
      i += 2;
    } else if (!rawPattern.test(value.charAt(i))) return false;
  }
  return true;
}

function splitUriAuthority(authority) {
  var text = String(authority || '');
  var at = text.lastIndexOf('@');
  if (at !== -1) {
    var userinfo = text.slice(0, at);
    if (!hasOnlyUriChars(userinfo, /^[a-z0-9._~!$&'()*+,;=:-]$/i)) return null;
    text = text.slice(at + 1);
  }
  var match = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(text);
  return match ? { host: match[1], port: match[2] } : null;
}

/**
 * An http/https URL. `opts.httpsOnly` and `opts.requireFqdn` are the extra
 * constraints a *consuming protocol* adds — BIMI has both; TLS-RPT and CAA
 * `iodef` have neither, and applying them everywhere rejected conforming
 * records.
 */
export function isHttpUri(value, opts) {
  var options = opts || {};
  var text = String(value || '').trim();
  if (/\s/.test(text) || !hasValidPercentEncoding(text)) return false;
  var match = /^(https?):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i.exec(text);
  if (!match) return false;
  if (options.httpsOnly && match[1].toLowerCase() !== 'https') return false;
  var authority = splitUriAuthority(match[2]);
  if (!authority || !isUriHost(authority.host)) return false;
  if (options.requireFqdn && !isFqdn(authority.host)) return false;
  // path-abempty = *( "/" segment ); query/fragment add pchar, "/" and
  // "?". Validate the productions, not merely the absence of whitespace —
  // `<`, `>`, `"`, `{` and friends are not URI characters.
  if (match[3] && match[3].charAt(0) !== '/') return false;
  var pchar = /^[a-z0-9._~!$&'()*+,;=:@\/-]$/i;
  var qchar = /^[a-z0-9._~!$&'()*+,;=:@\/?-]$/i;
  if (!hasOnlyUriChars(match[3] || '', pchar)) return false;
  if (!hasOnlyUriChars(match[4] || '', qchar)) return false;
  if (!hasOnlyUriChars(match[5] || '', qchar)) return false;
  return true;
}

function decodeUriPercent(value) {
  try { return decodeURIComponent(String(value || '')); }
  catch (_) { return null; }
}

function splitMailboxList(value) {
  var result = [];
  var start = 0;
  var quoted = false;
  var escaped = false;
  for (var i = 0; i < value.length; i++) {
    var ch = value.charAt(i);
    if (escaped) { escaped = false; continue; }
    if (quoted && ch === '\\') { escaped = true; continue; }
    if (ch === '"') { quoted = !quoted; continue; }
    if (ch === ',' && !quoted) { result.push(value.slice(start, i)); start = i + 1; }
  }
  if (quoted || escaped) return null;
  result.push(value.slice(start));
  return result;
}

function isMailbox(value) {
  var text = String(value || '');
  var at = -1;
  var quoted = false;
  var escaped = false;
  for (var i = 0; i < text.length; i++) {
    var ch = text.charAt(i);
    if (escaped) { escaped = false; continue; }
    if (quoted && ch === '\\') { escaped = true; continue; }
    if (ch === '"') { quoted = !quoted; continue; }
    if (ch === '@' && !quoted) { if (at !== -1) return false; at = i; }
  }
  if (quoted || escaped || at < 1 || at === text.length - 1) return false;
  var local = text.slice(0, at);
  var domain = text.slice(at + 1);
  var atext = /^[a-z0-9!#$%&'*+\-/=?^_`{|}~]+$/i;
  var validDotAtom = function (part) {
    var atoms = part.split('.');
    return atoms.length > 0 && atoms.every(function (atom) { return atext.test(atom); });
  };
  var localValid;
  if (local.charAt(0) === '"' && local.charAt(local.length - 1) === '"') {
    localValid = true;
    for (var j = 1; j < local.length - 1; j++) {
      var code = local.charCodeAt(j);
      if (local.charAt(j) === '\\') {
        j++;
        if (j >= local.length - 1 || local.charCodeAt(j) < 0x20 || local.charCodeAt(j) > 0x7e) localValid = false;
      } else if (local.charAt(j) === '"' || code < 0x21 || code > 0x7e) localValid = false;
    }
  } else localValid = validDotAtom(local);
  if (!localValid) return false;
  if (domain.charAt(0) === '[' && domain.charAt(domain.length - 1) === ']') {
    for (var k = 1; k < domain.length - 1; k++) {
      var d = domain.charCodeAt(k);
      if (!((d >= 33 && d <= 90) || (d >= 94 && d <= 126))) return false;
    }
    return true;
  }
  if (validDotAtom(domain)) return true;
  // RFC 6068 permits a UTF-8 percent-encoded internationalized domain. It
  // is converted to an A-label when a message is composed; syntax checking
  // here only establishes that it decoded as UTF-8 and remains label-shaped.
  if (!/[^\x00-\x7f]/.test(domain)) return false;
  return domain.split('.').every(function (label) {
    return label.length > 0 && !/^[\-]|\-$/.test(label) && !/[\s@\[\]\\/?#]/.test(label);
  });
}

/**
 * RFC 6068 `mailtoURI`. The local part and the domain may both be
 * percent-encoded, which is how the RFC writes a quoted local part
 * (`mailto:%22not%40me%22@example.org`) and a domain literal
 * (`mailto:user@%5B192.0.2.1%5D`) — both conformant, and both refused by a
 * plain addr-spec regex.
 */
export function isMailtoUri(value, opts) {
  var options = opts || {};
  var text = String(value || '').trim();
  if (text.slice(0, 7).toLowerCase() !== 'mailto:') return false;
  if (/\s/.test(text) || !hasValidPercentEncoding(text)) return false;
  var question = text.indexOf('?');
  var rawTo = text.slice(7, question === -1 ? text.length : question);
  // RFC 6068 requires URI-reserved '/', '?', '#', '[', ']', '&', ';' and
  // '=' inside addr-specs to be percent-encoded. A syntactically valid
  // percent escape is not enough if the raw character itself was forbidden.
  if (!rawTo || !hasOnlyUriChars(rawTo, /^[a-z0-9._~!$'()*+,:@-]$/i)) return false;
  var decodedTo = decodeUriPercent(rawTo);
  if (decodedTo === null) return false;
  var mailboxes = splitMailboxList(decodedTo);
  if (!mailboxes || !mailboxes.length || !mailboxes.every(isMailbox)) return false;
  if (options.requireFqdn && !mailboxes.every(function (mailbox) {
    return isFqdn(mailbox.slice(mailbox.lastIndexOf('@') + 1));
  })) return false;
  if (question !== -1) {
    var hfields = text.slice(question + 1).split('&');
    if (!hfields.length || hfields.some(function (field) {
      var equals = field.indexOf('=');
      if (equals === -1) return true;
      var hname = field.slice(0, equals);
      var hvalue = field.slice(equals + 1);
      var hchar = /^[a-z0-9._~!$'()*+,;:@-]$/i;
      return !hasOnlyUriChars(hname, hchar) || !hasOnlyUriChars(hvalue, hchar);
    })) return false;
  }
  return true;
}
