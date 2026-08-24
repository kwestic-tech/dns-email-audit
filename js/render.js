/* ──────────────────────────────────────────────────────────────────────────
   Node-building renderer.

   The rule this file exists to enforce:

       Reading outerHTML is permitted. Writing innerHTML or outerHTML is
       never permitted.

   Everything the interface paints is built with createElement/createTextNode
   and setAttribute against an allowlist, so a DNS-derived value can only ever
   land in a text node or an allowlisted attribute. There is no escape helper
   anywhere in the codebase, because there is no string-concatenation path left
   for one to serve.

   This file also owns the malformed-record display rules (spec §4). Two of
   them govern the rest:

     • Nothing invisible is silently dropped. Every character that renders as
       nothing, or that reorders its neighbours, is replaced at its exact
       position by a visible sentinel — ‹RLO›, ‹ZWSP›, ‹U+0007›. The character
       is genuinely gone from the text run, so no reordering survives, and the
       marker sits where it was, so the reader sees the technique.
     • Display caps never reach the data. Truncation and record caps apply to
       what is painted. The full value stays in the result object, in the CSV
       and in the HTML report.

   Loaded after js/i18n.js (for t/tp) and before js/app.js.
   ────────────────────────────────────────────────────────────────────────── */

(function (global) {
  'use strict';

  /* ── Attribute policy ───────────────────────────────────────────────── */

  // Exact attribute names the renderer may set. Anything not here throws, so
  // adding a rendered attribute is a deliberate edit to this list rather than
  // an accident at a call site.
  var ATTR_ALLOW = new Set([
    'id', 'class', 'title', 'style', 'lang', 'dir', 'role',
    'colspan', 'rowspan', 'scope',
    'type', 'value', 'placeholder', 'disabled', 'checked', 'selected',
    'href', 'target', 'rel', 'download',
    'src', 'alt', 'width', 'height',
    'charset', 'content', 'http-equiv', 'name', 'property',
    'viewbox', 'fill', 'd',
  ]);

  // Prefixes that are allowed wholesale. `on*` is never among them.
  var ATTR_PREFIXES = ['data-', 'aria-'];

  function attrAllowed(name) {
    var lower = String(name).toLowerCase();
    if (/^on/.test(lower)) return false;
    if (ATTR_ALLOW.has(lower)) return true;
    return ATTR_PREFIXES.some(function (p) { return lower.indexOf(p) === 0; });
  }

  function refuse(message) { throw new Error('[render] ' + message); }

  // Shared by both style forms. `url(` would fetch, `expression` is legacy IE
  // script, and quotes or angle brackets mean the value was built rather than
  // written as a literal.
  function styleGuard(value) {
    if (/[<>"']|url\s*\(|expression/i.test(value)) refuse('style value is not a literal');
  }

  /* ── Invisible-character handling (spec §4) ─────────────────────────── */

  // Named directional controls. These reorder the text around them, which is
  // the one malformation in section 4 that is a genuine output-integrity
  // attack rather than a display nuisance.
  var BIDI_NAMES = {
    0x202A: 'LRE', 0x202B: 'RLE', 0x202C: 'PDF', 0x202D: 'LRO', 0x202E: 'RLO',
    0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI',
    0x200E: 'LRM', 0x200F: 'RLM', 0x061C: 'ALM',
  };

  // Short names for the invisible characters worth naming. Anything else that
  // matches the category test below still gets a sentinel, spelled by code
  // point.
  var INVISIBLE_NAMES = {
    0x200B: 'ZWSP', 0x200C: 'ZWNJ', 0x200D: 'ZWJ', 0xFEFF: 'BOM',
    0x00AD: 'SHY', 0x2060: 'WJ',
    0x2028: 'LS', 0x2029: 'PS',
    0x115F: 'HCF', 0x1160: 'HJF', 0x3164: 'HF', 0xFFA0: 'HWHF',
    0x034F: 'CGJ', 0x17B4: 'KIVAQ', 0x17B5: 'KIVAA', 0x180E: 'MVS',
  };

  // MEMBERSHIP POLICY (spec §4, decided at 1.3 — "security/audit-first").
  //
  // `\p{Cf}` was the wrong set in both directions. It is not complete — it
  // misses U+034F, U+17B4/U+17B5 and U+180B–U+180F, all of which render as
  // nothing — and it is not safe, because it includes characters that are
  // genuine running text in their script (Arabic number signs, end-of-ayah
  // marks, Kaithi and Egyptian format controls).
  //
  // `Default_Ignorable_Code_Point` is the property Unicode defines for exactly
  // this question: characters a conforming renderer may show as nothing. It
  // covers every member of the old set except the line and paragraph
  // separators, and — verified against this runtime — it excludes the Arabic,
  // Syriac, Kaithi and Egyptian script-format characters outright, so those no
  // longer need an exception list at all.
  //
  // Three families ARE default-ignorable but are legitimate content, and are
  // exempted by range below. Everything else that is default-ignorable gets a
  // sentinel.
  var IGNORABLE_RE = /[\p{Default_Ignorable_Code_Point}]/u;

  // Zl and Zp are not default-ignorable, but a line or paragraph separator
  // still breaks the structure of a rendered value, so they are handled as
  // controls.
  var SEPARATORS = [0x2028, 0x2029];

  // Exempt: default-ignorable, but meaningful.
  //   • Variation selectors choose a glyph form — every emoji presentation
  //     sequence carries one, and marking them would put a sentinel inside
  //     ordinary emoji.
  //   • Musical and shorthand format controls are the notation's own layout,
  //     the same argument that keeps Arabic end-of-ayah unmarked.
  var EXEMPT_RANGES = [
    [0xFE00, 0xFE0F],    // variation selectors 1–16
    [0xE0100, 0xE01EF],  // variation selectors supplement
    [0x1BCA0, 0x1BCA3],  // shorthand format controls
    [0x1D173, 0x1D17A],  // musical notation format controls
  ];

  function isExempt(code) {
    for (var i = 0; i < EXEMPT_RANGES.length; i++) {
      if (code >= EXEMPT_RANGES[i][0] && code <= EXEMPT_RANGES[i][1]) return true;
    }
    return false;
  }

  function hex(code) {
    var s = code.toString(16).toUpperCase();
    while (s.length < 4) s = '0' + s;
    return s;
  }

  // A C0/C1 control, excluding the three whitespace characters that carry
  // meaning in a rendered value.
  function isControl(code) {
    if (code === 0x09 || code === 0x0A || code === 0x0D) return false;
    return (code >= 0x00 && code <= 0x1F) || (code >= 0x7F && code <= 0x9F);
  }

  /**
   * Classify one code point, or return null when it is ordinary text. Script
   * characters are never classified — a domain legitimately publishing Arabic
   * or Hebrew reorders correctly on its own and needs no intervention.
   */
  function classify(code) {
    if (BIDI_NAMES[code]) return { name: BIDI_NAMES[code], hygiene: 'bidi-override' };
    if (isControl(code)) return { name: 'U+' + hex(code), hygiene: 'control-char' };
    // A line or paragraph separator breaks the structure of a rendered value,
    // which is a control problem rather than a width problem.
    if (SEPARATORS.indexOf(code) !== -1) {
      return { name: INVISIBLE_NAMES[code], hygiene: 'control-char' };
    }
    if (isExempt(code)) return null;
    if (IGNORABLE_RE.test(String.fromCodePoint(code))) {
      return { name: INVISIBLE_NAMES[code] || 'U+' + hex(code), hygiene: 'zero-width' };
    }
    return null;
  }

  /**
   * Replace lone surrogates with U+FFFD. `JSON.parse` on a DoH response can
   * produce them, and so can the raw-chunk fallback in js/dns.js; normalizing
   * here means both paths render the same string.
   *
   * Written as an index walk rather than a regex on purpose: a regex needs a
   * lookbehind to spot a lone LOW surrogate, and a consuming alternative
   * silently skips every second one in a run (`\uDC00\uDC00` left the second
   * intact). Lookbehind is also newer than the browsers this file supports.
   * Well-formed pairs — every emoji and every other astral character — are
   * copied through untouched.
   */
  function normalize(value) {
    var str = String(value === undefined || value === null ? '' : value);
    var out = '';
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code >= 0xD800 && code <= 0xDBFF) {
        var next = str.charCodeAt(i + 1);
        if (next >= 0xDC00 && next <= 0xDFFF) { out += str[i] + str[i + 1]; i++; }
        else out += '�';
      } else if (code >= 0xDC00 && code <= 0xDFFF) {
        out += '�';
      } else {
        out += str[i];
      }
    }
    return out;
  }

  /**
   * Split a value into runs of ordinary text and invisible characters that
   * need a sentinel. Returns [{ kind: 'text'|'sentinel'|'noted', text, hygiene }].
   */
  function segment(value) {
    var raw = String(value === undefined || value === null ? '' : value);
    var str = normalize(raw);
    // Only report a lone surrogate when WE substituted one. A record that
    // published U+FFFD itself is not malformed UTF-8, and saying so would be a
    // false positive.
    var substituted = str !== raw;
    var out = [];
    var buffer = '';

    function flush() {
      if (buffer) { out.push({ kind: 'text', text: buffer }); buffer = ''; }
    }

    // Iterating the string yields whole code points, so an astral character is
    // classified once rather than as two surrogate halves.
    var chars = Array.from(str);
    for (var i = 0; i < chars.length; i++) {
      var ch = chars[i];
      var found = classify(ch.codePointAt(0));
      if (found) {
        flush();
        out.push({ kind: 'sentinel', text: '‹' + found.name + '›', hygiene: found.hygiene });
      } else {
        buffer += ch;
      }
    }
    flush();
    if (substituted) out.push({ kind: 'noted', hygiene: 'lone-surrogate' });
    return out;
  }

  /**
   * The value with every sentinel substituted, as a plain string. Used where
   * the destination is an attribute rather than a text node — a tooltip is
   * still displayed output, so an override inside one reorders exactly as it
   * would in a cell.
   */
  function sentinelText(value) {
    return segment(value).map(function (part) {
      return part.kind === 'noted' ? '' : part.text;
    }).join('');
  }

  /**
   * The hygiene classes present in a value, as stable tokens. Used by the
   * interface for its note and by the CSV's `record_hygiene` column
   * (OQ-SEC-11) — the CSV data column keeps the raw bytes, this names what
   * they contained.
   */
  function hygiene(value) {
    var seen = [];
    segment(value).forEach(function (part) {
      if (part.hygiene && seen.indexOf(part.hygiene) === -1) seen.push(part.hygiene);
    });
    // Anywhere in the value, not just at a label boundary: an `include:` host
    // is the position that matters and it is never at the start.
    if (/(^|[^a-z0-9])xn--/i.test(String(value || ''))) {
      if (seen.indexOf('punycode') === -1) seen.push('punycode');
    }
    if (isFormulaLeading(value)) {
      if (seen.indexOf('formula-leading') === -1) seen.push('formula-leading');
    }
    return seen;
  }

  /**
   * True when a spreadsheet would treat this value as a formula rather than
   * text. Excel and Sheets look past leading whitespace and quoting, so the
   * test is on the first *effective* character. The full-width forms matter in
   * CJK spreadsheet locales.
   */
  var FORMULA_LEAD_RE = /^[\s'"]*[=+\-@\t\r\n\uFF1D\uFF0B\uFF0D\uFF20]/;

  function isFormulaLeading(value) {
    return FORMULA_LEAD_RE.test(String(value === undefined || value === null ? '' : value));
  }

  /** Hygiene tokens for a whole result row, for the CSV column. */
  function hygieneOf(values) {
    var seen = [];
    (values || []).forEach(function (v) {
      hygiene(v).forEach(function (h) { if (seen.indexOf(h) === -1) seen.push(h); });
    });
    return seen;
  }

  /* ── Display caps (spec §4) ─────────────────────────────────────────── */

  // 1024 clears a 4096-bit RSA DKIM key, which runs to roughly 760 characters
  // with its tags. The 512 an earlier draft proposed would have truncated a
  // legitimate key.
  var MAX_VALUE_CHARS = 1024;
  // A hostname is at most 253 characters, so anything longer is malformed.
  var MAX_HOST_CHARS = 253;
  // Independent of the character cap; both apply.
  var MAX_RECORDS_SHOWN = 20;

  /* ── Factory ────────────────────────────────────────────────────────── */

  function factory(getDoc) {
    var api = {};

    function doc() { return getDoc(); }

    function text(value) {
      return doc().createTextNode(normalize(value));
    }

    function frag(children) {
      var f = doc().createDocumentFragment();
      appendAll(f, children);
      return f;
    }

    function appendAll(parent, children) {
      if (children === null || children === undefined || children === false) return parent;
      if (Array.isArray(children)) {
        children.forEach(function (c) { appendAll(parent, c); });
        return parent;
      }
      if (typeof children === 'string' || typeof children === 'number') {
        parent.appendChild(text(children));
        return parent;
      }
      if (children.nodeType) { parent.appendChild(children); return parent; }
      refuse('unsupported child of type ' + typeof children);
      return parent;
    }

    function el(tag, props, children) {
      var node = doc().createElement(tag);
      var p = props || {};

      Object.keys(p).forEach(function (key) {
        var value = p[key];
        if (value === null || value === undefined || value === false) return;

        if (key === 'innerHTML' || key === 'outerHTML') {
          refuse('refusing to set ' + key + ' on <' + tag + '>; build nodes instead');
        }
        if (key === 'textContent') { node.textContent = normalize(value); return; }
        if (key === 'className') { node.setAttribute('class', String(value)); return; }
        // `title` and `data-tip` are painted by the browser (the latter via
        // `content: attr(data-tip)` in css/style.css), so they are displayed
        // output and get the same sentinel substitution a cell does. Internal
        // values contain no invisible characters, so this is a no-op for them.
        if (key === 'title') { node.setAttribute('title', sentinelText(value)); return; }
        if (key === 'dataset') {
          Object.keys(value).forEach(function (d) {
            if (value[d] === null || value[d] === undefined) return;
            node.dataset[d] = sentinelText(value[d]);
          });
          return;
        }
        if (key === 'style') {
          // Style values are literals from this codebase, never DNS-derived.
          // BOTH forms are guarded: the object branch previously called
          // setProperty with no validation at all, so the "literals only"
          // claim was true of the string form only. CSP is not the renderer's
          // validation mechanism — the exported report carries a different
          // policy, and R.el exists to make unsafe construction hard by
          // default.
          if (typeof value === 'string') {
            styleGuard(value);
            node.setAttribute('style', value);
          } else {
            Object.keys(value).forEach(function (prop) {
              if (!/^[a-z][a-z-]*$/.test(prop)) refuse('style property "' + prop + '" is not a plain name');
              var v = String(value[prop]);
              styleGuard(v);
              node.style.setProperty(prop, v);
            });
          }
          return;
        }
        if (key === 'href') {
          // The only scheme the interface ever links to. Everything else is
          // dropped rather than rewritten, so a bad value is visibly inert.
          if (/^https:\/\//i.test(String(value))) node.setAttribute('href', String(value));
          return;
        }
        if (key === 'src') {
          // Same rule as href. Nothing passes DNS data to src today; the
          // asymmetry would be an invitation.
          if (/^https:\/\//i.test(String(value))) node.setAttribute('src', String(value));
          return;
        }
        if (!attrAllowed(key)) refuse('attribute "' + key + '" is not on the allowlist');
        node.setAttribute(key, sentinelText(value));
      });

      appendAll(node, children);
      return node;
    }

    /**
     * A DNS-derived value, rendered per section 4: sentinels substituted,
     * display truncated with a disclosure control, `labels.none` for empty.
     * `opts.max` overrides the character cap; `opts.none` overrides the empty
     * token.
     */
    function value(raw, opts) {
      var o = opts || {};
      var str = normalize(raw);
      var out = frag(null);

      if (!str || !str.trim()) {
        out.appendChild(el('span', { className: 'rv-none' }, o.none || t('labels.none')));
        return out;
      }

      // Split on CODE POINTS, not UTF-16 indexes. `str.slice(1024)` through an
      // astral character hands the high surrogate to the head and the low
      // surrogate to the tail; each is then normalized separately and the
      // character is destroyed — an emoji at the boundary became "\uFFFD\uFFFD".
      // The cap and the disclosure count are both in code points, which is also
      // what "characters" means to the reader.
      var max = o.max || MAX_VALUE_CHARS;
      var points = Array.from(str);
      var over = points.length > max;
      var head = over ? points.slice(0, max).join('') : str;
      var tail = over ? points.slice(max).join('') : '';
      var tailCount = over ? points.length - max : 0;

      // unicode-bidi: isolate on the container stops this value reordering its
      // neighbours. It cannot stop an override reordering the value's own
      // contents — that is what the sentinel substitution above does — but it
      // is free and contains anything residual.
      var wrap = el('span', { className: 'rv' });
      appendSegments(wrap, head);

      if (tail) {
        // Object form, so the property is readable and toggleable as
        // `rest.style.display` by the disclosure control in js/app.js.
        var rest = el('span', { className: 'rv-rest', style: { display: 'none' } });
        appendSegments(rest, tail);
        wrap.appendChild(rest);
        wrap.appendChild(el('button', {
          className: 'rv-more',
          type: 'button',
          // Length of the value as published, so the label stays stable no
          // matter how many sentinels the remainder contains.
          dataset: { rvMore: '1', rvCount: String(tailCount) },
        }, t('render.showMore', String(tailCount))));
      }

      out.appendChild(wrap);
      return out;
    }

    function appendSegments(parent, str) {
      segment(str).forEach(function (part) {
        if (part.kind === 'sentinel') {
          parent.appendChild(el('span', {
            className: 'rv-sentinel',
            title: t('render.hygiene.' + camel(part.hygiene)),
          }, part.text));
        } else if (part.kind === 'text') {
          parent.appendChild(text(part.text));
        }
      });
    }

    /**
     * A list of DNS records, capped at 20 displayed with a count of the
     * remainder. Analysis reads everything; only display is capped.
     */
    function list(values, opts) {
      var o = opts || {};
      var items = (values || []).filter(function (v) { return v !== null && v !== undefined; });
      var out = frag(null);

      if (!items.length) {
        out.appendChild(el('span', { className: 'rv-none' }, o.none || t('labels.none')));
        return out;
      }

      // The separator is the caller's, so this release does not change how any
      // existing cell looks: nameservers stayed comma-separated, MX kept its
      // newline, verifications kept their line breaks. Only the per-record
      // capping and sentinel substitution are new.
      var cap = o.cap || MAX_RECORDS_SHOWN;
      var sep = o.sep === undefined ? 'br' : o.sep;
      items.slice(0, cap).forEach(function (item, i) {
        if (i) out.appendChild(sep === 'br' ? el('br') : text(sep));
        out.appendChild(value(item, { max: o.max, none: o.none }));
      });

      if (items.length > cap) {
        out.appendChild(el('br'));
        out.appendChild(el('span', { className: 'rv-remainder' },
          tp('render.moreRecords', items.length - cap)));
      }
      return out;
    }

    /** A hostname, capped at the 253-character maximum a name can legally be. */
    function host(name) { return value(name, { max: MAX_HOST_CHARS }); }

    /** The record-hygiene note for a value or list of values. */
    function hygieneNote(values) {
      var classes = hygieneOf(Array.isArray(values) ? values : [values]);
      if (!classes.length) return null;
      return el('div', { className: 'rv-hygiene' }, [
        el('span', { className: 'rv-hygiene-label' }, t('render.hygieneTitle')),
        frag(classes.map(function (c) {
          return el('span', { className: 'rv-hygiene-item' }, t('render.hygiene.' + camel(c)));
        })),
      ]);
    }

    /** The only rich-text path: locale strings with a tiny tag allowlist. */
    function rich(str) {
      return i18n.sanitizeFragment(str);
    }

    api.el = el;
    api.frag = frag;
    api.text = text;
    api.rich = rich;
    api.value = value;
    api.sentinelText = sentinelText;
    api.list = list;
    api.host = host;
    api.hygieneNote = hygieneNote;
    return api;
  }

  function camel(token) {
    return String(token).replace(/-([a-z])/g, function (m, c) { return c.toUpperCase(); });
  }

  var R = factory(function () { return global.document; });

  /** Bind the factory to a detached document, for the two document builders. */
  R.for = function (ownerDoc) { return factory(function () { return ownerDoc; }); };

  // Exposed so js/app.js and the tests share one definition of each rule.
  R.sentinelText = sentinelText;
  R.isFormulaLeading = isFormulaLeading;
  R.hygiene = hygiene;
  R.hygieneOf = hygieneOf;
  R.segment = segment;
  R.normalize = normalize;
  R.attrAllowed = attrAllowed;
  R.MAX_VALUE_CHARS = MAX_VALUE_CHARS;
  R.MAX_HOST_CHARS = MAX_HOST_CHARS;
  R.MAX_RECORDS_SHOWN = MAX_RECORDS_SHOWN;

  global.R = R;
})(window);
