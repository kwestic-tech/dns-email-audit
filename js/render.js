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

  /* ── Invisible-character handling (spec §4) ─────────────────────────── */

  // Named directional controls. These are the characters that reorder text
  // around them, which is the one malformation in section 4 that is a genuine
  // output-integrity attack rather than a display nuisance.
  var BIDI_NAMES = {
    0x202A: 'LRE', 0x202B: 'RLE', 0x202C: 'PDF', 0x202D: 'LRO', 0x202E: 'RLO',
    0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI',
    0x200E: 'LRM', 0x200F: 'RLM',
  };

  // Characters that occupy no width, so two values differing only by one of
  // these render identically.
  var ZERO_WIDTH_NAMES = {
    0x200B: 'ZWSP', 0x200C: 'ZWNJ', 0x200D: 'ZWJ', 0xFEFF: 'BOM',
  };

  function hex4(code) {
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
   * Replace lone surrogates with U+FFFD. `JSON.parse` on a DoH response can
   * produce them, and so can the raw-chunk fallback in js/dns.js; normalizing
   * here means both paths render the same string.
   */
  function normalize(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, '�')
      .replace(/(^|[^\uD800-\uDBFF])([\uDC00-\uDFFF])/g, function (m, before) {
        return before + '�';
      });
  }

  /**
   * Split a value into runs of ordinary text and invisible characters that
   * need a sentinel. Returns [{ kind: 'text'|'sentinel', text, hygiene }].
   * Script characters are never touched — a domain legitimately publishing
   * Arabic or Hebrew reorders correctly on its own and needs no intervention.
   */
  function segment(value) {
    var str = normalize(value);
    var out = [];
    var buffer = '';

    function flush() {
      if (buffer) { out.push({ kind: 'text', text: buffer }); buffer = ''; }
    }

    for (var i = 0; i < str.length; i++) {
      var ch = str[i];
      var code = str.charCodeAt(i);
      var name = null;
      var hygiene = null;

      if (BIDI_NAMES[code]) { name = BIDI_NAMES[code]; hygiene = 'bidi-override'; }
      else if (ZERO_WIDTH_NAMES[code]) { name = ZERO_WIDTH_NAMES[code]; hygiene = 'zero-width'; }
      else if (isControl(code)) { name = 'U+' + hex4(code); hygiene = 'control-char'; }
      else if (code === 0xFFFD) { hygiene = 'lone-surrogate'; }

      if (name) {
        flush();
        out.push({ kind: 'sentinel', text: '‹' + name + '›', hygiene: hygiene });
      } else {
        buffer += ch;
        // U+FFFD is a visible character already, so it is recorded as a
        // hygiene observation without a sentinel standing in for it.
        if (hygiene) out.push({ kind: 'noted', hygiene: hygiene });
      }
    }
    flush();
    return out;
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
    if (/(^|\.)xn--/i.test(String(value || ''))) {
      if (seen.indexOf('punycode') === -1) seen.push('punycode');
    }
    return seen;
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
        if (key === 'title') { node.setAttribute('title', normalize(value)); return; }
        if (key === 'dataset') {
          Object.keys(value).forEach(function (d) {
            if (value[d] === null || value[d] === undefined) return;
            node.dataset[d] = String(value[d]);
          });
          return;
        }
        if (key === 'style') {
          // Style values are literals from this codebase, never DNS-derived.
          if (typeof value === 'string') node.setAttribute('style', value);
          else Object.keys(value).forEach(function (prop) { node.style.setProperty(prop, String(value[prop])); });
          return;
        }
        if (key === 'href') {
          // The only scheme the interface ever links to. Everything else is
          // dropped rather than rewritten, so a bad value is visibly inert.
          if (/^https:\/\//i.test(String(value))) node.setAttribute('href', String(value));
          return;
        }
        if (!attrAllowed(key)) refuse('attribute "' + key + '" is not on the allowlist');
        node.setAttribute(key, normalize(value));
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

      var max = o.max || MAX_VALUE_CHARS;
      var head = str.length > max ? str.slice(0, max) : str;
      var tail = str.length > max ? str.slice(max) : '';

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
          dataset: { rvMore: '1' },
        }, t('render.showMore', String(tail.length))));
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

      var cap = o.cap || MAX_RECORDS_SHOWN;
      items.slice(0, cap).forEach(function (item, i) {
        if (i) out.appendChild(el('br'));
        out.appendChild(value(item, { max: o.max }));
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
