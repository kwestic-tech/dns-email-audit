/* ──────────────────────────────────────────────────────────────────────────
   i18n — a tiny JSON-based translation layer for static/client-side apps.

   Design notes
   ------------
   • locales/en.json is the single source of truth. Every other locale file
     mirrors its shape; missing keys silently fall back to English.
   • English is ALSO inlined into js/locales-en.js (generated from en.json by
     `npm run build:fallback`) so the app works when opened straight from
     disk over file://, where fetch() of local JSON is blocked by the browser.
   • Other locales are fetched on demand from locales/<code>.json.
   • No dependencies, no build step, no bundler.
   ────────────────────────────────────────────────────────────────────────── */

(function (global) {
  'use strict';

  var STORAGE_KEY = 'dns-email-audit-lang';
  var DEFAULT_LANG = 'en';

  // Inlined English bundle (js/locales-en.js). Always present.
  var bundles = { en: global.__I18N_EN__ || {} };

  // Fallback registry, used when locales/index.json can't be fetched (file://).
  var locales = [
    { code: 'en', name: 'English', nativeName: 'English', label: '🌐 EN', dir: 'ltr' },
    { code: 'es', name: 'Spanish', nativeName: 'Español', label: '🌐 ES', dir: 'ltr' }
  ];

  var currentLang = DEFAULT_LANG;
  var listeners = [];

  /* ── Key resolution ─────────────────────────────────────────────────── */

  // 'issue.spf-missing.what' → walks the bundle object. Array indices work
  // too ('learnMore.bimi.sections.0.h').
  function resolve(bundle, key) {
    var parts = String(key).split('.');
    var node = bundle;
    for (var i = 0; i < parts.length; i++) {
      if (node === null || typeof node !== 'object') return undefined;
      node = node[parts[i]];
    }
    return node;
  }

  function lookup(key) {
    var hit = resolve(bundles[currentLang] || {}, key);
    if (hit !== undefined && hit !== null && hit !== '') return hit;
    var fallback = resolve(bundles[DEFAULT_LANG] || {}, key);
    return fallback === undefined ? null : fallback;
  }

  // One pass over the template, so a value substituted at {0} is never
  // rescanned. The sequential version this replaced let an argument containing
  // "{1}" pull the second argument into a position the translator never wrote,
  // which becomes reachable the moment a DNS-derived name is the first
  // argument. An index with no corresponding argument is left as written, so a
  // locale file with a stray {3} is visibly wrong rather than silently
  // "undefined".
  function interpolate(str, args) {
    return String(str).replace(/\{(\d+)\}/g, function (match, digits) {
      var i = Number(digits);
      return i < args.length ? String(args[i]) : match;
    });
  }

  /**
   * Translate a key. Extra arguments replace {0}, {1}, … placeholders.
   * Returns the key itself if nothing is found, which makes missing
   * translations obvious in the UI rather than silently blank.
   */
  function t(key) {
    var value = lookup(key);
    if (typeof value !== 'string') return key;
    return interpolate(value, Array.prototype.slice.call(arguments, 1));
  }

  /**
   * Translate a countable string. The key must point at an object of CLDR
   * plural categories, e.g. { "one": "{0} domain", "other": "{0} domains" }.
   * `n` is passed in as {0} automatically.
   */
  function tp(key, n) {
    var forms = lookup(key);
    if (!forms || typeof forms !== 'object') return t(key, n);
    var category = 'other';
    try {
      category = new Intl.PluralRules(currentLang).select(n);
    } catch (e) { /* older browser — 'other' is a safe default */ }
    var str = forms[category] || forms.other || forms.one;
    if (typeof str !== 'string') return String(n);
    var rest = Array.prototype.slice.call(arguments, 2);
    return interpolate(str, [n].concat(rest));
  }

  /** Return a non-string node (object or array) from the bundle, e.g. a guide. */
  function tRaw(key) {
    var value = lookup(key);
    return value === null ? undefined : value;
  }

  /* ── Rich text ──────────────────────────────────────────────────────
     Locale strings may carry a dozen inline tags. Turning them into nodes is
     the last string-to-markup step in the codebase, so it is a tokenizer that
     BUILDS nodes rather than a parser that is handed a string: there is no
     `innerHTML` assignment anywhere under js/, which is what makes the static
     scan's empty allowlist an honest claim rather than a judgment call.

     Fail-closed. Anything the tokenizer does not recognize as an allowlisted
     tag — a `<script>`, a malformed `<`, a stray close tag — is emitted as
     literal TEXT. It renders visibly as itself and serializes back to
     `&lt;script&gt;`, which is both safe and honest: nothing is silently
     dropped, matching the rule section 4 applies to invisible characters.

     The input is our own locale file, and tools/check-locales.mjs fails the
     build on any tag outside this allowlist, so the fail-closed branch is a
     backstop rather than a routine path.
     ──────────────────────────────────────────────────────────────────── */

  var RICH_TAGS = new Set(['A', 'BR', 'STRONG', 'CODE', 'EM', 'B', 'I', 'SMALL', 'UL', 'OL', 'LI', 'P']);
  var RICH_VOID = new Set(['BR']);

  // A conservative shape for a tag. Anything not matching exactly is not a tag
  // as far as this tokenizer is concerned.
  var TAG_RE = /^<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:\s+[a-zA-Z][a-zA-Z0-9-]*(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s">]+))?)*)\s*(\/?)>/;
  // Walks the attribute string one attribute at a time rather than scanning it
  // for `href=`. A scan picks the href out of ANOTHER attribute's value —
  // `<a title=" href=https://evil.example " href="https://good.example">` — so
  // attribute extraction has to be a parse, not a substring search.
  var ATTR_RE = /([a-zA-Z][a-zA-Z0-9-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s">]+)))?/g;

  function attrValue(attrs, wanted) {
    ATTR_RE.lastIndex = 0;
    var m;
    while ((m = ATTR_RE.exec(attrs))) {
      if (m[0] === '') { ATTR_RE.lastIndex++; continue; }
      if (m[1].toLowerCase() !== wanted) continue;
      return m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
    }
    return null;
  }

  var NAMED_ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  };

  function decodeEntities(str) {
    return String(str).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, function (match, body) {
      if (body.charAt(0) === '#') {
        var hex = body.charAt(1) === 'x' || body.charAt(1) === 'X';
        var code = hex ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        // Reject anything outside the scalar range, and surrogates, rather than
        // letting String.fromCodePoint throw or emit a lone surrogate.
        if (!isFinite(code) || code < 0 || code > 0x10FFFF) return match;
        if (code >= 0xD800 && code <= 0xDFFF) return '�';
        try { return String.fromCodePoint(code); } catch (e) { return match; }
      }
      var named = NAMED_ENTITIES[body.toLowerCase()];
      return named === undefined ? match : named;
    });
  }

  /**
   * Tokenize a locale rich-text string into a DocumentFragment. Returns live
   * nodes: nothing serializes a sanitized tree and reparses it, which is the
   * shape mutation XSS exploits and which the previous
   * `sanitizeHTML(html) → string` round trip had.
   */
  function sanitizeFragment(html) {
    var src = String(html === undefined || html === null ? '' : html);
    var root = document.createDocumentFragment();
    var stack = [{ tag: null, node: root }];

    function top() { return stack[stack.length - 1].node; }

    function pushText(raw) {
      if (!raw) return;
      var decoded = decodeEntities(raw);
      if (decoded) top().appendChild(document.createTextNode(decoded));
    }

    var i = 0;
    while (i < src.length) {
      var lt = src.indexOf('<', i);
      if (lt === -1) { pushText(src.slice(i)); break; }
      pushText(src.slice(i, lt));

      var match = TAG_RE.exec(src.slice(lt));
      if (!match) {
        // Not a well-formed tag. The '<' is content.
        pushText('<');
        i = lt + 1;
        continue;
      }

      var whole = match[0];
      var closing = match[1] === '/';
      var tag = match[2].toUpperCase();
      var attrs = match[3] || '';
      var selfClosed = match[4] === '/';
      i = lt + whole.length;

      if (!RICH_TAGS.has(tag)) { pushText(whole); continue; }

      if (closing) {
        var depth = -1;
        for (var k = stack.length - 1; k > 0; k--) {
          if (stack[k].tag === tag) { depth = k; break; }
        }
        // A close tag with no matching open is content, not a parse error.
        if (depth === -1) pushText(whole);
        else stack.length = depth;
        continue;
      }

      var el = document.createElement(tag.toLowerCase());
      if (tag === 'A') {
        var url = attrValue(attrs, 'href') || '';
        // Every other attribute is discarded, so no event handler, style or
        // target can arrive from a locale file.
        var decodedUrl = decodeEntities(url || '');
        if (/^https:\/\//i.test(decodedUrl)) {
          el.setAttribute('href', decodedUrl);
          el.setAttribute('target', '_blank');
          el.setAttribute('rel', 'noopener noreferrer');
        }
      }
      top().appendChild(el);
      if (!selfClosed && !RICH_VOID.has(tag)) stack.push({ tag: tag, node: el });
    }

    return root;
  }

  /* ── Loading ────────────────────────────────────────────────────────── */

  function fetchJSON(url) {
    return fetch(url, { cache: 'no-cache' }).then(function (r) {
      if (!r.ok) throw new Error(url + ' → HTTP ' + r.status);
      return r.json();
    });
  }

  function loadRegistry() {
    return fetchJSON('locales/index.json')
      .then(function (data) {
        if (data && Array.isArray(data.locales) && data.locales.length) {
          locales = data.locales;
        }
      })
      .catch(function () { /* keep the inline registry */ });
  }

  function loadBundle(code) {
    if (bundles[code]) return Promise.resolve(bundles[code]);
    return fetchJSON('locales/' + code + '.json').then(function (data) {
      bundles[code] = data;
      return data;
    });
  }

  /* ── Language detection ─────────────────────────────────────────────── */

  function isAvailable(code) {
    return locales.some(function (l) { return l.code === code; });
  }

  // Matches 'zh-TW' exactly first, then falls back to the base tag ('zh' → the
  // first shipped zh-* locale), then to English.
  function matchLocale(tag) {
    if (!tag) return null;
    var lower = String(tag).toLowerCase();
    var exact = locales.filter(function (l) { return l.code.toLowerCase() === lower; })[0];
    if (exact) return exact.code;
    var base = lower.split('-')[0];
    var partial = locales.filter(function (l) {
      return l.code.toLowerCase() === base || l.code.toLowerCase().indexOf(base + '-') === 0;
    })[0];
    return partial ? partial.code : null;
  }

  function detectLang() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved && isAvailable(saved)) return saved;
    } catch (e) { /* storage disabled — fall through to navigator */ }

    var preferred = (navigator.languages && navigator.languages.length)
      ? navigator.languages
      : [navigator.language || DEFAULT_LANG];

    for (var i = 0; i < preferred.length; i++) {
      var match = matchLocale(preferred[i]);
      if (match) return match;
    }
    return DEFAULT_LANG;
  }

  /* ── DOM application ────────────────────────────────────────────────── */

  function applyTranslations(root) {
    var scope = root || document;

    scope.querySelectorAll('[data-i18n]').forEach(function (el) {
      el.replaceChildren(sanitizeFragment(t(el.dataset.i18n)));
    });
    scope.querySelectorAll('[data-i18n-text]').forEach(function (el) {
      el.textContent = t(el.dataset.i18nText);
    });
    scope.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    });
    scope.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      el.title = t(el.dataset.i18nTitle);
    });
    scope.querySelectorAll('[data-i18n-aria-label]').forEach(function (el) {
      el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel));
    });

    if (root) return;

    document.title = t('doc.title');
    var desc = document.querySelector('meta[name="description"]');
    if (desc) desc.setAttribute('content', t('doc.description'));

    var meta = tRaw('meta') || {};
    document.documentElement.lang = currentLang;
    document.documentElement.dir = meta.dir || 'ltr';
  }

  function renderLangSelect() {
    var sel = document.getElementById('langSelect');
    if (!sel) return;
    sel.replaceChildren();
    locales.forEach(function (l) {
      var option = document.createElement('option');
      option.value = l.code;
      option.textContent = l.label || l.nativeName || l.code;
      sel.appendChild(option);
    });
    sel.value = currentLang;
    sel.title = t('topbar.langTitle');
  }

  /* ── Public API ─────────────────────────────────────────────────────── */

  /** Switch language, loading the bundle if needed. Returns a promise. */
  function setLang(code) {
    if (!isAvailable(code)) return Promise.resolve(false);
    return loadBundle(code)
      .then(function () {
        currentLang = code;
        try { localStorage.setItem(STORAGE_KEY, code); } catch (e) { /* ignore */ }
        applyTranslations();
        renderLangSelect();
        listeners.forEach(function (fn) { fn(code); });
        return true;
      })
      .catch(function (err) {
        console.warn('[i18n] failed to load locale "' + code + '":', err);
        return false;
      });
  }

  /** Register a callback fired after every successful language change. */
  function onChange(fn) { listeners.push(fn); }

  /** Boot: pick a language, load it, paint the DOM. Returns a promise. */
  function init() {
    return loadRegistry().then(function () {
      var code = detectLang();
      return loadBundle(code)
        .then(function () { currentLang = code; })
        .catch(function (err) {
          console.warn('[i18n] falling back to English:', err);
          currentLang = DEFAULT_LANG;
        })
        .then(function () {
          applyTranslations();
          renderLangSelect();
        });
    });
  }

  global.i18n = {
    t: t,
    tp: tp,
    tRaw: tRaw,
    sanitizeFragment: sanitizeFragment,
    init: init,
    setLang: setLang,
    onChange: onChange,
    applyTranslations: applyTranslations,
    get lang() { return currentLang; },
    get locales() { return locales.slice(); }
  };

  // Convenience globals — the app calls t()/tp() a few hundred times.
  global.t = t;
  global.tp = tp;
  global.tRaw = tRaw;
})(window);
