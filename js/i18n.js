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

  function interpolate(str, args) {
    for (var i = 0; i < args.length; i++) {
      str = str.split('{' + i + '}').join(String(args[i]));
    }
    return str;
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

  function sanitizeHTML(html) {
    var template = document.createElement('template');
    template.innerHTML = String(html || '');
    var allowed = new Set(['A', 'BR', 'STRONG', 'CODE', 'EM', 'B', 'I', 'SMALL', 'UL', 'OL', 'LI', 'P']);
    Array.from(template.content.querySelectorAll('*')).forEach(function (el) {
      if (!allowed.has(el.tagName)) {
        if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE' || el.tagName === 'IFRAME' || el.tagName === 'OBJECT') el.remove();
        else el.replaceWith.apply(el, Array.from(el.childNodes));
        return;
      }
      var originalHref = el.tagName === 'A' ? el.getAttribute('href') : null;
      Array.from(el.attributes).forEach(function (attr) { el.removeAttribute(attr.name); });
      if (el.tagName === 'A') {
        if (/^https:\/\//i.test(originalHref || '')) {
          el.setAttribute('href', originalHref);
          el.setAttribute('target', '_blank');
          el.setAttribute('rel', 'noopener noreferrer');
        } else el.replaceWith(document.createTextNode(el.textContent));
      }
    });
    return template.innerHTML;
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
      el.innerHTML = sanitizeHTML(t(el.dataset.i18n));
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
    sanitizeHTML: sanitizeHTML,
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
