/* ──────────────────────────────────────────────────────────────────────────
   UI, rendering and orchestration. The bundle's entry point.

   All user-facing text comes from the i18n layer (src/i18n/index.js →
   locales/*.json). The audit logic lives in js/dns.js and speaks only in
   stable tokens; this file is where tokens become words.

   Nothing here builds markup from strings. Every rendered value goes through
   src/ui/render.js (`R.el`, `R.text`, `R.value`), so a DNS-derived string can
   only land in a text node or an allowlisted attribute. There is deliberately
   no escape helper in this file: leaving one available would invite a new
   concatenation site, and the whole point of 0.2.3 is that no such site can
   exist. The two document builders construct a detached tree and read
   `outerHTML` once — reading is permitted, writing never is.

   ── What Task 2.6 did, and what it deliberately did not ──────────────────

   This file is `js/app.js` with its IIFE wrapper replaced. The 1,801-line body
   below is BYTE-IDENTICAL to the body of `(function (global) { … })(window)`,
   still at its original two-space indent, apart from the three substitutions
   named under "Ambient primitives" and "Boot" below. Nothing moved between
   files, nothing was renamed, and nothing was reindented; the function list
   extracted before and after the conversion is identical, 63 entries.

   Binding the runtime's parts as module-level `const` is what buys that. The
   body called `t`, `tp`, `tRaw`, `i18n`, `R` and `DnsAudit` as globals the
   other IIFEs had installed; it now closes over the same values, taken from
   one `createAuditRuntime()` call, and its own text did not have to change.

   Not side-effect-free, and it is the only file in `src/` that is not. Import
   it and the application constructs itself and wires the page.
   `src/runtime.js` is the side-effect-free half, and `tests/contract/
   runtime.test.mjs` asserts that importing THAT touches no DOM and makes no
   request.

   ── This file is a marked ADAPTER ────────────────────────────────────────

     LEGACY_ADAPTER

   Two things make it one, and both are scheduled:

   • It reads the ambient `window` to build its platform. Nothing else under
     `src/` may — `src/platform/browser.js` takes its window as an argument
     precisely so that the read happens in exactly one place, and that place is
     the entry point.
   • It installs the 24-name legacy global surface (§10's inventory). Those
     names have no consumer left inside the repository as of this commit —
     `js/app.js` was the last one — and they are kept, unchanged, so that this
     commit moves NO browser-visible surface. The two authorized compatibility
     deltas that remove them are Tasks 2.7 and 2.8, recorded ahead of time in
     `tests/fixtures/equivalence/compatibility-deltas.json`. One surface change
     per commit, each one named.

   ── Ambient primitives ───────────────────────────────────────────────────

   The body reaches for nine ambient names — `document`, `fetch`, `setTimeout`,
   `Blob`, `FileReader`, `URL`, `AbortController`, `Intl` and `open`. All nine
   are on spec §11's list, and all nine are bound below FROM THE PLATFORM
   rather than left to resolve against whatever global object the module
   happens to evaluate in. That is not ceremony: under `node:vm` the old IIFE
   resolved them against the sandbox's `window`, and an ES module imported into
   Node resolves them against Node's global object, where `document` does not
   exist. The binding is what lets the same source run in a browser, in the
   bundle and in a suite.

   Two of the nine could not be a plain binding and are named here so neither
   looks like an accident:

   • `open` — `js/app.js:385` called it as `global.open(url, '_blank',
     'noopener')`, a property of the IIFE's window parameter. It is now
     `open(...)`, the platform's bound method. Spec `1.3` added it to §11 for
     this call site; the arguments, including `noopener`, are unchanged and
     `tests/contract/platform.test.mjs` asserts all three reach the window in
     order.
   • `Date` — `js/app.js:1651` rendered the report's timestamp with
     `new Date().toLocaleString(i18n.lang)`. `Date` is a language built-in and
     §11 does not inject those; `platform.formatDateTime(date, locale)` exists
     for exactly this call and performs exactly that call. Substituted here,
     which is what makes the exported report's timestamp a controlled INPUT to
     an equivalence run rather than a field the canonicalizer has to ignore —
     spec Design §8 permits no timestamp wildcard.

   ── Boot ─────────────────────────────────────────────────────────────────

   The `DOMContentLoaded` listener now calls `runtime.mount()` where it called
   `i18n.init()`. Same function, one boot: `mount()` IS `i18n.init()` today,
   and `src/legacy-bridge.js` — which deliberately never called it, to avoid
   booting twice — is retired by this commit. The wiring itself stays in the
   listener; moving it into `src/ui/events.js` is Task 5.6, and doing it here
   would put a UI change inside a wrapper-only conversion. Spec §35.
   ────────────────────────────────────────────────────────────────────────── */

import { createAuditRuntime } from './runtime.js';
// The exported CSV and HTML report, Task 5.5. `serializeDocument` and
// `styleElement` come back here because `buildLearnMorePage()` emits a
// standalone document too and must not hold a second copy of the `</style>`
// escape rule.
import { createReport, serializeDocument, styleElement } from './ui/report.js';
import { createBrowserPlatform } from './platform/browser.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

/* ── LEGACY_ADAPTER ───────────────────────────────────────────────────────
 * Import order IS evaluation order. The generated tables are installed as
 * globals by a side-effect module rather than by an assignment in this file's
 * body, because ES imports are hoisted and an assignment written here would
 * run after every import had already evaluated. Nothing reads those globals
 * any more — `js/app.js` was the last reader and it is this file now — so what
 * the import buys today is only the unchanged 24-name surface. Task 2.8
 * removes it with the rest of the transition inputs.
 */
import './data/legacy-globals.js';

/**
 * ONE runtime for the page, and one platform inside it.
 *
 * The production construction path, and there is only one: no second way to
 * build the application exists and no branch here runs only for tests. Unit
 * and integration suites call the same `createAuditRuntime()`.
 *
 * One runtime means one DoH cache, which is v0.5.0's page lifetime exactly —
 * `tools/scoring.test.mjs:1888-1891` asserts the sibling reuse and
 * `PRIVACY.md:30-33` publishes the fan-out it produces. A second runtime here
 * would halve the cache's reach and change a published figure.
 */
const platform = createBrowserPlatform(window);
const runtime = createAuditRuntime({
  publicSuffixRules: PUBLIC_SUFFIX_RULES,
  dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
  englishBundle: LOCALE_EN,
  platform,
});

/**
 * The six names the body used to read off `window`.
 *
 * Bound as `const` at module top so the body below did not have to change.
 * Same values, same function identities, one instance each — which is what the
 * IIFEs were.
 */
const i18n = runtime.i18n;
const t = i18n.t;
const tp = i18n.tp;
const tRaw = i18n.tRaw;
const R = runtime.renderer;
const DnsAudit = runtime.engine;

/**
 * The nine ambient primitives the body reaches for, taken from the platform.
 *
 * `document` is bound once because a page has one and it never changes;
 * `src/ui/render.js` takes a getter instead because it is constructed before
 * the document it draws into is chosen.
 */
const document = platform.document;
const fetch = platform.fetch;
const setTimeout = platform.setTimeout;
const open = platform.open;
const URL = platform.URL;
const Blob = platform.Blob;
const FileReader = platform.FileReader;
const AbortController = platform.AbortController;
const Intl = platform.Intl;

/* ── LEGACY_ADAPTER: the 24-name global surface, unchanged ────────────────
 * `global` was the IIFE's parameter and it was `window`. Kept as a binding so
 * the assignments at the foot of the body — the 14 function globals and
 * `__APP_TEST__` — are byte-identical to what they were, and so that Task 2.8
 * removes them as a contiguous, mechanically auditable block.
 *
 * The five wiring names below came from `src/legacy-bridge.js`, which this
 * commit retires. Nothing reads them any more. They are assigned so that this
 * commit changes no browser-visible surface at all; Task 2.8 removes them.
 */
const global = window;
global.i18n = i18n;
global.t = t;
global.tp = tp;
global.tRaw = tRaw;
global.R = R;
/* `window.DnsAudit` is NOT assigned here, and its absence is the Task 2.7
 * delta. esbuild produces that name from this module's exports — §10's
 * "generated boundary" — so the source graph creates 23 globals and the bundle
 * creates 24. Assigning it here as well would put the 95-member engine on the
 * window until the outer `var DnsAudit = …` overwrote it a moment later, which
 * is the clobber spec 0.2 nearly shipped, observed rather than reasoned about:
 * with both in place the window ends up holding the two-member object anyway.
 */

  'use strict';

  var CONCURRENCY = 6;
  var MAX_DOMAINS = 200;
  var MAX_COMPREHENSIVE_DKIM_DOMAINS = 5;
  /**
   * Above this many domains the deep protocol checks turn themselves off.
   *
   * They cost three queries per MX host plus one TLSA query each — measured at
   * roughly seven extra queries per domain across the backtest sample — so a
   * 200-domain run would add well over a thousand lookups to a fan-out
   * `PRIVACY.md` already describes as large. The threshold is a starting point
   * to revisit against real use, not a law.
   */
  var MAX_DEEP_CHECK_DOMAINS = 50;
  /**
   * Whether the user has re-enabled the deep checks after seeing the notice.
   *
   * Deliberately a module variable and NOT `localStorage`. `PRIVACY.md` states
   * that this app writes "exactly one value" to storage and calls that the
   * entire footprint; a second key would falsify a published privacy claim to
   * remember a checkbox. The scope this gives is the browser tab's session — a
   * reload restores the default — and that was the accepted trade.
   */
  var deepChecksReEnabled = false;

  var results = [];
  var sortCol = null;
  var sortDir = 1;
  var auditController = null;
  var MAX_UPLOAD_BYTES = 1024 * 1024;

  /* ── Token → label ──────────────────────────────────────────────────── */

  // js/dns.js returns '@'-prefixed tokens for anything a translator owns.
  // Proper nouns ('Cloudflare', 'Google Workspace') come back verbatim.
  var TOKEN_KEYS = {
    '@unknown': 'provider.unknown',
    '@custom': 'provider.custom',
    '@custom-unknown': 'provider.customUnknown',
    '@self-hosted': 'provider.selfHosted',
    '@none': 'provider.none',
    '@null-mx': 'provider.nullMx',
    '@implicit-mx': 'provider.implicitMx',
    '@no-web': 'provider.noWebPresence',
    '@cname-loop': 'provider.cnameLoop',
    '@dns-error': 'provider.dnsError',
    '@cloudflare-proxied': 'provider.cloudflareProxied',
    '@porkbun-forwarding': 'provider.porkbunForwarding',
    '@dash': 'labels.dash',
  };

  function label(value) {
    if (typeof value !== 'string') return '';
    return TOKEN_KEYS[value] ? t(TOKEN_KEYS[value]) : value;
  }

  function spfLabel(spfStatus) {
    return t({
      missing: 'spf.missing',
      permerror: 'spf.permerror',
      warn: 'spf.issues',
      ok: 'spf.hardfail',
      softfail: 'spf.softfail',
      present: 'spf.present',
    }[spfStatus.status] || 'spf.present');
  }

  function dmarcLabel(dmarcStatus) {
    // 'unknown' is a lookup that failed, not a record that is absent. It gets
    // its own badge for the same reason 'dkim-unverified' does: presenting an
    // unexamined control as a missing one is the worse error for an auditor.
    if (dmarcStatus.status === 'unknown') return t('dmarc.unverified');
    if (dmarcStatus.status === 'permerror') return t('dmarc.permerror');
    if (dmarcStatus.status === 'missing') return t('dmarc.missing');
    // 'present' means receivers cannot act on the record — bad v=, unrecognised
    // p=, or duplicate tags.
    if (dmarcStatus.status === 'present') return t('dmarc.invalid');
    // t=y (RFC 9989): name the published policy AND the fact that it is not
    // being applied. Showing plain "none" here would hide the operator's
    // intent; showing plain "reject" would overstate their protection.
    if (dmarcStatus.testMode && dmarcStatus.policy) return tDns('dmarc.testMode', dmarcStatus.policy);
    if (dmarcStatus.status === 'warn') return t('dmarc.none');
    var suffix = '';
    if (dmarcStatus.pct < 100) suffix = ' ' + t('dmarc.pctSuffix', dmarcStatus.pct);
    if (dmarcStatus.policy === 'reject') return t('dmarc.reject') + suffix;
    if (dmarcStatus.policy === 'quarantine') return t('dmarc.quarantine') + suffix;
    return t('dmarc.set');
  }

  /* ── Score breakdown ────────────────────────────────────────────────── */

  // Trim trailing zeros so 1.5 shows as "1.5" and 6.0 as "6".
  function num(n) { return String(Math.round(n * 10) / 10); }

  function scoreBlock(score) {
    if (!score || !score.breakdown) return null;

    var rows = score.breakdown.pillars.map(function (p) {
      var ratio = p.max ? p.pts / p.max : 0;
      var color = ratio >= 1 ? 'var(--ok)' : ratio > 0 ? 'var(--warn)' : '#cbd5e1';
      return R.el('div', { className: 'sb-row' }, [
        R.el('span', { className: 'sb-label' }, t('score.pillar.' + p.key)),
        R.el('span', { className: 'sb-track' }, [
          R.el('span', {
            className: 'sb-fill',
            style: 'width:' + Math.round(ratio * 100) + '%;background:' + color + ';',
          }),
        ]),
        R.el('span', { className: 'sb-val' }, [
          R.text(num(p.pts)),
          R.el('small', null, '/' + p.max),
        ]),
      ]);
    });

    var parts = score.breakdown.dmarc || {};
    var partOrder = ['policy', 'subdomain', 'rua', 'alignment', 'ruf', 'uris'];
    var dmarcParts = partOrder
      .filter(function (k) { return parts[k] !== undefined; })
      .map(function (k) {
        var zero = !parts[k];
        return R.el('span', { className: 'sb-part' + (zero ? ' sb-part-zero' : '') }, [
          R.text(t('score.dmarcParts.' + k) + ' '),
          R.el('strong', null, num(parts[k])),
        ]);
      });

    return R.el('div', { className: 'score-block' }, [
      R.el('div', { className: 'score-head' }, [
        R.el('span', { className: 'score-total ' + score.cls }, [
          R.text(num(score.pts)),
          R.el('small', null, '/' + score.max),
        ]),
        R.el('span', { className: 'issues-section-label' }, t('score.label')),
        score.parked ? R.el('span', { className: 'score-note' }, t('score.parkedNote')) : null,
      ]),
      R.el('div', { className: 'sb-rows' }, rows),
      dmarcParts.length
        ? R.el('div', { className: 'sb-dmarc' }, [
          R.el('span', { className: 'sb-dmarc-label' }, t('score.dmarcParts.label')),
          dmarcParts,
        ])
        : null,
    ]);
  }

  /* ── The DNS/locale boundary ─────────────────────────────────────────
     Sentinel substitution belongs on the DNS-derived ARGUMENTS, before
     translation — not on the finished sentence. The translator's own text may
     legitimately use formatting characters; the interpolated argument is the
     untrusted half. Applying it to the completed string would rewrite both.

     Without this, an override inside an issue argument stayed live in the most
     important explanatory text on the page: the record itself rendered as
     `‹RLO›` while the message beside it still reordered.
     ──────────────────────────────────────────────────────────────────── */

  function dnsArgs(args) {
    return (args || []).map(function (a) {
      return typeof a === 'string' ? R.sentinelText(a) : a;
    });
  }

  /** `t()` for messages whose arguments come from DNS. */
  function tDns(key) {
    return t.apply(null, [key].concat(dnsArgs(Array.prototype.slice.call(arguments, 1))));
  }

  /**
   * `sentinel` defaults to true (the interface). The CSV passes false: its
   * data columns carry the published bytes, and the `record_hygiene` column
   * is what warns the reader (OQ-SEC-11).
   */
  function issueMessage(issue, sentinel) {
    var safe = sentinel === false ? function (x) { return x || []; } : dnsArgs;
    var args = issue.args ? safe(issue.args.slice()) : [];
    if (issue.noteKey) {
      args = [t.apply(null, ['dkim.' + issue.noteKey].concat(safe(issue.noteArgs || [])))];
    }
    return t.apply(null, ['issue.' + issue.key + '.msg'].concat(args));
  }

  /* ── Small helpers ──────────────────────────────────────────────────── */

  function $(id) { return document.getElementById(id); }

  function badge(text, cls) {
    return R.el('span', { className: 'badge badge-' + cls }, text);
  }

  function emailBadge(provider) {
    var cls = provider === '@none' ? 'crit' : provider === '@null-mx' ? 'ok' : provider === '@implicit-mx' ? 'warn' : provider === '@porkbun-forwarding' ? 'warn' : 'info';
    return badge(label(provider), cls);
  }

  function hostCls(h) {
    if (h === '@cname-loop') return 'crit';
    return 'muted';
  }

  /**
   * Apply the large-run rule to the deep-checks toggle, and say so.
   *
   * An explicit re-enable wins: having been told the cost and having ticked the
   * box again, the user is not told twice for the rest of the tab session.
   */
  /**
   * Record the user's answer to the notice.
   *
   * Only a re-enable is remembered. An explicit un-tick needs no memory — the
   * box is already clear and applyDeepCheckLimit() never ticks it back on — and
   * recording it would suppress the notice for someone who had never seen it.
   */
  function rememberDeepCheckChoice(checked) {
    if (!checked) return;
    deepChecksReEnabled = true;
    $('deepChecksNotice').style.display = 'none';
  }

  function applyDeepCheckLimit(domainCount) {
    var notice = $('deepChecksNotice');
    if (domainCount <= MAX_DEEP_CHECK_DOMAINS || deepChecksReEnabled) {
      notice.style.display = 'none';
      notice.textContent = '';
      return;
    }
    $('optDeepChecks').checked = false;
    notice.textContent = t('opt.deepChecksAutoDisabled', MAX_DEEP_CHECK_DOMAINS, domainCount);
    notice.style.display = '';
  }

  function showToast(msg) {
    var el = $('toast');
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(function () { el.classList.remove('show'); }, 3000);
  }

  // One appended span per line. The previous `el.innerHTML +=` serialized and
  // reparsed the whole log on every append, which a 200-domain run does at
  // least 200 times against a growing document.
  function log(msg, cls) {
    var el = $('progressLog');
    el.appendChild(R.el('span', { className: 'log-' + (cls || 'info') }, msg));
    el.appendChild(R.text('\n'));
    el.scrollTop = el.scrollHeight;
  }

  function parseDomains(raw) {
    var seen = new Set();
    return raw.split(/[\n,\s]+/).map(function (input) {
      var value = input.trim();
      if (!value) return '';
      try {
        var url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : 'http://' + value);
        var host = url.hostname.toLowerCase().replace(/\.$/, '');
        var labels = host.split('.');
        if (host.length > 253 || labels.length < 2 || labels.some(function (label) {
          return !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label);
        })) return '';
        return host;
      } catch (e) { return ''; }
    }).filter(function (domain) {
      if (!domain || seen.has(domain)) return false;
      seen.add(domain);
      return true;
    });
  }

  /* ── Document builders ──────────────────────────────────────────────
     Both build a tree in a detached document and serialize once. That is what
     lets `esc()` be deleted: there is no string being concatenated for an
     escape helper to protect. Serializing a node-built tree is safe by
     construction — a text node containing `<script>` serializes to
     `&lt;script&gt;` and reparses back to the same text node.
     ──────────────────────────────────────────────────────────────────── */

  // Structure and styling live here; every word comes from the locale file
  // under learnMore.<key>.
  var GUIDE_COLORS = {
    'bimi': '#7c3aed',
    'mta-sts': '#0284c7',
    'tls-rpt': '#0284c7',
    'caa': '#16a34a',
    'dnssec': '#d97706',
  };

  function guideCss(color) {
    return '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n' +
      "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#111827;line-height:1.7;font-size:15px}\n" +
      '.hero{background:linear-gradient(135deg,' + color + '22,' + color + '08);border-bottom:1px solid ' + color + '33;padding:48px 32px 40px;text-align:center}\n' +
      '.hero h1{font-size:28px;font-weight:800;color:#111827;margin-bottom:8px}\n' +
      '.hero .tag{display:inline-block;background:' + color + '18;color:' + color + ';border:1px solid ' + color + '44;border-radius:20px;padding:5px 16px;font-size:14px;font-weight:600;margin-bottom:16px}\n' +
      '.hero p{font-size:16px;color:#4b5563;max-width:600px;margin:0 auto}\n' +
      'main{max-width:760px;margin:0 auto;padding:40px 24px 80px}\n' +
      'section{background:#fff;border:1px solid #dde1e9;border-radius:12px;padding:28px 32px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.06)}\n' +
      'h2{font-size:18px;font-weight:700;color:#111827;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid #f0f2f5}\n' +
      'p{color:#374151;margin-bottom:0;font-size:15px}\n' +
      'p+pre,p+p{margin-top:14px}\n' +
      'pre{background:#f6f8fa;border:1px solid #dde1e9;border-radius:8px;padding:16px 18px;overflow-x:auto;margin-top:14px}\n' +
      "code{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:13px;color:#1e293b;line-height:1.8;white-space:pre}\n" +
      'a{color:' + color + ';text-decoration:underline;text-underline-offset:2px}\n' +
      '.back{display:inline-flex;align-items:center;gap:6px;margin-bottom:32px;color:#6b7280;font-size:14px;cursor:pointer;background:none;border:none;padding:0}\n' +
      '.back:hover{color:#111827}\n' +
      'footer{text-align:center;padding:24px;font-size:13px;color:#9ca3af}\n' +
      '@media(max-width:600px){.hero{padding:32px 20px 28px}.hero h1{font-size:22px}section{padding:20px 18px}main{padding:24px 12px 60px}}\n';
  }

  function buildLearnMorePage(key) {
    var data = tRaw('learnMore.' + key);
    if (!data) return null;
    var color = GUIDE_COLORS[key] || '#2563eb';

    var doc = document.implementation.createHTMLDocument('');
    var D = R.for(doc);

    doc.documentElement.setAttribute('lang', i18n.lang);
    doc.head.appendChild(D.el('meta', { charset: 'UTF-8' }));
    doc.head.appendChild(D.el('meta', {
      name: 'viewport', content: 'width=device-width, initial-scale=1.0',
    }));
    doc.head.appendChild(D.el('title', null, data.title));
    doc.head.appendChild(styleElement(D, guideCss(color)));

    doc.body.appendChild(D.el('div', { className: 'hero' }, [
      D.el('div', { className: 'tag' }, t('learnMore.badge')),
      D.el('h1', null, data.title),
      D.el('p', null, data.tagline),
    ]));

    var main = D.el('main', null, [
      D.el('span', { className: 'back' }, t('learnMore.close')),
    ]);
    (data.sections || []).forEach(function (s) {
      var section = D.el('section', null, [
        D.el('h2', null, s.h),
        D.el('p', null, D.rich(s.body)),
      ]);
      if (s.code) section.appendChild(D.el('pre', null, [D.el('code', null, s.code)]));
      if (s.body2) section.appendChild(D.el('p', null, D.rich(s.body2)));
      main.appendChild(section);
    });
    doc.body.appendChild(main);
    doc.body.appendChild(D.el('footer', null, t('learnMore.footer')));

    return serializeDocument(doc);
  }

  function openLearnMore(key) {
    var html = buildLearnMorePage(key);
    if (!html) return;
    var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    open(url, '_blank', 'noopener');
    setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
  }

  /* ── Row rendering ──────────────────────────────────────────────────── */

  /**
   * The state token as a phrase, or null when the state has no special name.
   *
   * `insecure` deliberately returns null so it keeps the shared "Not
   * configured" wording every other pillar uses. The other four get their own,
   * because "Not configured" is simply false for a zone that is signed but
   * unanchored, and worse than false for one whose validation is failing.
   */
  function dnssecStateLabel(dnssec) {
    var state = dnssec && dnssec.state;
    if (!state || state === 'secure' || state === 'insecure') return null;
    return t('dnssec.state.' + state);
  }

  /**
   * One dot descriptor for DNSSEC, shared by the compact strip and the full
   * one so the two cannot drift.
   *
   * `partial` drives the amber treatment that already exists for a duplicated
   * record, and it covers exactly `unanchored` and `mismatch` — the two states
   * where the operator has done real work that is not yet protecting anything.
   * `bogus` and `indeterminate` stay grey: amber reads as "nearly there", and
   * neither of those is. The `done` count is untouched, because amber is not
   * configured.
   */
  function dnssecDot(adv) {
    var dnssec = adv && adv.dnssec;
    var state = dnssec && dnssec.state;
    return {
      key: 'DNSSEC',
      ok: !!(dnssec && dnssec.signed),
      partial: state === 'unanchored' || state === 'mismatch',
      label: dnssecStateLabel(dnssec),
    };
  }

  function advMiniDots(adv) {
    if (!adv) return R.text(t('labels.dash'));
    var items = [
      { key: 'BIMI', ok: adv.bimi && adv.bimi.present, dup: adv.bimi && adv.bimi.multiple },
      { key: 'MTA-STS', ok: adv.mtaSts && adv.mtaSts.policyVerified, partial: adv.mtaSts && adv.mtaSts.present, dup: adv.mtaSts && adv.mtaSts.multiple },
      { key: 'TLS-RPT', ok: adv.tlsRpt && adv.tlsRpt.present, dup: adv.tlsRpt && adv.tlsRpt.multiple },
      { key: 'CAA', ok: adv.caa && adv.caa.found },
      dnssecDot(adv),
    ];
    var done = items.filter(function (i) { return i.ok; }).length;
    var dots = items.map(function (i) {
      // A duplicated record is not simply absent — it reads amber so the
      // operator can tell "never set up" from "set up twice, silently off".
      var state = i.label ? i.label
        : i.ok ? t('adv.configured') : i.partial ? t('adv.unverified') : i.dup ? t('adv.duplicated') : t('adv.notConfigured');
      var color = i.ok ? 'var(--ok)' : (i.partial || i.dup) ? 'var(--warn)' : '#cbd5e1';
      return R.el('span', {
        title: i.key + ': ' + state,
        style: 'display:inline-block;width:8px;height:8px;border-radius:50%;background:' +
          color + ';margin-right:2px;',
      });
    });
    return R.el('span', { style: 'display:inline-flex;align-items:center;gap:4px;' }, [
      dots,
      R.el('span', { style: 'font-size:10px;color:var(--ink3);margin-left:2px;' }, done + '/5'),
    ]);
  }

  function advFullDots(adv) {
    var items = [
      {
        key: 'BIMI', ok: adv.bimi && adv.bimi.present, dup: adv.bimi && adv.bimi.multiple,
        tip: adv.bimi && adv.bimi.present
          ? t('adv.tip.bimiOn', (adv.bimi.record || '').substring(0, 60))
          : (adv.bimi && adv.bimi.multiple) ? t('adv.tip.bimiDup') : t('adv.tip.bimiOff'),
      },
      {
        key: 'MTA-STS', ok: adv.mtaSts && adv.mtaSts.policyVerified, partial: adv.mtaSts && adv.mtaSts.present, dup: adv.mtaSts && adv.mtaSts.multiple,
        tip: adv.mtaSts && adv.mtaSts.policyVerified ? t('adv.tip.mtaStsOn')
          : (adv.mtaSts && adv.mtaSts.present) ? t('adv.tip.mtaStsUnverified')
          : (adv.mtaSts && adv.mtaSts.multiple) ? t('adv.tip.mtaStsDup') : t('adv.tip.mtaStsOff'),
      },
      {
        key: 'TLS-RPT', ok: adv.tlsRpt && adv.tlsRpt.present, dup: adv.tlsRpt && adv.tlsRpt.multiple,
        tip: adv.tlsRpt && adv.tlsRpt.present ? t('adv.tip.tlsRptOn')
          : (adv.tlsRpt && adv.tlsRpt.multiple) ? t('adv.tip.tlsRptDup') : t('adv.tip.tlsRptOff'),
      },
      {
        key: 'CAA', ok: adv.caa && adv.caa.found,
        tip: adv.caa && adv.caa.found
          ? t('adv.tip.caaOn', adv.caa.atDomain, (adv.caa.records || []).slice(0, 2).join(', '))
          : t('adv.tip.caaOff'),
      },
      Object.assign(dnssecDot(adv), {
        // The tooltip is the state, not a remedy. What to do about it is the
        // finding's job, and repeating it here would put two differently
        // worded instructions on one screen.
        tip: adv.dnssec && adv.dnssec.signed ? t('adv.tip.dnssecOn')
          : dnssecStateLabel(adv.dnssec) || t('adv.tip.dnssecOff'),
      }),
    ];
    var dots = items.map(function (i) {
      return R.el('span', {
        className: 'adv-dot ' + (i.ok ? 'dot-ok' : (i.partial || i.dup) ? 'dot-dup' : 'dot-miss'),
        dataset: { tip: i.tip },
      }, [R.el('span', { className: 'dot-pip' }), R.text(i.key)]);
    });
    return R.el('div', { className: 'adv-strip' }, [
      R.el('div', { className: 'adv-strip-label' }, t('labels.advanced')),
      R.el('div', { className: 'adv-dots' }, dots),
    ]);
  }

  function spfMeter(spfLookups) {
    var count = spfLookups.count;
    var pct = Math.min(100, (count / 10) * 100);
    var color = spfLookups.error ? 'var(--crit)' : spfLookups.warning ? 'var(--warn)' : 'var(--ok)';
    var text = spfLookups.error ? t('spf.meterOver', count)
      : spfLookups.warning ? t('spf.meterNear', count)
        : t('spf.meterOk', count);
    return R.el('div', { className: 'spf-meter', style: 'margin-top:6px;' }, [
      R.el('div', { className: 'spf-meter-bar' }, [
        R.el('div', {
          className: 'spf-meter-fill',
          style: 'width:' + pct + '%;background:' + color + ';',
        }),
      ]),
      R.el('span', {
        className: 'spf-meter-label',
        style: 'color:' + color + ';',
      }, text + ' ' + t('spf.meterSuffix')),
    ]);
  }

  // Every response kind dohFetch can report, mapped to a translatable label.
  // Anything not listed falls back to the generic error label.
  var WALK_STEP_KINDS = {
    'success': 'dmarc.stepKind.success',
    'nodata': 'dmarc.stepKind.nodata',
    'nxdomain': 'dmarc.stepKind.nxdomain',
    'servfail': 'dmarc.stepKind.servfail',
    'refused': 'dmarc.stepKind.refused',
    'timeout': 'dmarc.stepKind.timeout',
    'network-error': 'dmarc.stepKind.error',
    'http-error': 'dmarc.stepKind.error',
    'dns-error': 'dmarc.stepKind.error',
  };

  /**
   * The Tree Walk evidence trail (spec §7, OQ-DMARC-06).
   *
   * The found-at line always shows, because a policy discovered somewhere
   * other than the audited name is the single most surprising thing this
   * release can report and it should never need a click to find. The full step
   * list is what makes a surprising result explicable and is noise the rest of
   * the time, so it is expanded when the walk did something worth seeing —
   * an inherited policy, or a termination other than running out of labels —
   * and behind a disclosure control otherwise.
   *
   * Every DNS-derived name goes through R.value(), so display caps and
   * sentinel substitution apply here exactly as they do to a record.
   */
  function dmarcDiscoveryNode(r) {
    var d = r.dmarcDiscovery;
    if (!d) return null;
    var foundLine = d.applied
      ? tDns('dmarc.discoveryFoundAt', d.applied.foundAt, d.queries)
      : t('dmarc.discoveryNotFound', d.queries);
    // A walk can collect a record at more than one name — that is the whole
    // point of it — so "a record is here" and "this is the record receivers
    // apply" are different facts and the list has to say which is which.
    // Without this, a domain that stops at a psd=y boundary shows two
    // identical "record" rows and the reader cannot tell them apart.
    var appliedAt = d.applied ? '_dmarc.' + d.applied.foundAt : null;
    var steps = (d.steps || []).map(function (step) {
      // Mapped explicitly rather than interpolated into the key: t() returns
      // the key itself for a miss, so an unmapped response kind would render
      // as `dmarc.stepKind.whatever` in the interface instead of falling back.
      var kindKey = WALK_STEP_KINDS[step.kind] || 'dmarc.stepKind.error';
      var isApplied = step.selected && step.queryName === appliedAt;
      return R.el('div', { className: 'walk-step' }, [
        R.value(step.queryName),
        R.text(' · '),
        R.el('span', {
          className: isApplied ? 'walk-hit walk-applied' : step.selected ? 'walk-hit' : 'walk-miss',
        }, isApplied ? t('dmarc.stepApplied') : step.selected ? t('dmarc.stepSelected') : t(kindKey)),
      ]);
    });
    var interesting = (d.applied && d.applied.labelsUp > 0) || d.terminated !== 'root';
    var stepList = R.el('div', { className: 'showme-content', style: interesting ? 'display:block' : null }, [
      R.el('div', { className: 'showme-lbl' }, t('dmarc.discoverySteps')),
      R.frag(steps),
    ]);
    return R.el('div', { className: 'showme-wrap dmarc-discovery' }, [
      R.el('small', null, [
        R.text(foundLine),
        R.text(' · '),
        R.text(t('dmarc.terminated.' + d.terminated)),
      ]),
      // The shared toggleShowMe() rewrites textContent to the generic
      // open/close labels, which would silently replace this button's own
      // wording after one click. Carry the labels on the element so the toggle
      // can restore the right one.
      interesting ? null : R.el('button', {
        className: 'showme-btn', type: 'button',
        dataset: { openLabel: t('dmarc.showWalk'), closeLabel: t('showme.close') },
      }, t('dmarc.showWalk')),
      stepList,
    ]);
  }

  /**
   * The one line under a DKIM selector that says what the key actually is.
   *
   * Until now a found selector rendered only its raw TXT string, so the size —
   * the single most actionable fact about the key — was sitting decoded but
   * unread in front of the operator.
   *
   * `RSA` and `Ed25519` are algorithm names and stay in Latin script in every
   * locale; only the words around them are translated. A key the browser could
   * not confirm says nothing at all here, because "we did not check" is not a
   * finding and must not look like one.
   */
  function dkimKeyLine(key) {
    if (!key || !key.errors) return null;
    var parts;
    if (key.revoked) parts = [t('dkim.keyRevoked')];
    else if (key.errors.indexOf('unparseable-key') !== -1 ||
      key.errors.indexOf('bad-ed25519-length') !== -1) parts = [t('dkim.keyUnreadable')];
    else if (key.keyType === 'ed25519') parts = ['Ed25519'];
    else if (key.keyType === 'rsa' && key.keyBits) parts = [t('dkim.keyRsaBits', key.keyBits)];
    else parts = [t('dkim.keyUnknownType')];

    if (key.errors.indexOf('key-structure-invalid') !== -1) parts.push(t('dkim.keyStructureInvalid'));
    if (key.testing) parts.push(t('dkim.keyTesting'));
    if ((key.hashAlgorithms || []).length) parts.push(key.hashAlgorithms.join(', '));

    return R.el('div', { className: 'dkim-key-line' }, [
      R.el('span', null, t('dkim.keyLabel') + ':'),
      R.text(' '),
      R.el('strong', null, parts.join(' · ')),
    ]);
  }

  /**
   * MX records, annotated with what DNS says about each host.
   *
   * Falls back to the plain list when the deep checks did not run — an
   * un-annotated host must never be mistaken for one that resolved, so with no
   * audit to report the display is exactly what it was before.
   */
  function mxDetail(r) {
    var health = r.advanced && r.advanced.mxHealth;
    var hosts = (health && health.hosts) || [];
    if (!hosts.length) return R.list(r.mx, { sep: '\n' });
    return R.frag(hosts.map(function (h) {
      var state = h.resolves === 'yes'
        ? h.addresses.slice(0, 4).join(', ') + (h.addresses.length > 4 ? ' …' : '')
        : h.resolves === 'no' ? t('mx.doesNotResolve') : t('mx.notChecked');
      return R.el('div', { className: 'mx-host mx-host-' + h.resolves }, [
        R.el('code', null, R.host(h.preference + ' ' + h.host)),
        R.text(' — '),
        R.el('span', null, R.value(state)),
        h.isCname ? R.frag([R.text(' · '), R.el('span', null, t('mx.cnameTarget'))]) : null,
      ]);
    }));
  }

  /** The CAA set as a policy rather than as a green dot. */
  function caaDetail(r) {
    var caa = r.advanced && r.advanced.caa;
    if (!caa || !caa.found) return null;
    // A result carrying `found` without the parsed fields is a shape this
    // renderer has to survive rather than throw on — a saved report from an
    // earlier release, or any future caller that fills in less. A row that
    // throws here takes the whole table down with it, so the block simply has
    // nothing to say instead.
    if (!caa.parsed) return null;
    var issuers = caa.issuers || [];
    var wildcardIssuers = caa.wildcardIssuers || [];
    var unknownCritical = caa.unknownCritical || [];
    var line = function (label, node) {
      return R.el('div', null, [R.el('span', null, label + ':'), R.text(' '), node]);
    };
    var joinOrNone = function (values) {
      return values && values.length ? R.value(values.join(', ')) : R.text(t('caa.none'));
    };
    return R.frag([
      line(t('caa.issuers'), caa.issuanceBlocked
        ? R.el('strong', null, t('caa.blocksAll'))
        : joinOrNone(issuers)),
      // An absent issuewild set does not mean wildcards are unrestricted — it
      // means the issue set governs them. Rendering it as "none" would invert
      // the policy the operator published.
      line(t('caa.wildcard'), caa.wildcardBlocked
        ? R.el('strong', null, t('caa.wildcardBlocked'))
        : wildcardIssuers.length
          ? R.value(wildcardIssuers.join(', '))
          : R.text(t('caa.wildcardViaIssue'))),
      line(t('caa.iodef'), joinOrNone(caa.iodef)),
      unknownCritical.length
        ? line(t('caa.unknownCritical'), R.el('strong', null, R.value(unknownCritical.join(', '))))
        : null,
    ]);
  }

  /**
   * The DNSSEC chain, and where each part of the verdict came from.
   *
   * This block is acceptance criterion 2: every claim is attributed to the
   * resolver or to local computation, and the attribution is on screen rather
   * than only in the data model. Without it the interface would show a verdict
   * assembled from two very different kinds of evidence and let the reader
   * assume they were the same kind.
   *
   * It also states which link was checked. Showing one link of a chain without
   * naming it implies the tool walked the whole thing to the root, which it
   * does not — `OQ-SEC9-03`.
   *
   * Every collection defaults. A saved report from 0.4.0 carries only
   * `{ signed, state }`, and this has to render the state and stop rather than
   * throw: one thrown render takes down the entire table row.
   */
  function dnssecDetail(r) {
    var dnssec = r.advanced && r.advanced.dnssec;
    if (!dnssec || !dnssec.state) return null;
    var keys = dnssec.keys || [];
    var ds = dnssec.ds || [];
    var chain = dnssec.chain || [];

    var line = function (label, node) {
      return R.el('div', null, [R.el('span', null, label + ':'), R.text(' '), node]);
    };

    // Flags are named for the bit, never for the role: RFC 6840 §6.2 forbids
    // reading SEP as "this is the KSK", and RFC 5011 §2.1 needs a signature
    // check this release does not make before calling a key revoked.
    var keyLine = function (key) {
      var flags = [];
      if (key.hasSep) flags.push(t('dnssec.flag.sep'));
      if (key.hasRevokeFlag) flags.push(t('dnssec.flag.revoke'));
      return R.el('div', null, [
        R.el('code', null, R.text(String(key.keyTag))),
        R.text(' · ' + (key.algorithmName || String(key.algorithm))),
        flags.length ? R.text(' · ' + flags.join(', ')) : null,
      ]);
    };

    var dsLine = function (record) {
      return R.el('div', null, [
        R.el('code', null, R.text(String(record.keyTag))),
        R.text(' · ' + (record.digestName || String(record.digestType)) + ' — '),
        R.el('span', null, t('dnssec.match.' + record.match)),
      ]);
    };

    // The chain reads as a short list of claims, each prefixed by who is
    // making it. DS verdicts reuse the match vocabulary rather than a second
    // parallel set of strings that could describe the same fact differently.
    var chainLine = function (entry) {
      var detail = entry.detail || {};
      var claim;
      if (entry.claim === 'resolver-ad') {
        claim = t(detail.ad ? 'dnssec.claim.authenticated' : 'dnssec.claim.notAuthenticated');
      } else if (entry.claim === 'ds-confirms-dnskey') {
        claim = t('dnssec.claim.dsConfirms', String(detail.keyTag), detail.digestName || '');
      } else if (entry.claim === 'ds-no-matching-key' || entry.claim === 'ds-digest-mismatch' || entry.claim === 'ds-unverifiable') {
        claim = t('dnssec.claim.dsVerdict', String(detail.keyTag),
          t('dnssec.match.' + (detail.match || entry.claim.slice(3))));
      } else if (entry.claim === 'lookup-incomplete') {
        claim = t('dnssec.claim.lookupIncomplete', detail.query, detail.kind);
      } else {
        claim = t('dnssec.claim.' + entry.claim);
      }
      return R.el('div', null, [
        R.el('small', null, t('dnssec.source.' + entry.source)),
        R.text(' — '),
        R.el('span', null, claim),
      ]);
    };

    return R.frag([
      line(t('dnssec.status'), R.el('strong', null, t('dnssec.state.' + dnssec.state))),
      keys.length ? line(t('dnssec.keys'), R.frag(keys.map(keyLine))) : null,
      ds.length ? line(t('dnssec.ds'), R.frag(ds.map(dsLine))) : null,
      chain.length ? line(t('dnssec.chain'), R.frag(chain.map(chainLine))) : null,
    ]);
  }

  /**
   * TLSA, phrased as published rather than as active.
   *
   * The wording here is the whole point of the block. DANE protects nothing
   * unless the record is carried by a validated DNSSEC chain, and that chain
   * belongs to the MX host'"'"'s zone rather than to the audited domain — so the
   * strongest thing this may ever say is "published", with the resolver'"'"'s
   * per-host authentication reported separately from it. 0.5.0 retired the
   * `qualified` flag rather than completing it; see OQ-SEC9-07.
   */
  function tlsaDetail(r) {
    var tlsa = r.advanced && r.advanced.tlsa;
    var hosts = (tlsa && tlsa.hosts) || [];
    if (!hosts.length) return null;
    return R.frag([
      R.el('div', null, R.el('em', null, t('tlsa.published'))),
      R.frag(hosts.map(function (h) {
        var state = h.unknown ? t('tlsa.notChecked')
          : !h.present ? t('tlsa.notPublished')
            : h.authenticated ? t('tlsa.authenticated') : t('tlsa.unauthenticated');
        return R.el('div', null, [
          R.el('code', null, R.host(h.host)),
          R.text(' — '),
          R.el('span', null, state),
          h.present ? R.text(' (' + (h.records || []).length + ')') : null,
        ]);
      })),
    ]);
  }

  /**
   * The SPF record, or every conflicting record when there is more than one.
   *
   * With two `v=spf1` records the domain is in permerror and **none of them
   * applies** — RFC 7208 §4.5, and receivers do not merge them or pick the
   * stricter one. Showing only the first made the critical finding look
   * unsupported: a valid-looking record sat next to "Multiple SPF records
   * found", and the reasonable conclusion from that screen was that the tool
   * was wrong. Both records are the evidence; without them an operator cannot
   * tell which one to delete.
   *
   * The lookup meter is deliberately attached only in the single-record case.
   * It is computed from the first record, and beside a conflicting set it would
   * silently attribute one record's lookup count to all of them.
   */
  function spfDetail(r, spfMeterNode) {
    var records = r.spfRecords || (r.spfRecord ? [r.spfRecord] : []);
    if (records.length < 2) return R.frag([R.value(r.spfRecord), spfMeterNode]);
    return R.frag([
      R.el('div', { className: 'spf-conflict-note' }, t('spf.conflictingRecords', records.length)),
      R.frag(records.map(function (record) {
        return R.el('div', { className: 'spf-conflict-record' }, R.value(record));
      })),
    ]);
  }

  /**
   * The `SPF Record` column: the record, or the whole conflicting set.
   *
   * Exporting only the first match reproduced outside the UI exactly the
   * misleading presentation the panel was fixed for — a count in `Issues` names
   * how many records conflict, but the records themselves are the evidence, and
   * a consumer reading the export saw one valid-looking record beside a
   * permerror.
   *
   * Compatibility is preserved as far as it can be. The column keeps its index,
   * and a domain with one record (every domain not in permerror) produces a
   * byte-for-byte identical cell — the join is reached only when there is
   * genuinely more than one record to show. Records are joined with newlines in
   * resolver order; `toCsvText()` quotes every cell unconditionally and doubles
   * embedded quotes, so a newline inside the field is already RFC 4180 §2.6
   * transport and needs nothing here.
   *
   * `neutralizeCsvCell()` guards the leading character of the cell, which is the
   * first record's. Every line of a joined cell begins `v=spf1` by construction
   * — the set is filtered on that prefix — so no later line can smuggle in a
   * formula lead.
   */
  function spfRecordCell(r) {
    var records = r.spfRecords || (r.spfRecord ? [r.spfRecord] : []);
    if (records.length < 2) return r.spfRecord;
    return records.join('\n');
  }

  /** One cell for a domain's DKIM key sizes: a number, a range, or nothing. */
  function dkimKeyBitsCell(profile) {
    if (!profile || profile.minBits === null) return '';
    return profile.minBits === profile.maxBits
      ? String(profile.minBits)
      : profile.minBits + '-' + profile.maxBits;
  }

  function detailItem(labelText, valueNode, opts) {
    var o = opts || {};
    return R.el('div', { className: 'detail-item', style: o.style }, [
      R.el('div', { className: 'di-label', style: o.labelStyle }, labelText),
      R.el('div', { className: 'di-value', style: o.valueStyle }, valueNode),
    ]);
  }

  /**
   * Every DNS-derived string on a row, for the CSV's `record_hygiene` column
   * (OQ-SEC-11). The CSV's data columns keep the published bytes; this names
   * what those bytes contained.
   */
  function rowHygieneValues(r) {
    // Every conflicting SPF record, not just the first. The `SPF Record` cell
    // now exports the whole set, so a bidi override or zero-width character in
    // the second record would otherwise reach the export with nothing in the
    // `Record Hygiene` column naming it — the data columns carry the published
    // bytes verbatim by design, and that column is the only place the warning
    // lives. `spfRecord` stays as the fallback for a result predating the set.
    var spfValues = (r.spfRecords && r.spfRecords.length) ? r.spfRecords : [r.spfRecord];
    var values = [r.domain, r.dmarcRecord].concat(spfValues)
      .concat(r.ns || [], r.mx || [], r.verifications || []);
    (r.dkimStatus && r.dkimStatus.selectors || []).forEach(function (s) {
      values.push(s.value, s.cname, s.queryName);
    });
    if (r.advanced) {
      if (r.advanced.bimi) values.push(r.advanced.bimi.record);
      if (r.advanced.caa) values = values.concat(r.advanced.caa.records || []);
    }
    return values.filter(function (v) { return typeof v === 'string' && v; });
  }

  function appendRow(r) {
    var tbody = $('tableBody');
    var rowId = 'row-' + r.domain.replace(/\W/g, '-');
    var detailId = 'det-' + r.domain.replace(/\W/g, '-');

    if (r.error) {
      var etr = R.el('tr', { id: rowId, dataset: { domain: r.domain, overall: 'error' } }, [
        R.el('td'),
        R.el('td', { className: 'domain-cell' }, R.host(r.domain)),
        R.el('td', { colspan: '8' }, [
          badge(t(r.cancelled ? 'badge.cancelled' : 'badge.auditError'), r.cancelled ? 'muted' : 'crit'),
          R.el('span', { style: 'margin-left:8px;color:var(--ink3);font-size:12px' },
            R.sentinelText(r.message || '')),
        ]),
      ]);
      tbody.appendChild(etr);
      return;
    }

    // Unregistered domain — muted row, no detail, no metrics
    if (r.unregistered) {
      var utr = R.el('tr', {
        id: rowId,
        dataset: { domain: r.domain, overall: 'unregistered' },
        style: 'opacity:0.55',
      }, [
        R.el('td'),
        R.el('td', {
          className: 'domain-cell',
          style: 'color:var(--ink3);font-style:italic',
        }, R.host(r.domain)),
        R.el('td', {
          colspan: '8',
          dataset: { label: t('labels.status') },
          style: 'color:var(--ink3);font-size:12px;',
        }, badge(t('badge.notRegistered'), 'muted')),
      ]);
      tbody.appendChild(utr);
      return;
    }

    var spfB = badge(spfLabel(r.spfStatus), r.spfStatus.cls);
    var recognizedDkim = (r.dkimStatus.selectors || []).filter(function (s) { return !s.uncommon; });
    var uncommonDkim = (r.dkimStatus.selectors || []).filter(function (s) { return s.uncommon; });
    var dkimB = r.dkimStatus.found
      ? R.frag([
        recognizedDkim.length
          ? badge('✓ ' + recognizedDkim.map(function (s) { return s.sel; }).join(', '), 'ok')
          : null,
        uncommonDkim.map(function (s) {
          return R.frag([R.text(' '), badge(tDns('badge.dkimUncommon', s.queryName), 'warn')]);
        }),
      ])
      : r.dkimStatus.confidence === 'sampled'
        ? badge(t('badge.dkimUnverified'), 'warn')
        : badge(t('badge.notChecked'), 'muted');
    var dmarcB = badge(dmarcLabel(r.dmarcStatus), r.dmarcStatus.cls);
    var dnsB = badge(label(r.dnsProvider), r.dnsProvider === 'Cloudflare' ? 'muted' : 'info');
    var emailB = emailBadge(r.emailProvider);
    var hostB = badge(label(r.hosting), hostCls(r.hosting));

    var advCell = r.advScore
      ? advMiniDots(r.advanced)
      : R.el('span', { style: 'color:var(--ink3);font-size:11px;' }, t('labels.dash'));

    var critCount = r.issues.filter(function (i) { return i.sev === 'crit'; }).length;
    var warnCount = r.issues.filter(function (i) { return i.sev === 'warn'; }).length;
    var tipCount = (r.suggestions || []).length;
    var issueTag = R.frag([
      critCount ? R.el('span', { title: tp('rows.critical', critCount) }, '🔴') : null,
      warnCount ? R.el('span', { title: tp('rows.warning', warnCount) }, '🟡') : null,
      tipCount ? R.el('span', { title: tp('rows.suggestion', tipCount) }, '💡') : null,
    ]);

    // A grade standing on a check that could not be verified is marked in the
    // cell itself. The reason is already in the detail panel, but nobody
    // expands 200 rows to find it.
    var unproven = r.score.unproven || [];
    var gradeCls = 'score ' + r.score.cls + (unproven.length ? ' score-unproven' : '');
    var gradeTitle = unproven.length
      ? t('score.unproven', num(r.score.pts), r.score.max,
        unproven.map(function (k) { return t('score.pillar.' + k); }).join(', '))
      : t('score.outOf', num(r.score.pts), r.score.max);

    var hasCrit = r.issues.some(function (i) { return i.sev === 'crit'; });
    var hasWarn = r.issues.some(function (i) { return i.sev === 'warn'; });

    var tr = R.el('tr', {
      id: rowId,
      dataset: {
        domain: r.domain,
        dmarc: r.dmarcStatus.status === 'unknown' ? 'unknown'
          : r.dmarcStatus.status !== 'missing' ? 'yes' : 'no',
        dkim: r.dkimStatus.found ? 'yes'
          : (r.dkimStatus.confidence === 'sampled' || r.dkimStatus.confidence === 'not-checked') ? 'unknown' : 'no',
        spf: r.spfStatus.status !== 'missing' ? 'yes' : 'no',
        email: r.emailProvider !== '@none' && r.emailProvider !== '@null-mx' ? 'yes' : 'no',
        bimi: r.advanced && r.advanced.bimi && r.advanced.bimi.present ? 'yes' : 'no',
        caa: r.advanced && r.advanced.caa && r.advanced.caa.found ? 'yes' : 'no',
        dnssec: r.advanced && r.advanced.dnssec && r.advanced.dnssec.signed ? 'yes' : 'no',
        grade: r.score.grade,
        unproven: unproven.length ? 'yes' : 'no',
        overall: hasCrit ? 'crit' : hasWarn ? 'warn' : 'ok',
      },
    }, [
      R.el('td', null, [
        R.el('button', {
          className: 'expand-toggle',
          type: 'button',
          dataset: { detailId: detailId },
        }, '▶'),
      ]),
      R.el('td', { className: 'domain-cell' }, [
        R.host(r.domain),
        R.el('span', { style: 'margin-left:5px;font-size:11px;' }, issueTag),
      ]),
      R.el('td', { dataset: { label: t('th.grade') }, style: 'text-align:center' }, [
        R.el('span', { className: gradeCls, title: gradeTitle }, [
          R.text(r.score.grade),
          unproven.length ? R.el('span', { className: 'score-star' }, '*') : null,
        ]),
      ]),
      R.el('td', { dataset: { label: t('th.dns') } }, dnsB),
      R.el('td', { dataset: { label: t('th.email') } }, emailB),
      R.el('td', { dataset: { label: t('th.spf') } }, spfB),
      R.el('td', { dataset: { label: t('th.dkim') } }, dkimB),
      R.el('td', { dataset: { label: t('th.dmarc') } }, dmarcB),
      R.el('td', { dataset: { label: t('th.advanced') } }, advCell),
      R.el('td', { dataset: { label: t('th.hosting') } }, hostB),
    ]);
    tbody.appendChild(tr);

    // ── Detail row ──
    var dkimDetails = (r.dkimStatus.selectors || []).map(function (s) {
      return R.el('div', { className: 'dkim-record' }, [
        R.el('strong', null, s.uncommon
          ? tDns('dkim.uncommon', s.queryName)
          : R.sentinelText(s.sel + ' — ' + s.queryName)),
        s.viaSpf ? R.frag([R.text(' '), R.el('span', { className: 'dkim-via-spf' }, tDns('dkim.viaSpf', s.viaSpf))]) : null,
        s.cname
          ? R.el('div', null, [
            R.el('span', null, t('dkim.cnameTarget') + ':'),
            R.text(' '),
            R.el('code', null, R.host(s.cname)),
          ])
          : null,
        R.el('div', null, [
          R.el('span', null, t('dkim.txtRecord') + ':'),
          R.text(' '),
          R.el('code', { className: 'dkim-record-data' }, R.value(s.value)),
        ]),
        dkimKeyLine(s.key),
      ]);
    });
    (r.dkimStatus.missingSelectors || []).forEach(function (s) {
      dkimDetails.push(R.el('div', { className: 'dkim-record dkim-record-missing' }, [
        R.el('strong', null, tDns('dkim.noDomainKeyFound', s.queryName)),
        s.cname
          ? R.el('div', null, [
            R.el('span', null, t('dkim.cnameTarget') + ':'),
            R.text(' '),
            R.el('code', null, R.host(s.cname)),
          ])
          : null,
      ]));
    });
    if (!dkimDetails.length && r.dkimStatus.note) {
      dkimDetails.push(R.text(t(
        'dkim.' + r.dkimStatus.note,
        (r.dkimStatus.testedSelectors || []).length - (r.dkimStatus.failedSelectors || []).length,
        (r.dkimStatus.failedSelectors || []).length
      )));
    }

    var spfMeterNode = (r.advanced && r.advanced.spfLookups && r.spfRecord)
      ? spfMeter(r.advanced.spfLookups) : null;

    var issueNodes = r.issues.map(function (i) {
      var what = tRaw('issue.' + i.key + '.what');
      var fix = tRaw('issue.' + i.key + '.fix');
      var fixCode = tRaw('issue.' + i.key + '.fixCode');
      var showMe = what
        ? R.el('div', { className: 'showme-wrap' }, [
          R.el('button', { className: 'showme-btn', type: 'button' }, t('showme.open')),
          R.el('div', { className: 'showme-content' }, [
            R.el('div', { className: 'showme-lbl' }, t('showme.whatItIs')),
            R.el('div', { className: 'showme-text' }, R.rich(what)),
            R.el('div', { className: 'showme-lbl' }, t('showme.whatItNeeds')),
            R.el('div', { className: 'showme-text' }, [
              R.rich(fix || ''),
              fixCode ? R.el('div', { className: 'showme-code' }, fixCode) : null,
            ]),
          ]),
        ])
        : null;
      return R.el('div', { className: 'issue' }, [
        R.el('span', { className: 'icon' }, i.sev === 'crit' ? '🔴' : i.sev === 'warn' ? '⚠️' : 'ℹ️'),
        R.el('div', { className: 'issue-body' }, [
          R.el('span', { className: 'msg' }, issueMessage(i)),
          showMe,
        ]),
      ]);
    });

    var suggestNodes = (r.suggestions && r.suggestions.length)
      ? R.frag([
        R.el('hr', { className: 'suggestions-sep' }),
        R.el('div', { className: 'issues-section-label' }, t('labels.suggestions')),
        r.suggestions.map(function (s) {
          var guide = s.guide && tRaw('learnMore.' + s.guide);
          return R.el('div', { className: 'issue tip' }, [
            R.el('span', { className: 'icon' }, '💡'),
            R.el('div', { className: 'issue-body' }, [
              R.el('span', { className: 'msg' }, t('suggestion.' + s.key)),
              guide
                ? R.el('button', {
                  className: 'learnmore-btn',
                  type: 'button',
                  dataset: { guide: s.guide },
                }, t('btn.learnMore'))
                : null,
            ]),
          ]);
        }),
      ])
      : null;

    var wildcardNote = null;
    if (r.wildcardDkim || r.wildcardApex) {
      // The two depths get different colours because they mean different
      // things: one degrades DKIM discovery, the other is usually a deliberate
      // anti-spoofing measure and costs nothing.
      var colour = r.wildcardDkim ? 'var(--warn)' : 'var(--info)';
      var suffix = r.wildcardDkim ? 'Dkim' : 'Apex';
      wildcardNote = detailItem(
        t('labels.wildcard' + suffix + 'Title'),
        R.text(t('labels.wildcard' + suffix + 'Text')),
        { style: 'grid-column:1/-1', labelStyle: 'color:' + colour, valueStyle: 'color:' + colour }
      );
    }

    var hygieneNote = R.hygieneNote(rowHygieneValues(r));

    var dtr = R.el('tr', { id: detailId, className: 'detail-row' }, [
      R.el('td', { colspan: '11' }, [
        R.el('div', { className: 'detail-grid' }, [
          // Separators match 0.2.2 exactly: this release changes how values are
          // BUILT, not how they look. Only the 20-record cap and the sentinel
          // substitution are new.
          detailItem(t('labels.nameservers'), R.list(r.ns, { sep: ', ', none: t('labels.na') })),
          detailItem(t('labels.mx'), mxDetail(r)),
          detailItem(
            t('labels.spf') + (spfMeterNode ? ' · ' + t('labels.spfLookups') : ''),
            spfDetail(r, spfMeterNode)
          ),
          detailItem(t('labels.dmarc'), R.frag([
            R.value(r.dmarcRecord),
            r.dmarcAtDomain && r.dmarcAtDomain !== r.domain
              ? R.frag([R.el('br'), R.el('small', null, tDns('dmarc.inheritedFrom', r.dmarcAtDomain))])
              : null,
            dmarcDiscoveryNode(r),
          ])),
          detailItem(t('labels.dkim'), R.frag(dkimDetails)),
          caaDetail(r) ? detailItem(t('labels.caa'), caaDetail(r)) : null,
          dnssecDetail(r) ? detailItem(t('labels.dnssec'), dnssecDetail(r)) : null,
          tlsaDetail(r) ? detailItem(t('labels.tlsa'), tlsaDetail(r)) : null,
          detailItem(t('labels.verifications'), r.verifications.length
            ? R.list(r.verifications, { sep: 'br' })
            : R.text(t('labels.dash'))),
          wildcardNote,
        ]),
        hygieneNote,
        scoreBlock(r.score),
        r.advanced ? advFullDots(r.advanced) : null,
        (issueNodes.length || suggestNodes)
          ? R.el('div', { className: 'issues-block' }, [
            issueNodes.length
              ? R.frag([
                R.el('div', { className: 'issues-section-label' }, t('labels.issues')),
                issueNodes,
              ])
              : null,
            suggestNodes,
          ])
          : null,
      ]),
    ]);
    tbody.appendChild(dtr);
  }

  function toggleDetail(id, btn) {
    var el = $(id);
    btn.textContent = el.classList.toggle('open') ? '▼' : '▶';
  }

  function toggleShowMe(btn) {
    var content = btn.nextElementSibling;
    var open = content.style.display !== 'none' && content.style.display !== '';
    content.style.display = open ? 'none' : 'block';
    btn.textContent = open
      ? (btn.dataset.openLabel || t('showme.open'))
      : (btn.dataset.closeLabel || t('showme.close'));
  }

  // The disclosure control for a truncated value (spec §4). Display caps never
  // reach the data: the remainder was rendered into the DOM all along, just
  // hidden, and both exports carry the full value regardless.
  function toggleValueRest(btn) {
    var rest = btn.parentNode.querySelector('.rv-rest');
    if (!rest) return;
    var open = rest.style.display !== 'none';
    rest.style.display = open ? 'none' : 'inline';
    // The count comes from the value as published, recorded when the control
    // was built. Recomputing it from `rest.textContent` would count sentinel
    // markers instead — ‹RLO› is five characters standing for one — so the
    // number would change every time the reader collapsed the value.
    btn.textContent = open
      ? t('render.showMore', btn.dataset.rvCount || '0')
      : t('render.showLess');
  }

  /* ── Summary, filter, sort ──────────────────────────────────────────── */

  function tile(n, lbl, cls, denom) {
    var numNode = (denom !== undefined && denom !== null && denom !== n)
      ? R.frag([
        R.text(String(n)),
        R.el('small', { style: 'font-size:17px;font-weight:500;opacity:.5' }, ' (' + denom + ')'),
      ])
      : R.text(String(n));
    return R.el('div', { className: 'stat-tile' }, [
      R.el('div', { className: 'num ' + cls }, numNode),
      R.el('div', { className: 'lbl' }, lbl),
    ]);
  }

  function renderSummary() {
    var submitted = results.filter(function (r) { return !r.error; });
    var all = submitted.filter(function (r) { return !r.unregistered; });
    var reg = all.length;
    var tot = submitted.length;
    function count(fn) { return all.filter(fn).length; }

    var wildcardCount = count(function (r) { return r.wildcardDkim; });
    $('statsGrid').replaceChildren(R.frag([
      tile(reg, t('stat.domains'), 'c-muted', reg < tot ? tot : null),
      tile(count(function (r) { return r.emailProvider !== '@none' && r.emailProvider !== '@null-mx'; }), t('stat.haveEmail'), 'c-info', reg),
      tile(count(function (r) { return r.spfStatus && r.spfStatus.status !== 'missing'; }), 'SPF', 'c-ok', reg),
      tile(count(function (r) { return r.dkimStatus && r.dkimStatus.found; }), 'DKIM', 'c-ok', reg),
      // An unverified DMARC control is counted as neither present nor absent —
      // the tile states what was proven, and this one was not.
      tile(count(function (r) {
        return r.dmarcStatus && r.dmarcStatus.status !== 'missing' && r.dmarcStatus.status !== 'unknown';
      }), 'DMARC', 'c-ok', reg),
      tile(count(function (r) { return r.advanced && r.advanced.bimi && r.advanced.bimi.present; }), 'BIMI', 'c-tip', reg),
      tile(count(function (r) { return r.advanced && r.advanced.mtaSts && r.advanced.mtaSts.present; }), 'MTA-STS', 'c-tip', reg),
      tile(count(function (r) { return r.advanced && r.advanced.tlsRpt && r.advanced.tlsRpt.present; }), 'TLS-RPT', 'c-tip', reg),
      tile(count(function (r) { return r.advanced && r.advanced.caa && r.advanced.caa.found; }), 'CAA', 'c-tip', reg),
      tile(count(function (r) { return r.advanced && r.advanced.dnssec && r.advanced.dnssec.signed; }), 'DNSSEC', 'c-tip', reg),
      wildcardCount ? tile(wildcardCount, t('stat.wildcardDkim'), 'c-warn') : null,
    ]));
  }

  function filterTable() {
    var search = $('searchBox').value.toLowerCase();
    var filter = $('filterStatus').value;
    var visible = 0;

    document.querySelectorAll('#tableBody tr:not(.detail-row)').forEach(function (tr) {
      var domain = (tr.dataset.domain || '').toLowerCase();
      var matchesSearch = !search || domain.includes(search);
      var matchesFilter = true;
      if (filter === 'warn') matchesFilter = tr.dataset.overall === 'warn';
      else if (filter === 'crit') matchesFilter = tr.dataset.overall === 'crit';
      else if (filter === 'no-email') matchesFilter = tr.dataset.email === 'no';
      else if (filter === 'no-dmarc') matchesFilter = tr.dataset.dmarc === 'no';
      else if (filter === 'no-dkim') matchesFilter = tr.dataset.dkim === 'no';
      else if (filter === 'no-spf') matchesFilter = tr.dataset.spf === 'no';
      else if (filter === 'has-bimi') matchesFilter = tr.dataset.bimi === 'yes';
      else if (filter === 'no-caa') matchesFilter = tr.dataset.caa === 'no';
      else if (filter === 'no-dnssec') matchesFilter = tr.dataset.dnssec === 'no';

      var show = matchesSearch && matchesFilter;
      tr.classList.toggle('hidden', !show);
      var det = $('det-' + tr.id.replace('row-', ''));
      if (det) det.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    $('emptyState').style.display = visible === 0 ? 'block' : 'none';
    var total = document.querySelectorAll('#tableBody tr:not(.detail-row)').length;
    $('rowCount').textContent = visible < total
      ? t('rows.showing', visible, total)
      : tp('rows.count', total);
  }

  function updateRowCount() {
    var rows = document.querySelectorAll('#tableBody tr:not(.detail-row)').length;
    $('rowCount').textContent = tp('rows.count', rows);
  }

  function sortTable(col) {
    if (sortCol === col) sortDir *= -1; else { sortCol = col; sortDir = 1; }
    document.querySelectorAll('thead th').forEach(function (th) {
      th.classList.remove('sorted-asc', 'sorted-desc');
    });
    var hIdx = { domain: 1, grade: 2, dns: 3, email: 4, spf: 5, dkim: 6, dmarc: 7, adv: 8, hosting: 9 };
    var idx = hIdx[col];
    if (idx) document.querySelectorAll('thead th')[idx].classList.add(sortDir === 1 ? 'sorted-asc' : 'sorted-desc');

    var GRADE_ORDER = { 'A++': 0, 'A+': 1, 'A': 2, 'B': 3, 'C': 4, 'D': 5, 'F': 6, '': 7 };
    var tbody = $('tableBody');
    var collator = new Intl.Collator(i18n.lang);

    Array.from(tbody.querySelectorAll('tr:not(.detail-row)')).sort(function (a, b) {
      if (col === 'grade') {
        // Sort on the stored grade, not the rendered cell — locale-independent.
        return sortDir * ((GRADE_ORDER[a.dataset.grade] ?? 7) - (GRADE_ORDER[b.dataset.grade] ?? 7));
      }
      var av = col === 'domain' ? a.dataset.domain : (a.querySelectorAll('td')[idx]?.textContent?.trim() || '');
      var bv = col === 'domain' ? b.dataset.domain : (b.querySelectorAll('td')[idx]?.textContent?.trim() || '');
      return sortDir * collator.compare(av, bv);
    }).forEach(function (tr) {
      var det = $('det-' + tr.id.replace('row-', ''));
      tbody.appendChild(tr);
      if (det) tbody.appendChild(det);
    });
  }

  /* ── Audit run ──────────────────────────────────────────────────────── */

  async function startAudit() {
    if (auditController) return;
    var domains = parseDomains($('domainInput').value);
    if (!domains.length) { showToast(t('toast.noDomains')); return; }
    if (domains.length > MAX_DOMAINS) { showToast(t('toast.tooMany')); return; }
    if ($('optDKIM').checked && $('optDKIMComprehensive').checked && domains.length > MAX_COMPREHENSIVE_DKIM_DOMAINS) {
      showToast(t('toast.tooManyComprehensiveDkim', MAX_COMPREHENSIVE_DKIM_DOMAINS));
      return;
    }

    // Turn the deep checks off for a large run rather than refusing the run —
    // unlike the comprehensive DKIM cap above, nothing here is impossible at
    // scale, it is only expensive. The notice stays on screen because the user
    // is about to watch a checkbox they ticked come back clear, and an
    // unexplained change to what the tool measured is worse than the cost it
    // avoids.
    applyDeepCheckLimit(domains.length);

    // Pre-flight: verify we can reach the resolver before burning time on
    // queries that will all come back empty.
    var online = await DnsAudit.checkConnectivity();
    if (!online) {
      $('netBanner').style.display = 'block';
      $('netBanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    $('netBanner').style.display = 'none';

    var opts = {
      dkim: $('optDKIM').checked,
      dkimComprehensive: $('optDKIMComprehensive').checked,
      www: $('optWWW').checked,
      advanced: true,
      wildcard: $('optWildcard').checked,
      deepChecks: $('optDeepChecks').checked,
      selectors: $('dkimSelectors').value.split(/[\s,]+/).map(function (s) { return s.trim().toLowerCase(); })
        .filter(function (s) { return /^[a-z0-9][a-z0-9_-]{0,62}$/.test(s); }),
    };
    auditController = new AbortController();
    opts.signal = auditController.signal;

    results = new Array(domains.length);
    $('auditBtn').disabled = true;
    $('cancelBtn').style.display = '';
    $('auditBtn').replaceChildren(R.frag([
      R.el('span', { className: 'spinner' }),
      R.text(' ' + t('btn.auditRunning')),
    ]));
    ['clearBtn', 'exportCsvBtn', 'exportHtmlBtn'].forEach(function (id) { $(id).style.display = 'none'; });
    ['summarySection', 'resultsSection', 'emptyState'].forEach(function (id) { $(id).style.display = 'none'; });
    $('resultsToolbar').style.display = 'none';
    $('progressSection').style.display = 'block';
    $('tableBody').replaceChildren();
    $('progressLog').replaceChildren();
    $('progressFill').style.width = '0%';
    $('progressCounts').textContent = '0 / ' + domains.length;

    var done = 0;
    var queue = domains.map(function (domain, index) { return { domain: domain, index: index }; });
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, domains.length) }, async function () {
      while (queue.length) {
        var item = queue.shift();
        var domain = item.domain;
        log(t('progress.querying', domain));
        try {
          var result = await DnsAudit.analyzeDomain(domain, opts);
          results[item.index] = result;
        } catch (e) {
          var cancelled = e && (e.name === 'AbortError' || e.kind === 'cancelled');
          results[item.index] = { domain: domain, error: true, cancelled: cancelled, message: cancelled ? t('progress.cancelled') : e.message };
          log(cancelled ? t('progress.cancelledDomain', domain) : t('progress.error', domain, e.message), cancelled ? 'info' : 'err');
        }
        done++;
        $('progressFill').style.width = Math.round((done / domains.length) * 100) + '%';
        $('progressCounts').textContent = done + ' / ' + domains.length;
      }
    }));

    auditController = null;
    $('auditBtn').disabled = false;
    $('cancelBtn').style.display = 'none';
    $('auditBtn').textContent = t('btn.runAudit');
    ['clearBtn', 'exportCsvBtn', 'exportHtmlBtn'].forEach(function (id) { $(id).style.display = ''; });
    setTimeout(function () { $('progressSection').style.display = 'none'; }, 1200);

    $('tableBody').replaceChildren();
    results.filter(Boolean).forEach(appendRow);
    renderSummary();
    $('summarySection').style.display = 'block';
    $('resultsSection').style.display = 'block';
    $('resultsToolbar').style.display = 'flex';
    updateRowCount();
    var completed = results.filter(function (r) { return r && !r.error; }).length;
    showToast(completed ? tp('toast.auditDone', completed) : t('toast.auditCancelled'));
  }

  function cancelAudit() {
    if (auditController) auditController.abort();
  }

  /* ── Export ─────────────────────────────────────────────────────────── */

  /**
   * The exported artifacts, Task 5.5. `src/ui/report.js` owns them now.
   *
   * `getResults` is an ACCESSOR rather than the array: `results` is REPLACED
   * on each run, so a captured reference would export the previous one. The
   * five row formatters are passed because they belong to the table renderer,
   * which is still in this file; §12 gives `src/ui/` an edge to `ui/` siblings
   * and `i18n/` only, so everything else here is supplied rather than reached
   * for.
   */
  const { exportCSV, exportHTML, buildCsvRows, toCsvText, neutralizeCsvCell, buildReportDocument } =
    createReport({
      document, platform, i18n, renderer: R,
      englishBundle: global.__I18N_EN__,
      label, issueMessage, spfRecordCell, dkimKeyBitsCell, rowHygieneValues,
      showToast, $, getResults: function () { return results; },
    });

  /* ── Input helpers ──────────────────────────────────────────────────── */

  function loadFile(e) {
    var f = e.target.files[0];
    if (!f) return;
    if (f.size > MAX_UPLOAD_BYTES) { showToast(t('toast.fileTooLarge')); e.target.value = ''; return; }
    var reader = new FileReader();
    reader.onload = function (ev) {
      $('domainInput').value = ev.target.result;
      showToast(t('toast.fileLoaded', f.name));
    };
    reader.readAsText(f);
  }

  function loadExample() {
    $('domainInput').value = [
      'google.com', 'microsoft.com', 'apple.com', 'github.com', 'cloudflare.com',
      'netflix.com', 'shopify.com', 'slack.com', 'notion.so', 'figma.com',
    ].join('\n');
    showToast(t('toast.examplesLoaded'));
  }

  function clearAll() {
    results = [];
    $('domainInput').value = '';
    $('tableBody').replaceChildren();
    ['summarySection', 'resultsSection', 'emptyState'].forEach(function (id) { $(id).style.display = 'none'; });
    $('resultsToolbar').style.display = 'none';
    ['clearBtn', 'exportCsvBtn', 'exportHtmlBtn'].forEach(function (id) { $(id).style.display = 'none'; });
    $('searchBox').value = '';
  }

  function showHelp() {
    var el = $('helpBox');
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  }

  function setLang(code) {
    i18n.setLang(code).then(function (ok) {
      if (!ok) {
        showToast(t('toast.langFailed'));
        var sel = $('langSelect');
        if (sel) sel.value = i18n.lang;
      }
    });
  }

  /* ── Boot ───────────────────────────────────────────────────────────── */

  // Re-render results in the new language whenever it changes.
  i18n.onChange(function () {
    if (!results.length) return;
    $('tableBody').replaceChildren();
    results.filter(function (r) { return !r.error; }).forEach(appendRow);
    renderSummary();
    filterTable();
    showToast(t('toast.langChanged'));
  });

  document.addEventListener('DOMContentLoaded', function () {
    $('auditBtn').addEventListener('click', startAudit);
    $('cancelBtn').addEventListener('click', cancelAudit);
    $('fileInput').addEventListener('change', loadFile);
    $('optDeepChecks').addEventListener('change', function () { rememberDeepCheckChoice(this.checked); });
    $('examplesBtn').addEventListener('click', loadExample);
    $('clearBtn').addEventListener('click', clearAll);
    $('helpBtn').addEventListener('click', showHelp);
    $('exportCsvBtn').addEventListener('click', exportCSV);
    $('exportHtmlBtn').addEventListener('click', exportHTML);
    $('langSelect').addEventListener('change', function () { setLang(this.value); });
    $('searchBox').addEventListener('input', filterTable);
    $('filterStatus').addEventListener('change', filterTable);
    document.querySelectorAll('[data-sort]').forEach(function (el) {
      el.addEventListener('click', function () { sortTable(el.dataset.sort); });
    });
    $('tableBody').addEventListener('click', function (event) {
      var expand = event.target.closest('.expand-toggle');
      if (expand) { toggleDetail(expand.dataset.detailId, expand); return; }
      var show = event.target.closest('.showme-btn');
      if (show) { toggleShowMe(show); return; }
      var more = event.target.closest('.rv-more');
      if (more) { toggleValueRest(more); return; }
      var learn = event.target.closest('.learnmore-btn');
      if (learn) openLearnMore(learn.dataset.guide);
    });
    runtime.mount().then(function () {
      // Surface the sandbox banner immediately if DoH is unreachable.
      DnsAudit.checkConnectivity().then(function (ok) {
        if (!ok) $('netBanner').style.display = 'block';
      });
    });
  });

  /* ── The fourteen function globals are GONE, as of Task 2.8 ────────────
   *
   * `startAudit`, `cancelAudit`, `clearAll`, `exportCSV`, `exportHTML`,
   * `filterTable`, `loadExample`, `loadFile`, `openLearnMore`, `setLang`,
   * `showHelp`, `sortTable`, `toggleDetail` and `toggleShowMe` used to be
   * assigned here, under a comment that said "Exposed for the inline onclick
   * handlers in index.html". That comment had been wrong since 0.2.3: the CSP
   * carries no 'unsafe-inline', so `index.html` cannot have an inline handler
   * and does not have one. Every control is wired by `addEventListener` in the
   * `DOMContentLoaded` listener above, which is the only consumer these
   * functions ever had.
   *
   * Their removal is the second of the release's two authorized compatibility
   * deltas — spec §10, and `tests/fixtures/equivalence/compatibility-deltas.json`
   * records it. It is a DECISION, not a discovery: the search proved no
   * repository consumer, and it cannot prove no consumer. A static site can be
   * driven from a console, an extension or an embedding page absent from this
   * checkout, and this project publishes no documented JavaScript API to say
   * otherwise. `analyzeDomain` and `checkConnectivity` are the supported
   * surface from 0.6.0 onward.
   *
   * Everything below this line is still here on purpose. `__APP_TEST__` and the
   * i18n/renderer wiring names are marked adapters with repository consumers
   * and no ESM owner yet; they retire on their owners' schedule, which the
   * manifest's adapterRetirement block records.
   */

  // Exposed for tools/render.test.mjs and tools/export.test.mjs, which drive
  // these directly rather than through a live page.
  global.__APP_TEST__ = {
    appendRow: appendRow,
    buildLearnMorePage: buildLearnMorePage,
    buildReportDocument: buildReportDocument,
    buildCsvRows: buildCsvRows,
    toCsvText: toCsvText,
    neutralizeCsvCell: neutralizeCsvCell,
    issueMessage: issueMessage,
    tDns: tDns,
    rowHygieneValues: rowHygieneValues,
    scoreBlock: scoreBlock,
    advMiniDots: advMiniDots,
    advFullDots: advFullDots,
    spfMeter: spfMeter,
    tile: tile,
    badge: badge,
    detailItem: detailItem,
    log: log,
    applyDeepCheckLimit: applyDeepCheckLimit,
    rememberDeepCheckChoice: rememberDeepCheckChoice,
    // Models the one thing that clears this memory in production: a reload.
    // There is no production reset because a fresh page already is one.
    resetDeepCheckMemory: function () { deepChecksReEnabled = false; },
    dkimKeyLine: dkimKeyLine,
    mxDetail: mxDetail,
    caaDetail: caaDetail,
    dnssecDetail: dnssecDetail,
    dnssecDot: dnssecDot,
    tlsaDetail: tlsaDetail,
    dkimKeyBitsCell: dkimKeyBitsCell,
    spfDetail: spfDetail,
    spfRecordCell: spfRecordCell,
    MAX_DEEP_CHECK_DOMAINS: MAX_DEEP_CHECK_DOMAINS,
  };

/**
 * The supported facade, and the only supported browser API from 0.6.0 onward.
 * Spec §10, stage 3.
 *
 * Two members, from a 95-member surface — the only two the body above calls.
 * These are not merely the module's exports: esbuild assigns the ENTRY POINT'S
 * EXPORTS to `globalName`, so this list IS `window.DnsAudit`. A third export
 * added here would widen the supported API of the shipped application.
 *
 * That is why it is checked in rather than inferred. `src/facade.expected.json`
 * names the members, `tests/build/parity.test.mjs` asserts it against BOTH this
 * module's exports and the built bundle's global — exactly, in both directions
 * — and `tests/contract/state-matrix.test.mjs` reads the same file, so the
 * source contract and the artifact contract cannot drift apart.
 */
export const analyzeDomain = runtime.analyzeDomain;
export const checkConnectivity = runtime.checkConnectivity;
