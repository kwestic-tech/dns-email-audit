/* ──────────────────────────────────────────────────────────────────────────
   DNS querying and analysis.

   This file is deliberately free of user-facing English. Anything a person
   reads is represented here as a stable identifier — '@none', 'spf-missing',
   'noteWildcard' — and turned into words by js/app.js via the i18n layer.
   That keeps the audit logic and the translations independent: a translator
   never has to touch this file, and a bug fix here never breaks a locale.

   Tokens that stand in for translatable text are prefixed with '@'.
   Provider names that are proper nouns ('Cloudflare', 'Google Workspace')
   are passed through untranslated by design.
   ────────────────────────────────────────────────────────────────────────── */

(function (global) {
  'use strict';

  var DOH = 'https://cloudflare-dns.com/dns-query';
  var DKIM_SELECTORS = ['google', 'default', 'mail', 's1', 's2', 'selector1', 'selector2', 'dkim', 'sig1', 'odoo'];
  var DKIM_CATALOG = global.__DKIM_SELECTOR_CATALOG__ || { providers: {}, generic: [], temporal: [], prefixes: [], excluded: [] };
  var DKIM_SCAN_BATCH_SIZE = 24;
  var DKIM_PROVIDER_CATALOG_KEYS = {
    'Google Workspace': 'Google Workspace / Gmail',
    'Apple iCloud': 'Apple iCloud Mail',
    'Microsoft 365': 'Microsoft 365 / Exchange Online',
    'Zoho Mail': 'Zoho Mail & Zoho Suite',
    'Fastmail': 'Fastmail',
    'Proton Mail': 'Proton Mail',
    'Mailgun': 'Mailgun',
    'SendGrid': 'Twilio SendGrid',
    'Symantec/MessageLabs': 'Broadcom / Symantec / MessageLabs',
  };
  // Services a domain names directly in its own SPF record. An `include:` is
  // the domain stating that this vendor sends mail for it — the same claim MX
  // makes about the inbound provider, and just as good a reason to probe that
  // vendor's DKIM selectors. Without this, a Google-Workspace-on-MX domain
  // that runs support through Zendesk never gets `zendesk1`/`zendesk2` tried
  // outside a comprehensive scan, even though both are published.
  //
  // Each hostname below is the vendor's documented SPF include target, and was
  // confirmed to serve a live `v=spf1` record when this table was written.
  // Keys must match DKIM_CATALOG.providers exactly.
  var DKIM_SPF_INCLUDE_PROVIDERS = [
    { pattern: /(^|\.)mail\.zendesk\.com$/i, catalogKey: 'Zendesk' },
    { pattern: /(^|\.)sendgrid\.net$/i, catalogKey: 'Twilio SendGrid' },
    { pattern: /(^|\.)mailgun\.org$/i, catalogKey: 'Mailgun' },
    { pattern: /(^|\.)servers\.mcsv\.net$/i, catalogKey: 'Mailchimp / Mandrill' },
    { pattern: /(^|\.)mandrillapp\.com$/i, catalogKey: 'Mailchimp / Mandrill' },
    { pattern: /(^|\.)spf\.mtasv\.net$/i, catalogKey: 'Postmark (ActiveCampaign)' },
    { pattern: /(^|\.)cust-spf\.exacttarget\.com$/i, catalogKey: 'Salesforce / Marketing Cloud' },
    { pattern: /(^|\.)hubspot(email)?\.(com|net)$/i, catalogKey: 'HubSpot' },
    { pattern: /(^|\.)atlassian\.net$/i, catalogKey: 'Atlassian Jira / Service Desk' },
    { pattern: /(^|\.)freshdesk\.com$/i, catalogKey: 'Freshdesk / Freshworks' },
  ];
  var RECOGNIZED_DKIM_SELECTORS = new Set(
    DKIM_SELECTORS.concat(
      Object.values(DKIM_CATALOG.providers).flat(),
      DKIM_CATALOG.generic || [],
      DKIM_CATALOG.temporal || []
    )
  );
  var DOH_TIMEOUT_MS = 8000;
  var DOH_RETRIES = 1;
  var MAX_DOH_CONCURRENCY = 16;
  // Bounded, least-recently-used. The Map previously grew for the lifetime of
  // the page, so a long session auditing several batches retained every answer
  // it had ever seen. 4096 comfortably holds a full 200-domain run (including
  // comprehensive DKIM) while staying a fixed ceiling rather than a leak.
  var MAX_DOH_CACHE_ENTRIES = 4096;
  var dohCache = new Map();

  function dohCacheGet(key) {
    if (!dohCache.has(key)) return undefined;
    // Re-insert to move the entry to the most-recently-used end. Map preserves
    // insertion order, so the oldest key is always the first one.
    var value = dohCache.get(key);
    dohCache.delete(key);
    dohCache.set(key, value);
    return value;
  }

  function dohCacheSet(key, value) {
    if (dohCache.has(key)) dohCache.delete(key);
    dohCache.set(key, value);
    while (dohCache.size > MAX_DOH_CACHE_ENTRIES) {
      dohCache.delete(dohCache.keys().next().value);
    }
  }
  var activeDoh = 0;
  var dohWaiters = [];

  /* ── DNS-over-HTTPS core ────────────────────────────────────────────── */

  function dnsTypeNum(type) {
    return { NS: 2, A: 1, AAAA: 28, MX: 15, TXT: 16, CNAME: 5, CAA: 257 }[type] ?? 16;
  }

  function dnsError(kind, name, type, detail) {
    var e = new Error(kind + ' while querying ' + name + ' ' + type + (detail ? ': ' + detail : ''));
    e.name = kind === 'cancelled' ? 'AbortError' : 'DnsQueryError';
    e.kind = kind;
    e.queryName = name;
    e.queryType = type;
    return e;
  }

  async function acquireDohSlot(signal) {
    if (signal && signal.aborted) throw dnsError('cancelled', '', '');
    if (activeDoh < MAX_DOH_CONCURRENCY) { activeDoh++; return; }
    await new Promise(function (resolve, reject) {
      var waiter = { resolve: resolve, reject: reject, signal: signal, onAbort: null };
      if (signal) {
        waiter.onAbort = function () {
          var idx = dohWaiters.indexOf(waiter);
          if (idx !== -1) dohWaiters.splice(idx, 1);
          reject(dnsError('cancelled', '', ''));
        };
        signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      dohWaiters.push(waiter);
    });
    activeDoh++;
  }

  function releaseDohSlot() {
    activeDoh = Math.max(0, activeDoh - 1);
    var waiter = dohWaiters.shift();
    if (!waiter) return;
    if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
    waiter.resolve();
  }

  function responseKind(status, answerCount) {
    if (status === 0) return answerCount ? 'success' : 'nodata';
    if (status === 3) return 'nxdomain';
    if (status === 2) return 'servfail';
    if (status === 5) return 'refused';
    return 'dns-error';
  }

  async function fetchDohOnce(name, type, opts) {
    await acquireDohSlot(opts.signal);
    var controller = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; controller.abort(); }, opts.timeoutMs || DOH_TIMEOUT_MS);
    var forwardAbort = function () { controller.abort(); };
    if (opts.signal) opts.signal.addEventListener('abort', forwardAbort, { once: true });
    try {
      const params = new URLSearchParams({ name: name, type: String(dnsTypeNum(type)) });
      if (opts.dnssec) params.set('do', '1');
      if (opts.checkingDisabled) params.set('cd', '1');
      const r = await fetch(`${DOH}?${params}`, {
        headers: { Accept: 'application/dns-json' }, signal: controller.signal,
      });
      if (!r.ok) return { answers: [], ad: false, status: -1, kind: 'http-error', httpStatus: r.status };
      const j = await r.json();
      const answers = Array.isArray(j.Answer) ? j.Answer : [];
      const status = Number.isInteger(j.Status) ? j.Status : -1;
      return { answers: answers, ad: j.AD === true, status: status, kind: responseKind(status, answers.length) };
    } catch (e) {
      if (opts.signal && opts.signal.aborted) return { answers: [], ad: false, status: -1, kind: 'cancelled' };
      return { answers: [], ad: false, status: -1, kind: timedOut ? 'timeout' : 'network-error' };
    } finally {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener('abort', forwardAbort);
      releaseDohSlot();
    }
  }

  async function dohFetch(name, type, opts = {}) {
    const normalizedName = String(name || '').toLowerCase().replace(/\.$/, '');
    const key = [normalizedName, type, opts.dnssec ? 1 : 0, opts.checkingDisabled ? 1 : 0].join('|');
    if (!opts.noCache) {
      var cached = dohCacheGet(key);
      if (cached !== undefined) return cached;
    }
    var result;
    var retries = opts.retries ?? DOH_RETRIES;
    for (var attempt = 0; attempt <= retries; attempt++) {
      result = await fetchDohOnce(normalizedName, type, opts);
      if (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain' || result.kind === 'cancelled') break;
      if (attempt < retries) await new Promise(function (resolve) { setTimeout(resolve, 150 * (attempt + 1)); });
    }
    if (!opts.noCache && result && (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain')) dohCacheSet(key, result);
    return result;
  }

  /**
   * Run an optional enrichment check, turning a DNS failure into a stated
   * "unknown" instead of an exception.
   *
   * Everything behind opts.www / opts.wildcard / opts.advanced is enrichment:
   * the domain's actual email-security posture is already established by the
   * core NS/MX/TXT lookups. Before this existed, a transient SERVFAIL on any
   * one of them threw, and the throw discarded the entire audit — SPF, DKIM,
   * DMARC and all — for a domain whose real records had resolved perfectly.
   * Across a 200-domain run that is close to guaranteed to happen to someone.
   *
   * A resolver hiccup must degrade one check, never delete the result. What it
   * must NOT do is quietly become a passing or failing verdict, so every
   * fallback here marks itself unknown and the scorer treats it as unscored
   * rather than as zero.
   *
   * Cancellation is re-thrown: an aborted audit is not an unknown result.
   */
  async function optionalCheck(run, fallback) {
    try {
      return await run();
    } catch (error) {
      if (error && error.name === 'AbortError') throw error;
      return typeof fallback === 'function' ? fallback(error) : fallback;
    }
  }

  function requireUsable(result, name, type) {
    if (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain') return result;
    throw dnsError(result.kind, name, type, result.httpStatus ? 'HTTP ' + result.httpStatus : '');
  }

  function cleanAnswerData(data, type) {
    var value = String(data || '').trim();
    if (type !== 'TXT') return value.replace(/^"|"$/g, '').trim();
    var chunks = [];
    var re = /"((?:\\.|[^"\\])*)"/g;
    var match;
    while ((match = re.exec(value))) {
      // Confirmed divergence (spec 0.2.3 §4): the success path decodes \uXXXX
      // escapes, the fallback keeps the chunk verbatim, so a malformed escape
      // renders as its literal source text rather than as a decoded character.
      // That is the honest reading of an undecodable chunk and it is left
      // alone deliberately — changing it would change parsed record values.
      // Any lone surrogate JSON.parse does emit is normalized to U+FFFD at
      // display time by js/render.js, not here, so grades are unaffected.
      try { chunks.push(JSON.parse('"' + match[1] + '"')); }
      catch (e) { chunks.push(match[1]); }
    }
    return chunks.length ? chunks.join('') : value.replace(/^"|"$/g, '');
  }

  async function dohQuery(name, type, opts) {
    const { answers } = requireUsable(await dohFetch(name, type, opts), name, type);
    const num = dnsTypeNum(type);
    return answers.filter(a => a.type === num).map(a => cleanAnswerData(a.data, type));
  }

  async function dohAll(name, type, opts) {
    const { answers } = requireUsable(await dohFetch(name, type, opts), name, type);
    return answers.map(a => cleanAnswerData(a.data, a.type === 16 ? 'TXT' : type));
  }

  /** Pre-flight: can we reach the resolver at all? */
  async function checkConnectivity() {
    const result = await dohFetch('example.com', 'A', { noCache: true, retries: 0, timeoutMs: 5000 });
    return result.kind === 'success' || result.kind === 'nodata';
  }

  /* ── Provider detection ─────────────────────────────────────────────── */

  function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }

  // Record selection must be case-insensitive. RFC 7489 and RFC 7208 tag names
  // are case-insensitive, so `V=DMARC1` and `V=SPF1` are valid records that a
  // case-sensitive startsWith() would silently discard — reporting a protected
  // domain as having no policy at all. False negatives are the worse error for
  // a security tool, so match liberally here and validate the contents later.
  function startsWithCI(value, prefix) {
    return String(value || '').slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
  }

  var PSL_EXACT = new Set();
  var PSL_WILDCARD = new Set();
  var PSL_EXCEPTION = new Set();
  (global.__PUBLIC_SUFFIX_RULES__ || []).forEach(function (rule) {
    if (rule[0] === '!') PSL_EXCEPTION.add(rule.slice(1));
    else if (rule.startsWith('*.')) PSL_WILDCARD.add(rule.slice(2));
    else PSL_EXACT.add(rule);
  });

  function getOrganizationalDomain(domain) {
    var labels = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
    if (labels.length < 2) return labels.join('.');
    var suffixLength = 1; // prevailing "*" rule when the PSL has no match
    for (var i = 0; i < labels.length; i++) {
      var candidate = labels.slice(i).join('.');
      if (PSL_EXCEPTION.has(candidate)) {
        suffixLength = Math.max(1, labels.length - i - 1);
        break;
      }
      if (PSL_EXACT.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i);
      if (i > 0 && PSL_WILDCARD.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i + 1);
    }
    if (labels.length <= suffixLength) return labels.join('.');
    return labels.slice(-(suffixLength + 1)).join('.');
  }

  function detectDNSProvider(ns, domain) {
    if (!ns.length) return '@unknown';
    const n = ns.join(' ').toLowerCase();
    if (n.includes('cloudflare')) return 'Cloudflare';
    if (n.includes('porkbun')) return 'Porkbun';
    if (n.includes('awsdns')) return 'AWS Route 53';
    if (n.includes('googledomains') || n.includes('.google.com')) return 'Google Domains';
    if (n.includes('squarespacedns')) return 'Squarespace';
    if (n.includes('namecheap')) return 'Namecheap';
    if (n.includes('godaddy')) return 'GoDaddy';
    if (n.includes('dnsmadeeasy')) return 'DNS Made Easy';
    if (n.includes('ultradns')) return 'UltraDNS';
    if (n.includes('name.com')) return 'Name.com';
    if (n.includes('hover')) return 'Hover';

    // Self-hosted: nameservers live on the same domain being audited
    if (domain && ns.some(s => {
      const h = s.toLowerCase().replace(/\.$/, '');
      return h === domain || h.endsWith('.' + domain);
    })) return '@self-hosted';

    // Extract provider name, handling ccSLDs like .com.tw .co.uk .com.au
    const ccSLDs = new Set(['com', 'co', 'net', 'org', 'edu', 'gov', 'ac', 'ne', 'or', 'biz', 'nom']);
    const parts = ns[0].replace(/\.$/, '').split('.');
    if (parts.length >= 3) {
      const penultimate = parts[parts.length - 2].toLowerCase();
      const idx = ccSLDs.has(penultimate) && parts.length >= 4
        ? parts.length - 3   // ccSLD: step past second-level label (e.g. .com.tw, .co.uk)
        : parts.length - 2;  // standard TLD: e.g. "cloudns" from ns1.cloudns.net
      return cap(parts[idx]);
    }
    return '@custom';
  }

  function isNullMx(mx) {
    if (mx.length !== 1) return false;
    var parts = String(mx[0]).trim().split(/\s+/);
    return parts.length === 2 && parts[0] === '0' && parts[1] === '.';
  }

  function detectEmailProvider(mx, domain, addressRecords) {
    if (isNullMx(mx)) return '@null-mx';
    if (!mx.length) return addressRecords && addressRecords.length ? '@implicit-mx' : '@none';
    const m = mx.join(' ').toLowerCase();
    if (m.includes('aspmx.l.google') || m.includes('smtp.google') || m.includes('googlemail')) return 'Google Workspace';
    if (m.includes('icloud') || m.includes('mail.icloud')) return 'Apple iCloud';
    if (m.includes('protection.outlook') || m.includes('mail.protection')) return 'Microsoft 365';
    if (m.includes('zoho')) return 'Zoho Mail';
    if (m.includes('mxroute')) return 'MXroute';
    if (m.includes('fastmail')) return 'Fastmail';
    if (m.includes('protonmail')) return 'Proton Mail';
    if (m.includes('mailgun')) return 'Mailgun';
    if (m.includes('sendgrid')) return 'SendGrid';
    if (m.includes('porkbun')) return '@porkbun-forwarding';
    if (m.includes('forwardemail')) return 'Forward Email';
    if (m.includes('messagelabs')) return 'Symantec/MessageLabs';

    // Self-hosted: MX points back to the same domain
    if (domain && mx.some(r => {
      const host = r.replace(/^\d+\s+/, '').toLowerCase().replace(/\.$/, '');
      return host === domain || host.endsWith('.' + domain);
    })) return '@self-hosted';

    return '@custom-unknown';
  }

  function detectHosting(aRecs, wwwCname, domain) {
    const a = aRecs.join(' ');
    const c = wwwCname.join(' ').toLowerCase();
    if (c.includes('odoo.com')) return 'Odoo';
    if (c.includes('shopify')) return 'Shopify';
    if (c.includes('webflow')) return 'Webflow';
    if (c.includes('squarespace')) return 'Squarespace';
    if (c.includes('wix.com')) return 'Wix';
    if (c.includes('wpengine') || c.includes('wordpress.com')) return 'WordPress';
    if (c.includes('netlify')) return 'Netlify';
    if (c.includes('vercel') || c.includes('now.sh')) return 'Vercel';
    if (c.includes('github.io')) return 'GitHub Pages';
    if (c.includes('pages.dev')) return 'Cloudflare Pages';
    if (c.includes('porkbun')) return 'Porkbun Hosting';
    if (c.includes('fastly')) return 'Fastly';
    if (c.includes('icloudmailadmin')) return '@dash';
    if (a.includes('104.21') || a.includes('172.67') || a.includes('104.18')) return '@cloudflare-proxied';
    if (a.includes('185.199.')) return 'GitHub Pages';
    if (a.includes('76.76.21') || a.includes('76.223')) return 'Vercel';
    if (!aRecs.length && !wwwCname.length) return '@no-web';
    return '@custom';
  }

  /* ── Email security analysis ────────────────────────────────────────── */

  // Warnings are returned as issue keys so they can be looked up in the
  // locale files and in the "Show me" explainer content.
  function analyzeSpf(spf, emailProvider, multiple) {
    // RFC 7208 §4.5: more than one v=spf1 record is a permerror. SPF fails for
    // ALL mail regardless of what the records say, so this outranks every other
    // finding about the record's contents.
    if (multiple) return { status: 'permerror', cls: 'crit', warnings: ['spf-multiple-records'] };
    if (!spf) return { status: 'missing', cls: 'crit', warnings: [] };
    const warnings = [];
    const lower = spf.toLowerCase();
    if (emailProvider === 'Google Workspace' && !lower.includes('_spf.google.com') && !lower.includes('google.com')) warnings.push('spf-missing-google');
    if (emailProvider === 'Apple iCloud' && !lower.includes('icloud')) warnings.push('spf-missing-icloud');
    if (emailProvider === 'Microsoft 365' && !lower.includes('protection.outlook')) warnings.push('spf-missing-microsoft');
    if (/(?:^|\s)\+all(?:\s|$)/i.test(spf)) warnings.push('spf-all-permit');
    if (/(?:^|\s)\?all(?:\s|$)/i.test(spf)) warnings.push('spf-neutral');
    if (warnings.length) return { status: 'warn', cls: 'warn', warnings };
    if (/(?:^|\s)-all(?:\s|$)/i.test(spf)) return { status: 'ok', cls: 'ok', warnings: [] };
    if (/(?:^|\s)~all(?:\s|$)/i.test(spf)) return { status: 'softfail', cls: 'warn', warnings: ['spf-softfail'] };
    return { status: 'present', cls: 'ok', warnings: [] };
  }

  function validDkimSelector(selector) {
    return /^[a-z0-9][a-z0-9_-]{0,62}$/.test(selector);
  }

  function dkimKeyRecords(answers) {
    return answers.filter(function (answer) { return answer.type === 16; })
      .map(function (answer) { return cleanAnswerData(answer.data, 'TXT'); })
      .filter(function (value) {
        var tags = Object.create(null);
        String(value || '').split(';').forEach(function (part) {
          var separator = part.indexOf('=');
          if (separator < 0) return;
          tags[part.slice(0, separator).trim().toLowerCase()] = part.slice(separator + 1).trim();
        });
        return Object.prototype.hasOwnProperty.call(tags, 'p') && tags.p.length > 0 &&
          (!tags.v || tags.v.toLowerCase() === 'dkim1');
      });
  }

  // Only the literal include:/redirect= hostnames of the domain's own record
  // count. Following an included record into its own includes would attribute
  // the vendor's upstream to the audited domain — freshdesk.com's SPF includes
  // sendgrid.net, which says nothing about who signs the domain's mail — and
  // would cost DNS lookups this function deliberately does not make.
  function spfReferencedCatalogKeys(spf) {
    var keys = new Set();
    if (!spf) return keys;
    parseSpfTerms(spf).forEach(function (term) {
      if (term.modifier ? term.name !== 'redirect' : term.name !== 'include') return;
      // A macro can't be reduced to a literal hostname, so there is nothing to
      // match — the same treatment countSpfLookups() gives it.
      if (!term.value || term.value.indexOf('%{') !== -1) return;
      var host = term.value.replace(/\.$/, '');
      DKIM_SPF_INCLUDE_PROVIDERS.forEach(function (entry) {
        if (entry.pattern.test(host)) keys.add(entry.catalogKey);
      });
    });
    return keys;
  }

  function catalogSelectors(emailProvider, comprehensive, spfRecord) {
    var providerKey = DKIM_PROVIDER_CATALOG_KEYS[emailProvider];
    var providerSelectors = providerKey && DKIM_CATALOG.providers[providerKey]
      ? DKIM_CATALOG.providers[providerKey] : [];
    if (comprehensive) {
      return Object.values(DKIM_CATALOG.providers).flat()
        .concat(DKIM_CATALOG.generic || [], DKIM_CATALOG.temporal || []);
    }
    // Comprehensive mode already covers every provider, so this only widens the
    // provider-aware scan. .concat() returns a new array each time, leaving the
    // catalog's own arrays untouched.
    spfReferencedCatalogKeys(spfRecord).forEach(function (key) {
      if (key !== providerKey && DKIM_CATALOG.providers[key]) {
        providerSelectors = providerSelectors.concat(DKIM_CATALOG.providers[key]);
      }
    });
    return providerSelectors;
  }

  // Which tested selectors exist *only* because SPF named their vendor. A
  // selector the MX provider (or the base list, or the user) would have
  // supplied anyway is not attributed here — it needed no explaining.
  function spfSelectorSources(selectors, emailProvider, comprehensive, spfRecord) {
    var sources = new Map();
    if (comprehensive) return sources;
    var providerKey = DKIM_PROVIDER_CATALOG_KEYS[emailProvider];
    var baseline = new Set(buildDkimSelectorList(selectors, emailProvider, false));
    spfReferencedCatalogKeys(spfRecord).forEach(function (key) {
      if (key === providerKey || !DKIM_CATALOG.providers[key]) return;
      DKIM_CATALOG.providers[key].forEach(function (selector) {
        var name = String(selector || '').trim().toLowerCase();
        // Set iteration follows SPF term order, so a selector two referenced
        // vendors share is credited to the one named first — deterministically.
        if (baseline.has(name) || sources.has(name)) return;
        sources.set(name, key);
      });
    });
    return sources;
  }

  function buildDkimSelectorList(selectors, emailProvider, comprehensive, spfRecord) {
    return Array.from(new Set(
      (selectors || []).concat(DKIM_SELECTORS, catalogSelectors(emailProvider, comprehensive, spfRecord))
        .map(function (selector) { return String(selector || '').trim().toLowerCase(); })
        .filter(validDkimSelector)
    ));
  }

  function isRecognizedDkimSelector(selector) {
    return RECOGNIZED_DKIM_SELECTORS.has(String(selector || '').trim().toLowerCase());
  }

  async function inspectDkimSelector(domain, selector, queryOpts, synthesized) {
    var queryName = `${selector}._domainkey.${domain}`;
    var name = queryName;
    var visited = new Set();
    var firstCname = '';

    for (var depth = 0; depth < 6; depth++) {
      if (visited.has(name)) break;
      visited.add(name);
      var result = requireUsable(await dohFetch(name, 'TXT', queryOpts), name, 'TXT');
      // A wildcard covering _domainkey answers every selector query alike, so a
      // value it synthesizes is not evidence of a key at this selector. Drop
      // those by content; what survives is published for this selector only.
      var keys = dkimKeyRecords(result.answers).filter(function (value) {
        return !(synthesized && synthesized.has(value));
      });
      if (keys.length) {
        return { sel: selector, queryName: queryName, keys: keys, cname: firstCname };
      }
      var cnameAnswer = result.answers.find(function (answer) { return answer.type === 5; });
      if (!cnameAnswer) break;
      name = cleanAnswerData(cnameAnswer.data, 'CNAME').toLowerCase().replace(/\.$/, '');
      if (!firstCname) firstCname = name;
    }
    return { sel: selector, queryName: queryName, keys: [], cname: firstCname };
  }

  async function checkDKIM(domain, wildcard, selectors, emailProvider, comprehensive, spfRecord, queryOpts) {
    var wildcardDkim = !!(wildcard && wildcard.dkim);
    var synthesized = new Set((wildcard && wildcard.records) || []);
    var selectorList = buildDkimSelectorList(selectors, emailProvider, comprehensive, spfRecord);
    var spfSources = spfSelectorSources(selectors, emailProvider, comprehensive, spfRecord);
    var suppliedSelectors = new Set((selectors || [])
      .map(function (selector) { return String(selector || '').trim().toLowerCase(); })
      .filter(validDkimSelector));
    const found = [];
    const missingSelectors = [];
    const duplicated = [];
    const failedSelectors = [];
    for (var offset = 0; offset < selectorList.length; offset += DKIM_SCAN_BATCH_SIZE) {
      var batch = selectorList.slice(offset, offset + DKIM_SCAN_BATCH_SIZE);
      var checks = await Promise.all(batch.map(async function (selector) {
        try {
          return await inspectDkimSelector(domain, selector, queryOpts, synthesized);
        } catch (error) {
          if (error && error.name === 'AbortError') throw error;
          return { sel: selector, keys: [], cname: '', error: true };
        }
      }));
      for (const { sel, queryName, keys, cname, error } of checks) {
        if (error) { failedSelectors.push(sel); continue; }
        // RFC 6376 §3.6.2.2: key records MUST be unique per selector; with more
        // than one the result is undefined, so verification may fail depending on
        // which verifier looks.
        if (keys.length > 1) duplicated.push(sel);
        if (keys.length) {
          found.push({
            sel: sel,
            queryName: queryName,
            type: cname ? 'cname' : 'key',
            value: keys[0],
            cname: cname,
            uncommon: !isRecognizedDkimSelector(sel),
            viaSpf: spfSources.get(sel) || '',
          });
        } else if (suppliedSelectors.has(sel)) {
          missingSelectors.push({ sel: sel, queryName: queryName, cname: cname });
        }
      }
    }

    if (!found.length) {
      return { found: false, selectors: [], missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, confidence: 'sampled', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: wildcardDkim ? 'noteWildcard' : failedSelectors.length ? 'noteNotFoundWithErrors' : 'noteNotFound' };
    }
    return { found: true, selectors: found, missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, confidence: 'observed', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: '' };
  }

  // Valid policy values per RFC 9989 §4.7, ordered weakest → strongest.
  var POLICY_RANK = { none: 0, quarantine: 1, reject: 2 };

  /* ── RFC 9989 tag vocabulary ─────────────────────────────────────────────
     DMARCbis was published in May 2026 as RFC 9989 (with RFC 9990 covering
     aggregate reporting and RFC 9991 failure reporting), obsoleting RFC 7489
     and RFC 9091. The tag list below is the complete set it defines.

     `pct`, `rf` and `ri` are gone. A receiver implementing RFC 9989 ignores
     them, so we neither score them nor treat them as errors — but we do say
     they are there, because a record written against RFC 7489 will behave
     differently depending on which spec the receiver implements, and the
     operator should know that before it bites them.
     ───────────────────────────────────────────────────────────────────────── */
  var DMARC_TAGS_RFC9989 = ['v', 'p', 'sp', 'np', 'adkim', 'aspf', 'fo', 'rua', 'ruf', 'psd', 't'];
  var DMARC_TAGS_REMOVED = ['pct', 'rf', 'ri'];
  var DMARC_FO_VALUES = ['0', '1', 'd', 's'];

  /**
   * Parse a DMARC record into its tags (RFC 9989 §4.7).
   *
   * Two things this has to get right that a naive regex does not:
   *
   *  1. Tag names must be anchored. An unanchored /p=([^;]+)/ matches the `p=`
   *     inside `sp=` and `np=`, so `sp=reject; p=none` would parse as
   *     policy=reject. Tag order is arbitrary in real records.
   *  2. Tag names are case-insensitive — `P=REJECT` is valid and appears in
   *     the wild. Values are case-insensitive too, with one exception: the
   *     `v=` value is case SENSITIVE and must be exactly `DMARC1`.
   *
   * Subdomain policies inherit rather than default to permissive:
   * `sp` falls back to `p`, and `np` falls back to `sp` then `p`. A record with
   * `p=reject` and no `sp` DOES reject subdomain mail. `effectiveSp` and
   * `effectiveNp` carry the resolved values so scoring never has to re-derive
   * them.
   */
  function parseDmarcTag(record, name) {
    // (?:^|;)\s* anchors to a tag boundary so 'p' cannot match inside 'sp'/'np'.
    var m = record.match(new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*([^;]*)', 'i'));
    if (!m) return null;
    var value = m[1].trim();
    return value === '' ? null : value;
  }

  function normalizePolicy(value) {
    if (!value) return null;
    var lower = String(value).toLowerCase();
    return POLICY_RANK[lower] !== undefined ? lower : null;
  }

  /**
   * RFC 9989 §4.7: `v` MUST be the first tag, and its value is case sensitive
   * with `DMARC1` the only accepted spelling. A record that fails either test
   * "MUST be ignored" in its entirety — so this is a hard failure, not a nit.
   * We still parse the rest of the record afterwards so the report can say
   * what the operator *meant* alongside the fact that nobody will honour it.
   */
  function validateDmarcVersion(record) {
    var m = String(record || '').match(/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*([^;]*)/);
    if (!m) return { valid: false, reason: 'absent' };
    if (m[1].toLowerCase() !== 'v') return { valid: false, reason: 'not-first' };
    if (m[2].trim() !== 'DMARC1') return { valid: false, reason: 'bad-value' };
    return { valid: true, reason: null };
  }

  /**
   * Parse a `rua=`/`ruf=` value into its individual destinations.
   *
   * RFC 9989 §4.7 defines a comma-separated list of DMARC URIs, each with an
   * optional `!` size-limit suffix (digits plus an optional k/m/g/t unit).
   * A literal `!` inside a URI must be percent-encoded, so the LAST `!` is
   * unambiguously the delimiter.
   *
   * Only `mailto:` is a registered destination scheme for DMARC reporting.
   * Anything else parses but is undeliverable, which is reported separately
   * from outright malformed syntax because the fix is different.
   */
  function parseDmarcUriList(value) {
    var entries = String(value || '').split(',')
      .map(function (v) { return v.trim(); })
      .filter(Boolean);

    var uris = entries.map(function (raw) {
      var bang = raw.lastIndexOf('!');
      var uri = bang === -1 ? raw : raw.slice(0, bang);
      var limit = bang === -1 ? '' : raw.slice(bang + 1);
      var limitValid = limit === '' || /^\d+[kmgt]?$/i.test(limit);
      var scheme = (uri.indexOf(':') === -1 ? '' : uri.slice(0, uri.indexOf(':'))).toLowerCase();
      var mailbox = scheme === 'mailto' ? uri.slice(7) : '';
      var at = mailbox.lastIndexOf('@');
      var domain = at > 0 ? mailbox.slice(at + 1).toLowerCase().replace(/\.$/, '') : '';
      var wellFormed = scheme === 'mailto' && at > 0 && /^[^\s@]+\.[^\s@.]+$/.test(domain);
      return {
        raw: raw, uri: uri, scheme: scheme,
        mailbox: wellFormed ? mailbox : '',
        domain: wellFormed ? domain : '',
        sizeLimit: limit,
        unsupportedScheme: scheme !== '' && scheme !== 'mailto',
        valid: wellFormed && limitValid,
      };
    });

    return {
      uris: uris,
      count: uris.length,
      valid: uris.length > 0 && uris.every(function (u) { return u.valid; }),
      invalid: uris.filter(function (u) { return !u.valid; }).map(function (u) { return u.raw; }),
      domains: uris.filter(function (u) { return u.valid; }).map(function (u) { return u.domain; }),
    };
  }

  function analyzeDmarc(dmarc, multiple) {
    // RFC 9989 §4.7: with multiple records, policy discovery terminates and
    // DMARC is not applied at all — the domain is unprotected despite looking
    // configured. Distinct from 'missing' because the fix differs (delete a
    // duplicate vs. publish a first record).
    if (multiple) return emptyDmarcStatus('permerror');
    if (!dmarc) return emptyDmarcStatus('missing');

    var parsedTags = parseTagList(dmarc);
    var tag = function (name) { return parseDmarcTag(dmarc, name); };
    var version = validateDmarcVersion(dmarc);

    var rawPolicy = tag('p');
    var policy = normalizePolicy(rawPolicy) || 'none';
    var rawSp = tag('sp');
    var rawNp = tag('np');
    var sp = normalizePolicy(rawSp);
    var np = normalizePolicy(rawNp);

    // "Absent, so it inherits" and "present but not a policy value" are
    // different problems with different fixes, and normalizePolicy() collapses
    // both to null. Keep the distinction so the finding can name the value the
    // operator actually wrote instead of reporting a tag they did not omit.
    var tagState = function (raw, normalized) {
      return raw === null ? 'absent' : normalized === null ? 'invalid' : 'valid';
    };
    var spState = tagState(rawSp, sp);
    var npState = tagState(rawNp, np);

    // Inheritance chain per RFC 9989 §4.7. Note that sp/np apply only to
    // subdomains of the Organizational Domain, never to the domain itself.
    var effectiveSp = sp || policy;
    var effectiveNp = np || sp || policy;

    // ── t= (RFC 9989 §4.7, new) ──
    // Test mode. `t=y` tells receivers the owner is still evaluating and the
    // policy should NOT be applied. Reports keep flowing. This is bis's
    // replacement for ramping with pct=, and it means `p=reject; t=y` gives
    // exactly as much spoofing protection as `p=none` — which is none.
    var rawT = tag('t');
    var tValid = rawT === null || /^[yn]$/i.test(String(rawT).trim());
    var testMode = String(rawT || 'n').trim().toLowerCase() === 'y';

    // ── psd= (RFC 9989 §4.7, new) ──
    // Marks a Public Suffix Domain so the Tree Walk knows where to stop.
    // Default is 'u' (unknown — use normal discovery), NOT 'n'.
    var rawPsd = tag('psd');
    var psdValid = rawPsd === null || /^[ynu]$/i.test(String(rawPsd).trim());
    var psd = String(rawPsd || 'u').trim().toLowerCase();

    // ── fo= (RFC 9989 §4.7) ──
    // Colon-separated subset of 0/1/d/s. Its content MUST be ignored when no
    // ruf= is present, which makes fo-without-ruf a silent no-op worth naming.
    var rawFo = tag('fo');
    var fo = rawFo === null ? '0' : String(rawFo).trim().toLowerCase();
    var foValid = rawFo === null || fo.split(':').every(function (v) {
      return DMARC_FO_VALUES.indexOf(v.trim()) !== -1;
    });

    // ── pct= (removed in RFC 9989) ──
    // Parsed for reporting only. It no longer contributes to the score: a
    // bis-conformant receiver ignores it outright. Guard against NaN anyway —
    // an unguarded parseInt used to poison every downstream total.
    var rawPct = tag('pct');
    var pct = 100;
    var pctValid = true;
    if (rawPct !== null) {
      var parsed = parseInt(rawPct, 10);
      if (isNaN(parsed)) { pctValid = false; }
      else { pct = Math.max(0, Math.min(100, parsed)); pctValid = parsed >= 0 && parsed <= 100; }
    }

    // RFC 9989 §4.7 defines exactly two alignment modes, `r` and `s`. Anything
    // else used to become `r` silently, which is the correct RECEIVER
    // behaviour and a poor auditor one: `adkim=strict` reads as strict to the
    // person who wrote it and relaxes alignment in practice. Keep the receiver
    // behaviour, report the divergence.
    var alignmentState = function (raw) {
      if (raw === null) return 'absent';
      var value = String(raw).trim().toLowerCase();
      return value === 's' ? 's' : value === 'r' ? 'r' : 'invalid';
    };
    var rawAdkim = tag('adkim');
    var rawAspf = tag('aspf');
    var adkimState = alignmentState(rawAdkim);
    var aspfState = alignmentState(rawAspf);
    var adkim = adkimState === 's' ? 's' : 'r';
    var aspf = aspfState === 's' ? 's' : 'r';

    var ruaUris = parseDmarcUriList(tag('rua'));
    var rufUris = parseDmarcUriList(tag('ruf'));
    var rua = ruaUris.count > 0;
    var ruf = rufUris.count > 0;

    // Classify every tag actually present against the RFC 9989 vocabulary.
    var presentTags = Object.keys(parsedTags.tags);
    var removedTags = presentTags.filter(function (k) { return DMARC_TAGS_REMOVED.indexOf(k) !== -1; });
    var unknownTags = presentTags.filter(function (k) {
      return DMARC_TAGS_RFC9989.indexOf(k) === -1 && DMARC_TAGS_REMOVED.indexOf(k) === -1;
    });

    // The published policy is what the operator wrote; the effective policy is
    // what receivers will actually do. Test mode is the only thing that can
    // make them differ, and keeping both means the UI can show the gap rather
    // than silently reporting one as the other.
    var effectivePolicy = testMode ? 'none' : policy;
    var enforcing = effectivePolicy === 'quarantine' || effectivePolicy === 'reject';

    // `present` covers a record receivers cannot act on: an unusable v=, an
    // unrecognized p=, or duplicate tags. A record exists, so it is neither
    // 'missing' nor trustworthy enforcement.
    var malformed = !version.valid
      || rawPolicy === null
      || normalizePolicy(rawPolicy) === null
      || parsedTags.duplicates.length > 0;
    var status = malformed ? 'present'
      : enforcing ? 'ok'
        : 'warn';

    return {
      status: status,
      cls: status === 'ok' ? 'ok' : 'warn',
      policy: policy, sp: sp, np: np,
      policyRaw: rawPolicy, spRaw: rawSp, npRaw: rawNp,
      spState: spState, npState: npState,
      adkimState: adkimState, aspfState: aspfState,
      adkimRaw: rawAdkim, aspfRaw: rawAspf,
      effectivePolicy: effectivePolicy,
      effectiveSp: effectiveSp, effectiveNp: effectiveNp,
      pct: pct, pctValid: pctValid, pctPresent: rawPct !== null,
      adkim: adkim, aspf: aspf,
      rua: rua, ruf: ruf, ruaUris: ruaUris, rufUris: rufUris,
      enforcing: enforcing,
      fo: fo, foValid: foValid, foPresent: rawFo !== null,
      testMode: testMode, tValid: tValid,
      psd: psd, psdValid: psdValid, psdPresent: rawPsd !== null,
      version: version,
      removedTags: removedTags, unknownTags: unknownTags,
      malformed: malformed, duplicateTags: parsedTags.duplicates,
    };
  }

  /** Shared shape for the "there is nothing to analyse" outcomes. */
  function emptyDmarcStatus(status) {
    return {
      // 'unknown' is not a failed control, it is an unexamined one: the walk
      // hit a transient DNS error and the record could not be read. It must
      // never wear the same red as a domain that genuinely published nothing.
      status: status, cls: status === 'unknown' ? 'warn' : 'crit',
      policy: '', effectivePolicy: '',
      rua: false, ruf: false,
      ruaUris: parseDmarcUriList(''), rufUris: parseDmarcUriList(''),
      sp: null, np: null, effectiveSp: null, effectiveNp: null,
      pct: 100, pctValid: true, pctPresent: false,
      adkim: 'r', aspf: 'r', enforcing: false,
      policyRaw: null, spRaw: null, npRaw: null,
      spState: 'absent', npState: 'absent',
      adkimState: 'absent', aspfState: 'absent',
      adkimRaw: null, aspfRaw: null,
      fo: '0', foValid: true, foPresent: false,
      testMode: false, tValid: true,
      psd: 'u', psdValid: true, psdPresent: false,
      version: { valid: false, reason: 'absent' },
      removedTags: [], unknownTags: [], duplicateTags: [],
    };
  }

  /**
   * Report destinations outside the audited domain's organizational domain.
   *
   * RFC 9989 §5.6: sending reports to a domain you do not control requires the
   * receiving domain to publish `<source>._report._dmarc.<destination>`. Until
   * it does, conformant receivers discard those reports — so the operator gets
   * silence and assumes everything is fine. Kept separate from analyzeDmarc so
   * that function stays pure and domain-agnostic.
   */
  function findExternalReportDestinations(dmarcStatus, policyDomain, orgDomains) {
    if (!dmarcStatus || !policyDomain) return [];
    // RFC 9990 §4 defines the externality test against the ORGANIZATIONAL
    // DOMAIN on both sides, which after this release means the Tree Walk
    // result rather than the Public Suffix List. `orgDomains` carries the
    // walked answers; an absent entry falls back to the name itself, which is
    // the §4.10.2 fallback and never the PSL.
    var lookup = function (name) {
      var found = orgDomains && (typeof orgDomains.get === 'function' ? orgDomains.get(name) : orgDomains[name]);
      return found || name;
    };
    var org = lookup(policyDomain);
    var seen = new Set();
    return []
      .concat(dmarcStatus.ruaUris ? dmarcStatus.ruaUris.domains : [])
      .concat(dmarcStatus.rufUris ? dmarcStatus.rufUris.domains : [])
      .filter(function (dest) {
        if (!dest || seen.has(dest)) return false;
        seen.add(dest);
        return dest !== org && lookup(dest) !== org;
      });
  }

  /**
   * Resolve the Organizational Domain of every candidate report destination
   * with a Tree Walk, so the externality test in RFC 9990 §4 is answered by
   * DNS rather than by the vendored Public Suffix List.
   *
   * This is the query cost `OQ-DMARC-04` accepted knowingly: the externality
   * test now walks the destination's tree as well as the audited domain's. The
   * dohFetch() cache absorbs most of it across a run, because report
   * destinations repeat heavily (a few reporting vendors serve most domains).
   * A destination that already equals the policy domain's Organizational
   * Domain is settled by string comparison and never walked.
   */
  // A record's rua=/ruf= list is written by whoever controls the domain being
  // audited, and parseDmarcUriList() caps nothing — so without a bound here the
  // query count for one domain is set by a third party's record content. Twenty
  // distinct destinations would be 160 queries. Destinations past the cap fall
  // back to their bare name, which per findExternalReportDestinations() can only
  // make one look external: a "verify this" notice rather than a silent pass.
  var MAX_WALKED_REPORT_DESTINATIONS = 10;

  async function resolveDestinationOrgDomains(dmarcStatus, policyDomain, policyOrgDomain, queryOpts) {
    var orgDomains = new Map();
    orgDomains.set(policyDomain, policyOrgDomain);
    var candidates = [];
    var seen = new Set([policyOrgDomain]);
    []
      .concat(dmarcStatus && dmarcStatus.ruaUris ? dmarcStatus.ruaUris.domains : [])
      .concat(dmarcStatus && dmarcStatus.rufUris ? dmarcStatus.rufUris.domains : [])
      .forEach(function (dest) {
        if (!dest || seen.has(dest)) return;
        seen.add(dest);
        if (candidates.length < MAX_WALKED_REPORT_DESTINATIONS) candidates.push(dest);
      });
    await Promise.all(candidates.map(async function (dest) {
      var discovery = await optionalCheck(function () { return discoverDmarc(dest, queryOpts); }, null);
      // A walk that failed leaves the destination's Organizational Domain
      // unknown. Falling back to the name itself keeps the comparison honest:
      // it can only ever make the destination look external, which produces a
      // "verify this" notice rather than a silent pass.
      orgDomains.set(dest, (discovery && discovery.organizationalDomain) || dest);
    }));
    return orgDomains;
  }

  /**
   * Verify that each external report destination has authorized this domain.
   *
   * RFC 9990 §4: when a destination's organizational domain differs from the
   * policy domain's, the receiver queries
   *
   *   <policy-domain>._report._dmarc.<destination-host>
   *
   * and requires a TXT record whose FIRST tag is `v=DMARC1`. A wildcard form,
   * `*._report._dmarc.<destination-host>`, authorizes every domain at once and
   * is what most reporting vendors publish rather than a record per customer.
   *
   * Authorization is evaluated per URI: an unauthorized destination is dropped
   * on its own. It does not invalidate the DMARC record and it does not affect
   * the other destinations, which is why this returns a verdict per destination
   * rather than one verdict for the record.
   *
   * A DNS failure is reported as 'unverifiable' rather than 'unauthorized' —
   * a timeout is not evidence of a missing record, and calling it one would
   * send someone chasing a vendor over our own flaky lookup.
   */
  async function checkExternalReportAuth(domain, destinations, queryOpts) {
    var policyDomain = String(domain || '').toLowerCase().replace(/\.$/, '');
    var unique = [];
    var seen = new Set();
    (destinations || []).forEach(function (d) {
      var host = String(d || '').toLowerCase().replace(/\.$/, '');
      if (host && !seen.has(host)) { seen.add(host); unique.push(host); }
    });

    // RFC 9990 §4 step 6: "the 'v=DMARC1' tag is mandatory and MUST appear
    // first in the list. Discard any that do not pass this test."
    // validateDmarcVersion() owns that rule for policy records already, and a
    // startsWith() check does not: it accepts `v=DMARC1x`, which is not the
    // current version and authorizes nothing.
    var parses = function (record) { return validateDmarcVersion(record).valid; };

    // Step 8, verbatim: "If at least one TXT resource record remains in the
    // set after parsing, then the external reporting arrangement was
    // authorized by the Report Consumer."
    //
    // This is PERMISSIVE, and deliberately the opposite of the DMARC policy
    // duplicate rule in discoverDmarc(), where RFC 9989 §4.10 step 2 discards
    // every record when more than one is returned. The two questions are asked
    // at different names, for different purposes, by different RFCs, and they
    // answer them differently. Do not "fix" either one to match the other.
    async function lookup(queryName) {
      var response = await dohFetch(queryName, 'TXT', queryOpts);
      if (response.kind === 'cancelled') throw dnsError('cancelled', queryName, 'TXT');
      if (response.kind !== 'success' && response.kind !== 'nodata' && response.kind !== 'nxdomain') {
        throw dnsError(response.kind, queryName, 'TXT', response.httpStatus ? 'HTTP ' + response.httpStatus : '');
      }
      var records = response.answers.filter(function (a) { return a.type === 16; })
        .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
      return { kind: response.kind, records: records, authorized: records.filter(parses) };
    }

    return Promise.all(unique.map(async function (host) {
      var exact = policyDomain + '._report._dmarc.' + host;
      var wildcard = '*._report._dmarc.' + host;
      // RFC 9990 §4 step 4: "If the length of the constructed name exceed DNS
      // limits, a positive determination of the external reporting relationship
      // cannot be made; stop." Cannot-determine and not-authorized are
      // different facts, and this release cares about that distinction
      // everywhere else.
      if (exact.length > 253) {
        return {
          destination: host, state: 'unverifiable', via: null, queryName: exact,
          record: '', error: 'name-too-long',
        };
      }
      try {
        var exactResult = await lookup(exact);
        if (exactResult.authorized.length) {
          return {
            destination: host, state: 'authorized', via: 'exact', queryName: exact,
            record: exactResult.authorized[0], recordCount: exactResult.authorized.length,
            exactKind: exactResult.kind,
          };
        }
        var wildcardResult = await lookup(wildcard);
        if (wildcardResult.authorized.length) {
          return {
            destination: host, state: 'authorized', via: 'wildcard', queryName: wildcard,
            record: wildcardResult.authorized[0], recordCount: wildcardResult.authorized.length,
            exactKind: exactResult.kind,
          };
        }
        // A TXT record that exists but does not parse authorizes nothing —
        // worth distinguishing from nothing at all, because it usually means a
        // truncated or hand-mangled record.
        //
        // The response kind is kept because the two misses mean different
        // things to the operator: NXDOMAIN at the exact name with the record
        // on the wildcard is ordinary vendor practice, while NOERROR carrying
        // unrelated TXT data usually means the record went to the wrong name.
        var malformed = exactResult.records.length || wildcardResult.records.length;
        return {
          destination: host, state: 'unauthorized', via: null, queryName: exact,
          record: malformed ? (exactResult.records[0] || wildcardResult.records[0]) : '',
          malformed: !!malformed,
          exactKind: exactResult.kind, wildcardKind: wildcardResult.kind,
        };
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        return { destination: host, state: 'unverifiable', via: null, queryName: exact, record: '', error: e && e.kind };
      }
    }));
  }

  /* ── RFC 9989 DNS Tree Walk ──────────────────────────────────────────────
     Discovery only. No parsing, no scoring, no English. The walk locates the
     record; analyzeDmarc() interprets it and calcDmarcScore() grades it.

     The parameters below are transcribed from the published RFC 9989 text
     (rfc-editor.org, May 2026, obsoletes 7489/9091), not reconstructed from
     memory or another implementation. §4.10, verbatim:

       "To guard against such abuse of the DNS, a shortcut is built into the
        process so that Author Domains with more than eight labels do not
        result in more than eight DNS queries."

       3. Break the subject DNS domain name into a set of ordered labels.
          Assign the count of labels to "x", and number the labels from right
          to left [...]
       4. If x < 8, remove the left-most (highest-numbered) label from the
          subject domain.  If x >= 8, remove the left-most (highest-numbered)
          labels from the subject domain until 7 labels remain.  The resulting
          DNS domain name is the new target for the next lookup.
       7. Determine the target for the next query by removing the left-most
          label from the target of the previous query.  Repeat steps 5, 6, and
          7 until the process stops or there are no more labels remaining.

     So the budget is eight queries, and it is reached by SHORTENING rather
     than by aborting: a thirteen-label name is cut to seven labels after the
     first query and then walks one label at a time, so it lands on the TLD on
     query eight exactly. There is deliberately no 'query-limit' termination
     state, because running out of queries before running out of labels cannot
     happen. §4.10's own worked example ends at "_dmarc.com".
     ───────────────────────────────────────────────────────────────────────── */

  var DMARC_WALK_SHORTCUT_AT = 8;   // RFC 9989 §4.10 step 4: "If x >= 8"
  var DMARC_WALK_SHORTEN_TO = 7;    // RFC 9989 §4.10 step 4: "until 7 labels remain"

  function domainLabels(name) {
    return String(name || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  }

  /**
   * The ordered list of subject names a Tree Walk queries, per §4.10 steps
   * 3, 4 and 7. Exported for testing because the label arithmetic is the part
   * of this release most likely to be subtly wrong.
   */
  function dmarcWalkTargets(domain) {
    var labels = domainLabels(domain);
    if (!labels.length) return [];
    var targets = [labels.join('.')];
    // Step 4. The first reduction is the only one that may remove more than
    // one label; every reduction after it is step 7's single label.
    var next = labels.length >= DMARC_WALK_SHORTCUT_AT
      ? labels.slice(labels.length - DMARC_WALK_SHORTEN_TO)
      : labels.slice(1);
    while (next.length) {
      targets.push(next.join('.'));
      next = next.slice(1);
    }
    return targets;
  }

  /**
   * Is this TXT string a DMARC Policy Record for selection purposes?
   *
   * RFC 9989 §4.10 steps 2 and 6: "Records that do not start with a 'v' tag
   * that identifies the current version of DMARC are discarded." The tag NAME
   * is case-insensitive and the VALUE is not, which is exactly what
   * validateDmarcVersion() already encodes — routing through it keeps one
   * function owning the rule rather than two spellings of it drifting apart.
   */
  function isDmarcPolicyRecord(txt) {
    return validateDmarcVersion(txt).valid;
  }

  /**
   * Explain a TXT string that failed the strict pass but was probably meant
   * to be a DMARC record. Diagnosis only: nothing here ever becomes a policy.
   *
   * The point is the difference between "you have no DMARC record" and "you
   * have a DMARC record that no receiver will read, and here is why".
   */
  function diagnoseDmarcRecord(txt) {
    var version = validateDmarcVersion(txt);
    if (version.valid) return null;
    var vTag = parseDmarcTag(txt, 'v');
    if (vTag !== null) {
      var value = String(vTag);
      if (value.toLowerCase() === 'dmarc1') {
        if (value !== 'DMARC1') return 'version-bad-case';
        return version.reason === 'not-first' ? 'version-not-first' : null;
      }
      // `v=DMARC1x` and `v=DMARC2`: a version tag that is not this version.
      // checkExternalReportAuth() rejects exactly this spelling on the
      // authorization side, so leaving it undiagnosed here — rendering as a
      // bare "no DMARC record" — was the inconsistent half.
      if (/^dmarc/i.test(value) && parseDmarcTag(txt, 'p') !== null) return 'version-bad-case';
      return null;                                 // v=spf1 and friends
    }
    // No v= at all. Only call it a DMARC record if it looks like one.
    return parseDmarcTag(txt, 'p') !== null ? 'version-absent' : null;
  }

  /** The name one label below `ancestor`, taken from `subject`'s own labels. */
  function oneLabelBelow(subject, ancestor) {
    var subjectLabels = domainLabels(subject);
    var depth = domainLabels(ancestor).length + 1;
    if (depth > subjectLabels.length) return null;
    return subjectLabels.slice(subjectLabels.length - depth).join('.');
  }

  /**
   * RFC 9989 §4.10 Tree Walk: discover the DMARC Policy Record that applies to
   * `domain`, and the Organizational Domain, without consulting a Public
   * Suffix List.
   *
   * Two things this must not get wrong, both of which an earlier draft did:
   *
   *  - The walk does NOT stop at the first record it finds. Steps 2 and 6 stop
   *    early only when a single surviving record carries "psd=n" or "psd=y".
   *    A plain valid record is collected and the walk continues. Stopping at
   *    the first match reports the wrong policy domain for exactly the
   *    delegated-subdomain case DMARCbis exists to serve.
   *  - Duplicate records at one name are DISCARDED and the walk CONTINUES
   *    (step 2: "If multiple DMARC Policy Records are returned for a single
   *    target, they are all discarded"). A duplicate is evidence, not a
   *    termination reason, and a record higher in the tree still applies.
   *
   * `opts.apexTxt` is the audited name's own TXT set, which analyzeDomain
   * already holds. It costs no query and catches the common case of a record
   * published at the apex instead of under _dmarc.
   */
  async function discoverDmarc(domain, queryOpts, opts) {
    var subject = domainLabels(domain).join('.');
    var targets = dmarcWalkTargets(subject);
    var steps = [];
    var observed = [];
    var collected = [];
    var terminated = 'root';
    var psdBoundary = null;
    var error = null;

    // Costs nothing: the caller already has this TXT set.
    ((opts && opts.apexTxt) || []).forEach(function (txt) {
      if (isDmarcPolicyRecord(txt)) {
        observed.push({ queryName: subject, record: txt, why: 'at-apex-not-underscore' });
      }
    });

    for (var i = 0; i < targets.length; i++) {
      var target = targets[i];
      var queryName = '_dmarc.' + target;
      var response = await dohFetch(queryName, 'TXT', queryOpts);

      if (response.kind === 'cancelled') throw dnsError('cancelled', queryName, 'TXT');
      if (response.kind !== 'success' && response.kind !== 'nodata' && response.kind !== 'nxdomain') {
        // A failed lookup is not a missing record. Even with a record already
        // collected lower down, the names above could not be examined, so the
        // HIGHEST record — which is what selection needs — is not knowable.
        // optionalCheck()'s rule applies: an unknown control is never an
        // absent one.
        steps.push({ queryName: queryName, kind: response.kind, txtCount: 0, dmarcCount: 0, selected: false });
        terminated = 'error';
        error = response.kind;
        break;
      }

      var txts = response.answers.filter(function (a) { return a.type === 16; })
        .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
      var records = txts.filter(isDmarcPolicyRecord);
      var step = {
        queryName: queryName, kind: response.kind,
        txtCount: txts.length, dmarcCount: records.length, selected: false,
      };
      steps.push(step);

      if (records.length > 1) {
        // Discarded, but recorded: every receiver ignores both, which is a
        // real misconfiguration even when a policy higher up still governs.
        observed.push({ queryName: queryName, record: records[0], why: 'multiple-at-step' });
        continue;
      }

      if (!records.length) {
        txts.forEach(function (txt) {
          var why = diagnoseDmarcRecord(txt);
          if (why) observed.push({ queryName: queryName, record: txt, why: why });
        });
        continue;
      }

      var record = records[0];
      var rawPsd = parseDmarcTag(record, 'psd');
      var psd = rawPsd === null ? 'u' : String(rawPsd).trim().toLowerCase();
      step.selected = true;
      collected.push({
        name: target, record: record, psd: psd,
        labelsUp: domainLabels(subject).length - domainLabels(target).length,
      });

      // Steps 2 and 6: "If a single record remains and it contains a 'psd=n'
      // or 'psd=y' tag, stop." Anything else, including the default psd=u,
      // continues the walk.
      if (psd === 'y') { terminated = 'psd-y'; psdBoundary = target; break; }
      if (psd === 'n') { terminated = 'psd-n'; break; }
    }

    var result = {
      applied: null,
      policyDomain: null,
      organizationalDomain: subject,
      psdBoundary: psdBoundary,
      steps: steps,
      terminated: terminated,
      queries: steps.length,
      observed: observed,
      error: error,
    };
    // A transient error leaves the upper tree unexamined, so the HIGHEST record
    // is not knowable and neither is the Organizational Domain. Report the
    // audited name as the Organizational Domain per §4.10.2's fallback rather
    // than guessing from a partial walk.
    //
    // One record survives that, and only one: the Author Domain's own. RFC
    // 9989 §4.10.1 settles it on the first query, before any walk happens —
    // "Policy discovery first starts with a query for a valid DMARC Policy
    // Record at the name created by prepending the label '_dmarc' to the
    // Author Domain [...] If a valid DMARC Policy Record is found there, then
    // this is the DMARC Policy Record to be applied to the message" — and the
    // walk is performed only "If no valid DMARC Policy Record is found by the
    // first query". Nothing found higher up can displace it, so a SERVFAIL at
    // _dmarc.com cannot turn a domain's own p=reject into an unknown.
    if (terminated === 'error') {
      var ownRecord = collected.filter(function (e) { return e.name === subject; })[0];
      if (ownRecord) {
        result.applied = {
          record: ownRecord.record, foundAt: ownRecord.name,
          labelsUp: 0, inherited: false,
        };
        result.policyDomain = ownRecord.name;
      }
      return result;
    }

    result.organizationalDomain = selectOrganizationalDomain(subject, collected);
    var applied = selectAppliedRecord(subject, collected, result.organizationalDomain);
    if (applied) {
      result.applied = {
        record: applied.record,
        foundAt: applied.name,
        labelsUp: applied.labelsUp,
        inherited: applied.name !== subject,
      };
      result.policyDomain = applied.name;
    }
    return result;
  }

  /**
   * RFC 9989 §4.10.2, verbatim:
   *
   *   "For each Tree Walk that retrieved valid DMARC Policy Records, select
   *    the Organizational Domain from the domains for which valid DMARC Policy
   *    Records were retrieved from the longest to the shortest:
   *    1. If a valid DMARC Policy Record contains the 'psd' tag set to 'n'
   *       ('psd=n'), this is the Organizational Domain [...]
   *    2. If a valid DMARC Policy Record, other than the one for the domain
   *       where the Tree Walk started, contains the 'psd' tag set to 'y'
   *       ('psd=y'), the Organizational Domain is the domain one label below
   *       this one in the DNS hierarchy [...]
   *    3. Otherwise, select the DMARC Policy Record found at the name with the
   *       fewest number of labels. [...]
   *    If this process does not determine the Organizational Domain, then the
   *    initial target domain is the Organizational Domain."
   *
   * Only rule 3 is "the highest name carrying a record". Under rule 2 the
   * Organizational Domain may carry no DMARC record at all — which is the
   * whole point of psd=, and is why this is not the same value as
   * `applied.foundAt`. The closing sentence is why this never returns null.
   */
  function selectOrganizationalDomain(subject, collected) {
    for (var i = 0; i < collected.length; i++) {
      var entry = collected[i];
      if (entry.psd === 'n') return entry.name;
      if (entry.psd === 'y' && entry.name !== subject) {
        return oneLabelBelow(subject, entry.name) || subject;
      }
    }
    if (collected.length) {
      return collected.reduce(function (best, entry) {
        return domainLabels(entry.name).length < domainLabels(best.name).length ? entry : best;
      }).name;
    }
    return subject;
  }

  /**
   * RFC 9989 §4.10.1: "The DMARC Policy Record to be applied to an email
   * message will be the record found at any of the following locations, listed
   * from highest preference to lowest: the Author Domain; the Organizational
   * Domain of the Author Domain; the PSD of the Author Domain."
   *
   * The preference list is why this is not simply "the highest name carrying a
   * record". §4.10.1's closing note is explicit:
   *
   *   "Note: PSD policy is not used for Organizational Domains that have
   *    published a DMARC Policy Record."
   *
   * So when a psd=y boundary is found AND the Organizational Domain below it
   * published its own record, that record wins over the PSD's — even though
   * the PSD sits higher in the tree. Where no psd tag is involved, §4.10.2
   * rule 3 makes the Organizational Domain the fewest-labels record, so this
   * collapses to §B.4.2's "the highest element in the DNS tree with a DMARC
   * Policy Record" and the two readings agree.
   */
  function selectAppliedRecord(subject, collected, organizationalDomain) {
    var atSubject = collected.filter(function (e) { return e.name === subject; })[0];
    if (atSubject) return atSubject;
    var atOrg = collected.filter(function (e) { return e.name === organizationalDomain; })[0];
    if (atOrg) return atOrg;
    if (!collected.length) return null;
    return collected.reduce(function (best, entry) {
      return domainLabels(entry.name).length < domainLabels(best.name).length ? entry : best;
    });
  }

  /**
   * RFC 9989 §3.2.13 and Appendix A.4: existence is a property of the NAME,
   * not of any record type. "if any RR exists for a domain, then the domain
   * exists"; an NXDOMAIN response means the name does not exist, while a
   * NODATA response (NOERROR, no records of the queried type) means the name
   * exists but that type does not.
   *
   * So a NOERROR of either shape is 'yes', and a transient failure is
   * 'unknown' — never 'no'. Reading a timeout as non-existence would apply the
   * np= branch of a policy to a name that is plainly there.
   *
   * analyzeDomain() derives this from the NS response it already holds rather
   * than calling here; this exists for the destinations and fixtures that have
   * no such response to hand.
   */
  async function domainExists(name, queryOpts) {
    var response = await dohFetch(name, 'NS', queryOpts);
    if (response.kind === 'cancelled') throw dnsError('cancelled', name, 'NS');
    return existenceFromResponse(response);
  }

  function existenceFromResponse(response) {
    if (!response) return 'unknown';
    if (response.kind === 'nxdomain') return 'no';
    if (response.kind === 'success' || response.kind === 'nodata') return 'yes';
    return 'unknown';
  }

  /**
   * Apply the discovered record's inheritance rules to a parsed DMARC status,
   * returning a NEW object.
   *
   * RFC 9989 §4.10.1: "If the DMARC Policy Record to be applied is that of
   * either the Organizational Domain or the PSD and the Author Domain is a
   * subdomain of that domain, then the Domain Owner Assessment Policy is taken
   * from the 'sp' tag (if any) if the Author Domain exists or the 'np' tag (if
   * any) if the Author Domain does not exist. In the absence of applicable
   * 'sp' or 'np' tags, the 'p' tag policy is used for subdomains."
   *
   * `effectiveSp` and `effectiveNp` already carry that fallback chain, so the
   * only new decision here is WHICH of the two governs — and that turns on
   * domain existence, which was previously never tested. When existence is
   * unknown the weaker of the two governs, matching the weakest-link rule the
   * scorer already uses.
   *
   * This replaces an in-place mutation of dmarcStatus. That mutation was the
   * only place a status object was edited after construction, which made it
   * easy to miss when reasoning about the record.
   */
  function applyInheritance(dmarcStatus, discovery, existence) {
    if (!dmarcStatus || !discovery || !discovery.applied || !discovery.applied.inherited) return dmarcStatus;
    if (dmarcStatus.status === 'missing' || dmarcStatus.status === 'permerror' || dmarcStatus.status === 'present') {
      return dmarcStatus;
    }
    var governing = existence === 'no' ? dmarcStatus.effectiveNp
      : existence === 'yes' ? dmarcStatus.effectiveSp
        : weakerPolicy(dmarcStatus.effectiveSp, dmarcStatus.effectiveNp);
    var policy = governing || dmarcStatus.policy;
    var effectivePolicy = dmarcStatus.testMode ? 'none' : policy;
    var enforcing = effectivePolicy === 'quarantine' || effectivePolicy === 'reject';
    var status = enforcing ? 'ok' : 'warn';
    return Object.assign({}, dmarcStatus, {
      inherited: true,
      inheritedFrom: discovery.applied.foundAt,
      organizationalPolicy: dmarcStatus.policy,
      appliedBranch: existence === 'no' ? 'np' : existence === 'yes' ? 'sp' : 'weakest',
      policy: policy,
      effectivePolicy: effectivePolicy,
      enforcing: enforcing,
      status: status,
      cls: status === 'ok' ? 'ok' : 'warn',
    });
  }

  function weakerPolicy(a, b) {
    var ra = POLICY_RANK[a], rb = POLICY_RANK[b];
    if (ra === undefined) return b;
    if (rb === undefined) return a;
    return ra <= rb ? a : b;
  }

  /* ── Advanced checks ────────────────────────────────────────────────── */

  async function checkCAA(domain, queryOpts) {
    // Walk up the domain tree (CAA can be inherited from parent)
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const check = parts.slice(i).join('.');
      const { answers } = requireUsable(await dohFetch(check, 'CAA', queryOpts), check, 'CAA');
      const caaAnswers = answers.filter(a => a.type === 257);
      if (caaAnswers.length > 0) {
        return { found: true, records: caaAnswers.map(a => a.data), atDomain: check };
      }
    }
    return { found: false, records: [], atDomain: null };
  }

  function parseTagList(record) {
    var tags = {};
    var duplicates = [];
    String(record || '').split(';').forEach(function (part) {
      var at = part.indexOf('=');
      if (at === -1) return;
      var key = part.slice(0, at).trim().toLowerCase();
      var value = part.slice(at + 1).trim();
      if (Object.prototype.hasOwnProperty.call(tags, key)) duplicates.push(key);
      else tags[key] = value;
    });
    return { tags: tags, duplicates: duplicates };
  }

  function validateMtaStsRecord(record) {
    var parsed = parseTagList(record);
    var valid = parsed.tags.v && parsed.tags.v.toLowerCase() === 'stsv1' && !!parsed.tags.id && !parsed.duplicates.length;
    return { valid: valid, id: parsed.tags.id || '', errors: parsed.duplicates.length ? ['duplicate-tags'] : valid ? [] : ['invalid-syntax'] };
  }

  function validateTlsRptRecord(record) {
    var parsed = parseTagList(record);
    var destinations = String(parsed.tags.rua || '').split(',').map(function (v) { return v.trim(); }).filter(Boolean);
    var validDestination = destinations.length && destinations.every(function (v) { return /^(mailto:|https:)/i.test(v); });
    var valid = parsed.tags.v && parsed.tags.v.toLowerCase() === 'tlsrptv1' && validDestination && !parsed.duplicates.length;
    return { valid: !!valid, destinations: destinations, errors: parsed.duplicates.length ? ['duplicate-tags'] : valid ? [] : ['invalid-syntax'] };
  }

  function validateBimiRecord(record) {
    var parsed = parseTagList(record);
    var logo = parsed.tags.l || '';
    var authority = parsed.tags.a || '';
    var valid = parsed.tags.v && parsed.tags.v.toLowerCase() === 'bimi1' && /^https:\/\//i.test(logo) &&
      (!authority || /^https:\/\//i.test(authority)) && !parsed.duplicates.length;
    return { valid: !!valid, logo: logo, authority: authority, errors: parsed.duplicates.length ? ['duplicate-tags'] : valid ? [] : ['invalid-syntax'] };
  }

  async function resolveWebsite(domain, queryOpts) {
    var current = 'www.' + domain;
    var visited = new Set();
    var chain = [];
    for (var depth = 0; depth < 12; depth++) {
      if (visited.has(current)) return { loop: true, chain: chain, addresses: [] };
      visited.add(current);
      var result = requireUsable(await dohFetch(current, 'CNAME', queryOpts), current, 'CNAME');
      var cnames = result.answers.filter(function (a) { return a.type === 5; })
        .map(function (a) { return a.data.replace(/\.$/, '').toLowerCase(); });
      if (!cnames.length) {
        var addresses = await Promise.all([dohQuery(current, 'A', queryOpts), dohQuery(current, 'AAAA', queryOpts)]);
        return { loop: false, chain: chain, addresses: addresses[0].concat(addresses[1]) };
      }
      current = cnames[0];
      chain.push(current);
    }
    return { loop: true, chain: chain, addresses: [] };
  }

  async function checkDNSSEC(domain, queryOpts) {
    // AD=true means the validating resolver authenticated the answer. If the
    // normal query SERVFAILs but succeeds with checking disabled, the chain is
    // bogus rather than merely unsigned.
    const validated = await dohFetch(domain, 'NS', Object.assign({}, queryOpts, { dnssec: true }));
    if (validated.kind === 'success' || validated.kind === 'nodata') {
      return { signed: validated.ad, state: validated.ad ? 'secure' : 'insecure' };
    }
    if (validated.kind === 'servfail') {
      const unchecked = await dohFetch(domain, 'NS', Object.assign({}, queryOpts, { dnssec: true, checkingDisabled: true }));
      if (unchecked.kind === 'success' || unchecked.kind === 'nodata') return { signed: false, state: 'bogus' };
    }
    return { signed: false, state: 'indeterminate', error: validated.kind };
  }

  function parseSpfTerms(spf) {
    return String(spf || '').trim().split(/\s+/).slice(1).map(function (raw) {
      var term = raw.toLowerCase();
      var qualifier = /^[+\-~?]/.test(term) ? term[0] : '+';
      if (qualifier !== '+') term = term.slice(1);
      var modifierAt = term.indexOf('=');
      if (modifierAt !== -1) return { raw: raw, name: term.slice(0, modifierAt), value: term.slice(modifierAt + 1), modifier: true };
      var mechanism = term.split(/[:/]/, 1)[0];
      var value = term.indexOf(':') === -1 ? '' : term.slice(term.indexOf(':') + 1).split('/')[0];
      return { raw: raw, name: mechanism, value: value, qualifier: qualifier, modifier: false };
    });
  }

  async function countSpfLookups(spf, domain, queryOpts) {
    var visited = new Set();
    var cycles = [];
    var voidLookups = 0;
    var indeterminate = false;

    async function walk(record, recordDomain, depth) {
      if (depth > 20) { indeterminate = true; return 0; }
      var terms = parseSpfTerms(record);
      var count = 0;
      for (var i = 0; i < terms.length; i++) {
        var term = terms[i];
        var causesLookup = (!term.modifier && ['include', 'a', 'mx', 'ptr', 'exists'].includes(term.name)) ||
          (term.modifier && term.name === 'redirect');
        if (!causesLookup) continue;
        count++;

        if ((term.name === 'include' || term.name === 'redirect') && term.value) {
          if (term.value.includes('%{')) { indeterminate = true; continue; }
          var child = term.value.toLowerCase().replace(/\.$/, '');
          var edge = recordDomain + '>' + child;
          if (visited.has(edge)) { cycles.push(child); continue; }
          visited.add(edge);
          var result = requireUsable(await dohFetch(child, 'TXT', queryOpts), child, 'TXT');
          var txts = result.answers.filter(function (a) { return a.type === 16; })
            .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
          var records = txts.filter(function (v) { return startsWithCI(v, 'v=spf1'); });
          if (!records.length) { voidLookups++; continue; }
          if (records.length > 1) { indeterminate = true; continue; }
          count += await walk(records[0], child, depth + 1);
        }
      }
      return count;
    }

    var count = await walk(spf, domain, 0);
    return {
      count: count,
      warning: count >= 8 && count <= 10,
      error: count > 10 || voidLookups > 2,
      voidLookups: voidLookups,
      cycles: cycles,
      indeterminate: indeterminate,
    };
  }


  /* ── SPF subnet size & redundancy ───────────────────────────────────────
     Two advisory checks over the ip4:/ip6:/a/mx mechanisms written directly
     into one record: how much address space each block authorizes, and which
     a/mx mechanisms only restate something a block already covers.

     Both are deliberately ownership-blind. Whether a /20 belongs to the
     domain owner or to a shared host is not answerable over DoH, and guessing
     would be worse than saying nothing, so this reports size and leaves the
     context to the reader. That is why nothing here reaches calcScore: it is
     reported, not graded.

     Sized against live records while this was written — irs.gov, github.com,
     bbc.co.uk and cloudflare.com all publish their own large blocks and all
     land in the top tier — so the top tier is worded as "review this", not
     as a fault.
     ──────────────────────────────────────────────────────────────────────── */

  var IP_FAMILY_BITS = { ipv4: 32, ipv6: 128 };

  function ipv4ToBigInt(text) {
    var parts = String(text).split('.');
    if (parts.length !== 4) return null;
    var value = 0n;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return null;
      var octet = Number(parts[i]);
      if (octet > 255) return null;
      value = (value << 8n) | BigInt(octet);
    }
    return value;
  }

  /**
   * Parse an IPv6 literal into one 128-bit BigInt, or null if it isn't one.
   *
   * Two things make this more than a split on ':'. `::` elides a run of zero
   * hextets, so the text has to be expanded to exactly 8 groups before any
   * arithmetic — splitting naively leaves `2001:db8::1` three groups short
   * and silently misaligns every bit of the address. And 128 bits does not
   * fit in a Number, which loses precision above 53, so this is BigInt from
   * end to end rather than anything that could round.
   */
  function ipv6ToBigInt(text) {
    var str = String(text);
    if (str.indexOf(':') === -1) return null;
    // RFC 4291 §2.2.3 allows the low 32 bits in dotted-quad form
    // (::ffff:192.0.2.1). Fold it into two hextets first.
    var embedded = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(str);
    if (embedded) {
      var v4 = ipv4ToBigInt(embedded[1]);
      if (v4 === null) return null;
      str = str.slice(0, embedded.index) +
        ((v4 >> 16n) & 0xffffn).toString(16) + ':' + (v4 & 0xffffn).toString(16);
    }
    var halves = str.split('::');
    if (halves.length > 2) return null;                       // '::' may appear once
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    var groups = head;
    if (halves.length === 2) {
      var fill = 8 - head.length - tail.length;
      if (fill < 0) return null;
      groups = head.concat(new Array(fill).fill('0'), tail);
    }
    if (groups.length !== 8) return null;
    var value = 0n;
    for (var i = 0; i < 8; i++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
      value = (value << 16n) | BigInt(parseInt(groups[i], 16));
    }
    return value;
  }

  /**
   * Parse `address` or `address/prefix` into { address, prefix, bits }.
   *
   * Returns null for anything malformed rather than throwing or guessing. A
   * bad prefix is not a /32: '/33', '/-1' and '/abc' all return null so the
   * caller drops that one mechanism and still audits the rest of the record.
   * An absent prefix is a single host — /32 for IPv4, /128 for IPv6.
   */
  function parseIpCidr(text, family) {
    var bits = IP_FAMILY_BITS[family];
    if (!bits) return null;
    var value = String(text || '');
    var prefix = bits;
    var slash = value.lastIndexOf('/');
    if (slash !== -1) {
      var suffix = value.slice(slash + 1);
      value = value.slice(0, slash);
      if (!/^\d{1,3}$/.test(suffix)) return null;
      prefix = Number(suffix);
      if (prefix > bits) return null;
    }
    var address = family === 'ipv6' ? ipv6ToBigInt(value) : ipv4ToBigInt(value);
    if (address === null) return null;
    return { address: address, prefix: prefix, bits: bits };
  }

  /** Is `address` inside `block`? Compare only the prefix bits of each. */
  function cidrContains(block, address) {
    if (block.prefix === 0) return true;
    var shift = BigInt(block.bits - block.prefix);
    return (block.address >> shift) === (address >> shift);
  }

  /**
   * Severity for one authorized block, by family.
   *
   * IPv4 is judged on host count, because blocks that size really are handed
   * to single organizations: a /24 is 256 addresses and it is unusual for a
   * sender to control that much space directly.
   *
   * IPv6 must NOT reuse that table. Allocation there is tier-based, not
   * host-count-based — RFC 4291 §2.5.4 makes /64 the standard single-subnet
   * allocation, frequently one mail server — while the 2^n reasoning that
   * makes an IPv4 /24 worth a look would rate that same /64 as eighteen
   * quintillion hosts and scream about it. nih.gov publishes four of them and
   * they are entirely unremarkable, which is the whole argument for a
   * separate table.
   */
  function classifySpfSubnet(prefix, family) {
    if (family === 'ipv6') {
      if (prefix >= 64) return 'LOW';      // /64 or tighter — one subnet at most
      if (prefix >= 48) return 'MEDIUM';   // multi-subnet / small site block
      return 'HIGH';                       // /47 and shorter — ISP/RIR scale
    }
    if (prefix >= 29) return 'LOW';        // 1–8 addresses
    if (prefix >= 25) return 'MEDIUM';     // 9–128 addresses
    return 'HIGH';                         // /24 and shorter — 256+
  }

  var SPF_IP_MECHANISM = /^(ip4|ip6):(.+)$/i;
  // `a` and `mx`, with the optional host and the optional dual-CIDR suffix
  // RFC 7208 §5.3 allows on both: a, mx, a:host, mx:host, a/24, mx:host//64.
  var SPF_HOST_MECHANISM = /^(a|mx)(?::([^/]+))?((?:\/\/?\d+)*)$/i;

  function stripSpfQualifier(raw) {
    var text = String(raw || '');
    return /^[+\-~?]/.test(text) ? text.slice(1) : text;
  }

  /**
   * Classify every ip4:/ip6: block in a record. Pure — no DNS, never throws.
   *
   * Split out from the redundancy half deliberately: a resolver failure
   * during redundancy resolution must not take the size findings down with
   * it, and these need no network at all.
   */
  function classifySpfSubnets(spf) {
    var blocks = { ipv4: [], ipv6: [] };
    var subnets = [];
    String(spf || '').trim().split(/\s+/).slice(1).forEach(function (raw) {
      var match = SPF_IP_MECHANISM.exec(stripSpfQualifier(raw));
      if (!match) return;
      var family = match[1].toLowerCase() === 'ip6' ? 'ipv6' : 'ipv4';
      var block = parseIpCidr(match[2], family);
      // A malformed mechanism drops itself out of the audit instead of
      // aborting it — the rest of the record is still worth reporting on.
      if (!block) return;
      blocks[family].push({ mechanism: raw, block: block });
      subnets.push({
        type: 'SPF_LARGE_SUBNET',
        severity: classifySpfSubnet(block.prefix, family),
        mechanism: raw,
        family: family,
        prefix: block.prefix,
      });
    });
    return { subnets: subnets, blocks: blocks };
  }

  /**
   * Find a/mx mechanisms whose resolved addresses an ip4:/ip6: block in the
   * same record already authorizes.
   *
   * Costs no DNS at all unless the record contains at least one ip4:/ip6:
   * block — with no block present nothing can be contained in one, so the
   * whole resolution phase is skipped. That keeps records built purely from
   * include: (google.com, apple.com, most of the sample) free.
   *
   * Scope is one record: nested IPs inside include: are not followed, and
   * ptr: is ignored outright (RFC 7208 §5.5 discourages its use).
   */
  async function findSpfRedundancy(spf, domain, blocks, queryOpts) {
    if (!blocks.ipv4.length && !blocks.ipv6.length) return [];

    var mechanisms = [];
    String(spf || '').trim().split(/\s+/).slice(1).forEach(function (raw) {
      var match = SPF_HOST_MECHANISM.exec(stripSpfQualifier(raw));
      // A dual-CIDR suffix widens the mechanism beyond the addresses it
      // resolves to — `mx/24` authorizes a /24 around every MX host — so
      // containment of the bare addresses would not prove it redundant.
      if (!match || match[3]) return;
      mechanisms.push({
        mechanism: raw,
        name: match[1].toLowerCase(),
        host: (match[2] || '').toLowerCase().replace(/\.$/, ''),
      });
    });

    var findings = [];
    var seen = new Set();
    for (var i = 0; i < mechanisms.length; i++) {
      var mech = mechanisms[i];
      // Bare `a`/`mx` and `a:host`/`mx:host` are separate checks, so the key
      // is the mechanism as written, not the name it happens to resolve.
      var key = mech.name + ':' + mech.host;
      if (seen.has(key)) continue;
      seen.add(key);

      var targets;
      if (mech.host) {
        targets = [mech.host];
      } else if (mech.name === 'a') {
        targets = [domain];
      } else {
        var mxRecords = await dohQuery(domain, 'MX', queryOpts);
        targets = mxRecords.map(function (record) {
          var parts = String(record).trim().split(/\s+/);
          return parts[parts.length - 1].replace(/\.$/, '').toLowerCase();
        }).filter(function (name) { return name && name !== '.'; });  // null MX authorizes nothing
      }

      var resolved = [];
      for (var j = 0; j < targets.length; j++) {
        var answers = await Promise.all([
          dohQuery(targets[j], 'A', queryOpts),
          dohQuery(targets[j], 'AAAA', queryOpts),
        ]);
        answers[0].forEach(function (text) { resolved.push({ family: 'ipv4', text: text }); });
        answers[1].forEach(function (text) { resolved.push({ family: 'ipv6', text: text }); });
      }
      if (!resolved.length) continue;

      var coveredBy = [];
      var covered = 0;
      resolved.forEach(function (entry) {
        var address = entry.family === 'ipv6' ? ipv6ToBigInt(entry.text) : ipv4ToBigInt(entry.text);
        if (address === null) return;
        // Families never cross-check: an IPv4 address is tested only against
        // ip4: blocks and an IPv6 address only against ip6:.
        var hit = blocks[entry.family].find(function (candidate) {
          return cidrContains(candidate.block, address);
        });
        if (!hit) return;
        covered++;
        if (coveredBy.indexOf(hit.mechanism) === -1) coveredBy.push(hit.mechanism);
      });

      if (!covered) continue;
      findings.push({
        type: 'SPF_REDUNDANCY',
        severity: 'LOW',
        mechanism: mech.mechanism,
        covered: covered,
        total: resolved.length,
        // This equality *is* the dual-stack rule: `full` requires every
        // resolved address in both families to have matched a same-family
        // block. A hostname with an AAAA record in a record carrying no ip6:
        // mechanism can never reach it, so "remove this" can never be advice
        // that silently drops IPv6 authorization.
        full: covered === resolved.length,
        coveredBy: coveredBy,
      });
    }
    return findings;
  }

  async function auditSpfSubnets(spf, domain, queryOpts) {
    var classified = classifySpfSubnets(spf);
    var redundancy = await findSpfRedundancy(spf, domain, classified.blocks, queryOpts);
    return { subnets: classified.subnets, redundancy: redundancy, unknown: false };
  }

  /* ── Scoring model ──────────────────────────────────────────────────────
     One weighted 0–100 rubric. Weights live here as data so they can be
     inspected, tested and tuned without touching the logic.

     Two pillars are deliberately asymmetric:
      • DMARC carries the most weight — it is the richest signal available and
        the only one that makes SPF and DKIM enforceable.
      • DNSSEC counts for points AND gates the A tier. An unsigned zone means
        every record above it can be spoofed, so it is not merely additive.
     ───────────────────────────────────────────────────────────────────────── */

  var WEIGHTS = {
    dmarc: 30, spf: 15, dkim: 15, dnssec: 15,
    caa: 10, mtaSts: 8, bimi: 4, tlsRpt: 3,
  };

  // Parked domains (an explicit null MX) are scored on a different rubric: DKIM, BIMI,
  // MTA-STS and TLS-RPT are meaningless without mail flow, so the weight
  // redistributes onto the checks that actually harden an unused domain.
  var PARKED_WEIGHTS = { spf: 30, dmarc: 30, dnssec: 25, caa: 15 };

  var GRADE_THRESHOLDS = [
    { min: 85, grade: 'A++', cls: 'score-aplusplus', requiresDnssec: true },
    { min: 75, grade: 'A+', cls: 'score-aplus', requiresDnssec: true },
    { min: 65, grade: 'A', cls: 'score-a', requiresDnssec: true },
    { min: 50, grade: 'B', cls: 'score-b', requiresDnssec: false },
    { min: 30, grade: 'C', cls: 'score-c', requiresDnssec: false },
    { min: 10, grade: 'D', cls: 'score-d', requiresDnssec: false },
    { min: 0, grade: 'F', cls: 'score-f', requiresDnssec: false },
  ];

  /**
   * DMARC sub-score, 0–30 (RFC 9989). Returns the component breakdown so the
   * UI can explain the number rather than just assert it.
   *
   * Changed from the RFC 7489 rubric: `pct` no longer earns points, because
   * RFC 9989 removed the tag and conformant receivers ignore it. Its four
   * points moved to `policy` (+2), `rua` (+1) and a new `uris` component (+1)
   * that pays for report destinations receivers can actually deliver to —
   * reporting is now standards-track in its own right (RFC 9990 / 9991), and
   * a record whose rua= is malformed is a monitoring blind spot.
   *
   * Test mode (`t=y`) scores at the `none` tier regardless of what p= says,
   * because receivers are explicitly told not to apply the policy.
   */
  function calcDmarcScore(d) {
    var parts = { policy: 0, subdomain: 0, rua: 0, alignment: 0, ruf: 0, uris: 0 };
    // 'present' = a record receivers cannot act on (bad v=, unrecognised p=,
    // duplicate tags). Worth no more than having no record at all.
    if (!d || d.status === 'missing' || d.status === 'present'
      || d.status === 'permerror' || d.status === 'unknown') {
      return { pts: 0, parts: parts };
    }

    // Score what receivers will actually do, not what the record claims.
    parts.policy = { reject: 12, quarantine: 8, none: 3 }[d.effectivePolicy || d.policy] || 0;

    // Score the EFFECTIVE subdomain posture, not whether sp/np are written out.
    // Absent tags inherit p, so `p=reject` alone protects subdomains fully.
    // Take the weaker of the two branches — security is the weakest link.
    // Test mode collapses the whole record to none, subdomains included.
    var subRank = d.testMode ? 0 : Math.min(
      POLICY_RANK[d.effectiveSp] !== undefined ? POLICY_RANK[d.effectiveSp] : 0,
      POLICY_RANK[d.effectiveNp] !== undefined ? POLICY_RANK[d.effectiveNp] : 0
    );
    parts.subdomain = [1, 4, 6][subRank] || 0;

    if (d.rua) parts.rua = 6;
    if (d.adkim === 's') parts.alignment += 1.5;
    if (d.aspf === 's') parts.alignment += 1.5;
    if (d.ruf) parts.ruf = 2;

    // Deliverable report destinations. Nothing published earns nothing; a
    // published-but-unparseable destination earns nothing either, which is the
    // point — it looks configured and silently is not.
    if (d.ruaUris && d.ruaUris.valid && (!d.ruf || (d.rufUris && d.rufUris.valid))) parts.uris = 1;

    var total = parts.policy + parts.subdomain + parts.rua + parts.alignment + parts.ruf + parts.uris;
    return { pts: Math.round(Math.min(WEIGHTS.dmarc, total)), parts: parts };
  }

  /**
   * SPF sub-score, 0–15.
   *
   * A record that exceeds the 10-lookup limit evaluates to permerror, which
   * receivers treat as a failure — so it scores zero regardless of how strict
   * the qualifier looks. Likewise `+all` and `?all` authorise everyone and are
   * worth nothing, while a missing provider include is a real record one line
   * short and keeps partial credit.
   */
  function calcSpfScore(spfStatus, advanced) {
    if (!spfStatus || spfStatus.status === 'missing' || spfStatus.status === 'permerror') return 0;
    if (advanced && advanced.spfLookups && advanced.spfLookups.error) return 0;

    var warnings = spfStatus.warnings || [];
    var worthless = warnings.indexOf('spf-all-permit') !== -1 || warnings.indexOf('spf-neutral') !== -1;
    if (worthless) return 0;

    if (spfStatus.status === 'ok') return WEIGHTS.spf;        // -all
    if (spfStatus.status === 'softfail') return 10;           // ~all
    return 8;                                                 // present, or missing include
  }

  function gradeFor(pts, dnssecSigned) {
    for (var i = 0; i < GRADE_THRESHOLDS.length; i++) {
      var tier = GRADE_THRESHOLDS[i];
      if (pts < tier.min) continue;
      if (tier.requiresDnssec && !dnssecSigned) continue;
      return { grade: tier.grade, cls: tier.cls };
    }
    return { grade: 'F', cls: 'score-f' };
  }

  function calcAdvScore(adv) {
    if (!adv) return null;
    const checks = [
      adv.bimi?.present,
      adv.mtaSts?.policyVerified,
      adv.tlsRpt?.present,
      adv.caa?.found,
      adv.dnssec?.signed,
    ];
    // A check whose lookup failed is neither done nor outstanding, so it comes
    // out of the denominator rather than counting against the domain.
    const unknown = [
      adv.bimi?.unknown,
      adv.mtaSts?.unknown,
      adv.tlsRpt?.unknown,
      adv.caa?.unknown,
      adv.dnssec?.state === 'indeterminate',
    ].filter(Boolean).length;
    return { done: checks.filter(Boolean).length, total: 5 - unknown, unknown: unknown };
  }

  /* ── Issues & suggestions ───────────────────────────────────────────── */

  // Each issue carries a key (→ locale lookup) and optional `args` used to
  // fill {0} placeholders in the translated message.
  function buildIssues({ emailProvider, spfStatus, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, wildcardApex, wildcardDkim, hosting, advanced, domain }) {
    const issues = [];

    // Reported by the depth that was actually measured. A wildcard only the
    // apex probe sees never reaches DKIM, and is often deliberate: Apple
    // publishes `*.apple.com IN TXT "v=spf1 redirect=_spf.apple.com"` so mail
    // from an invented subdomain meets a real SPF policy instead of none. Worth
    // reporting, not worth penalising.
    if (wildcardDkim) issues.push({ key: 'wildcard-txt-dkim', sev: 'warn' });
    else if (wildcardApex) issues.push({ key: 'wildcard-txt-apex', sev: 'info' });
    if (hosting === '@cname-loop') issues.push({ key: 'dns-loop', sev: 'crit' });
    if (emailProvider === '@none') issues.push({ key: 'no-mx', sev: 'crit' });
    if (emailProvider === '@implicit-mx') issues.push({ key: 'implicit-mx', sev: 'warn' });
    // Multiple-record failures come first: the fix ("delete the duplicate")
    // differs from the missing-record fix ("publish one"), and a domain in this
    // state must not also be told its record is absent.
    if (spfStatus.status === 'permerror') issues.push({ key: 'spf-multiple-records', sev: 'crit' });
    else if (spfStatus.status === 'missing') issues.push({ key: 'spf-missing', sev: 'crit' });

    // Content warnings are moot on a permerror — the record never evaluates, and
    // 'spf-multiple-records' is already raised above as critical. Re-pushing it
    // here would list the same finding twice at two severities.
    if (spfStatus.status !== 'permerror') {
      spfStatus.warnings.forEach(key => {
        issues.push({ key, sev: 'warn' });
      });
    }

    if (!dkimStatus.found && dkimStatus.confidence !== 'not-checked' && emailProvider !== '@none' && emailProvider !== '@null-mx' && emailProvider !== '@porkbun-forwarding') {
      // The note strings take the completed and failed selector counts. Carry
      // them on the issue: without them the renderer emits the raw "{0}"/"{1}"
      // placeholders, and a failed lookup now makes that note far more common.
      var testedCount = (dkimStatus.testedSelectors || []).length;
      var failedCount = (dkimStatus.failedSelectors || []).length;
      issues.push({
        key: dkimStatus.confidence === 'sampled' ? 'dkim-unverified' : 'dkim-missing',
        // An unfound selector now costs the full DKIM weight, so it is a
        // warning either way — 'info' was only defensible while the sampled
        // case went unscored.
        sev: 'warn',
        noteKey: dkimStatus.note,
        noteArgs: [testedCount - failedCount, failedCount],
      });
    }

    // Turning off "Check DKIM selectors" is a deliberate opt-out, so the guard
    // above correctly refuses to call it a missing record. But the pillar still
    // scores zero, and 15 points vanishing with nothing said about them is
    // worse than the grade range this replaced. Name the trade instead.
    if (dkimStatus.confidence === 'not-checked' && emailProvider !== '@none' && emailProvider !== '@null-mx' && emailProvider !== '@porkbun-forwarding') {
      issues.push({ key: 'dkim-not-checked', sev: 'info' });
    }
    /* Duplicate records are no longer a policy verdict, so the finding is
       raised from the walk's own evidence rather than from a `permerror`
       status that the Tree Walk never produces. It stays CRITICAL: publishing
       two records at one name makes every receiver ignore both, and an auditor
       that reported only "no DMARC record" would be describing the symptom
       instead of the cause.

       What changes is that the message must not lie. When a record higher in
       the tree still governs, the finding says the duplicate is ignored AND
       names the policy that actually applies — never "no DMARC policy
       applies", because one does. That is the entire point of the corrected
       walk. Hence two keys rather than one. */
    var observed = (dmarcDiscovery && dmarcDiscovery.observed) || [];
    var observedWhere = function (why) { return observed.filter(function (o) { return o.why === why; }); };
    var duplicates = observedWhere('multiple-at-step');
    if (duplicates.length) {
      issues.push(dmarcStatus.status === 'missing' || dmarcStatus.status === 'permerror'
        ? { key: 'dmarc-multiple-records', sev: 'crit', args: [duplicates[0].queryName] }
        : {
          key: 'dmarc-multiple-records-inherited', sev: 'crit',
          args: [duplicates[0].queryName, dmarcDiscovery.applied.foundAt, dmarcStatus.effectivePolicy || dmarcStatus.policy],
        });
    }
    if (dmarcStatus.status === 'unknown') {
      issues.push({
        key: 'dmarc-unverified', sev: 'warn',
        args: [(dmarcDiscovery && dmarcDiscovery.error) || 'dns-error'],
      });
    } else if (dmarcStatus.status === 'permerror' && !duplicates.length) issues.push({ key: 'dmarc-multiple-records', sev: 'crit', args: ['_dmarc.' + domain] });
    else if (dmarcStatus.status === 'missing' && !duplicates.length) issues.push({ key: 'dmarc-missing', sev: 'warn' });

    /* A misplaced or miscased v= tag is now diagnosed as misplaced rather than
       reported as absent. These never change the policy verdict — the record
       genuinely is not one a receiver will read — they change the message from
       "you have no DMARC record" to "you have a DMARC record that no receiver
       will read, and here is why". */
    var governed = !!(dmarcDiscovery && dmarcDiscovery.applied);
    var DIAGNOSIS_KEYS = {
      'version-not-first': 'dmarc-version-not-first',
      'version-bad-case': 'dmarc-version-bad-value',
      'version-absent': 'dmarc-version-missing',
    };
    Object.keys(DIAGNOSIS_KEYS).forEach(function (why) {
      var hits = observedWhere(why);
      // Name the DNS name the broken record is actually at. The walk visits up
      // to eight names, so the defect may well be at a parent the operator does
      // not control, and an unlocated "your record is malformed" sends them
      // looking in the wrong zone.
      if (hits.length) issues.push({ key: DIAGNOSIS_KEYS[why], sev: 'crit', args: [hits[0].queryName] });
    });

    /* A record on the apex is only critical when it is the operator's ONLY
       DMARC record. Alongside a working `_dmarc` record it is a leftover copy —
       untidy, not dangerous — and the critical text asserting that "the domain
       is treated as having no DMARC policy at all" would simply be false. Same
       rule as the duplicate finding above: the message must never claim no
       policy applies when one does. */
    var apex = observedWhere('at-apex-not-underscore');
    if (apex.length) {
      issues.push(governed
        ? { key: 'dmarc-at-apex-ignored', sev: 'info', args: [dmarcDiscovery.applied.foundAt] }
        : { key: 'dmarc-at-apex', sev: 'crit' });
    }
    if (dmarcStatus.status === 'warn' && dmarcStatus.policy === 'none') issues.push({ key: 'dmarc-none', sev: 'warn' });
    // p=quarantine is real enforcement, so this is a nudge rather than a defect —
    // reject is the end state, and nothing else surfaces that gap.
    if (dmarcStatus.status === 'ok' && dmarcStatus.policy === 'quarantine') issues.push({ key: 'dmarc-quarantine', sev: 'info' });
    // Test mode without reporting is the one combination that makes no sense
    // at all: t=y exists so you can watch the reports before enforcing.
    if ((dmarcStatus.status === 'ok' || dmarcStatus.testMode) && !dmarcStatus.rua) {
      issues.push({ key: 'dmarc-no-rua', sev: 'info' });
    }

    // Subdomain gaps only matter where the effective policy is genuinely weaker
    // than the organizational one — an absent sp/np inherits p and is fine.
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveSp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-sp', sev: 'warn', args: [dmarcStatus.effectiveSp, dmarcStatus.policy] });
    }
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveNp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-np', sev: 'warn', args: [dmarcStatus.effectiveNp, dmarcStatus.policy] });
    }

    /* ── RFC 9989 conformance ──────────────────────────────────────────────
       Severity here tracks consequence, not spec pedantry. A record receivers
       must ignore is critical; a policy that silently is not being applied is
       a warning; a tag that has simply stopped meaning anything is info.
       ───────────────────────────────────────────────────────────────────── */

    // v= absent, not first, or not exactly 'DMARC1' → the whole record MUST be
    // ignored (RFC 9989 §4.7). Since the Tree Walk's strict pass is
    // validateDmarcVersion() itself, no record with a bad v= is ever applied,
    // so that case now arrives through the diagnosis block above instead. What
    // is left here is a record receivers WILL read and cannot act on.
    if (dmarcStatus.status === 'present' && dmarcStatus.duplicateTags && dmarcStatus.duplicateTags.length) {
      issues.push({ key: 'dmarc-duplicate-tags', sev: 'crit', args: [dmarcStatus.duplicateTags.join(', ')] });
    } else if (dmarcStatus.status === 'present') {
      issues.push({ key: 'dmarc-invalid-policy', sev: 'crit' });
    }

    // t=y: receivers are told not to apply the policy. `p=reject; t=y` offers
    // exactly as much protection as p=none, so this is the headline finding
    // for such a record, not a footnote.
    if (dmarcStatus.testMode && dmarcStatus.status !== 'missing' && dmarcStatus.status !== 'permerror') {
      issues.push({ key: 'dmarc-test-mode', sev: dmarcStatus.policy === 'none' ? 'info' : 'warn', args: [dmarcStatus.policy] });
    }
    if (dmarcStatus.tValid === false) issues.push({ key: 'dmarc-bad-t', sev: 'warn' });

    /* Tag values that parse but are not what the operator wrote.
       normalizePolicy() and the alignment defaults both fall back silently,
       which is the correct RECEIVER behaviour and a poor auditor one: an
       `sp=rejcet` inherits p= and looks deliberate in the record. Report the
       divergence and name the value, without changing what receivers do. */
    if (dmarcStatus.spState === 'invalid') issues.push({ key: 'dmarc-bad-sp', sev: 'warn', args: [dmarcStatus.spRaw] });
    if (dmarcStatus.npState === 'invalid') issues.push({ key: 'dmarc-bad-np', sev: 'warn', args: [dmarcStatus.npRaw] });
    if (dmarcStatus.adkimState === 'invalid') issues.push({ key: 'dmarc-bad-adkim', sev: 'warn', args: [dmarcStatus.adkimRaw] });
    if (dmarcStatus.aspfState === 'invalid') issues.push({ key: 'dmarc-bad-aspf', sev: 'warn', args: [dmarcStatus.aspfRaw] });

    /* np= applies to NON-EXISTENT subdomains of the Organizational Domain
       (RFC 9989 §4.10.1). It was previously carried into the audited name's
       verdict without ever testing whether that name exists — and it plainly
       does, or the NS lookup would have returned NXDOMAIN. Say so, so the
       reported policy is explicable: the record's np= is real, it is simply
       not the branch that governs here. */
    if (dmarcStatus.inherited && dmarcExistence === 'yes' && dmarcStatus.npState !== 'absent'
      && POLICY_RANK[dmarcStatus.effectiveNp] !== POLICY_RANK[dmarcStatus.effectiveSp]) {
      issues.push({ key: 'dmarc-np-not-applied', sev: 'info', args: [dmarcStatus.effectiveNp, dmarcStatus.effectiveSp] });
    }

    // pct= was removed by RFC 9989. "This tag is obsolete, remove it" is advice
    // rather than a defect, so it is raised as a recommendation (see
    // buildSuggestions) and not repeated here. What DOES belong here is the
    // subset with a live consequence: a pct that receivers still on RFC 7489
    // will act on differently from receivers that have migrated.
    if (dmarcStatus.pctPresent && dmarcStatus.enforcing && dmarcStatus.pctValid && dmarcStatus.pct < 100) {
      issues.push({ key: 'dmarc-partial-pct', sev: 'warn', args: [dmarcStatus.pct, 100 - dmarcStatus.pct] });
    }
    if (dmarcStatus.status !== 'missing' && !dmarcStatus.pctValid) {
      issues.push({ key: 'dmarc-bad-pct', sev: 'warn' });
    }

    // Report destinations that will not receive anything.
    if (dmarcStatus.rua && dmarcStatus.ruaUris && !dmarcStatus.ruaUris.valid) {
      issues.push({ key: 'dmarc-rua-invalid', sev: 'warn', args: [dmarcStatus.ruaUris.invalid.join(', ')] });
    }
    if (dmarcStatus.ruf && dmarcStatus.rufUris && !dmarcStatus.rufUris.valid) {
      issues.push({ key: 'dmarc-ruf-invalid', sev: 'warn', args: [dmarcStatus.rufUris.invalid.join(', ')] });
    }
    // fo= is defined only alongside ruf=; without it, receivers MUST ignore it.
    if (dmarcStatus.foPresent && !dmarcStatus.ruf) issues.push({ key: 'dmarc-fo-without-ruf', sev: 'info' });
    if (dmarcStatus.foValid === false) issues.push({ key: 'dmarc-bad-fo', sev: 'warn' });

    /* Reports sent outside the organizational domain need the destination to
       authorize them (RFC 9990 §4), or conformant receivers drop them
       silently. Authorization is per URI, so this reports per destination —
       one unauthorized vendor does not invalidate the record or stop reports
       reaching the other destinations.

       When the lookup ran, say only what it found: a domain whose vendor has
       published the record correctly should hear nothing at all. The blanket
       "verify this" notice is the fallback for when the check did not run. */
    // Resolved by analyzeDomain with a Tree Walk per destination (RFC 9990 §4).
    // The fallback keeps buildIssues callable on its own in tests, where no
    // walk has run and every destination is compared against the bare name.
    var externalReports = externalReportDestinations || findExternalReportDestinations(dmarcStatus, domain);
    if (externalReports.length) {
      var reportAuth = advanced && advanced.reportAuth;
      if (reportAuth && reportAuth.length) {
        var unauthorized = reportAuth.filter(function (r) { return r.state === 'unauthorized'; });
        var unverifiable = reportAuth.filter(function (r) { return r.state === 'unverifiable'; });
        if (unauthorized.length) {
          issues.push({
            key: 'dmarc-external-unauthorized', sev: 'warn',
            args: [unauthorized.map(function (r) { return r.destination; }).join(', ')],
          });
        }
        if (unverifiable.length) {
          issues.push({
            key: 'dmarc-external-unverifiable', sev: 'info',
            args: [unverifiable.map(function (r) { return r.destination; }).join(', ')],
          });
        }
      } else {
        issues.push({ key: 'dmarc-external-reporting', sev: 'info', args: [externalReports.join(', ')] });
      }
    }

    if (dmarcStatus.psdValid === false) issues.push({ key: 'dmarc-bad-psd', sev: 'warn' });
    if (dmarcStatus.psd === 'y' && domain && getOrganizationalDomain(domain) === domain) {
      issues.push({ key: 'dmarc-psd-invalid', sev: 'warn' });
    }
    if (dmarcStatus.removedTags && dmarcStatus.removedTags.length) {
      var stillRemoved = dmarcStatus.removedTags.filter(function (k) { return k !== 'pct'; });
      if (stillRemoved.length) issues.push({ key: 'dmarc-removed-tags', sev: 'info', args: [stillRemoved.join(', ')] });
    }
    if (dmarcStatus.unknownTags && dmarcStatus.unknownTags.length) {
      issues.push({ key: 'dmarc-unknown-tags', sev: 'info', args: [dmarcStatus.unknownTags.join(', ')] });
    }
    if (emailProvider === '@porkbun-forwarding') issues.push({ key: 'porkbun-forward', sev: 'warn' });

    // Silently-inactive controls: configured, believed working, not working.
    if (advanced?.mtaSts?.multiple) issues.push({ key: 'mta-sts-multiple-records', sev: 'warn' });
    else if (advanced?.mtaSts?.advertised && !advanced.mtaSts.present) issues.push({ key: 'mta-sts-invalid', sev: 'warn' });
    else if (advanced?.mtaSts?.present && !advanced.mtaSts.policyVerified) issues.push({ key: 'mta-sts-policy-unverified', sev: 'info' });
    if (advanced?.tlsRpt?.multiple) issues.push({ key: 'tls-rpt-multiple-records', sev: 'warn' });
    else if (advanced?.tlsRpt?.advertised && !advanced.tlsRpt.present) issues.push({ key: 'tls-rpt-invalid', sev: 'warn' });
    if (advanced?.bimi?.multiple) issues.push({ key: 'bimi-multiple-records', sev: 'warn' });
    else if (advanced?.bimi?.advertised && !advanced.bimi.present) issues.push({ key: 'bimi-invalid', sev: 'warn' });
    if (dkimStatus?.duplicated?.length) {
      issues.push({ key: 'dkim-multiple-records', sev: 'warn', args: [dkimStatus.duplicated.join(', ')] });
    }

    if (advanced?.spfLookups?.error) {
      issues.push({ key: 'spf-over-limit', sev: 'crit', args: [advanced.spfLookups.count] });
    } else if (advanced?.spfLookups?.warning) {
      issues.push({ key: 'spf-near-limit', sev: 'warn', args: [advanced.spfLookups.count] });
    }
    if (advanced?.spfLookups?.cycles?.length) issues.push({ key: 'spf-cycle', sev: 'crit', args: [advanced.spfLookups.cycles.join(', ')] });

    // Advisory only — none of this moves the score (see calcScore). Severity
    // here is deliberately below the spec's own HIGH/MEDIUM labels, which the
    // structured findings still carry: a large block is a thing to look at,
    // not a misconfiguration. irs.gov, github.com, bbc.co.uk and
    // cloudflare.com all publish one, and putting them on the same line as
    // "no SPF record" would teach people to ignore the critical list.
    //
    // Grouped one line per tier rather than one per mechanism. Per-mechanism
    // lines drown the report: stanford.edu publishes 15 ip4: mechanisms and
    // nih.gov six medium blocks, and the single-host ones say nothing at all,
    // so the LOW tier is classified but never surfaced as an issue.
    if (advanced?.spfSubnets) {
      const subnets = advanced.spfSubnets.subnets || [];
      const large = subnets.filter(s => s.severity === 'HIGH').map(s => s.mechanism);
      const medium = subnets.filter(s => s.severity === 'MEDIUM').map(s => s.mechanism);
      if (large.length) issues.push({ key: 'spf-large-subnet', sev: 'warn', args: [large.join(', ')] });
      if (medium.length) issues.push({ key: 'spf-medium-subnet', sev: 'info', args: [medium.join(', ')] });

      // Removing one a/mx mechanism frees exactly one of the 10 lookups, so
      // the advice is worth much more next to the current count than alone.
      const lookups = advanced.spfLookups;
      const counted = lookups && !lookups.unknown && !lookups.indeterminate ? lookups.count : null;
      (advanced.spfSubnets.redundancy || []).forEach(finding => {
        if (!finding.full) {
          issues.push({ key: 'spf-partial-coverage', sev: 'info', args: [finding.covered, finding.total, finding.mechanism] });
        } else if (counted === null) {
          issues.push({ key: 'spf-redundant-mechanism-nocount', sev: 'info', args: [finding.mechanism, finding.coveredBy.join(', ')] });
        } else {
          issues.push({ key: 'spf-redundant-mechanism', sev: 'info', args: [finding.mechanism, finding.coveredBy.join(', '), counted, counted - 1] });
        }
      });
    }
    if (advanced?.spfLookups?.indeterminate) issues.push({ key: 'spf-indeterminate', sev: 'info' });
    if (advanced?.dnssec?.state === 'bogus') issues.push({ key: 'dnssec-bogus', sev: 'crit' });
    else if (advanced?.dnssec?.state === 'indeterminate') issues.push({ key: 'dnssec-indeterminate', sev: 'warn' });

    // Name the checks that could not be completed. An audit that quietly omits
    // a control looks identical to one where the control is fine, so the gap
    // has to be stated rather than left to the reader to notice. These now
    // score zero rather than sitting outside the grade, which is why this is a
    // warning: points were actually lost, and a re-run is what recovers them.
    var unverified = [];
    if (advanced?.caa?.unknown) unverified.push('CAA');
    if (advanced?.mtaSts?.unknown) unverified.push('MTA-STS');
    if (advanced?.tlsRpt?.unknown) unverified.push('TLS-RPT');
    if (advanced?.bimi?.unknown) unverified.push('BIMI');
    if (advanced?.spfLookups?.unknown) unverified.push('SPF');
    if (hosting === '@dns-error') unverified.push('Website');
    if (unverified.length) {
      issues.push({ key: 'checks-unverified', sev: 'warn', args: [unverified.join(', ')] });
    }

    return issues;
  }

  // `guide` names the Learn more page to link to (see locales → learnMore).
  function buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    const tips = [];

    // Deliberately ahead of the `advanced` guard: this one is derived from the
    // DMARC record alone, so it must still surface when the advanced checks
    // are switched off. RFC 9989 removed pct= outright — there is no valid
    // value any more, so the recommendation is always "remove it", whatever
    // the number says.
    if (dmarcStatus && dmarcStatus.pctPresent && dmarcStatus.status !== 'missing') {
      tips.push({ key: 'dmarc-pct-obsolete', guide: 'dmarc-rfc9989' });
    }

    if (!advanced) return tips;

    const hasEmail = emailProvider !== '@none' && emailProvider !== '@null-mx';
    const dmarcEnforced = dmarcStatus.status === 'ok' && (dmarcStatus.policy === 'quarantine' || dmarcStatus.policy === 'reject');

    // Every tip below says "you do not have this — add it". None of them may
    // fire on a check whose lookup failed, because we do not know whether the
    // record is there. Telling someone to publish a record they already have
    // is worse than saying nothing.
    if (advanced.bimi?.unknown) { /* not verified — cannot advise */ }
    else if (advanced.bimi?.multiple) { /* duplicate already raised as an issue */ }
    else if (!advanced.bimi?.present && dmarcEnforced && dkimStatus.found) tips.push({ key: 'bimiEligible', guide: 'bimi' });
    else if (!advanced.bimi?.present && hasEmail) tips.push({ key: 'bimiPrereq', guide: 'bimi' });

    // Skip the "not configured" tip when the record exists but is duplicated —
    // buildIssues already raises the duplicate, and telling someone to publish
    // a record they already have twice is actively confusing.
    if (!advanced.mtaSts?.unknown && !advanced.mtaSts?.present && !advanced.mtaSts?.multiple && hasEmail) tips.push({ key: 'mta-sts', guide: 'mta-sts' });
    if (!advanced.tlsRpt?.unknown && !advanced.tlsRpt?.present && !advanced.tlsRpt?.multiple && hasEmail) tips.push({ key: 'tls-rpt', guide: 'tls-rpt' });
    if (!advanced.caa?.unknown && !advanced.caa?.found) tips.push({ key: 'caa', guide: 'caa' });
    if (advanced.dnssec?.state !== 'indeterminate' && !advanced.dnssec?.signed) tips.push({ key: 'dnssec', guide: 'dnssec' });

    return tips;
  }

  /* ── Scoring ────────────────────────────────────────────────────────── */

  /**
   * Pillars that scored zero because this audit could not verify them, rather
   * than because the control is genuinely absent.
   *
   * This changes no score. The zero stands, the grade is a single letter, and
   * `pts` is unaffected — it exists so the UI can mark the grade as resting on
   * a check that a re-run or an extra selector could still settle. Without it
   * that fact lives only inside the expanded detail panel, which nobody opens
   * across a 200-domain table.
   *
   * SPF is deliberately absent: an unknown lookup *count* does not zero the SPF
   * pillar (see calcSpfScore), so there is no lost point to recover there.
   */
  function unprovenPillars(dkimStatus, advanced, dmarcStatus) {
    var out = [];
    // A DMARC pillar zeroed because the walk could not complete is unproven,
    // not absent. Without this the grade rests on a check that never ran and
    // says so nowhere — the exact gap 'dkim-unverified' exists to close.
    if (dmarcStatus && dmarcStatus.status === 'unknown') out.push('dmarc');
    if (dkimStatus && !dkimStatus.found &&
      (dkimStatus.confidence === 'sampled' || dkimStatus.confidence === 'not-checked')) out.push('dkim');
    if (advanced && advanced.dnssec && advanced.dnssec.state === 'indeterminate') out.push('dnssec');
    if (advanced && advanced.caa && advanced.caa.unknown) out.push('caa');
    if (advanced && advanced.mtaSts && advanced.mtaSts.unknown) out.push('mtaSts');
    if (advanced && advanced.bimi && advanced.bimi.unknown) out.push('bimi');
    if (advanced && advanced.tlsRpt && advanced.tlsRpt.unknown) out.push('tlsRpt');
    return out;
  }

  function calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    // A wildcard TXT record no longer scores an instant F. The furthest it can
    // reach is DKIM discovery, and SPF, DMARC, DNSSEC and CAA stay perfectly
    // measurable underneath it. A poisoned _domainkey leaves DKIM unproven,
    // which scores zero like every other unproven control here.
    var dnssecSigned = !!(advanced && advanced.dnssec && advanced.dnssec.signed);
    var dmarc = calcDmarcScore(dmarcStatus);

    // ── Parked / no-email domain ────────────────────────────────────────
    // Scored on PARKED_WEIGHTS: a domain that will never send mail is hardened
    // by refusing it outright (null MX + SPF -all + DMARC reject), so it can
    // legitimately reach the A tier. DKIM/BIMI/MTA-STS/TLS-RPT are excluded
    // because they cannot apply.
    if (emailProvider === '@null-mx') {
      var parkedSpf = 0;
      if (spfStatus.status === 'ok') parkedSpf = PARKED_WEIGHTS.spf;          // -all blocks
      else if (spfStatus.status !== 'missing') parkedSpf = 15;                // record, not blocking

      // Test mode collapses to none here too — a parked domain publishing
      // p=reject; t=y is not actually refusing anything.
      var parkedDmarc = { reject: 30, quarantine: 20, none: 8 }[dmarcStatus.effectivePolicy || dmarcStatus.policy] || 0;
      if (dmarcStatus.status === 'missing') parkedDmarc = 0;

      var parkedPillars = [
        { key: 'spf', pts: parkedSpf, max: PARKED_WEIGHTS.spf },
        { key: 'dmarc', pts: parkedDmarc, max: PARKED_WEIGHTS.dmarc },
        { key: 'dnssec', pts: dnssecSigned ? PARKED_WEIGHTS.dnssec : 0, max: PARKED_WEIGHTS.dnssec },
        { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? PARKED_WEIGHTS.caa : 0, max: PARKED_WEIGHTS.caa },
      ];
      var parkedPts = parkedPillars.reduce(function (sum, p) { return sum + p.pts; }, 0);
      var parkedGrade = gradeFor(parkedPts, dnssecSigned);
      var parkedKeys = parkedPillars.map(function (p) { return p.key; });

      return {
        grade: parkedGrade.grade, cls: parkedGrade.cls,
        pts: parkedPts, max: 100, parked: true,
        // DKIM is not a parked pillar, so an unproven DKIM check cannot mark a
        // parked grade — there were no points to lose.
        unproven: unprovenPillars(dkimStatus, advanced, dmarcStatus).filter(function (k) { return parkedKeys.indexOf(k) !== -1; }),
        breakdown: { pillars: parkedPillars, dmarc: dmarc.parts },
      };
    }

    // ── Active email domain ─────────────────────────────────────────────
    // A control this audit could not prove scores zero, exactly like a control
    // that is genuinely absent. The alternative — leaving it unscored and
    // reporting a floor–ceiling grade range — reads as an error rather than a
    // result, and the two-letter grade told nobody what to do next. The cost of
    // that honesty is that a failed lookup now costs real points, so every
    // unproven control has an issue attached saying so and how to fix it:
    // 'dkim-unverified', 'dkim-not-checked', 'dnssec-indeterminate' and
    // 'checks-unverified' in buildIssues().
    var pillars = [
      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },
      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },
      { key: 'dkim', pts: dkimStatus && dkimStatus.found ? WEIGHTS.dkim : 0, max: WEIGHTS.dkim },
      { key: 'dnssec', pts: dnssecSigned ? WEIGHTS.dnssec : 0, max: WEIGHTS.dnssec },
      { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? WEIGHTS.caa : 0, max: WEIGHTS.caa },
      { key: 'mtaSts', pts: (advanced && advanced.mtaSts && advanced.mtaSts.present && advanced.mtaSts.policyVerified !== false) ? WEIGHTS.mtaSts :
        (advanced && advanced.mtaSts && advanced.mtaSts.present) ? WEIGHTS.mtaSts / 2 : 0, max: WEIGHTS.mtaSts },
      { key: 'bimi', pts: (advanced && advanced.bimi && advanced.bimi.present) ? WEIGHTS.bimi : 0, max: WEIGHTS.bimi },
      { key: 'tlsRpt', pts: (advanced && advanced.tlsRpt && advanced.tlsRpt.present) ? WEIGHTS.tlsRpt : 0, max: WEIGHTS.tlsRpt },
    ];

    var pts = pillars.reduce(function (sum, p) { return sum + (p.pts || 0); }, 0);
    var graded = gradeFor(pts, dnssecSigned);

    return {
      grade: graded.grade, cls: graded.cls,
      pts: pts, max: 100, parked: false,
      unproven: unprovenPillars(dkimStatus, advanced, dmarcStatus),
      breakdown: { pillars: pillars, dmarc: dmarc.parts },
    };
  }

  /* ── Orchestrated per-domain audit ──────────────────────────────────── */

  async function analyzeDomain(domain, opts) {
    const d = domain.toLowerCase().trim();
    const queryOpts = { signal: opts.signal };

    // Probe NS first — NXDOMAIN (Status 3) means the domain isn't registered
    const nsResult = await dohFetch(d, 'NS', queryOpts);
    requireUsable(nsResult, d, 'NS');
    const ns = nsResult.answers.filter(a => a.type === 2).map(a => a.data.replace(/^"|"$/g, '').trim());
    if (nsResult.status === 3) {
      return { domain: d, unregistered: true, error: false };
    }

    const [mx, txt, aRec, aaaaRec] = await Promise.all([
      dohQuery(d, 'MX', queryOpts),
      dohQuery(d, 'TXT', queryOpts),
      dohQuery(d, 'A', queryOpts),
      dohQuery(d, 'AAAA', queryOpts),
    ]);

    const dnsProvider = detectDNSProvider(ns, d);
    const emailProvider = detectEmailProvider(mx, d, aRec.concat(aaaaRec));
    // Count matches rather than .find() — every one of these record types
    // fails closed when more than one exists (see the multiple-record checks
    // in buildIssues), so the count is part of the signal, not noise.
    const spfMatches = txt.filter(v => startsWithCI(v, 'v=spf1'));
    const spfRecord = spfMatches[0] || '';
    const spfMultiple = spfMatches.length > 1;
    const spfStatus = analyzeSpf(spfRecord, emailProvider, spfMultiple);
    const verifications = txt.filter(v => startsWithCI(v, 'google-site-verification') || startsWithCI(v, 'apple-domain'));

    // RFC 9989 §4.10 Tree Walk. This replaces the two-query PSL approximation:
    // one query at _dmarc.<domain>, and on a miss one more at the name the
    // vendored Public Suffix List picked. No DMARC decision consults the PSL
    // after this release (OQ-DMARC-04); the vendored list stays only for the
    // hosting and provider heuristics.
    const dmarcDiscovery = await discoverDmarc(d, queryOpts, { apexTxt: txt });
    // §3.2.13 and Appendix A.4: existence is a property of the name. The NS
    // response above already answers it — NXDOMAIN returned early as
    // unregistered, so anything reaching here resolved without one — so this
    // costs no extra query.
    const dmarcExistence = existenceFromResponse(nsResult);
    const dmarcRecord = dmarcDiscovery.applied ? dmarcDiscovery.applied.record : '';
    const dmarcAtDomain = dmarcDiscovery.applied ? dmarcDiscovery.applied.foundAt : d;
    const organizationalDomain = dmarcDiscovery.organizationalDomain;
    // Duplicates are no longer a policy verdict. RFC 9989 §4.10 step 2 discards
    // them and the walk continues, so a record higher in the tree still
    // applies; the duplicate survives as `observed[]` evidence and buildIssues
    // raises it from there, still critical. `multiple` therefore stays false
    // here — passing true would resurrect the permerror it replaces.
    // A walk that ended in a transient DNS error examined nothing conclusive:
    // the record could not be read, so the honest verdict is 'unknown'. Letting
    // it fall through to analyzeDmarc('') would report 'missing' — telling the
    // operator their domain is spoofable on the strength of our own failed
    // lookup. This is optionalCheck()'s rule applied to the core path.
    const dmarcUnverified = dmarcDiscovery.terminated === 'error' && !dmarcDiscovery.applied;
    const dmarcStatus = dmarcUnverified
      ? emptyDmarcStatus('unknown')
      : applyInheritance(analyzeDmarc(dmarcRecord, false), dmarcDiscovery, dmarcExistence);
    // The externality test in RFC 9990 §4 is defined against Organizational
    // Domains, which now means walked ones on both sides.
    // The walked map exists to answer RFC 9990 §4's externality test. Compare
    // against the Organizational Domain of the name the policy was FOUND at,
    // not the audited name's — under a PSD those differ, and pairing a policy
    // domain with someone else's organizational domain records a relationship
    // that does not hold.
    const policyOrgDomain = dmarcDiscovery.applied && dmarcDiscovery.applied.inherited
      ? (await optionalCheck(function () { return discoverDmarc(dmarcAtDomain, queryOpts); }, null) || {}).organizationalDomain || organizationalDomain
      : organizationalDomain;
    const dmarcOrgDomains = await resolveDestinationOrgDomains(
      dmarcStatus, dmarcAtDomain, policyOrgDomain, queryOpts
    );
    const externalReportDestinations = findExternalReportDestinations(dmarcStatus, dmarcAtDomain, dmarcOrgDomains);

    // Wildcard TXT synthesis is measured at both depths that matter, because
    // only the deeper one predicts harm. The apex probe (one label) shows a
    // `* IN TXT` record exists. The _domainkey probe (two labels) shows whether
    // that synthesis actually reaches DKIM selector names — the only lookup a
    // wildcard can poison, because selector names are unpredictable and carry
    // no version prefix to filter on. Every other check here matches a version
    // prefix (v=DMARC1, v=STSv1, v=BIMI1, v=spf1) and discards a stray wildcard
    // string on its own.
    //
    // The depth is measured rather than inferred. RFC 4592 2.2.1 stops
    // synthesis below an existing node, which protects any domain publishing
    // _domainkey, but not every nameserver honours that — so only the probe is
    // authoritative.
    //
    // A failed probe must not read as "no wildcard", so each depth stays false
    // until its own probe returns.
    let wildcardApex = false;
    let wildcardDkim = false;
    let wildcardDkimRecords = [];
    if (opts.wildcard) {
      const [apexProbe, dkimProbe] = await Promise.all([
        optionalCheck(() => dohQuery(`_wildcardtest99xyz.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_wildcardtest99xyz._domainkey.${d}`, 'TXT', queryOpts), null),
      ]);
      wildcardApex = apexProbe !== null && apexProbe.length > 0;
      wildcardDkim = dkimProbe !== null && dkimProbe.length > 0;
      wildcardDkimRecords = wildcardDkim ? dkimProbe : [];
    }

    let dkimStatus = { found: false, selectors: [], testedSelectors: [], confidence: 'not-checked', note: '' };
    if (opts.dkim && emailProvider !== '@none' && emailProvider !== '@null-mx') {
      dkimStatus = await checkDKIM(d, { dkim: wildcardDkim, records: wildcardDkimRecords }, opts.selectors, emailProvider, opts.dkimComprehensive, spfRecord, queryOpts);
    }

    let hosting = '@dash';
    if (opts.www) {
      const website = await optionalCheck(
        () => resolveWebsite(d, queryOpts),
        error => ({ loop: false, chain: [], addresses: [], error: (error && error.kind) || 'dns-error' })
      );
      hosting = website.error ? '@dns-error'
        : website.loop ? '@cname-loop'
          : detectHosting(website.addresses, website.chain, d);
    }

    // ── Advanced checks ──
    let advanced = { bimi: null, mtaSts: null, tlsRpt: null, caa: null, dnssec: null, spfLookups: null, spfSubnets: null, reportAuth: null };
    if (opts.advanced) {
      // Every entry is wrapped independently. Promise.all rejects on the first
      // failure, so without this one unlucky lookup would take the other six
      // down with it and abort the audit.
      const [bimiTxt, mtaStsTxt, tlsRptTxt, caaResult, dnssecResult, spfLookups, spfSubnets, reportAuth] = await Promise.all([
        optionalCheck(() => dohQuery(`default._bimi.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_mta-sts.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_smtp._tls.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => checkCAA(d, queryOpts),
          error => ({ found: false, records: [], atDomain: null, unknown: true, error: (error && error.kind) || 'dns-error' })),
        checkDNSSEC(d, queryOpts),
        spfRecord
          ? optionalCheck(() => countSpfLookups(spfRecord, d, queryOpts),
            error => ({ count: 0, warning: false, error: false, voidLookups: 0, cycles: [], indeterminate: true, unknown: true, queryError: (error && error.kind) || 'dns-error' }))
          : Promise.resolve({ count: 0, warning: false, error: false, voidLookups: 0, cycles: [], indeterminate: false }),
        // The size half of this needs no DNS, so a resolver failure during
        // the redundancy half falls back to the size findings alone rather
        // than discarding both.
        spfRecord
          ? optionalCheck(() => auditSpfSubnets(spfRecord, d, queryOpts),
            () => ({ subnets: classifySpfSubnets(spfRecord).subnets, redundancy: [], unknown: true }))
          : Promise.resolve({ subnets: [], redundancy: [], unknown: false }),
        optionalCheck(() => checkExternalReportAuth(dmarcAtDomain, externalReportDestinations, queryOpts), []),
      ]);

      // All three specs say the same thing: filter to the versioned records,
      // and if the result isn't exactly one, treat the domain as not having
      // the feature at all (RFC 8461 §3.1, RFC 8460 §3, BIMI draft §7.2).
      // So `present` is false when duplicated — the operator believes the
      // control is active when it is not, which is worth saying out loud.
      // A null here is a lookup that failed, not a domain without the record.
      // `unknown` carries that distinction through to scoring and the UI so an
      // unverified control is never presented as an absent one.
      const bimiMatches = bimiTxt ? bimiTxt.filter(v => startsWithCI(v, 'v=BIMI1')) : [];
      const mtaMatches = mtaStsTxt ? mtaStsTxt.filter(v => startsWithCI(v, 'v=STSv1')) : [];
      const tlsMatches = tlsRptTxt ? tlsRptTxt.filter(v => startsWithCI(v, 'v=TLSRPTv1')) : [];

      const bimiRecord = bimiMatches[0] || '';
      const mtaRecord = mtaMatches[0] || '';
      const tlsRecord = tlsMatches[0] || '';
      const bimiValidation = validateBimiRecord(bimiRecord);
      const mtaValidation = validateMtaStsRecord(mtaRecord);
      const tlsValidation = validateTlsRptRecord(tlsRecord);

      advanced = {
        bimi: { present: bimiMatches.length === 1 && bimiValidation.valid, advertised: bimiMatches.length === 1, record: bimiRecord, validation: bimiValidation, multiple: bimiMatches.length > 1, unknown: bimiTxt === null },
        mtaSts: { present: mtaMatches.length === 1 && mtaValidation.valid, advertised: mtaMatches.length === 1, policyVerified: false, record: mtaRecord, validation: mtaValidation, multiple: mtaMatches.length > 1, unknown: mtaStsTxt === null },
        tlsRpt: { present: tlsMatches.length === 1 && tlsValidation.valid, advertised: tlsMatches.length === 1, record: tlsRecord, validation: tlsValidation, multiple: tlsMatches.length > 1, unknown: tlsRptTxt === null },
        caa: caaResult,
        dnssec: dnssecResult,
        spfLookups,
        spfSubnets,
        reportAuth,
      };
    }

    const issues = buildIssues({ emailProvider, spfStatus, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, wildcardApex, wildcardDkim, hosting, advanced, domain: d });
    const suggestions = buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const score = calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const advScore = opts.advanced ? calcAdvScore(advanced) : null;

    return {
      domain: d, ns, mx, txt, aRec, aaaaRec, dnsProvider, emailProvider,
      spfRecord, spfStatus, dmarcRecord, dmarcStatus, dmarcDiscovery, dmarcExistence,
      // Retained as an alias of dmarcDiscovery.applied.foundAt for one release
      // so the CSV export and the saved report keep working, then removed.
      dmarcAtDomain, organizationalDomain, dkimStatus,
      wildcardApex, wildcardDkim, hosting, verifications, advanced, advScore,
      issues, suggestions, score,
    };
  }

  global.DnsAudit = {
    DOH,
    DKIM_SELECTORS,
    buildDkimSelectorList,
    catalogSelectors,
    spfSelectorSources,
    spfReferencedCatalogKeys,
    isRecognizedDkimSelector,
    checkDKIM,
    dkimKeyRecords,
    analyzeDomain,
    checkConnectivity,
    dohFetch,
    // exported for unit testing / reuse
    detectDNSProvider,
    detectEmailProvider,
    isNullMx,
    detectHosting,
    getOrganizationalDomain,
    analyzeSpf,
    analyzeDmarc,
    parseDmarcTag,
    validateDmarcVersion,
    parseDmarcUriList,
    findExternalReportDestinations,
    resolveDestinationOrgDomains,
    checkExternalReportAuth,
    discoverDmarc,
    dmarcWalkTargets,
    isDmarcPolicyRecord,
    diagnoseDmarcRecord,
    selectOrganizationalDomain,
    selectAppliedRecord,
    applyInheritance,
    domainExists,
    optionalCheck,
    startsWithCI,
    countSpfLookups,
    parseSpfTerms,
    ipv4ToBigInt,
    ipv6ToBigInt,
    parseIpCidr,
    cidrContains,
    classifySpfSubnet,
    classifySpfSubnets,
    findSpfRedundancy,
    auditSpfSubnets,
    validateMtaStsRecord,
    validateTlsRptRecord,
    validateBimiRecord,
    calcScore,
    calcDmarcScore,
    calcSpfScore,
    gradeFor,
    buildIssues,
    buildSuggestions,
    WEIGHTS,
    PARKED_WEIGHTS,
    GRADE_THRESHOLDS,
    POLICY_RANK,
    DMARC_TAGS_RFC9989,
    DMARC_TAGS_REMOVED,
  };
})(window);
