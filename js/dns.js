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
  var dohCache = new Map();
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
    if (!opts.noCache && dohCache.has(key)) return dohCache.get(key);
    var result;
    var retries = opts.retries ?? DOH_RETRIES;
    for (var attempt = 0; attempt <= retries; attempt++) {
      result = await fetchDohOnce(normalizedName, type, opts);
      if (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain' || result.kind === 'cancelled') break;
      if (attempt < retries) await new Promise(function (resolve) { setTimeout(resolve, 150 * (attempt + 1)); });
    }
    if (!opts.noCache && result && (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain')) dohCache.set(key, result);
    return result;
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

  function catalogSelectors(emailProvider, comprehensive) {
    var providerKey = DKIM_PROVIDER_CATALOG_KEYS[emailProvider];
    var providerSelectors = providerKey && DKIM_CATALOG.providers[providerKey]
      ? DKIM_CATALOG.providers[providerKey] : [];
    if (!comprehensive) return providerSelectors;
    return Object.values(DKIM_CATALOG.providers).flat()
      .concat(DKIM_CATALOG.generic || [], DKIM_CATALOG.temporal || []);
  }

  function buildDkimSelectorList(selectors, emailProvider, comprehensive) {
    return Array.from(new Set(
      (selectors || []).concat(DKIM_SELECTORS, catalogSelectors(emailProvider, comprehensive))
        .map(function (selector) { return String(selector || '').trim().toLowerCase(); })
        .filter(validDkimSelector)
    ));
  }

  function isRecognizedDkimSelector(selector) {
    return RECOGNIZED_DKIM_SELECTORS.has(String(selector || '').trim().toLowerCase());
  }

  async function inspectDkimSelector(domain, selector, queryOpts) {
    var queryName = `${selector}._domainkey.${domain}`;
    var name = queryName;
    var visited = new Set();
    var firstCname = '';

    for (var depth = 0; depth < 6; depth++) {
      if (visited.has(name)) break;
      visited.add(name);
      var result = requireUsable(await dohFetch(name, 'TXT', queryOpts), name, 'TXT');
      var keys = dkimKeyRecords(result.answers);
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

  async function checkDKIM(domain, wildcardBug, selectors, emailProvider, comprehensive, queryOpts) {
    var selectorList = buildDkimSelectorList(selectors, emailProvider, comprehensive);
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
          return await inspectDkimSelector(domain, selector, queryOpts);
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
          });
        } else if (suppliedSelectors.has(sel)) {
          missingSelectors.push({ sel: sel, queryName: queryName, cname: cname });
        }
      }
    }

    if (!found.length) {
      return { found: false, selectors: [], missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, confidence: 'sampled', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: wildcardBug ? 'noteWildcard' : failedSelectors.length ? 'noteNotFoundWithErrors' : 'noteNotFound' };
    }
    return { found: true, selectors: found, missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, confidence: 'observed', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: '' };
  }

  // Valid policy values per RFC 7489 §6.3, ordered weakest → strongest.
  var POLICY_RANK = { none: 0, quarantine: 1, reject: 2 };

  /**
   * Parse a DMARC record into its tags (RFC 7489, plus `np` from RFC 9091).
   *
   * Two things this has to get right that a naive regex does not:
   *
   *  1. Tag names must be anchored. An unanchored /p=([^;]+)/ matches the `p=`
   *     inside `sp=` and `np=`, so `sp=reject; p=none` would parse as
   *     policy=reject. Tag order is arbitrary in real records.
   *  2. Tag names and values are case-insensitive — `P=REJECT` is valid and
   *     appears in the wild.
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

  function analyzeDmarc(dmarc, multiple) {
    // RFC 7489 §6.6.3: with multiple records, policy discovery terminates and
    // DMARC is not applied at all — the domain is unprotected despite looking
    // configured. Distinct from 'missing' because the fix differs (delete a
    // duplicate vs. publish a first record).
    if (multiple) {
      return {
        status: 'permerror', cls: 'crit', policy: '', rua: false, ruf: false,
        sp: null, np: null, effectiveSp: null, effectiveNp: null,
        pct: 100, pctValid: true, adkim: 'r', aspf: 'r', enforcing: false,
      };
    }
    if (!dmarc) {
      return {
        status: 'missing', cls: 'crit', policy: '', rua: false, ruf: false,
        sp: null, np: null, effectiveSp: null, effectiveNp: null,
        pct: 100, pctValid: true, adkim: 'r', aspf: 'r', enforcing: false,
      };
    }

    var parsedTags = parseTagList(dmarc);
    var tag = function (name) { return parseDmarcTag(dmarc, name); };

    var rawPolicy = tag('p');
    var policy = normalizePolicy(rawPolicy) || 'none';
    var sp = normalizePolicy(tag('sp'));
    var np = normalizePolicy(tag('np'));

    // Inheritance chain per RFC 7489 §6.3 and RFC 9091 §2.
    var effectiveSp = sp || policy;
    var effectiveNp = np || sp || policy;

    // pct defaults to 100 when absent. Guard against NaN and out-of-range
    // values — an unguarded parseInt poisons every downstream total.
    var rawPct = tag('pct');
    var pct = 100;
    var pctValid = true;
    if (rawPct !== null) {
      var parsed = parseInt(rawPct, 10);
      if (isNaN(parsed)) { pctValid = false; }
      else { pct = Math.max(0, Math.min(100, parsed)); pctValid = parsed >= 0 && parsed <= 100; }
    }

    var adkim = (String(tag('adkim') || 'r').toLowerCase() === 's') ? 's' : 'r';
    var aspf = (String(tag('aspf') || 'r').toLowerCase() === 's') ? 's' : 'r';

    var rua = !!tag('rua');
    var ruf = !!tag('ruf');
    var enforcing = policy === 'quarantine' || policy === 'reject';

    // `present` covers a record whose p= value is unrecognized — malformed, but
    // a record exists, so it is neither 'missing' nor trustworthy enforcement.
    var malformed = rawPolicy === null || normalizePolicy(rawPolicy) === null || parsedTags.duplicates.length > 0;
    var status = malformed ? 'present'
      : enforcing ? 'ok'
        : 'warn';

    return {
      status: status,
      cls: status === 'ok' ? 'ok' : 'warn',
      policy: policy, sp: sp, np: np,
      effectiveSp: effectiveSp, effectiveNp: effectiveNp,
      pct: pct, pctValid: pctValid,
      adkim: adkim, aspf: aspf,
      rua: rua, ruf: ruf, enforcing: enforcing,
      malformed: malformed, duplicateTags: parsedTags.duplicates,
    };
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
   * DMARC sub-score, 0–30. Returns the component breakdown so the UI can
   * explain the number rather than just assert it.
   */
  function calcDmarcScore(d) {
    var parts = { policy: 0, subdomain: 0, pct: 0, rua: 0, alignment: 0, ruf: 0 };
    // 'present' = a record exists but p= is not a recognised value. Receivers
    // cannot act on it, so it is worth no more than having no record.
    if (!d || d.status === 'missing' || d.status === 'present' || d.status === 'permerror') {
      return { pts: 0, parts: parts };
    }

    parts.policy = { reject: 10, quarantine: 7, none: 3 }[d.policy] || 0;

    // Score the EFFECTIVE subdomain posture, not whether sp/np are written out.
    // Absent tags inherit p, so `p=reject` alone protects subdomains fully.
    // Take the weaker of the two branches — security is the weakest link.
    var subRank = Math.min(
      POLICY_RANK[d.effectiveSp] !== undefined ? POLICY_RANK[d.effectiveSp] : 0,
      POLICY_RANK[d.effectiveNp] !== undefined ? POLICY_RANK[d.effectiveNp] : 0
    );
    parts.subdomain = [1, 4, 6][subRank] || 0;

    // pct throttles enforcement. Irrelevant at p=none, so award in full there
    // rather than penalising a domain for a tag that has no effect.
    parts.pct = d.enforcing ? (4 * (d.pct / 100)) : 4;

    if (d.rua) parts.rua = 5;
    if (d.adkim === 's') parts.alignment += 1.5;
    if (d.aspf === 's') parts.alignment += 1.5;
    if (d.ruf) parts.ruf = 2;

    var total = parts.policy + parts.subdomain + parts.pct + parts.rua + parts.alignment + parts.ruf;
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
    return { done: checks.filter(Boolean).length, total: 5 };
  }

  /* ── Issues & suggestions ───────────────────────────────────────────── */

  // Each issue carries a key (→ locale lookup) and optional `args` used to
  // fill {0} placeholders in the translated message.
  function buildIssues({ emailProvider, spfStatus, dkimStatus, dmarcStatus, wildcardBug, hosting, advanced }) {
    const issues = [];

    if (wildcardBug) issues.push({ key: 'wildcard-txt', sev: 'crit' });
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
      issues.push({
        key: dkimStatus.confidence === 'sampled' ? 'dkim-unverified' : 'dkim-missing',
        sev: dkimStatus.confidence === 'sampled' ? 'info' : 'warn', noteKey: dkimStatus.note,
      });
    }
    if (dmarcStatus.status === 'permerror') issues.push({ key: 'dmarc-multiple-records', sev: 'crit' });
    else if (dmarcStatus.status === 'missing') issues.push({ key: 'dmarc-missing', sev: 'warn' });
    if (dmarcStatus.status === 'warn' && dmarcStatus.policy === 'none') issues.push({ key: 'dmarc-none', sev: 'warn' });
    // p=quarantine is real enforcement, so this is a nudge rather than a defect —
    // reject is the end state, and nothing else surfaces that gap.
    if (dmarcStatus.status === 'ok' && dmarcStatus.policy === 'quarantine') issues.push({ key: 'dmarc-quarantine', sev: 'info' });
    if (dmarcStatus.status === 'ok' && !dmarcStatus.rua) issues.push({ key: 'dmarc-no-rua', sev: 'info' });

    // Subdomain gaps only matter where the effective policy is genuinely weaker
    // than the organizational one — an absent sp/np inherits p and is fine.
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveSp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-sp', sev: 'warn', args: [dmarcStatus.effectiveSp, dmarcStatus.policy] });
    }
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveNp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-np', sev: 'warn', args: [dmarcStatus.effectiveNp, dmarcStatus.policy] });
    }
    if (dmarcStatus.enforcing && dmarcStatus.pct < 100) {
      issues.push({ key: 'dmarc-partial-pct', sev: 'warn', args: [dmarcStatus.pct, 100 - dmarcStatus.pct] });
    }
    if (dmarcStatus.status !== 'missing' && !dmarcStatus.pctValid) {
      issues.push({ key: 'dmarc-bad-pct', sev: 'warn' });
    }
    if (dmarcStatus.status === 'present') {
      issues.push({ key: 'dmarc-invalid-policy', sev: 'crit' });
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
    if (advanced?.spfLookups?.indeterminate) issues.push({ key: 'spf-indeterminate', sev: 'info' });
    if (advanced?.dnssec?.state === 'bogus') issues.push({ key: 'dnssec-bogus', sev: 'crit' });
    else if (advanced?.dnssec?.state === 'indeterminate') issues.push({ key: 'dnssec-indeterminate', sev: 'info' });

    return issues;
  }

  // `guide` names the Learn more page to link to (see locales → learnMore).
  function buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    const tips = [];
    if (!advanced) return tips;

    const hasEmail = emailProvider !== '@none' && emailProvider !== '@null-mx';
    const dmarcEnforced = dmarcStatus.status === 'ok' && (dmarcStatus.policy === 'quarantine' || dmarcStatus.policy === 'reject');

    if (advanced.bimi?.multiple) { /* duplicate already raised as an issue */ }
    else if (!advanced.bimi?.present && dmarcEnforced && dkimStatus.found) tips.push({ key: 'bimiEligible', guide: 'bimi' });
    else if (!advanced.bimi?.present && hasEmail) tips.push({ key: 'bimiPrereq', guide: 'bimi' });

    // Skip the "not configured" tip when the record exists but is duplicated —
    // buildIssues already raises the duplicate, and telling someone to publish
    // a record they already have twice is actively confusing.
    if (!advanced.mtaSts?.present && !advanced.mtaSts?.multiple && hasEmail) tips.push({ key: 'mta-sts', guide: 'mta-sts' });
    if (!advanced.tlsRpt?.present && !advanced.tlsRpt?.multiple && hasEmail) tips.push({ key: 'tls-rpt', guide: 'tls-rpt' });
    if (!advanced.caa?.found) tips.push({ key: 'caa', guide: 'caa' });
    if (!advanced.dnssec?.signed) tips.push({ key: 'dnssec', guide: 'dnssec' });

    return tips;
  }

  /* ── Scoring ────────────────────────────────────────────────────────── */

  function calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, wildcardBug, advanced }) {
    // A wildcard TXT record breaks DKIM and DMARC lookups on every subdomain,
    // which invalidates everything else measured here. Unchanged: instant F.
    if (wildcardBug) {
      return { grade: 'F', cls: 'score-f', pts: 0, max: 100, breakdown: null, parked: false };
    }

    var dnssecSigned = !!(advanced && advanced.dnssec && advanced.dnssec.signed);
    var dnssecUnknown = !!(advanced && advanced.dnssec && advanced.dnssec.state === 'indeterminate');
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

      var parkedDmarc = { reject: 30, quarantine: 20, none: 8 }[dmarcStatus.policy] || 0;
      if (dmarcStatus.status === 'missing') parkedDmarc = 0;

      var parkedPillars = [
        { key: 'spf', pts: parkedSpf, max: PARKED_WEIGHTS.spf },
        { key: 'dmarc', pts: parkedDmarc, max: PARKED_WEIGHTS.dmarc },
        { key: 'dnssec', pts: dnssecSigned ? PARKED_WEIGHTS.dnssec : 0, max: PARKED_WEIGHTS.dnssec },
        { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? PARKED_WEIGHTS.caa : 0, max: PARKED_WEIGHTS.caa },
      ];
      var parkedPts = parkedPillars.reduce(function (sum, p) { return sum + p.pts; }, 0);
      var parkedGrade = gradeFor(parkedPts, dnssecSigned);

      return {
        grade: parkedGrade.grade, cls: parkedGrade.cls,
        pts: parkedPts, max: 100, parked: true,
        breakdown: { pillars: parkedPillars, dmarc: dmarc.parts },
      };
    }

    // ── Active email domain ─────────────────────────────────────────────
    var dkimUnknown = !!(dkimStatus && !dkimStatus.found && (dkimStatus.confidence === 'sampled' || dkimStatus.confidence === 'not-checked'));
    var pillars = [
      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },
      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },
      { key: 'dkim', pts: dkimStatus && dkimStatus.found ? WEIGHTS.dkim : dkimUnknown ? null : 0, max: WEIGHTS.dkim, unknown: dkimUnknown },
      { key: 'dnssec', pts: dnssecSigned ? WEIGHTS.dnssec : dnssecUnknown ? null : 0, max: WEIGHTS.dnssec, unknown: dnssecUnknown },
      { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? WEIGHTS.caa : 0, max: WEIGHTS.caa },
      { key: 'mtaSts', pts: (advanced && advanced.mtaSts && advanced.mtaSts.present && advanced.mtaSts.policyVerified !== false) ? WEIGHTS.mtaSts :
        (advanced && advanced.mtaSts && advanced.mtaSts.present) ? WEIGHTS.mtaSts / 2 : 0, max: WEIGHTS.mtaSts },
      { key: 'bimi', pts: (advanced && advanced.bimi && advanced.bimi.present) ? WEIGHTS.bimi : 0, max: WEIGHTS.bimi },
      { key: 'tlsRpt', pts: (advanced && advanced.tlsRpt && advanced.tlsRpt.present) ? WEIGHTS.tlsRpt : 0, max: WEIGHTS.tlsRpt },
    ];

    var pts = pillars.reduce(function (sum, p) { return sum + (p.pts || 0); }, 0);
    var unknownPoints = pillars.reduce(function (sum, p) { return sum + (p.unknown ? p.max : 0); }, 0);
    var maxPossible = Math.min(100, pts + unknownPoints);
    var graded = gradeFor(pts, dnssecSigned);
    var upper = gradeFor(maxPossible, dnssecSigned || dnssecUnknown);
    var displayGrade = graded.grade === upper.grade ? graded.grade : graded.grade + '–' + upper.grade;

    return {
      grade: displayGrade, gradeMin: graded.grade, gradeMax: upper.grade, cls: graded.cls,
      pts: pts, maxPossible: maxPossible, max: 100, uncertain: unknownPoints > 0, parked: false,
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

    var dmarcAtDomain = d;
    var dmarcTxts = await dohQuery(`_dmarc.${d}`, 'TXT', queryOpts);
    var dmarcMatches = dmarcTxts.filter(v => startsWithCI(v, 'v=DMARC1'));
    const organizationalDomain = getOrganizationalDomain(d);
    if (!dmarcMatches.length && organizationalDomain && organizationalDomain !== d) {
      dmarcAtDomain = organizationalDomain;
      dmarcTxts = await dohQuery(`_dmarc.${organizationalDomain}`, 'TXT', queryOpts);
      dmarcMatches = dmarcTxts.filter(v => startsWithCI(v, 'v=DMARC1'));
    }
    const dmarcRecord = dmarcMatches[0] || '';
    const dmarcMultiple = dmarcMatches.length > 1;
    const dmarcStatus = analyzeDmarc(dmarcRecord, dmarcMultiple);
    if (dmarcAtDomain !== d && dmarcStatus.status !== 'missing' && dmarcStatus.status !== 'permerror' && dmarcStatus.status !== 'present') {
      dmarcStatus.inherited = true;
      dmarcStatus.organizationalPolicy = dmarcStatus.policy;
      dmarcStatus.policy = dmarcStatus.effectiveSp;
      dmarcStatus.enforcing = dmarcStatus.policy === 'quarantine' || dmarcStatus.policy === 'reject';
      dmarcStatus.status = dmarcStatus.enforcing ? 'ok' : 'warn';
      dmarcStatus.cls = dmarcStatus.status === 'ok' ? 'ok' : 'warn';
    }

    let wildcardBug = false;
    if (opts.wildcard) {
      const testSub = await dohQuery(`_wildcardtest99xyz.${d}`, 'TXT', queryOpts);
      wildcardBug = testSub.length > 0;
    }

    let dkimStatus = { found: false, selectors: [], testedSelectors: [], confidence: 'not-checked', note: '' };
    if (opts.dkim && emailProvider !== '@none' && emailProvider !== '@null-mx') {
      dkimStatus = await checkDKIM(d, wildcardBug, opts.selectors, emailProvider, opts.dkimComprehensive, queryOpts);
    }

    let hosting = '@dash';
    if (opts.www) {
      const website = await resolveWebsite(d, queryOpts);
      hosting = website.loop ? '@cname-loop' : detectHosting(website.addresses, website.chain, d);
    }

    // ── Advanced checks ──
    let advanced = { bimi: null, mtaSts: null, tlsRpt: null, caa: null, dnssec: null, spfLookups: null };
    if (opts.advanced) {
      const [bimiTxt, mtaStsTxt, tlsRptTxt, caaResult, dnssecResult, spfLookups] = await Promise.all([
        dohQuery(`default._bimi.${d}`, 'TXT', queryOpts),
        dohQuery(`_mta-sts.${d}`, 'TXT', queryOpts),
        dohQuery(`_smtp._tls.${d}`, 'TXT', queryOpts),
        checkCAA(d, queryOpts),
        checkDNSSEC(d, queryOpts),
        spfRecord ? countSpfLookups(spfRecord, d, queryOpts) : Promise.resolve({ count: 0, warning: false, error: false, voidLookups: 0, cycles: [], indeterminate: false }),
      ]);

      // All three specs say the same thing: filter to the versioned records,
      // and if the result isn't exactly one, treat the domain as not having
      // the feature at all (RFC 8461 §3.1, RFC 8460 §3, BIMI draft §7.2).
      // So `present` is false when duplicated — the operator believes the
      // control is active when it is not, which is worth saying out loud.
      const bimiMatches = bimiTxt.filter(v => startsWithCI(v, 'v=BIMI1'));
      const mtaMatches = mtaStsTxt.filter(v => startsWithCI(v, 'v=STSv1'));
      const tlsMatches = tlsRptTxt.filter(v => startsWithCI(v, 'v=TLSRPTv1'));

      const bimiRecord = bimiMatches[0] || '';
      const mtaRecord = mtaMatches[0] || '';
      const tlsRecord = tlsMatches[0] || '';
      const bimiValidation = validateBimiRecord(bimiRecord);
      const mtaValidation = validateMtaStsRecord(mtaRecord);
      const tlsValidation = validateTlsRptRecord(tlsRecord);

      advanced = {
        bimi: { present: bimiMatches.length === 1 && bimiValidation.valid, advertised: bimiMatches.length === 1, record: bimiRecord, validation: bimiValidation, multiple: bimiMatches.length > 1 },
        mtaSts: { present: mtaMatches.length === 1 && mtaValidation.valid, advertised: mtaMatches.length === 1, policyVerified: false, record: mtaRecord, validation: mtaValidation, multiple: mtaMatches.length > 1 },
        tlsRpt: { present: tlsMatches.length === 1 && tlsValidation.valid, advertised: tlsMatches.length === 1, record: tlsRecord, validation: tlsValidation, multiple: tlsMatches.length > 1 },
        caa: caaResult,
        dnssec: dnssecResult,
        spfLookups,
      };
    }

    const issues = buildIssues({ emailProvider, spfStatus, dkimStatus, dmarcStatus, wildcardBug, hosting, advanced });
    const suggestions = buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const score = calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, wildcardBug, advanced });
    const advScore = opts.advanced ? calcAdvScore(advanced) : null;

    return {
      domain: d, ns, mx, txt, aRec, aaaaRec, dnsProvider, emailProvider,
      spfRecord, spfStatus, dmarcRecord, dmarcStatus, dmarcAtDomain, organizationalDomain, dkimStatus,
      wildcardBug, hosting, verifications, advanced, advScore,
      issues, suggestions, score,
    };
  }

  global.DnsAudit = {
    DOH,
    DKIM_SELECTORS,
    buildDkimSelectorList,
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
    startsWithCI,
    countSpfLookups,
    parseSpfTerms,
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
  };
})(window);
