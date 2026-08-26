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

  var DNS_TYPES = {
    A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
    DS: 43, DNSKEY: 48, TLSA: 52, CAA: 257,
  };

  /**
   * Map a record type name to its IANA number.
   *
   * This used to end in `?? 16`, which made the function total by answering
   * every unknown type with the TXT number. The cost of that totality was the
   * worst failure this codebase can produce: a caller asking for `DS` issued a
   * TXT query, filtered the answers for type 16, found none, and received a
   * plausible-looking empty array. No error, no warning, and a confident
   * "no records published" about a type that was never asked for.
   *
   * Every existing call site passes a supported literal, so throwing is
   * behaviour-preserving for the code that exists and fail-fast for the code
   * that comes next. `hasOwnProperty` rather than a bare lookup so a type name
   * that collides with `Object.prototype` ("constructor", "toString") throws
   * instead of returning a function.
   */
  function dnsTypeNum(type) {
    if (!Object.prototype.hasOwnProperty.call(DNS_TYPES, type)) {
      var error = new Error('unsupported DNS type: ' + type);
      // Named so optionalCheck() re-throws it. An unsupported type is a
      // programming error, not a resolver hiccup, and degrading it to a stated
      // "unknown" would hide exactly what the throw exists to surface.
      error.name = 'DnsTypeError';
      throw error;
    }
    return DNS_TYPES[type];
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
    // Resolved before the slot and before the try: the catch below turns every
    // throw into 'network-error', so an unsupported type checked inside it
    // would be reported as a resolver failure — the same silent-wrong-answer
    // shape dnsTypeNum() was changed to prevent, one layer up.
    const typeNum = dnsTypeNum(type);
    await acquireDohSlot(opts.signal);
    var controller = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; controller.abort(); }, opts.timeoutMs || DOH_TIMEOUT_MS);
    var forwardAbort = function () { controller.abort(); };
    if (opts.signal) opts.signal.addEventListener('abort', forwardAbort, { once: true });
    try {
      const params = new URLSearchParams({ name: name, type: String(typeNum) });
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
    dnsTypeNum(type);   // throw on an unsupported type before the cache, not only on a miss
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
   *
   * So is DnsTypeError. A query for a record type the transport does not know
   * is a bug in this file, not a resolver hiccup, and reporting it as a stated
   * "unknown" would restore the very failure dnsTypeNum() throws to prevent:
   * the check silently never runs and the interface says so in the calm voice
   * it uses for a domain the resolver was merely slow about.
   */
  async function optionalCheck(run, fallback) {
    try {
      return await run();
    } catch (error) {
      if (error && (error.name === 'AbortError' || error.name === 'DnsTypeError')) throw error;
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

  /**
   * Split a selector's TXT answers into usable keys and revoked ones.
   *
   * `dkimKeyRecords()` above answers "is there a usable key here", and its
   * filter drops any record whose `p=` is empty. That is right for discovery
   * and wrong for reporting: RFC 6376 3.6.1 defines an empty `p=` as key
   * REVOCATION, so the records it discards are precisely the ones a domain
   * publishes to say "this selector is dead". Reporting a revoked selector as
   * absent tells the operator to go and create a key they deliberately killed.
   *
   * So the two questions are answered separately rather than by loosening the
   * existing filter, which would let a revoked key satisfy "DKIM is present".
   */
  function dkimRecordSet(answers) {
    var keys = [];
    var revoked = [];
    var unusable = [];
    var malformed = [];
    (answers || []).filter(function (answer) { return answer.type === 16; })
      .forEach(function (answer) {
        var value = cleanAnswerData(answer.data, 'TXT');
        var parsed = parseDkimKeyTagList(value);
        var tags = parsed.tags;
        // v= is optional for a DKIM key, but when it is present it identifies
        // the protocol. Keep malformed DKIM-family values (`DKIM2`, `dkim1`)
        // so the analyzer can explain them; ignore a record that explicitly
        // identifies some OTHER protocol. This matters for wildcard TXT:
        // gov.uk synthesizes its `v=DMARC1; p=reject` record at every selector,
        // and treating its DMARC p= tag as a public key awarded 15 DKIM points.
        if (Object.prototype.hasOwnProperty.call(tags, 'v') && !/^dkim/i.test(tags.v)) return;
        if (!Object.prototype.hasOwnProperty.call(tags, 'p')) {
          // Ignore unrelated TXT at a selector, but retain a recognizable DKIM
          // candidate whose required p= tag is missing. Dropping it here made
          // the analyzer's `missing-p` error unreachable and reported an empty
          // DNS name where the operator had actually published a broken key.
          if (Object.prototype.hasOwnProperty.call(tags, 'v')) malformed.push(value);
          return;
        }
        if (tags.p.length === 0) { revoked.push(value); return; }
        // Key-shaped is not the same as usable. A record with an unrecognized
        // `k=`, a service list that excludes email, or a hash list this
        // verifier cannot use is published and conformant — and answering "yes,
        // DKIM is configured" on the strength of it is a claim about signing
        // that the record does not support.
        if (analyzeDkimKey(value).appliesToEmail) keys.push(value);
        else unusable.push(value);
      });
    return { keys: keys, revoked: revoked, unusable: unusable, malformed: malformed };
  }

  /* ── DKIM public key analysis (RFC 6376 3.6.1, RFC 8463) ──────────────
     Everything here is pure and synchronous. The size of an RSA modulus is
     the single most actionable fact about a DKIM key and it must not depend
     on a secure context, so it is read with a DER length walk rather than
     with Web Crypto (OQ-DEPTH-02). Web Crypto validates the structure on top,
     where it exists, and its absence is recorded as an unknown — never as a
     bad key. A browser that cannot check a key has said nothing about it.
     ───────────────────────────────────────────────────────────────────── */

  var DKIM_KEY_TAGS = ['v', 'h', 'k', 'n', 'p', 's', 't'];
  // RFC 6376 §3.6.1 registers these hash names; a verifier that supports
  // neither has nothing to verify with.
  var DKIM_SUPPORTED_HASHES = ['sha1', 'sha256'];
  // hyphenated-word = ALPHA *(ALPHA / DIGIT / "-") — the extension token shape
  // shared by the h=, s= and t= vocabularies.
  var DKIM_TOKEN = /^[a-z](?:[a-z0-9-]*[a-z0-9])?$/i;

  /**
   * Parse the complete RFC 6376 §3.2 tag-list grammar used by a DKIM key.
   *
   * This is deliberately not the permissive `parseTagList()` helper used by
   * protocols that merely want a map. A key verifier must reject a bare
   * fragment, an illegal tag name, bad folding, or a version tag in the wrong
   * position. Silently skipping those pieces makes `dkim-key-malformed`
   * impossible to emit because the analyzer has already forgotten the error.
   */
  function parseDkimKeyTagList(record) {
    var source = String(record === undefined || record === null ? '' : record);
    var errors = [];
    // FWS permits CRLF only when followed by WSP. Unfold it while retaining
    // the following WSP; every other control is outside tag-value grammar.
    var unfolded = source.replace(/\r\n(?=[ \t])/g, '');
    if (/[\r\n]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(unfolded)) errors.push('invalid-tag-list');

    var parts = unfolded.split(';');
    if (parts.length > 1 && /^[ \t]*$/.test(parts[parts.length - 1])) parts.pop();
    var tags = Object.create(null);
    var duplicates = [];
    var order = [];
    parts.forEach(function (part) {
      if (!part || /^[ \t]*$/.test(part)) { errors.push('invalid-tag-list'); return; }
      var equals = part.indexOf('=');
      if (equals === -1) { errors.push('invalid-tag-list'); return; }
      var left = part.slice(0, equals);
      if (!/^[ \t]*[a-z][a-z0-9_]*[ \t]*$/i.test(left)) {
        errors.push('invalid-tag-list'); return;
      }
      var name = left.trim();
      var value = part.slice(equals + 1).replace(/^[ \t]+|[ \t]+$/g, '');
      if (!/^(?:[\x21-\x3a\x3c-\x7e]|[ \t])*$/.test(value)) {
        errors.push('invalid-tag-list'); return;
      }
      order.push(name);
      if (Object.prototype.hasOwnProperty.call(tags, name)) duplicates.push(name);
      else tags[name] = value;
    });
    if (!order.length) errors.push('invalid-tag-list');
    if (duplicates.length) errors.push('duplicate-tags');
    return { tags: tags, duplicates: duplicates, order: order, errors: Array.from(new Set(errors)) };
  }

  /**
   * Split a colon-separated DKIM tag list, or null if it is not one.
   *
   * A PRESENT tag with an empty value is malformed — `h=` and `s=` are lists of
   * at least one entry, and an empty one says nothing while looking like a
   * restriction. An ABSENT tag is a different thing entirely and never reaches
   * here: `s=` defaults to `*`, and `h=` defaults to every algorithm.
   */
  function parseDkimTagList(value, allowStar) {
    var entries = String(value === undefined || value === null ? '' : value).split(':')
      .map(function (part) { return part.trim().toLowerCase(); });
    if (!entries.length || entries.some(function (entry) { return entry === ''; })) return null;
    for (var i = 0; i < entries.length; i++) {
      if (allowStar && entries[i] === '*') continue;
      if (!DKIM_TOKEN.test(entries[i])) return null;
    }
    return entries;
  }

  /** RFC 6376's DKIM-Quoted-Printable used by the human-readable n= tag. */
  function isDkimQuotedPrintable(value) {
    var text = String(value === undefined || value === null ? '' : value).replace(/[ \t]/g, '');
    for (var i = 0; i < text.length; i++) {
      var code = text.charCodeAt(i);
      if (text.charAt(i) === '=') {
        if (!/^[0-9A-F]{2}$/.test(text.slice(i + 1, i + 3))) return false;
        i += 2;
      } else if (!((code >= 0x21 && code <= 0x3a) || code === 0x3c || (code >= 0x3e && code <= 0x7e))) {
        return false;
      }
    }
    return true;
  }

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
  function base64ToBytes(value) {
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

  /**
   * Read one DER tag-length-value at `pos`. Returns null for anything that is
   * not well-formed, which is the whole point: a `p=` value truncated by a TXT
   * chunking mistake decodes to bytes that are not a key, and that must read as
   * "unparseable" rather than as a key of whatever size the garbage implies.
   */
  function derReadTlv(bytes, pos) {
    if (pos + 2 > bytes.length) return null;
    var tag = bytes[pos];
    var lengthByte = bytes[pos + 1];
    var start, length;
    if (lengthByte < 0x80) {
      length = lengthByte;
      start = pos + 2;
    } else {
      var count = lengthByte & 0x7f;
      // 0 is BER indefinite length, which DER forbids; over 4 bytes is a
      // length no DKIM key has and a sign the input is not DER at all.
      if (count === 0 || count > 4) return null;
      if (pos + 2 + count > bytes.length) return null;
      // X.690 10.1: the definite length must use the FEWEST possible octets.
      // A leading zero octet is never the fewest, and neither is the long form
      // for a value the short form can express. Accepting either let BER
      // encodings through a walk this release calls authoritative DER — and
      // two encodings of one key is one more than a canonical form allows.
      if (bytes[pos + 2] === 0x00) return null;
      length = 0;
      for (var i = 0; i < count; i++) length = (length * 256) + bytes[pos + 2 + i];
      if (length < 0x80) return null;
      start = pos + 2 + count;
    }
    if (start + length > bytes.length) return null;
    return { tag: tag, start: start, length: length, end: start + length };
  }

  /**
   * Bit length of a DER INTEGER that must be positive, non-zero and minimally
   * encoded — which is what RFC 8017 3.1 requires of both RSA fields. Returns
   * null for anything else, so a value that is merely tagged INTEGER cannot
   * pass as a modulus.
   *
   * The length is counted from the highest set bit of the first significant
   * octet, not from the encoded byte width. Those differ whenever the top octet
   * is below 0x80, and the difference lands on the wrong side of this release's
   * own threshold: a 128-byte modulus whose leading significant octet is 0x01 is
   * a 1017-bit key, and reporting it as 1024 both prints a false number and
   * swaps the critical `dkim-key-weak` finding for the informational 1024-bit
   * one.
   *
   * Real RSA keys have the top bit of the modulus set, so for every key in the
   * backtest sample every rule here is satisfied and the two bit-length answers
   * agree — which is exactly why all of this had to be established by
   * construction rather than waited for.
   */
  function derPositiveInteger(bytes, tlv) {
    var start = tlv.start;
    var length = tlv.length;
    if (length < 1) return null;                                  // empty INTEGER
    // X.690 8.3.2 encodes sign in the first octet's high bit, so anything with
    // it set is negative — and RSA has no negative values.
    if ((bytes[start] & 0x80) !== 0) return null;
    if (length === 1 && bytes[start] === 0x00) return null;       // zero
    // Minimal form: a leading 0x00 exists only to keep a high-bit-set value
    // positive. Any other leading zero is padding DER does not permit, and
    // silently stripping it would report a size for a non-conformant encoding.
    if (length > 1 && bytes[start] === 0x00 && (bytes[start + 1] & 0x80) === 0) return null;
    if (bytes[start] === 0x00) { start++; length--; }             // the one sign octet
    var top = bytes[start];
    var topBits = 0;
    while (top) { topBits++; top >>= 1; }
    // The significant range is returned as well as the size, because comparing
    // two of these needs the octets and not just their width.
    return { start: start, length: length, bits: (length - 1) * 8 + topBits };
  }

  /**
   * Compare two positive integers by their significant octets: -1, 0 or 1.
   *
   * Both are already minimally encoded with any sign octet stripped, so the
   * wider value is the larger one and equal widths compare lexicographically.
   * That is an exact comparison of arbitrarily large values using nothing but
   * byte reads — an earlier version compared bit lengths instead and called it
   * the best available without bignum arithmetic, which was simply wrong: it
   * accepted `e == n` and any same-width `e > n`.
   */
  function compareDerMagnitude(bytes, left, right) {
    if (left.length !== right.length) return left.length < right.length ? -1 : 1;
    for (var i = 0; i < left.length; i++) {
      if (bytes[left.start + i] !== bytes[right.start + i]) {
        return bytes[left.start + i] < bytes[right.start + i] ? -1 : 1;
      }
    }
    return 0;
  }

  // rsaEncryption, OID 1.2.840.113549.1.1.1 — the nine content octets of the
  // AlgorithmIdentifier's OBJECT IDENTIFIER.
  var RSA_ENCRYPTION_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

  /**
   * Does this AlgorithmIdentifier SEQUENCE name rsaEncryption, correctly?
   *
   * RFC 3279 2.3.1 requires the parameters field to be ASN.1 NULL for this
   * algorithm, and RFC 8017 A.1 says the same. Matching the OID and stopping
   * there accepted an AlgorithmIdentifier carrying arbitrary parameters — an
   * OCTET STRING, or nothing at all — which is not the structure the OID
   * promises.
   */
  function isRsaAlgorithmIdentifier(bytes, algorithm) {
    var oid = derReadTlv(bytes, algorithm.start);
    if (!oid || oid.tag !== 0x06 || oid.length !== RSA_ENCRYPTION_OID.length) return false;
    for (var i = 0; i < RSA_ENCRYPTION_OID.length; i++) {
      if (bytes[oid.start + i] !== RSA_ENCRYPTION_OID[i]) return false;
    }
    var parameters = derReadTlv(bytes, oid.end);
    if (!parameters || parameters.tag !== 0x05 || parameters.length !== 0) return false;
    // NULL must also END the AlgorithmIdentifier: no trailing members.
    return parameters.end === algorithm.end;
  }

  /**
   * Read `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
   * out of a SEQUENCE already located, and return the modulus bit length.
   *
   * One helper for both envelopes on purpose. The bare PKCS#1 path checked the
   * exponent and its boundary while the SPKI path checked neither, so an SPKI
   * key whose exponent tag had been altered walked cleanly and reported a size —
   * leaving an optional browser API as the only thing that would reject
   * malformed DER, in a function documented as authoritative without it.
   *
   * **Where this stops, deliberately.** The walk establishes that the encoding
   * is canonical DER and that the values satisfy the cheap NECESSARY conditions
   * RFC 8017 3.1 states: positive, minimally encoded, both odd, and
   * 3 <= e < n. It does not establish that they are SUFFICIENT. Proving `n` is
   * a product of two distinct primes, or that gcd(e, lambda(n)) is 1, needs the
   * private factors, which a public key does not carry — and factoring a
   * 2048-bit modulus is not a thing a DNS audit does in a browser. So a key
   * that passes here is well-formed, not proven usable. Web Crypto confirms
   * further where it can, for SPKI only, and its silence is never a verdict.
   */
  function derReadRsaPublicKey(bytes, sequence) {
    var modulus = derReadTlv(bytes, sequence.start);
    if (!modulus || modulus.tag !== 0x02) return null;
    var exponent = derReadTlv(bytes, modulus.end);
    if (!exponent || exponent.tag !== 0x02) return null;
    // The exponent must end the sequence: no trailing content, no third member.
    if (exponent.end !== sequence.end) return null;

    // Both fields are values, not just tags. RFC 8017 3.1 defines `n` and `e`
    // as positive integers with 3 <= e < n; checking the tag alone accepted an
    // empty exponent and a negative modulus.
    var modulusValue = derPositiveInteger(bytes, modulus);
    var exponentValue = derPositiveInteger(bytes, exponent);
    if (!modulusValue || !exponentValue) return null;
    // Both are odd. RFC 8017 3.1 makes `n` a product of distinct odd primes,
    // so an even modulus is not an RSA modulus at all; and `e` must be coprime
    // to lambda(n), which is even. The exponent was checked here from the
    // start and the modulus was not — the same condition, two lines apart.
    if ((bytes[modulusValue.start + modulusValue.length - 1] & 1) === 0) return null;
    if ((bytes[exponentValue.start + exponentValue.length - 1] & 1) === 0) return null;
    // At least 3. A single content octet is the only way to encode a value
    // below 128, so nothing wider needs comparing.
    if (exponentValue.length === 1 && bytes[exponentValue.start] < 3) return null;
    // And strictly below the modulus — compared exactly, octet by octet. This
    // says nothing about the modulus's factors and needs no arithmetic beyond
    // byte reads.
    if (compareDerMagnitude(bytes, exponentValue, modulusValue) >= 0) return null;
    return modulusValue.bits;
  }

  /**
   * Walk an RSA public key to its modulus. Returns { bits, encoding } or null.
   *
   * BOTH envelopes are valid DKIM key encodings and both are accepted:
   *
   *   pkcs1  RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
   *   spki   SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
   *
   * RFC 6376 3.6.1 describes the `p=` value as a DER-encoded `RSAPublicKey`,
   * and the errata clarify that it MAY be wrapped in a SubjectPublicKeyInfo.
   * So a bare PKCS#1 key is conformant, not a curiosity to be tolerated.
   *
   * An earlier version of this function refused the bare form so that the walk
   * and Web Crypto could never disagree. That had the dependency backwards:
   * `crypto.subtle.importKey` accepts 'spki' and not 'pkcs1', and letting an
   * implementation's import surface decide what the protocol permits would have
   * reported a perfectly valid published key as unparseable. The DER walk is
   * authoritative for the size; Web Crypto confirms only what it can express.
   *
   * Returns null for anything that is not one of these two structures, and null
   * is reported as unparseable rather than guessed at.
   */
  function rsaPublicKeyShape(bytes) {
    if (!bytes) return null;
    var outer = derReadTlv(bytes, 0);
    if (!outer || outer.tag !== 0x30) return null;
    // DER encodes exactly one top-level value. Trailing bytes mean this is not
    // a key, and without this check a truncated blob whose prefix happens to
    // parse would yield a confident size for something unusable.
    if (outer.end !== bytes.length) return null;

    var first = derReadTlv(bytes, outer.start);
    if (!first) return null;

    // Bare PKCS#1: the outer SEQUENCE *is* the RSAPublicKey.
    if (first.tag === 0x02) {
      var pkcs1Bits = derReadRsaPublicKey(bytes, outer);
      return pkcs1Bits === null ? null : { bits: pkcs1Bits, encoding: 'pkcs1' };
    }

    // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }.
    // Every container boundary is checked, so no nesting level may carry
    // trailing content, and the algorithm is confirmed to be RSA rather than
    // assumed from the shape.
    if (first.tag !== 0x30) return null;
    if (!isRsaAlgorithmIdentifier(bytes, first)) return null;
    var bitString = derReadTlv(bytes, first.end);
    if (!bitString || bitString.tag !== 0x03 || bitString.length < 1) return null;
    if (bitString.end !== outer.end) return null;
    // First content octet of a BIT STRING counts the unused trailing bits. A
    // key is a whole number of bytes, so anything but zero means this is not
    // the structure we think it is.
    if (bytes[bitString.start] !== 0x00) return null;
    var inner = derReadTlv(bytes, bitString.start + 1);
    if (!inner || inner.tag !== 0x30 || inner.end !== bitString.end) return null;
    var spkiBits = derReadRsaPublicKey(bytes, inner);
    return spkiBits === null ? null : { bits: spkiBits, encoding: 'spki' };
  }

  /**
   * Analyze one DKIM key record. Pure, synchronous, no DNS, no Web Crypto.
   *
   * `errors` carries tokens, never English — js/dns.js does not speak to the
   * user. `cryptoValidated` starts null meaning "not attempted"; only
   * inspectDkimSelector() moves it to true or false, and false never on its
   * own makes a key invalid.
   */
  function analyzeDkimKey(txtValue) {
    var parsed = parseDkimKeyTagList(txtValue);
    var tags = parsed.tags;
    var errors = parsed.errors.slice();

    var version = null;
    if (Object.prototype.hasOwnProperty.call(tags, 'v')) {
      if (tags.v === 'DKIM1') version = 'DKIM1';
      else errors.push('bad-version');
      if (parsed.order[0] !== 'v') errors.push('version-not-first');
    }

    // Reasons a well-formed record still cannot sign this domain's email.
    // Kept apart from `errors` on purpose: none of these is a malformed record,
    // and telling an operator their key is broken when they deliberately scoped
    // it to another service would be the same false verdict in a new place.
    var restrictions = [];

    var rawKeyType = Object.prototype.hasOwnProperty.call(tags, 'k') ? tags.k.trim() : 'rsa';
    var keyType = rawKeyType.toLowerCase();
    if (!DKIM_TOKEN.test(rawKeyType)) errors.push('invalid-key-type');
    if (keyType !== 'rsa' && keyType !== 'ed25519') {
      keyType = 'unknown';
      // RFC 6376 §3.6.1: "Unrecognized key types MUST be ignored." Ignored is
      // not malformed — the record may be perfectly valid for a verifier that
      // knows the type. It simply cannot be counted as a key we can use.
      restrictions.push('unsupported-key-type');
    }

    var hasP = Object.prototype.hasOwnProperty.call(tags, 'p');
    var rawKey = hasP ? tags.p : '';
    // RFC 6376 3.6.1: "An empty value means that this public key has been
    // revoked." Revocation is a deliberate act and a complete record, so it is
    // reported as such and not as a parse failure.
    var revoked = hasP && rawKey.replace(/\s+/g, '').length === 0;
    if (!hasP) errors.push('missing-p');

    var bytes = null;
    var keyBytes = null;
    var keyBits = null;
    var keyEncoding = null;
    if (hasP && !revoked) {
      bytes = base64ToBytes(rawKey);
      if (bytes === null) {
        errors.push('unparseable-key');
      } else {
        keyBytes = bytes.length;
        if (keyType === 'ed25519') {
          // RFC 8463 3: the value is the raw 32-byte Ed25519 public key, not
          // an SPKI structure, so there is no modulus and keyBits stays null.
          if (keyBytes !== 32) errors.push('bad-ed25519-length');
        } else if (keyType === 'rsa') {
          var shape = rsaPublicKeyShape(bytes);
          if (shape === null) errors.push('unparseable-key');
          else {
            keyBits = shape.bits;
            keyEncoding = shape.encoding;
          }
        }
      }
    }

    // Each list tag is validated only when PRESENT. An unknown but well-formed
    // token is an extension and stays in the reported list rather than being
    // called malformed — RFC 6376 is explicit that the vocabularies are
    // extensible.
    var hashAlgorithms = [];
    if (Object.prototype.hasOwnProperty.call(tags, 'h')) {
      hashAlgorithms = parseDkimTagList(tags.h, false) || [];
      if (!hashAlgorithms.length) errors.push('invalid-tag-list');
      else if (!hashAlgorithms.some(function (h) { return DKIM_SUPPORTED_HASHES.indexOf(h) !== -1; })) {
        // Well-formed, and it offers this verifier nothing to work with.
        restrictions.push('no-supported-hash');
      }
    }

    var serviceTypes = [];
    if (Object.prototype.hasOwnProperty.call(tags, 's')) {
      serviceTypes = parseDkimTagList(tags.s, true) || [];
      if (!serviceTypes.length) errors.push('invalid-tag-list');
      // RFC 6376 §3.6.1: a verifier MUST ignore a key record whose service
      // type list does not include the service being verified. `s=tlsrpt`
      // (RFC 8460) is a legitimate restriction and a perfectly good record —
      // it is simply not a key for ordinary email, and counting it as one is
      // how this audit came to report DKIM found where none applies.
      else if (serviceTypes.indexOf('email') === -1 && serviceTypes.indexOf('*') === -1) {
        restrictions.push('service-not-email');
      }
    }

    var flags = [];
    if (Object.prototype.hasOwnProperty.call(tags, 't')) {
      flags = parseDkimTagList(tags.t, false) || [];
      if (!flags.length) errors.push('invalid-tag-list');
    }

    if (Object.prototype.hasOwnProperty.call(tags, 'n') && !isDkimQuotedPrintable(tags.n)) {
      errors.push('invalid-notes');
    }

    var unknownTags = Object.keys(tags).filter(function (name) {
      return DKIM_KEY_TAGS.indexOf(name) === -1;
    });

    return {
      valid: errors.length === 0,
      version: version,
      keyType: keyType,
      revoked: revoked,
      keyBits: keyBits,
      keyBytes: keyBytes,
      // Which of the two conformant RSA envelopes this key uses, as evidence.
      // It is NOT a quality signal — both are valid — but it explains why Web
      // Crypto confirmed one key and stayed silent about another.
      keyEncoding: keyEncoding,
      hashAlgorithms: hashAlgorithms,
      serviceTypes: serviceTypes,
      flags: flags,
      testing: flags.indexOf('y') !== -1,
      strictSubdomain: flags.indexOf('s') !== -1,
      notes: Object.prototype.hasOwnProperty.call(tags, 'n') ? tags.n : '',
      unknownTags: unknownTags,
      cryptoValidated: null,
      errors: Array.from(new Set(errors)),
      restrictions: restrictions,
      // Does this record APPLY to ordinary email for this domain?
      //
      // Deliberately not "is it well-formed". A key with a truncated `p=` was
      // meant for email and is broken, so it still counts as DKIM found and is
      // reported broken by `dkim-key-unparseable` — dropping it here would
      // silently convert a warning about a broken key into "no DKIM at all",
      // which is a worse answer and a regression of an existing finding. What
      // this excludes is the record that is perfectly good and simply not for
      // this purpose: an unrecognized `k=`, or `s=` scoped to another service.
      appliesToEmail: !revoked && restrictions.length === 0,
    };
  }

  /**
   * Optional structural confirmation through Web Crypto.
   *
   * Confirmation only, and only for the encoding Web Crypto can express. It
   * never lowers a verdict reached without it:
   *
   *  - no `crypto.subtle` → `cryptoValidated` stays null, "we did not check"
   *  - a bare PKCS#1 key → also null. `importKey` takes 'spki' and not
   *    'pkcs1', so there is nothing here to confirm a conformant bare key
   *    with, and silence is the honest record. Treating that silence as a
   *    failure would report a valid published key as broken on the strength of
   *    an API's input formats.
   *  - an SPKI key that fails to import → `key-structure-invalid`, with the
   *    DER-derived size left exactly as it was. The size was read without the
   *    browser's help and does not become less true because the browser
   *    declined to confirm it.
   */
  async function validateDkimKeyStructure(key, txtValue) {
    var subtle = typeof crypto !== 'undefined' && crypto && crypto.subtle;
    if (!subtle || key.keyType !== 'rsa' || key.revoked || key.keyBits === null) return key;
    if (key.keyEncoding !== 'spki') return key;
    var bytes = base64ToBytes(parseDkimKeyTagList(txtValue).tags.p);
    if (!bytes) return key;
    try {
      await subtle.importKey('spki', bytes,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
      key.cryptoValidated = true;
    } catch (e) {
      key.cryptoValidated = false;
      if (key.errors.indexOf('key-structure-invalid') === -1) key.errors.push('key-structure-invalid');
      key.valid = false;
    }
    return key;
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
      var notSynthesized = function (value) { return !(synthesized && synthesized.has(value)); };
      var set = dkimRecordSet(result.answers);
      var keys = set.keys.filter(notSynthesized);
      var unusable = set.unusable.filter(notSynthesized);
      var malformed = set.malformed.filter(notSynthesized);
      // A revoked key stops the walk as surely as a live one does. It is an
      // answer — the operator published it on purpose to retire the selector —
      // and continuing past it would report the selector as absent, which reads
      // as "you never set this up" rather than "you turned this off".
      var revoked = set.revoked.filter(notSynthesized);
      if (keys.length || revoked.length || unusable.length || malformed.length) {
        return { sel: selector, queryName: queryName, keys: keys, revoked: revoked, unusable: unusable, malformed: malformed, cname: firstCname };
      }
      var cnameAnswer = result.answers.find(function (answer) { return answer.type === 5; });
      if (!cnameAnswer) break;
      name = cleanAnswerData(cnameAnswer.data, 'CNAME').toLowerCase().replace(/\.$/, '');
      if (!firstCname) firstCname = name;
    }
    return { sel: selector, queryName: queryName, keys: [], revoked: [], unusable: [], malformed: [], cname: firstCname };
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
    const revokedSelectors = [];
    const unusableSelectors = [];
    const malformedSelectors = [];
    for (var offset = 0; offset < selectorList.length; offset += DKIM_SCAN_BATCH_SIZE) {
      var batch = selectorList.slice(offset, offset + DKIM_SCAN_BATCH_SIZE);
      var checks = await Promise.all(batch.map(async function (selector) {
        try {
          return await inspectDkimSelector(domain, selector, queryOpts, synthesized);
        } catch (error) {
          if (error && error.name === 'AbortError') throw error;
          return { sel: selector, keys: [], revoked: [], unusable: [], malformed: [], cname: '', error: true };
        }
      }));
      for (const { sel, queryName, keys, revoked, unusable, malformed, cname, error } of checks) {
        if (error) { failedSelectors.push(sel); continue; }
        // Reported whether or not a live key was also found, because a revoked
        // record left behind next to a working one is a different situation
        // from a selector that is only a revocation.
        (revoked || []).forEach(function (value) {
          revokedSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
        // Published here, and not a key this domain's email can be verified
        // with. Reported so the operator sees why the selector did not count,
        // rather than being told nothing was found at a name they configured.
        (unusable || []).forEach(function (value) {
          unusableSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
        (malformed || []).forEach(function (value) {
          malformedSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
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
            key: analyzeDkimKey(keys[0]),
          });
        } else if (suppliedSelectors.has(sel) && !(revoked || []).length && !(unusable || []).length && !(malformed || []).length) {
          // Only when NOTHING was published here. A selector carrying a revoked
          // key or one scoped to another service has a record at that name, and
          // reporting "No Domain Key Found" alongside a finding that describes
          // the record contradicts itself — the operator is told in one line
          // that the name is empty and in the next what it contains.
          missingSelectors.push({ sel: sel, queryName: queryName, cname: cname });
        }
      }
    }

    // One parallel pass rather than one await per selector. The DER walk has
    // already produced every size this reports; all that is outstanding is the
    // optional structural confirmation, and it never lowers a size.
    await Promise.all(found.map(function (entry) { return validateDkimKeyStructure(entry.key, entry.value); }));
    const keyProfile = summarizeDkimKeys(found);

    if (!found.length) {
      return { found: false, selectors: [], missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, revokedSelectors, unusableSelectors, malformedSelectors, keyProfile, confidence: 'sampled', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: wildcardDkim ? 'noteWildcard' : failedSelectors.length ? 'noteNotFoundWithErrors' : 'noteNotFound' };
    }
    return { found: true, selectors: found, missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, revokedSelectors, unusableSelectors, malformedSelectors, keyProfile, confidence: 'observed', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: '' };
  }

  /**
   * Roll the per-selector key analyses up to one domain-level profile.
   *
   * `mixed` is about strength, not algorithm: RSA-1024 next to RSA-2048 means
   * mail signed by the weaker selector is only as strong as that selector, so
   * the domain's real DKIM strength is its minimum and not its best. Ed25519
   * alongside RSA is not mixed in that sense — RFC 8463 double-signing is the
   * recommended migration path — so it is counted in `algorithms` and left out
   * of `mixed`.
   */
  function summarizeDkimKeys(selectors) {
    var sizes = [];
    var algorithms = [];
    (selectors || []).forEach(function (entry) {
      var key = entry && entry.key;
      if (!key) return;
      if (algorithms.indexOf(key.keyType) === -1) algorithms.push(key.keyType);
      if (typeof key.keyBits === 'number') sizes.push(key.keyBits);
    });
    return {
      minBits: sizes.length ? Math.min.apply(null, sizes) : null,
      maxBits: sizes.length ? Math.max.apply(null, sizes) : null,
      algorithms: algorithms,
      mixed: sizes.length > 1 && Math.min.apply(null, sizes) !== Math.max.apply(null, sizes),
    };
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
    // Legacy, and unreachable from analyzeDomain(): the Tree Walk never passes
    // `multiple`, because RFC 9989 §4.10 step 2 discards duplicate records at a
    // name and CONTINUES the walk — a record higher in the tree can still
    // apply, so a duplicate is no longer a policy verdict. Retained because
    // analyzeDmarc() is exported and directly constructed in tests, and because
    // removing a status token is a breaking change to a shape
    // report-comparison (0.8.0) exports. Do not describe this as current
    // discovery behaviour; buildIssues() raises the duplicate from the walk's
    // own observed[] evidence instead.
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
  /** Every report destination host a record names, in RFC 9990 §3.5's order. */
  function reportDestinationHosts(dmarcStatus) {
    var seen = new Set();
    return []
      .concat(dmarcStatus && dmarcStatus.ruaUris ? dmarcStatus.ruaUris.domains : [])
      .concat(dmarcStatus && dmarcStatus.rufUris ? dmarcStatus.rufUris.domains : [])
      .filter(function (dest) {
        if (!dest || seen.has(dest)) return false;
        seen.add(dest);
        return true;
      });
  }

  /**
   * Decide which destinations this audit will examine, and record how many it
   * declined to.
   *
   * The truncation is surfaced rather than silent: showing ten verdicts for a
   * record naming twenty destinations would imply every URI had been checked,
   * which is the same "unknown presented as known" error this codebase refuses
   * everywhere else.
   */
  function planReportDestinations(dmarcStatus, policyDomain, orgDomains) {
    var all = reportDestinationHosts(dmarcStatus);
    var checked = all.slice(0, MAX_REPORT_DESTINATIONS);
    return {
      external: findExternalReportDestinations(dmarcStatus, policyDomain, orgDomains, checked),
      total: all.length,
      omitted: all.slice(MAX_REPORT_DESTINATIONS),
    };
  }

  function findExternalReportDestinations(dmarcStatus, policyDomain, orgDomains, hosts) {
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
    return (hosts || reportDestinationHosts(dmarcStatus)).filter(function (dest) {
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
  // query count for one audit is set by that record's own content.
  //
  // The bound has to cover the WHOLE destination-driven workflow. Capping only
  // the Organizational Domain walks left the authorization lookups uncapped, so
  // twenty destinations still produced forty authorization queries and the
  // "bound" was not one. RFC 9990 §3.5 sanctions a limit explicitly — reports
  // go to every URI "up to the Receiver's limits on supported URIs" — and fixes
  // the order to apply it in: receivers "MUST evaluate the provided reporting
  // URIs (see [RFC9989]) in the order given".
  var MAX_REPORT_DESTINATIONS = 10;

  async function resolveDestinationOrgDomains(dmarcStatus, policyDomain, policyOrgDomain, queryOpts) {
    var orgDomains = new Map();
    orgDomains.set(policyDomain, policyOrgDomain);
    var candidates = reportDestinationHosts(dmarcStatus)
      .slice(0, MAX_REPORT_DESTINATIONS)
      .filter(function (dest) { return dest !== policyOrgDomain; });
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
  /**
   * Parse one external-authorization TXT record per RFC 9990 §4 step 6.
   *
   * > For each record returned, parse the result as a series of "tag=value"
   * > pairs, i.e., the same overall format as the DMARC Policy Record (see
   * > Section 4.7 of [RFC9989]).  In particular, the "v=DMARC1" tag is
   * > mandatory and MUST appear first in the list.  Discard any that do not
   * > pass this test.  A trailing ";" is optional.
   *
   * The `v=DMARC1` test is necessary and NOT sufficient: "parse the result as
   * a series of tag=value pairs" is part of the same step, so a record whose
   * remaining syntax is not tag=value must be discarded before step 8 counts
   * the survivors. Checking only the version tag accepted
   * `v=DMARC1; this-is-not-a-tag-value-pair` as an authorization.
   *
   * Step 9 lets the Report Consumer override the report destination, but "the
   * overriding URI MUST use the same destination host from the first step".
   * This tool never sends reports, so the override changes no verdict — it is
   * captured because an "authorized" result that silently dropped it would be
   * incomplete evidence about where conformant receivers actually deliver.
   */
  function parseReportAuthRecord(record, destinationHost) {
    var text = String(record || '');
    if (!validateDmarcVersion(text).valid) return { valid: false, reason: 'version' };
    var segments = text.split(';');
    // "A trailing ';' is optional" — so one empty tail segment is allowed, but
    // an empty segment anywhere else is a syntax error rather than a courtesy.
    if (segments.length && segments[segments.length - 1].trim() === '') segments.pop();
    var wellFormed = segments.every(function (segment) {
      return /^\s*[A-Za-z][A-Za-z0-9_-]*\s*=\s*[^;]*$/.test(segment);
    });
    if (!wellFormed) return { valid: false, reason: 'syntax' };

    var rua = parseDmarcTag(text, 'rua');
    var override = null;
    var overrideValid = true;
    var overrideReason = null;
    if (rua !== null) {
      var parsed = parseDmarcUriList(rua);
      var hosts = parsed.uris.filter(function (u) { return u.valid; }).map(function (u) { return u.domain; });
      override = rua;
      /* Step 9 lets the Report Consumer override the destination, but "the
         overriding URI MUST use the same destination host from the first
         step", and the paragraph after the algorithm says what a violation
         costs:

         > Further, if the confirming record includes a URI whose host is again
         > different than the domain publishing that override, the Mail
         > Receiver generating the report MUST NOT generate a report to either
         > the original or the override URI.

         So a cross-host override does not merely void itself — it makes the
         whole arrangement unusable, and neither URI receives anything. That is
         a different fact from "the destination never authorized you", and it
         has a different fix, so it gets its own state rather than being folded
         into `unauthorized`.

         A merely malformed override is not the same case. RFC 9990 §3.5 says
         of reporting URIs that "if any of the URIs are malformed, they SHOULD
         be ignored" — ignored, not escalated — so the authorization stands and
         the override is dropped. */
      if (parsed.count > 0 && hosts.length && !hosts.every(function (h) { return h === destinationHost; })) {
        overrideValid = false;
        overrideReason = 'cross-host';
      } else if (!parsed.valid || parsed.count === 0) {
        overrideValid = false;
        overrideReason = 'malformed';
      }
    }
    return {
      valid: true, reason: null,
      override: override, overrideValid: overrideValid, overrideReason: overrideReason,
    };
  }

  async function checkExternalReportAuth(domain, destinations, queryOpts) {
    var policyDomain = String(domain || '').toLowerCase().replace(/\.$/, '');
    var unique = [];
    var seen = new Set();
    (destinations || []).forEach(function (d) {
      var host = String(d || '').toLowerCase().replace(/\.$/, '');
      if (host && !seen.has(host)) { seen.add(host); unique.push(host); }
    });

    return Promise.all(unique.map(async function (host) {
      var exact = policyDomain + '._report._dmarc.' + host;
      // RFC 9990 §4 step 4: "If the length of the constructed name exceed DNS
      // limits, a positive determination of the external reporting
      // relationship cannot be made; stop." Cannot-determine and
      // not-authorized are different facts.
      if (exact.length > 253) {
        return {
          destination: host, state: 'unverifiable', via: null, queryName: exact,
          record: '', error: 'name-too-long',
        };
      }
      try {
        /* RFC 9990 §4 constructs and queries exactly ONE name (steps 2, 3 and
           5). A Report Consumer willing to receive reports for any domain
           publishes `*._report._dmarc.<host>`, and the resolver synthesizes
           that RRset while answering this query — there is no second lookup to
           make. Querying the asterisk owner literally is not the algorithm and
           gets a different question answered: RFC 4592 §2.3 is explicit that
           "when a wildcard domain name appears in a message's query section, no
           special processing occurs", so such a query retrieves the literal
           wildcard node rather than exercising synthesis.

           That distinction changes verdicts, which is why this is not merely a
           saved query. Wildcard synthesis is suppressed when the queried name
           already exists, so a destination whose exact owner holds unrelated or
           malformed TXT data is NOT authorized under RFC 9990 — while a
           literal wildcard lookup would find `v=DMARC1` and wrongly authorize
           it. Verified against three live reporting vendors: the constructed
           query already returns the synthesized answer. */
        var response = await dohFetch(exact, 'TXT', queryOpts);
        if (response.kind === 'cancelled') throw dnsError('cancelled', exact, 'TXT');
        if (response.kind !== 'success' && response.kind !== 'nodata' && response.kind !== 'nxdomain') {
          throw dnsError(response.kind, exact, 'TXT', response.httpStatus ? 'HTTP ' + response.httpStatus : '');
        }
        var records = response.answers.filter(function (a) { return a.type === 16; })
          .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
        var parsed = records.map(function (r) { return parseReportAuthRecord(r, host); });
        var authorizedAt = parsed.findIndex(function (p) { return p.valid; });

        /* Step 8, verbatim: "If at least one TXT resource record remains in the
           set after parsing, then the external reporting arrangement was
           authorized by the Report Consumer."

           Permissive, and deliberately the opposite of the DMARC policy
           duplicate rule in discoverDmarc(), where RFC 9989 §4.10 step 2
           discards every record when more than one is returned. The two
           questions are asked at different names, for different purposes, by
           different RFCs, and they answer them differently. Do not "fix"
           either one to match the other. */
        if (authorizedAt !== -1) {
          var winner = parsed[authorizedAt];
          // An arrangement whose override points at a third party is not a
          // usable reporting destination: conformant receivers send to neither
          // URI. Reporting it as `authorized` would tell the operator their
          // reports are flowing when nothing is being sent at all.
          var crossHost = winner.overrideReason === 'cross-host';
          return {
            destination: host,
            state: crossHost ? 'override-mismatch' : 'authorized',
            via: 'exact', queryName: exact,
            record: records[authorizedAt],
            recordCount: parsed.filter(function (p) { return p.valid; }).length,
            exactKind: response.kind,
            override: winner.override || null,
            overrideValid: winner.override ? winner.overrideValid : null,
            overrideReason: winner.overrideReason || null,
          };
        }
        // A TXT record that exists but does not parse authorizes nothing —
        // worth distinguishing from nothing at all, because it usually means a
        // truncated or hand-mangled record.
        return {
          destination: host, state: 'unauthorized', via: null, queryName: exact,
          record: records[0] || '', malformed: records.length > 0,
          exactKind: response.kind,
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

  /* ── CAA (RFC 8659, RFC 9495) ─────────────────────────────────────────
     A CAA record set is a policy, and reducing it to a green dot loses the
     whole policy. `0 issue ";"` locks out every certificate authority and
     `0 issuewild ";"` locks out wildcards only; before this, both rendered
     identically to `0 issue "letsencrypt.org"`.
     ───────────────────────────────────────────────────────────────────── */

  // RFC 8659 §4 defines issue, issuewild and iodef; RFC 9495 §3 defines
  // issuemail. `contactemail` and `contactphone` are NOT from RFC 9495 — the
  // IANA CAA registry attributes both to CA/Browser Forum documents, and an
  // earlier comment here cited the wrong source for them.
  var CAA_KNOWN_TAGS = ['issue', 'issuewild', 'iodef', 'issuemail', 'contactemail', 'contactphone'];
  // Properties whose Property Value is an issuer-domain-name with optional
  // parameters: RFC 8659 §4.2 and §4.3, and RFC 9495 §3.
  var CAA_ISSUER_TAGS = ['issue', 'issuewild', 'issuemail'];
  // RFC 8659 §4.2: label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
  var CAA_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
  // RFC 8659 §4.2: value = *(%x21-3A / %x3C-7E) — VCHAR excluding ';' and SP.
  var CAA_PARAMETER_VALUE = /^[\x21-\x3A\x3C-\x7E]*$/;
  // RFC 8659 §4.4: the iodef value is a URL using the mailto, http or https
  // scheme. The scheme list is the start of the check, not the whole of it.

  /**
   * Validate an `issue` / `issuewild` / `issuemail` Property Value and return
   * its issuer-domain-name — `''` for a value that authorizes nobody, or null
   * when the value does not match the grammar at all.
   *
   * The distinction matters more than it looks. RFC 8659 §4.2 uses `%%%%%` as
   * its own example of a malformed value and requires a CA to treat it like an
   * absent issuer-domain-name, so a domain publishing only that has blocked
   * issuance. Reading the text before the first semicolon as a CA identity
   * turned that into "authorized: %%%%%" and reported the policy backwards —
   * the strongest form of the mistake this release exists to avoid, because it
   * says a domain is open when the RFC says it is shut.
   */
  function parseCaaIssueValue(value) {
    var text = String(value === undefined || value === null ? '' : value);
    var semicolon = text.indexOf(';');
    var domain = (semicolon === -1 ? text : text.slice(0, semicolon)).trim();
    if (domain) {
      var labels = domain.split('.');
      for (var i = 0; i < labels.length; i++) {
        if (!CAA_LABEL.test(labels[i])) return null;
      }
    }
    if (semicolon !== -1) {
      var rest = text.slice(semicolon + 1).trim();
      // A trailing ';' with nothing after it is legal: the parameters section
      // is optional even once its separator is present.
      if (rest) {
        var parameters = rest.split(';');
        for (var j = 0; j < parameters.length; j++) {
          var parameter = parameters[j].trim();
          var equals = parameter.indexOf('=');
          if (equals < 1) return null;
          if (!CAA_LABEL.test(parameter.slice(0, equals))) return null;
          if (!CAA_PARAMETER_VALUE.test(parameter.slice(equals + 1))) return null;
        }
      }
    }
    return domain.toLowerCase();
  }

  /**
   * RFC 8659 §4.4: an iodef destination is a mailto, http or https **URL**.
   *
   * A scheme prefix is not a URL. `mailto:not an address` starts with a
   * supported scheme and is not a destination anything can report to, so the
   * whole value goes through the same validators the other records use.
   */
  function isCaaIodefUrl(value) {
    return isMailtoUri(value) || isHttpUri(value, false);
  }

  /**
   * Parse one CAA record from its presentation form: `<flags> <tag> "<value>"`.
   *
   * Captured from the resolver rather than assumed — Cloudflare returns
   * `0 issue "letsencrypt.org"` and `0 iodef "mailto:dns-admin@example.org"`,
   * with the value quoted and the flags and tag bare. Unlike the DS/DNSKEY/TLSA
   * path this one IS quoted, which is why checkCAA() reads `a.data` directly
   * instead of going through cleanAnswerData().
   */
  function parseCaaRecord(presentationString) {
    var text = String(presentationString || '').trim();
    var errors = [];
    var match = /^(\S+)\s+(\S+)\s*([\s\S]*)$/.exec(text);
    if (!match) {
      return { flags: 0, critical: false, tag: '', value: '', known: false, valid: false, errors: ['unparseable-record'] };
    }

    var flags = 0;
    if (/^\d{1,3}$/.test(match[1]) && Number(match[1]) <= 255) flags = Number(match[1]);
    else errors.push('bad-flags');

    // RFC 8659 §4.1: the tag is 1–15 ALPHA/DIGIT octets, and it is matched
    // case-insensitively, so it is lowercased here once for every comparison.
    var tag = match[2].toLowerCase();
    if (!/^[a-z0-9]{1,15}$/.test(tag)) errors.push('bad-tag');

    var raw = match[3].trim();
    var value;
    if (/^".*"$/.test(raw)) value = raw.slice(1, -1).replace(/\\(.)/g, '$1');
    else {
      value = raw;
      // Not fatal: the value is still readable and every resolver observed
      // quotes it, so an unquoted one is worth naming without discarding.
      if (raw) errors.push('unquoted-value');
    }

    var known = CAA_KNOWN_TAGS.indexOf(tag) !== -1;

    // A known tag is a promise about the value's grammar, and until now only
    // the tag was checked. `contactemail` and `contactphone` are deliberately
    // NOT validated here. Neither affects the derived issuance posture, both
    // are defined by CA/Browser Forum documents rather than by an RFC this
    // file otherwise tracks, and a partial mailbox or telephone parser is far
    // easier to reject wrongly than to check usefully — a false
    // `caa-malformed` on a real record is worse than an unvalidated one.
    var issuer = null;
    if (known && CAA_ISSUER_TAGS.indexOf(tag) !== -1) {
      issuer = parseCaaIssueValue(value);
      if (issuer === null) errors.push('bad-issue-value');
    }
    if (known && tag === 'iodef' && !isCaaIodefUrl(value)) errors.push('bad-iodef-url');

    return {
      flags: flags,
      // RFC 8659 §4.1: bit 0, the most significant bit, is the Issuer Critical
      // flag. A CA that does not understand a critical property MUST refuse to
      // issue — so an unrecognized tag with this bit set is a live outage risk,
      // and the same tag without it is inert.
      critical: (flags & 0x80) !== 0,
      tag: tag,
      value: value,
      known: known,
      // The validated issuer-domain-name: '' authorizes nobody, null means the
      // value did not parse. Never a guess at what the operator might have
      // meant.
      issuer: issuer,
      valid: errors.length === 0,
      errors: errors,
    };
  }

  function summarizeCaa(records) {
    var parsed = records.map(parseCaaRecord);
    var issueRecords = parsed.filter(function (r) { return r.tag === 'issue'; });
    var wildRecords = parsed.filter(function (r) { return r.tag === 'issuewild'; });
    // Only a record that PARSED contributes an issuer. A malformed value is an
    // absent issuer-domain-name per RFC 8659 §4.2, which is why it can block
    // issuance rather than authorize a CA whose name is nonsense.
    var namedIssuers = function (group) {
      return group.filter(function (r) { return r.valid && r.issuer; })
        .map(function (r) { return r.issuer; });
    };
    var issuers = namedIssuers(issueRecords);
    var wildcardIssuers = namedIssuers(wildRecords);

    return {
      parsed: parsed,
      issuers: issuers,
      // Empty is not "unrestricted". RFC 8659 §4.3: with no issuewild present,
      // wildcard issuance is governed by the issue set. Reading an absent
      // issuewild as "wildcards are open" inverts the policy.
      wildcardIssuers: wildcardIssuers,
      // RFC 8659 §4.2: an issue value of ';' (or empty) names no issuer, and a
      // set of those authorizes nobody at all.
      issuanceBlocked: issueRecords.length > 0 && issuers.length === 0,
      wildcardBlocked: wildRecords.length > 0 && wildcardIssuers.length === 0,
      iodef: parsed.filter(function (r) { return r.tag === 'iodef'; }).map(function (r) { return r.value; }),
      unknownCritical: parsed.filter(function (r) { return !r.known && r.critical; }).map(function (r) { return r.tag; }),
      // The raw presentation string, not the parsed tag: a record that failed
      // to parse may have no usable tag to name it by, and the operator needs
      // to see the text they published in order to find it in their zone.
      malformed: records.filter(function (raw, i) { return !parsed[i].valid; }),
    };
  }

  async function checkCAA(domain, queryOpts) {
    // Walk up the domain tree (CAA can be inherited from parent)
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const check = parts.slice(i).join('.');
      const { answers } = requireUsable(await dohFetch(check, 'CAA', queryOpts), check, 'CAA');
      const caaAnswers = answers.filter(a => a.type === 257);
      if (caaAnswers.length > 0) {
        const records = caaAnswers.map(a => a.data);
        return Object.assign({ found: true, records: records, atDomain: check }, summarizeCaa(records));
      }
    }
    return Object.assign({ found: false, records: [], atDomain: null }, summarizeCaa([]));
  }

  /* ── MX health (DNS only) ─────────────────────────────────────────────
     No SMTP, ever. Everything below is inferred from DNS, so it reports what
     is published and never what a delivery attempt would do.
     ───────────────────────────────────────────────────────────────────── */

  /** Prefix width used to notice that every MX host sits in one block. */
  var MX_PREFIX_BITS = { ipv4: 24, ipv6: 48 };

  /** Render a network address back to text, for the prefix label only. */
  function bigIntToIp(value, family) {
    if (family === 'ipv4') {
      return [24n, 16n, 8n, 0n].map(function (shift) { return String((value >> shift) & 0xffn); }).join('.');
    }
    var groups = [];
    for (var i = 7; i >= 0; i--) groups.push((((value >> BigInt(i * 16)) & 0xffffn)).toString(16));
    return groups.join(':');
  }

  /** `10 mail.example.com.` → `{ preference: 10, host: 'mail.example.com' }`. */
  function parseMxRecord(record) {
    var parts = String(record || '').trim().split(/\s+/);
    if (parts.length < 2 || !/^\d+$/.test(parts[0])) return null;
    var host = parts.slice(1).join(' ').replace(/\.$/, '').toLowerCase();
    if (!host) return null;
    return { preference: Number(parts[0]), host: host };
  }

  /**
   * Resolve every MX target and report what DNS alone can say about it.
   *
   * An MX host that does not resolve is a total inbound mail outage, and today
   * it reads in the interface exactly like a healthy mail domain. That is the
   * finding this function exists for; the rest — CNAME targets, single points
   * of failure, address-block concentration — are hygiene notes.
   *
   * Each host is resolved independently and a failure degrades that host to
   * `resolves: 'unknown'`. A resolver hiccup on one target must not turn the
   * other targets' answers into an outage report, and must never let a host we
   * could not check be counted as dangling. That is optionalCheck()'s rule
   * applied per host rather than to the audit as a whole.
   */
  async function auditMxHosts(mx, domain, queryOpts) {
    var entries = (mx || []).map(parseMxRecord).filter(Boolean);
    if (!entries.length) {
      return {
        hosts: [], danglingHosts: [], cnameHosts: [], duplicatePreferences: [],
        singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: false,
      };
    }

    // Distinct delivery targets. Two MX records naming the same exchange at
    // different preferences are one host, one point of failure and one set of
    // lookups — mapping records straight to audits queried it twice, counted it
    // twice in the CSV, and suppressed `mx-single-host` on a domain that has
    // exactly one. The records themselves stay in `entries` for the preference
    // analysis, which is about the records and not the targets.
    var targets = [];
    var byHost = Object.create(null);
    entries.forEach(function (entry) {
      var target = byHost[entry.host];
      if (target) { target.preferences.push(entry.preference); return; }
      target = { host: entry.host, preference: entry.preference, preferences: [entry.preference] };
      byHost[entry.host] = target;
      targets.push(target);
    });
    // The lowest preference is the one a sender reaches first, so it is the one
    // that describes the target.
    targets.forEach(function (target) {
      target.preference = Math.min.apply(null, target.preferences);
    });

    var hosts = await Promise.all(targets.map(async function (entry) {
      var UNKNOWN = {};
      var results = await Promise.all([
        optionalCheck(function () { return dohQuery(entry.host, 'A', queryOpts); }, UNKNOWN),
        optionalCheck(function () { return dohQuery(entry.host, 'AAAA', queryOpts); }, UNKNOWN),
        optionalCheck(function () { return dohQuery(entry.host, 'CNAME', queryOpts); }, UNKNOWN),
      ]);
      var v4 = results[0] === UNKNOWN ? null : results[0];
      var v6 = results[1] === UNKNOWN ? null : results[1];
      var cname = results[2] === UNKNOWN ? null : results[2];
      var addresses = (v4 || []).concat(v6 || []);
      return {
        host: entry.host,
        preference: entry.preference,
        // Every preference this host is published at. One host at two
        // preferences is still one host, and the duplication is evidence.
        preferences: entry.preferences,
        addresses: addresses,
        v4Count: v4 ? v4.length : 0,
        v6Count: v6 ? v6.length : 0,
        // 'no' is claimed only when both address lookups actually returned.
        // One failed lookup and one empty answer is not evidence of absence.
        resolves: addresses.length ? 'yes' : (v4 === null || v6 === null) ? 'unknown' : 'no',
        isCname: cname === null ? false : cname.length > 0,
        cnameUnknown: cname === null,
        inAudited: entry.host === domain || entry.host.endsWith('.' + domain),
      };
    }));

    var seenPreferences = Object.create(null);
    var duplicatePreferences = [];
    entries.forEach(function (entry) {
      if (seenPreferences[entry.preference]) {
        if (duplicatePreferences.indexOf(entry.preference) === -1) duplicatePreferences.push(entry.preference);
      }
      seenPreferences[entry.preference] = true;
    });

    // Only hosts whose addresses we actually read can tell us anything about
    // concentration, so an unknown host is left out rather than counted as
    // sharing or not sharing a block.
    var groups = Object.create(null);
    hosts.filter(function (h) { return h.resolves === 'yes'; }).forEach(function (h) {
      h.addresses.forEach(function (address) {
        var family = address.indexOf(':') === -1 ? 'ipv4' : 'ipv6';
        var block = parseIpCidr(address + '/' + MX_PREFIX_BITS[family], family);
        if (!block) return;
        var network = block.address >> BigInt(block.bits - block.prefix) << BigInt(block.bits - block.prefix);
        var label = bigIntToIp(network, family) + '/' + MX_PREFIX_BITS[family];
        if (!groups[label]) groups[label] = [];
        if (groups[label].indexOf(h.host) === -1) groups[label].push(h.host);
      });
    });
    var sharedPrefixes = Object.keys(groups)
      .filter(function (label) { return groups[label].length > 1; })
      .map(function (label) { return { prefix: label, hosts: groups[label] }; });

    var resolved = hosts.filter(function (h) { return h.resolves === 'yes'; });
    var withV6 = resolved.filter(function (h) { return h.v6Count > 0; });

    return {
      hosts: hosts,
      danglingHosts: hosts.filter(function (h) { return h.resolves === 'no'; }).map(function (h) { return h.host; }),
      cnameHosts: hosts.filter(function (h) { return h.isCname; }).map(function (h) { return h.host; }),
      duplicatePreferences: duplicatePreferences,
      singleHost: hosts.length === 1,
      ipv6Coverage: !resolved.length ? 'none'
        : withV6.length === resolved.length ? 'all'
          : withV6.length ? 'some' : 'none',
      sharedPrefixes: sharedPrefixes,
      unknown: hosts.some(function (h) { return h.resolves === 'unknown'; }),
    };
  }

  /* ── TLSA / DANE (RFC 6698, RFC 7671) ─────────────────────────────────
     Syntax only. Nothing here connects to port 25 and nothing compares a TLSA
     record against a certificate, so what is reported is what is published.

     The labelling rule matters more than the parsing. DANE is meaningful only
     when the TLSA record is carried by a validated DNSSEC chain: without one,
     anyone on the path can strip or rewrite the record, so an unsigned TLSA
     record provides no protection whatsoever while looking exactly like
     protection.

     Two separate facts, deliberately not merged. `authenticated` is the AD bit
     the validating resolver returned for this exact name, which is real
     evidence and is what the unsigned finding is gated on — without it the
     finding would announce "your TLSA is unprotected" on a correctly signed
     zone purely because this release had not looked. `qualified` is the
     stronger claim that the chain was walked and verified, which
     dnssec-evidence (0.5.0) supplies; it stays false here, and every string
     the interface shows says "published", never "enabled".
     ───────────────────────────────────────────────────────────────────── */

  var TLSA_MATCHING_LENGTHS = { 1: 32, 2: 64 };   // SHA-256, SHA-512; 0 is a full cert, any length

  /**
   * Parse one TLSA record from its presentation form.
   *
   * Captured from the resolver before this was written, because the shape is
   * not the one the neighbouring DS parser would suggest: Cloudflare returns
   * TLSA as `3 1 1 ( 87D109DD… )` — parenthesised, with spaces inside the
   * parentheses, in uppercase hex — where DS comes back as four plain fields
   * in lowercase. Splitting on whitespace the way a DS parser does yields
   * ['3','1','1','('] and reads the association data as an empty string,
   * raising no error at all. Hence the explicit strip.
   */
  function parseTlsaRecord(presentationString) {
    var text = String(presentationString || '').trim();
    var match = /^(\d+)\s+(\d+)\s+(\d+)\s+([\s\S]+)$/.exec(text);
    if (!match) {
      return { usage: null, selector: null, matchingType: null, data: '', valid: false, errors: ['unparseable-record'] };
    }
    var usage = Number(match[1]);
    var selector = Number(match[2]);
    var matchingType = Number(match[3]);

    var errors = [];
    // The wrapper is either absent or one balanced outer pair. Stripping each
    // side independently accepted `( ABCD…` and `ABCD… )` alike, which defeats
    // the syntactic contract of a parser written specifically for this
    // presentation form.
    var body = match[4].trim();
    var opened = body.charAt(0) === '(';
    var closed = body.length > 1 && body.charAt(body.length - 1) === ')';
    if (opened !== closed) {
      return {
        usage: usage, selector: selector, matchingType: matchingType,
        data: '', valid: false, errors: ['unbalanced-parentheses'],
      };
    }
    if (opened) body = body.slice(1, -1);
    var data = body.replace(/\s+/g, '').toLowerCase();

    // RFC 6698 §2.1.1–2.1.3, and RFC 7671 §4 for the SMTP-usable subset.
    if (!(usage >= 0 && usage <= 3)) errors.push('bad-usage');
    if (!(selector >= 0 && selector <= 1)) errors.push('bad-selector');
    if (!(matchingType >= 0 && matchingType <= 2)) errors.push('bad-matching-type');
    if (!/^[0-9a-f]+$/.test(data) || data.length % 2 !== 0) errors.push('bad-association-data');
    else {
      var expected = TLSA_MATCHING_LENGTHS[matchingType];
      // Matching type 0 is the full certificate or SPKI, of no fixed length.
      if (expected !== undefined && data.length / 2 !== expected) errors.push('bad-digest-length');
    }

    return {
      usage: usage, selector: selector, matchingType: matchingType,
      data: data, valid: errors.length === 0, errors: errors,
    };
  }

  /**
   * Look up `_25._tcp.<host>` for every MX host and validate what comes back.
   */
  async function checkTlsa(mxHosts, queryOpts) {
    var hosts = await Promise.all((mxHosts || []).map(async function (host) {
      var queryName = '_25._tcp.' + host;
      var UNKNOWN = {};
      // `do=1` costs nothing — the query is being made anyway — and it is the
      // difference between "this record is not protected" and "we did not
      // look". The filter on type 52 is not optional either: a TLSA query
      // commonly returns a CNAME alongside the records, because pointing
      // _25._tcp.<host> at a shared _dane.<zone> name is ordinary practice,
      // and handing that CNAME string to the record parser would report a
      // malformed TLSA record on a correctly configured host.
      var result = await optionalCheck(function () {
        return dohFetch(queryName, 'TLSA', Object.assign({}, queryOpts, { dnssec: true }))
          .then(function (r) { return requireUsable(r, queryName, 'TLSA'); });
      }, UNKNOWN);
      if (result === UNKNOWN) {
        return { host: host, queryName: queryName, records: [], present: false, authenticated: null, unknown: true };
      }
      var records = result.answers.filter(function (a) { return a.type === 52; })
        .map(function (a) { return parseTlsaRecord(cleanAnswerData(a.data, 'TLSA')); });
      return {
        host: host,
        queryName: queryName,
        records: records,
        present: records.length > 0,
        // The AD bit from the same validating resolver checkDNSSEC() already
        // trusts, read for THIS name rather than for the audited domain — an
        // MX host usually lives in someone else's zone, so the audited
        // domain's DNSSEC status says nothing about whether this record is
        // protected. null means the lookup did not complete.
        authenticated: result.ad === true,
        unknown: false,
      };
    }));

    var present = hosts.filter(function (h) { return h.present; });
    return {
      hosts: hosts,
      anyPresent: present.length > 0,
      // Every host that publishes TLSA does so under an authenticated chain.
      // Evidence, not a verdict: it is what the `tlsa-published-unsigned`
      // finding is gated on, and it is deliberately NOT the same thing as
      // `qualified`.
      allAuthenticated: present.length > 0 && present.every(function (h) { return h.authenticated === true; }),
      unauthenticatedHosts: present.filter(function (h) { return h.authenticated === false; })
        .map(function (h) { return h.host; }),
      unknown: hosts.some(function (h) { return h.unknown; }),
      // Stays false until dnssec-evidence (0.5.0) walks the DS/DNSKEY chain.
      // The AD bit above says a validating resolver authenticated the answer,
      // which is good evidence and not the same as having verified the chain
      // ourselves — so nothing in this release calls DANE active, and the
      // interface says "published", never "enabled".
      qualified: false,
    };
  }

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
  function isHttpUri(value, opts) {
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
  function isMailtoUri(value, opts) {
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

  /**
   * Split a record into ordered `{ name, value }` fields, or null if any field
   * is not `name=value`.
   *
   * Ordered, because RFC 8461 §3.1 and RFC 8460 §3 both require the version
   * field FIRST — a fact an unordered tag map cannot express, which is why
   * `id=abc; v=STSv1` validated. A single trailing delimiter is permitted by
   * both ABNFs.
   */
  function parseOrderedFields(record, opts) {
    var options = opts || {};
    var parts = String(record === undefined || record === null ? '' : record).split(';');
    if (parts.length > 1 && parts[parts.length - 1].trim() === '') parts.pop();
    var fields = [];
    for (var i = 0; i < parts.length; i++) {
      // `field-delim = *WSP ";" *WSP`, so whitespace belongs to the delimiter.
      var field = parts[i].trim();
      var equals = field.indexOf('=');
      if (equals === -1) return null;
      var name = field.slice(0, equals);
      var value = field.slice(equals + 1);
      // MTA-STS and TLS-RPT write their fields as single literals —
      // `%s"v=STSv1"`, `%s"id="`, `%s"rua="` — and their extensions as
      // `name "=" value`. None of those admits whitespace around the `=`, so
      // trimming it accepted `v = STSv1`. BIMI's grammar is looser, hence an
      // option rather than a blanket rule.
      if (!options.strictFieldSyntax) { name = name.trim(); value = value.trim(); }
      fields.push({ name: name, value: value });
    }
    return fields;
  }

  /**
   * Records at a protocol's dedicated owner that MENTION its version field.
   *
   * Recognition is case-insensitive and order-independent on purpose, while
   * validation stays exact. That is the point: a record has to be recognizable
   * as a candidate before it can be diagnosed as a malformed one.
   */
  function versionCandidates(records, token) {
    var pattern = new RegExp('(^|;)\\s*v\\s*=\\s*' + token + '\\s*(;|$)', 'i');
    return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
  }

  /** Records a conforming sender keeps before applying the full validator. */
  function leadingVersionMatches(records, token) {
    // The version literal itself is exact and case-sensitive. The delimiter,
    // however, is `*WSP ";" *WSP` in MTA-STS/TLS-RPT (and tolerated by the
    // BIMI parser), so valid whitespace before the semicolon must not make a
    // sender-compatible record disappear from the effective set.
    var pattern = new RegExp('^v=' + token + '[ \\t]*(?:;|$)');
    return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
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

  // RFC 8461 §3.1: sts-id = 1*32(ALPHA / DIGIT). No hyphens, no 33rd character.
  var STS_ID = /^[a-z0-9]{1,32}$/i;
  // sts-ext-name = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")
  var EXT_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;
  // sts-ext-value = 1*(%x21-3A / %x3C-7E) — VCHAR without ';', and no space.
  // sts-ext-value / tlsrpt-ext-value = 1*(%x21-3A / %x3C / %x3E-7E) — VCHAR
  // excluding ';' (0x3B), '=' (0x3D), SP and controls. The earlier range
  // included 0x3D, so `ext=a=b` validated in both protocols.
  var RECORD_EXT_VALUE = /^[\x21-\x3A\x3C\x3E-\x7E]+$/;
  // BIMI's pinned grammar does not carry the same exclusion, so it keeps the
  // looser value class rather than inheriting a restriction from a different
  // specification.
  var BIMI_EXT_VALUE = /^[\x21-\x3A\x3C-\x7E]+$/;

  /**
   * Validate an MTA-STS TXT record against RFC 8461 §3.1.
   *
   * Ordered and anchored, not a tag-bag lookup. The ABNF puts the version
   * FIRST and writes it `%s"STSv1"`, which is case-SENSITIVE — so
   * `id=abc; v=STSv1` and `v=stsv1` are both unusable and both previously
   * validated. `id` is 1–32 alphanumerics: `has-hyphen` is not one, nor is a
   * 33-character string. A bare `garbage` field is not an extension; the
   * extension grammar requires a name and a value, so it cannot be dropped
   * silently.
   *
   * Getting this wrong suppressed `mta-sts-invalid` — a finding whose entire
   * purpose is to catch a control the operator believes is working.
   */
  function validateMtaStsRecord(record) {
    var fields = parseOrderedFields(record, { strictFieldSyntax: true });
    if (!fields || !fields.length) return { valid: false, id: '', errors: ['invalid-syntax'] };

    var seen = Object.create(null);
    var syntax = fields[0].name === 'v' && fields[0].value === 'STSv1';
    var id = '';
    for (var i = 0; i < fields.length; i++) {
      var name = fields[i].name;
      // RFC 8461 §3.1: "Parsers MUST accept TXT records ... If any non-repeated
      // field is duplicated, all entries except for the first SHALL be
      // ignored." A blanket duplicate rejection is the opposite of that: it
      // called a conformant record invalid, and then reported the LAST id as
      // effective — the one every sender discards.
      if (seen[name]) continue;
      seen[name] = true;
      if (i === 0) continue;
      if (name === 'id') { id = fields[i].value; if (!STS_ID.test(id)) syntax = false; }
      else if (name === 'v') continue;
      else if (!EXT_NAME.test(name) || !RECORD_EXT_VALUE.test(fields[i].value)) syntax = false;
    }
    if (!id) syntax = false;
    return { valid: syntax, id: id, errors: syntax ? [] : ['invalid-syntax'] };
  }

  /**
   * Validate a TLS-RPT TXT record against RFC 8460 §3.
   *
   * Same shape as MTA-STS: version first, `%s"TLSRPTv1"` case-sensitive, and
   * every `rua` destination a real `https:` or `mailto:` URI. Prefix matching
   * accepted `mailto:not an address`, which is a string beginning with a
   * scheme and not a URI.
   */
  function validateTlsRptRecord(record) {
    var fields = parseOrderedFields(record, { strictFieldSyntax: true });
    if (!fields || !fields.length) return { valid: false, destinations: [], errors: ['invalid-syntax'] };

    var seen = Object.create(null);
    var syntax = fields[0].name === 'v' && fields[0].value === 'TLSRPTv1';
    var destinations = [];
    var sawRua = false;
    for (var i = 0; i < fields.length; i++) {
      var name = fields[i].name;
      if (i === 0) { seen[name] = true; continue; }
      // `tlsrpt-record = tlsrpt-version 1*(field-delim tlsrpt-field)` with
      // `tlsrpt-field = tlsrpt-rua / tlsrpt-extension`, so MORE THAN ONE `rua`
      // field is grammatical and conformant. Rejecting it discarded a valid
      // record and threw away the first destination as evidence.
      if (name === 'rua') {
        sawRua = true;
        var uris = fields[i].value.split(',').map(function (v) { return v.trim(); }).filter(Boolean);
        if (!uris.length) syntax = false;
        uris.forEach(function (uri) {
          // RFC 8460 imports RFC 3986 whole; it adds no FQDN rule.
          // It does add one encoding rule: comma, exclamation and semicolon
          // must not occur raw inside a destination URI.
          if (/[!,;]/.test(uri) || (!isMailtoUri(uri) && !isHttpUri(uri, { httpsOnly: true }))) syntax = false;
          destinations.push(uri);
        });
        continue;
      }
      // Everything else is non-repeatable: keep the first, ignore later copies.
      if (seen[name]) continue;
      seen[name] = true;
      if (name === 'v') continue;
      if (!EXT_NAME.test(name) || !RECORD_EXT_VALUE.test(fields[i].value)) syntax = false;
    }
    if (!sawRua) syntax = false;
    return { valid: syntax, destinations: destinations, errors: syntax ? [] : ['invalid-syntax'] };
  }

  // Indicator formats the BIMI draft registers. SVG Tiny PS, plain or gzipped.
  var BIMI_LOGO_SUFFIX = /\.svgz?(\?[^#]*)?(#.*)?$/i;

  /**
   * Validate a BIMI TXT record against draft-brand-indicators-for-message-
   * identification §4.3 (revision as of 2026-08; BIMI is still an
   * Internet-Draft, so this is pinned deliberately and a later revision should
   * be a deliberate change here and in the fixtures).
   *
   * Three things the previous version could not express:
   *
   *  - `l=` PRESENT AND EMPTY is a valid, explicit declination to publish an
   *    indicator. `parsed.tags.l || ''` collapsed that into "missing", so a
   *    conformant record was reported invalid.
   *  - `v=BIMI1` is case-sensitive and must come first, so `v=bimi1` and
   *    `l=…; v=BIMI1` are both unusable and both validated before.
   *  - `https://` is a scheme and two slashes. A logo URL needs a real host,
   *    and an indicator needs an SVG suffix — a `.png` is not one.
   */
  function validateBimiRecord(record) {
    var fields = parseOrderedFields(record);
    if (!fields || !fields.length) {
      return { valid: false, logo: '', authority: '', declined: false, errors: ['invalid-syntax'] };
    }

    var seen = Object.create(null);
    var duplicates = [];
    var syntax = fields[0].name === 'v' && fields[0].value === 'BIMI1';
    var logo = '';
    var authority = '';
    var sawLogo = false;
    for (var i = 0; i < fields.length; i++) {
      var name = fields[i].name;
      if (seen[name]) duplicates.push(name);
      seen[name] = true;
      if (i === 0) continue;
      if (name === 'l') {
        sawLogo = true;
        logo = fields[i].value;
        // BIMI is the protocol that adds the FQDN and HTTPS constraints.
        if (logo && !(isHttpUri(logo, { httpsOnly: true, requireFqdn: true }) && BIMI_LOGO_SUFFIX.test(logo))) syntax = false;
      } else if (name === 'a') {
        authority = fields[i].value;
        if (authority && !isHttpUri(authority, { httpsOnly: true, requireFqdn: true })) syntax = false;
      } else if (name === 'v') syntax = false;
      else if (!EXT_NAME.test(name) || !BIMI_EXT_VALUE.test(fields[i].value)) syntax = false;
    }
    // `l=` is required; it may be empty, but it may not be absent.
    if (!sawLogo) syntax = false;
    var valid = syntax && !duplicates.length;
    return {
      valid: valid,
      logo: logo,
      authority: authority,
      // An explicit "we publish no indicator", which is a conformant record and
      // not a broken one. The caller decides what to show; this only reports it.
      declined: valid && sawLogo && !logo,
      errors: duplicates.length ? ['duplicate-tags'] : valid ? [] : ['invalid-syntax'],
    };
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

  /* ── DNSSEC record parsing (RFC 4034) ──────────────────────────────────
     Two presentation forms from one resolver, and they must not share a
     normalizer. A DS digest is hex, so folding its case is free. A DNSKEY
     public key is base64 — case-carrying, with `+`, `/` and `=` in it — and
     folding its case destroys it silently: every digest then fails to match
     and a perfectly healthy zone is reported as a broken chain. That is the
     most damaging verdict this tool can produce, so the two parsers are
     written apart rather than factored together.

     These parsers read the numeric presentation form this project's one
     resolver returns, captured before any of this was written in
     docs/specs/fixtures/dnssec-live-states-0.5.0.md. RFC 4034 also permits
     algorithm mnemonics in zone-file presentation format; Cloudflare's JSON
     never emits them, and rather than accept a grammar nothing here can
     produce, an alphabetic algorithm field is reported as unparseable. That is
     a deliberate scope statement, not an oversight.

     A note on what `valid` means. It is a statement about the RECORD — the
     fields parsed, the protocol is 3, the base64 decoded. It is NOT a
     statement that the key is usable. Whether the key material is even
     structurally possible for its declared algorithm is `keyStructure`, and
     whether the key may verify RRsets at all is the zone flag. Collapsing
     those into one boolean is how a recognized name gets accepted without its
     registered value grammar, which is the failure 0.4.0 spent three review
     rounds removing from CAA, MTA-STS and DKIM in turn.
     ───────────────────────────────────────────────────────────────────── */

  /**
   * IANA DNS Security Algorithm Numbers, current as of 2026-08-26. Protocol
   * identifiers, not prose — the localization contract lists them among the
   * terms that are never translated.
   *
   * 18 (MLDSA44) is an early allocation held by an Internet-Draft rather than
   * an RFC. It is carried because the registry carries it: a resolver could
   * return it, and reporting the number with no name is worse than reporting
   * the name the registry gives.
   */
  var DNSSEC_ALGORITHMS = {
    0: 'DELETE', 1: 'RSAMD5', 2: 'DH', 3: 'DSA', 5: 'RSASHA1',
    6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256',
    10: 'RSASHA512', 12: 'ECC-GOST', 13: 'ECDSAP256SHA256',
    14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448', 17: 'SM2SM3',
    18: 'MLDSA44', 23: 'ECC-GOST12',
    252: 'INDIRECT', 253: 'PRIVATEDNS', 254: 'PRIVATEOID',
  };

  /**
   * The IANA registry's Zone Signing column is a separate protocol fact from
   * whether this build recognizes an algorithm's key grammar. The complete
   * named registry is recorded here: false is an affirmative prohibition,
   * while an absent value remains unknown for an unassigned future number.
   * Only algorithms marked true may contribute usable anchoring evidence.
   */
  var DNSSEC_ZONE_SIGNING = {
    0: false, 1: false, 2: false, 3: true, 5: true, 6: true, 7: true,
    8: true, 10: true, 12: true, 13: true, 14: true, 15: true, 16: true,
    17: true, 18: true, 23: true, 252: false, 253: true, 254: true,
  };

  function dnssecAlgorithmEligibility(algorithm) {
    if (!Object.prototype.hasOwnProperty.call(DNSSEC_ZONE_SIGNING, algorithm)) return 'unknown';
    return DNSSEC_ZONE_SIGNING[algorithm] ? 'eligible' : 'ineligible';
  }

  /**
   * Deprecated for signing. RFC 9905 §3.1 obsoletes RFC 8624's algorithm
   * table: RSAMD5, DSA and both DSA/RSASHA1-NSEC3 variants are MUST NOT, and
   * RSASHA1 is likewise no longer permitted for new signing. RFC 9906
   * deprecates the GOST R 34.10-2001 algorithm and its digest.
   *
   * ECC-GOST12 (23) is NOT here: RFC 9558 registers it as a current
   * replacement for 12, not as a deprecated algorithm.
   */
  var DEPRECATED_DNSSEC_ALGORITHMS = [1, 3, 5, 6, 7, 12];

  /**
   * IANA DS digest algorithms, current as of 2026-08-26. Types 5 and 6 were
   * missing here, which meant a one-octet digest declaring type 6 was accepted
   * as a valid record with no name — a currently registered digest parsed
   * without its registered grammar, which is exactly what the unknown-value
   * fallback is NOT for.
   */
  var DNSSEC_DIGESTS = {
    1: 'SHA-1', 2: 'SHA-256', 3: 'GOST-R-34.11-94', 4: 'SHA-384',
    5: 'GOST-R-34.11-2012', 6: 'SM3',
  };
  var DNSSEC_DIGEST_LENGTHS = { 1: 20, 2: 32, 3: 32, 4: 48, 5: 32, 6: 32 };

  /**
   * SHA-1 is "deprecated for delegation" per RFC 9905 and the IANA registry —
   * it must not be used for NEW delegations but remains required for
   * validating existing ones. GOST R 34.11-94 is deprecated outright by
   * RFC 9906. Both are reported; neither is a reason to refuse to compute.
   */
  var DEPRECATED_DNSSEC_DIGESTS = [1, 3];

  // RFC 4034 §2.1.1 and RFC 5011 §7. Each of these names a BIT, and the
  // parser reports the bit rather than a role — see parseDnskey().
  var DNSKEY_FLAG_SEP = 0x0001;      // bit 15: secure entry point, advisory only
  var DNSKEY_FLAG_ZONE = 0x0100;     // bit 7: this key may verify RRsets in the zone
  var DNSKEY_FLAG_REVOKE = 0x0080;   // bit 8: RFC 5011 revocation, half of a proof

  /**
   * Public key lengths that are fixed by their algorithm's specification.
   * RFC 6605 §4 (ECDSA Q is the uncompressed point x|y, so 64 and 96) and
   * RFC 8080 §3 (Ed25519 32 octets, Ed448 57).
   */
  var DNSKEY_FIXED_KEY_LENGTHS = { 13: 64, 14: 96, 15: 32, 16: 57 };

  // RFC 3110 §2 exponent-and-modulus encoding, used by every RSA algorithm.
  var RSA_DNSSEC_ALGORITHMS = [1, 5, 7, 8, 10];

  /**
   * Is this key material structurally possible for the algorithm it declares?
   *
   * Three answers, and the third is the point. `'invalid'` means a recognized
   * algorithm carrying material it cannot possibly be — a one-octet Ed25519
   * key. `'unknown'` means this build does not know the algorithm's key
   * grammar, which is an honest thing to say about DSA, GOST, SM2 and ML-DSA
   * and must never be read as a fault: a DS digest is computed over the raw
   * RDATA, so a parent and child can agree perfectly about a key whose
   * internals nothing here can parse.
   *
   * Only `'invalid'` disqualifies. Rejecting `'unknown'` would refuse zones
   * signed to a specification newer than this build, which is the opposite
   * failure and the one three of 0.4.0's eight rounds were spent undoing.
   */
  function dnskeyStructure(algorithm, bytes) {
    if (!bytes) return 'unknown';
    var fixed = DNSKEY_FIXED_KEY_LENGTHS[algorithm];
    if (fixed !== undefined) return bytes.length === fixed ? 'valid' : 'invalid';
    if (RSA_DNSSEC_ALGORITHMS.indexOf(algorithm) === -1) return 'unknown';

    // RFC 3110 §2: lengths 1–255 use the one-octet form; only longer
    // exponents use zero plus a two-octet length. Exponent and modulus are
    // unsigned integers with no leading zero octets, and each is limited to
    // 4096 bits. Section 3 gives the modulus a 512-bit protocol minimum.
    if (bytes.length < 1) return 'invalid';
    var exponentLength = bytes[0];
    var offset = 1;
    if (exponentLength === 0) {
      if (bytes.length < 3) return 'invalid';
      exponentLength = (bytes[1] << 8) | bytes[2];
      offset = 3;
      if (exponentLength <= 255) return 'invalid';
    }
    if (exponentLength === 0 || exponentLength > 512) return 'invalid';
    if (offset + exponentLength >= bytes.length) return 'invalid';
    var modulusOffset = offset + exponentLength;
    var modulusLength = bytes.length - modulusOffset;
    if (modulusLength < 64 || modulusLength > 512) return 'invalid';
    if (bytes[offset] === 0 || bytes[modulusOffset] === 0) return 'invalid';
    return 'valid';
  }

  /**
   * Split a record into its fixed leading integers and one trailing blob,
   * unwrapping the optional parenthesis pair around the blob.
   *
   * The balanced-pair rule is `parseTlsaRecord()`'s, and for the same reason:
   * stripping each side independently accepts `( ABCD` and `ABCD )` alike,
   * which defeats the point of a parser written for a presentation form. What
   * is deliberately NOT shared is case folding — see the block comment above.
   */
  function splitRdataFields(presentationString, leadingFields) {
    var text = String(presentationString || '').trim();
    var pattern = new RegExp('^' + new Array(leadingFields + 1).join('(\\d+)\\s+') + '([\\s\\S]+)$');
    var match = pattern.exec(text);
    if (!match) return null;
    var body = match[leadingFields + 1].trim();
    var opened = body.charAt(0) === '(';
    var closed = body.length > 1 && body.charAt(body.length - 1) === ')';
    if (opened !== closed) return { unbalanced: true };
    if (opened) body = body.slice(1, -1);
    return {
      numbers: match.slice(1, leadingFields + 1).map(Number),
      body: body.replace(/\s+/g, ''),
    };
  }

  /**
   * A domain name in DNS wire format: each label prefixed by its length byte,
   * lowercased, terminated by a zero byte. RFC 4034 §5.1.4 hashes this ahead
   * of the DNSKEY RDATA, so an error here is an error in every digest.
   *
   * Returns null rather than guessing. A label over 63 octets, a name over 255,
   * or a byte outside ASCII cannot be encoded correctly, and writing the wrong
   * bytes anyway would produce a mismatch verdict about the operator's zone
   * that is really a statement about our own encoder.
   *
   * ASCII is checked BEFORE case folding, and the order is load-bearing.
   * JavaScript's toLowerCase() is Unicode case conversion, not the ASCII-only
   * folding RFC 4034 §6.2 defines: U+212A KELVIN SIGN lowercases to plain
   * 'k'. Folding first therefore turned a name this function must refuse into
   * one it accepts, and computed a digest for `k.example` when the caller
   * asked about `K.example` — a different owner name, which is a different
   * zone.
   */
  function dnsWireName(domain) {
    var raw = String(domain || '').replace(/\.$/, '');
    if (!raw) return new Uint8Array([0]);
    // Reject anything outside ASCII before any transformation touches it.
    if (!/^[\x00-\x7f]*$/.test(raw)) return null;
    var name = raw.toLowerCase();
    var labels = name.split('.');
    var total = 1;
    for (var i = 0; i < labels.length; i++) {
      if (!labels[i].length || labels[i].length > 63) return null;
      total += 1 + labels[i].length;
    }
    if (total > 255) return null;
    var bytes = new Uint8Array(total);
    var out = 0;
    for (var j = 0; j < labels.length; j++) {
      bytes[out++] = labels[j].length;
      for (var k = 0; k < labels[j].length; k++) {
        bytes[out++] = labels[j].charCodeAt(k);
      }
    }
    bytes[out] = 0;
    return bytes;
  }

  /** RFC 4034 §2.1: flags(2) || protocol(1) || algorithm(1) || public key. */
  function dnskeyRdata(key) {
    if (!key || !key.valid) return null;
    var publicKey = base64ToBytes(key.publicKey);
    if (!publicKey) return null;
    var rdata = new Uint8Array(4 + publicKey.length);
    rdata[0] = (key.flags >> 8) & 0xff;
    rdata[1] = key.flags & 0xff;
    rdata[2] = key.protocol;
    rdata[3] = key.algorithm;
    rdata.set(publicKey, 4);
    return rdata;
  }

  /**
   * The key tag, which is what links a DS to a DNSKEY. An off-by-one here does
   * not fail loudly — it reports a spurious mismatch on a healthy zone, which
   * the spec calls the worst defect this project could ship. Checked against
   * the reference key in RFC 4034 §5.4, whose stated tag is 60485.
   *
   * The general case is RFC 4034 Appendix B. Algorithm 1 is NOT: Appendix B.1
   * is erroneous, and **RFC 6840 §5.5 is the normative text**. B.1 correctly
   * says the tag is the most significant 16 of the least significant 24 bits
   * of the modulus and then names the wrong octets for it — "fourth-to-last
   * and third-to-last", where §5.5 corrects it to the third-to-last and
   * second-to-last. Implementing the appendix as written would produce a tag
   * one octet out on every RSAMD5 key, which is to say a mismatch verdict on
   * every zone still using one.
   *
   * The modulus ends the RDATA under RFC 3110's encoding, so the last octets
   * of the RDATA are the last octets of the modulus.
   */
  function dnskeyKeyTag(rdata, algorithm) {
    if (!rdata) return null;
    if (algorithm === 1) return rdata.length < 3 ? 0 : (rdata[rdata.length - 3] << 8) + rdata[rdata.length - 2];
    var accumulator = 0;
    for (var i = 0; i < rdata.length; i++) {
      accumulator += (i & 1) ? rdata[i] : rdata[i] << 8;
    }
    accumulator += (accumulator >> 16) & 0xffff;
    return accumulator & 0xffff;
  }

  /**
   * Parse one DNSKEY presentation string.
   *
   * Every flag is reported as the bit it is, never as the role it suggests.
   * `hasSep` is the SEP bit and not "this is the KSK": RFC 6840 §6.2 says the
   * bit "has no effect on how a DNSKEY may be used" and that validation is
   * prohibited from consulting it, so a key without SEP may be the only secure
   * entry point a zone has. `hasRevokeFlag` is the REVOKE bit and not "this
   * key is revoked": RFC 5011 §2.1 makes a key revoked when a resolver sees it
   * in a SELF-SIGNED RRset with the bit set, and this release does not
   * validate RRSIGs, so it holds one half of a two-part proof.
   *
   * `hasZoneFlag` is the one flag that does carry a normative consequence —
   * RFC 4034 §2.1.1 says a key without it MUST NOT verify RRsets — and even
   * that is reported here and applied where matching happens.
   *
   * `publicKey` stays the base64 text rather than becoming a byte array. It is
   * the evidence the resolver returned, it survives export and comparison
   * intact, and a 2048-bit key as a Uint8Array serializes into a 259-entry
   * object in every report this result reaches. `dnskeyRdata()` decodes it
   * where bytes are actually needed.
   */
  function parseDnskey(presentationString) {
    var blank = {
      flags: null, protocol: null, algorithm: null, algorithmName: null,
      algorithmEligibility: 'unknown',
      publicKey: '', keyBytes: 0, keyTag: null, keyStructure: 'unknown',
      hasSep: false, hasZoneFlag: false, hasRevokeFlag: false,
      deprecated: false, valid: false, errors: ['unparseable-record'],
    };
    var fields = splitRdataFields(presentationString, 3);
    if (!fields) return blank;
    if (fields.unbalanced) return Object.assign({}, blank, { errors: ['unbalanced-parentheses'] });

    var flags = fields.numbers[0];
    var protocol = fields.numbers[1];
    var algorithm = fields.numbers[2];
    var errors = [];

    if (!(flags >= 0 && flags <= 0xffff)) errors.push('bad-flags');
    // RFC 4034 §2.1.2: the protocol field MUST have value 3, and a DNSKEY with
    // any other value MUST be treated as invalid.
    if (protocol !== 3) errors.push('bad-protocol');
    if (!(algorithm >= 0 && algorithm <= 255)) errors.push('bad-algorithm');

    var publicKey = fields.body;
    var bytes = publicKey ? base64ToBytes(publicKey) : null;
    if (!publicKey) errors.push('empty-key');
    else if (!bytes) errors.push('bad-key-encoding');

    var valid = errors.length === 0;
    // Reserved flag bits are ignored on receipt (RFC 4034 §2.1.1). A record
    // carrying one is parseable, and nothing here rejects it for that.
    var parsed = {
      flags: flags,
      protocol: protocol,
      algorithm: algorithm,
      // An unregistered algorithm number is not an error. The registry grows,
      // and a resolver may return a key this build has never heard of; the
      // honest report is the number with no name beside it.
      algorithmName: DNSSEC_ALGORITHMS[algorithm] || null,
      algorithmEligibility: dnssecAlgorithmEligibility(algorithm),
      publicKey: publicKey,
      keyBytes: bytes ? bytes.length : 0,
      keyTag: null,
      keyStructure: valid ? dnskeyStructure(algorithm, bytes) : 'unknown',
      hasSep: valid && (flags & DNSKEY_FLAG_SEP) !== 0,
      hasZoneFlag: valid && (flags & DNSKEY_FLAG_ZONE) !== 0,
      hasRevokeFlag: valid && (flags & DNSKEY_FLAG_REVOKE) !== 0,
      deprecated: DEPRECATED_DNSSEC_ALGORITHMS.indexOf(algorithm) !== -1,
      valid: valid,
      errors: errors,
    };
    if (valid) parsed.keyTag = dnskeyKeyTag(dnskeyRdata(parsed), algorithm);
    return parsed;
  }

  /** Parse one DS presentation string. RFC 4034 §5.1. */
  function parseDs(presentationString) {
    var blank = {
      keyTag: null, algorithm: null, algorithmName: null,
      algorithmEligibility: 'unknown',
      digestType: null, digestName: null, digest: '',
      deprecated: false, valid: false, errors: ['unparseable-record'],
    };
    var fields = splitRdataFields(presentationString, 3);
    if (!fields) return blank;
    if (fields.unbalanced) return Object.assign({}, blank, { errors: ['unbalanced-parentheses'] });

    var keyTag = fields.numbers[0];
    var algorithm = fields.numbers[1];
    var digestType = fields.numbers[2];
    var errors = [];

    if (!(keyTag >= 0 && keyTag <= 0xffff)) errors.push('bad-key-tag');
    if (!(algorithm >= 0 && algorithm <= 255)) errors.push('bad-algorithm');
    if (!(digestType >= 0 && digestType <= 255)) errors.push('bad-digest-type');

    // Hex, so folding the case is safe and necessary: Cloudflare returns this
    // lowercase and dns.google returns it uppercase, and the comparison this
    // feeds is a string equality.
    var digest = fields.body.toLowerCase();
    if (!digest) errors.push('empty-digest');
    else if (!/^[0-9a-f]+$/.test(digest) || digest.length % 2 !== 0) errors.push('bad-digest');
    else {
      var expected = DNSSEC_DIGEST_LENGTHS[digestType];
      // Every REGISTERED digest type has its length checked, including the two
      // this build cannot compute. A registered type parsed without its
      // registered grammar is not forward compatibility, it is a gap. Only a
      // genuinely unassigned or private-use value is carried unjudged.
      if (expected !== undefined && digest.length / 2 !== expected) errors.push('bad-digest-length');
    }

    return {
      keyTag: keyTag,
      algorithm: algorithm,
      algorithmName: DNSSEC_ALGORITHMS[algorithm] || null,
      algorithmEligibility: dnssecAlgorithmEligibility(algorithm),
      digestType: digestType,
      digestName: DNSSEC_DIGESTS[digestType] || null,
      digest: digest,
      deprecated: DEPRECATED_DNSSEC_DIGESTS.indexOf(digestType) !== -1,
      valid: errors.length === 0,
      errors: errors,
    };
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
  function buildIssues({ emailProvider, spfStatus, spfRecords, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, reportPlan, wildcardApex, wildcardDkim, hosting, advanced, domain }) {
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
    // The count is part of the evidence: "Multiple SPF records found" with a
    // single valid-looking record beside it reads as a bug in this tool, which
    // is how it was reported. Saying "2" costs nothing and matches how
    // `dkim-multiple-records` already names its selectors.
    if (spfStatus.status === 'permerror') {
      issues.push({ key: 'spf-multiple-records', sev: 'crit', args: [(spfRecords || []).length || 2] });
    }
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
        var mismatched = reportAuth.filter(function (r) { return r.state === 'override-mismatch'; });
        if (mismatched.length) {
          issues.push({
            key: 'dmarc-external-override-mismatch', sev: 'warn',
            args: [
              mismatched.map(function (r) { return r.destination; }).join(', '),
              mismatched.map(function (r) { return r.override; }).join(', '),
            ],
          });
        }
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

    if (reportPlan && reportPlan.omitted && reportPlan.omitted.length) {
      issues.push({
        key: 'dmarc-report-destinations-truncated', sev: 'info',
        args: [reportPlan.total - reportPlan.omitted.length, reportPlan.total, reportPlan.omitted.join(', ')],
      });
    }

    if (dmarcStatus.psdValid === false) issues.push({ key: 'dmarc-bad-psd', sev: 'warn' });
    /* `dmarc-psd-invalid` was removed here. It asked the Public Suffix List
       whether a psd=y declaration was justified, which broke OQ-DMARC-04's
       invariant that no DMARC decision consults the PSL — and, worse, it asked
       about the AUDITED name rather than the name carrying the applied record.
       A domain inheriting the valid `_dmarc.gov` PSD record (psd=y, applied
       from `gov`) is its own PSL organizational domain, so the check fired and
       called a correct CISA-operated declaration invalid: a false positive on
       the exact inherited-PSD case this release adds. There is no DNS-only test
       that disproves a psd= declaration — the declaration is the protocol's own
       source of truth — and a vendored list snapshot is not evidence strong
       enough for "this domain is not a public suffix". `dmarc-bad-psd` above
       still checks the value vocabulary, which is protocol-defined.
       Reconsidered for 0.6.0, it would have to be explicitly heuristic,
       informational, and evaluated at `dmarcDiscovery.applied.foundAt`. */
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
    // A declination is a valid record that asserts no indicator, so it is
    // neither present nor invalid.
    else if (advanced?.bimi?.advertised && !advanced.bimi.present && !advanced.bimi.declined) issues.push({ key: 'bimi-invalid', sev: 'warn' });
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

    /* ── DKIM key strength (RFC 8301, RFC 6376, RFC 8463) ──────────────────
       Grouped one line per condition rather than one per selector: a domain
       running six selectors at 1024 bits would otherwise contribute six
       identical informational lines and bury everything else.

       The 1024-bit line is INFORMATIONAL on purpose, and that was decided by
       counting rather than arguing (OQ-DEPTH-05). Across the 40-domain
       backtest sample, 35 of 66 keys are RSA-1024 — on 21 of the 27 domains
       that publish DKIM at all, Microsoft, GitHub, Apple, PayPal, Stripe and
       the EFF among them. A warning firing on ~78% of audited domains is not
       a signal, it is a thing people learn to scroll past, and it would take
       the genuinely critical sub-1024 line down with it.
       ───────────────────────────────────────────────────────────────────── */
    var dkimKeys = (dkimStatus?.selectors || []).filter(function (entry) { return entry.key; });
    var byCondition = function (predicate) {
      return dkimKeys.filter(function (entry) { return predicate(entry.key); })
        .map(function (entry) { return entry.sel; });
    };
    // Syntax evidence is wider than usable signing keys. Revoked, service-
    // scoped and missing-p= candidates can all be malformed too; restricting
    // these findings to `selectors` made the most broken records disappear
    // from the very diagnostics intended to explain them.
    var dkimEvidence = dkimKeys
      .concat(dkimStatus?.unusableSelectors || [])
      .concat(dkimStatus?.revokedSelectors || [])
      .concat(dkimStatus?.malformedSelectors || []);
    var evidenceByCondition = function (predicate) {
      return Array.from(new Set(dkimEvidence.filter(function (entry) {
        return entry.key && predicate(entry.key);
      }).map(function (entry) { return entry.sel; })));
    };

    var weakKeys = dkimKeys.filter(function (e) { return typeof e.key.keyBits === 'number' && e.key.keyBits < 1024; });
    if (weakKeys.length) {
      issues.push({ key: 'dkim-key-weak', sev: 'crit', args: [
        weakKeys.map(function (e) { return e.sel + ' (' + e.key.keyBits + ')'; }).join(', '),
      ] });
    }
    var thousandKeys = byCondition(function (k) { return k.keyBits === 1024; });
    if (thousandKeys.length) issues.push({ key: 'dkim-key-1024', sev: 'info', args: [thousandKeys.join(', ')] });

    // Published at a selector, and not a key this domain's ordinary email can be
    // verified with — an unrecognized `k=`, or an `s=` scoped to another
    // service such as RFC 8460's `tlsrpt`. Informational because the record is
    // conformant and very likely deliberate; it is here so that a domain whose
    // only DKIM records are inapplicable is told why the audit found none,
    // rather than being told nothing exists at a name they configured.
    if (dkimStatus?.unusableSelectors?.length) {
      issues.push({ key: 'dkim-key-not-email', sev: 'info', args: [
        dkimStatus.unusableSelectors.map(function (r) { return r.sel; }).join(', '),
      ] });
    }

    if (dkimStatus?.revokedSelectors?.length) {
      issues.push({ key: 'dkim-key-revoked', sev: 'warn', args: [
        dkimStatus.revokedSelectors.map(function (r) { return r.sel; }).join(', '),
      ] });
    }

    // 'unparseable-key' is the truncated-p= case, which is a completely silent
    // DKIM failure: the record is present, the selector is found, and no
    // verifier can use it. 'key-structure-invalid' is the same outcome by a
    // different route. A key we could not check because the browser has no
    // Web Crypto is NOT here, and must never be — that is cryptoValidated:
    // null, and it means we said nothing, not that the key is bad.
    var DECODE_ERRORS = ['unparseable-key', 'key-structure-invalid', 'bad-ed25519-length'];
    var hasDecodeError = function (k) {
      return k.errors.some(function (e) { return DECODE_ERRORS.indexOf(e) !== -1; });
    };
    var brokenKeys = evidenceByCondition(hasDecodeError);
    if (brokenKeys.length) issues.push({ key: 'dkim-key-unparseable', sev: 'warn', args: [brokenKeys.join(', ')] });

    // Every other way a key record can be invalid. Without this, a record the
    // analyzer itself marks `valid: false` — an empty `h=`, a duplicated tag, a
    // bad version — counted as a found key and said nothing at all, so the
    // audit reported DKIM present on the strength of a record it knew was
    // malformed.
    var malformedKeys = evidenceByCondition(function (k) { return !k.valid && !hasDecodeError(k); });
    if (malformedKeys.length) issues.push({ key: 'dkim-key-malformed', sev: 'warn', args: [malformedKeys.join(', ')] });

    var testingKeys = byCondition(function (k) { return k.testing; });
    if (testingKeys.length) issues.push({ key: 'dkim-key-testing', sev: 'info', args: [testingKeys.join(', ')] });

    // Only when sha1 is the ONLY hash offered. `h=sha256:sha1` lets a verifier
    // choose SHA-256 and is not a finding; RFC 8301 deprecates sha1 as a
    // signing hash, not as an entry in a list.
    var sha1Keys = byCondition(function (k) {
      return k.hashAlgorithms.length > 0 && k.hashAlgorithms.every(function (h) { return h === 'sha1'; });
    });
    if (sha1Keys.length) issues.push({ key: 'dkim-key-sha1', sev: 'warn', args: [sha1Keys.join(', ')] });

    if (dkimStatus?.keyProfile?.mixed) {
      issues.push({ key: 'dkim-key-mixed', sev: 'info', args: [dkimStatus.keyProfile.minBits, dkimStatus.keyProfile.maxBits] });
    }

    /* ── CAA policy (RFC 8659, RFC 9495) ──────────────────────────────── */
    if (advanced?.caa?.found) {
      if (advanced.caa.issuanceBlocked) {
        issues.push({ key: 'caa-blocks-all-issuance', sev: 'warn', args: [advanced.caa.atDomain] });
      }
      // RFC 8659 §4.1: a CA that does not recognize a critical property MUST
      // refuse to issue. So this is an issuance outage waiting for the next
      // renewal, not a tidiness note — and it is invisible until then.
      if (advanced.caa.unknownCritical?.length) {
        issues.push({ key: 'caa-unknown-critical-tag', sev: 'warn', args: [advanced.caa.unknownCritical.join(', ')] });
      }
      if (advanced.caa.malformed?.length) {
        issues.push({ key: 'caa-malformed', sev: 'warn', args: [advanced.caa.malformed.join(', ')] });
      }
      if (!advanced.caa.iodef?.length) issues.push({ key: 'caa-no-iodef', sev: 'info' });
      // Distinct issuers, not record count: `issue` and `issuewild` for the
      // same CA is one issuer, and counting records would call it two.
      var caaIssuers = (advanced.caa.issuers || []).concat(advanced.caa.wildcardIssuers || [])
        .filter(function (v, i, all) { return all.indexOf(v) === i; });
      if (caaIssuers.length === 1 && !advanced.caa.issuanceBlocked) {
        issues.push({ key: 'caa-single-issuer', sev: 'info', args: [caaIssuers[0]] });
      }
    }

    /* ── MX health ────────────────────────────────────────────────────── */
    if (advanced?.mxHealth?.hosts?.length) {
      var mxHealth = advanced.mxHealth;
      // Critical, and the only critical finding in this group: an MX host that
      // does not resolve accepts no mail at all. Hosts we could not check are
      // 'unknown' and are deliberately not in this list.
      if (mxHealth.danglingHosts.length) {
        issues.push({ key: 'mx-dangling', sev: 'crit', args: [mxHealth.danglingHosts.join(', ')] });
      }
      // RFC 2181 §10.3 and RFC 5321 §5.1 both forbid it. It frequently works
      // anyway, which is why it survives in the wild and why it is a warning
      // rather than an error — it breaks in specific, hard-to-diagnose ways.
      if (mxHealth.cnameHosts.length) {
        issues.push({ key: 'mx-cname-target', sev: 'warn', args: [mxHealth.cnameHosts.join(', ')] });
      }
      if (mxHealth.singleHost) issues.push({ key: 'mx-single-host', sev: 'info', args: [mxHealth.hosts[0].host] });
      if (mxHealth.ipv6Coverage === 'none') issues.push({ key: 'mx-no-ipv6', sev: 'info' });
      mxHealth.sharedPrefixes.forEach(function (group) {
        issues.push({ key: 'mx-same-prefix', sev: 'info', args: [group.prefix, group.hosts.join(', ')] });
      });
      if (mxHealth.duplicatePreferences.length) {
        issues.push({ key: 'mx-duplicate-preference', sev: 'info', args: [mxHealth.duplicatePreferences.join(', ')] });
      }
    }

    /* ── TLSA / DANE ──────────────────────────────────────────────────── */
    if (advanced?.tlsa?.anyPresent) {
      var tlsa = advanced.tlsa;
      // Gated on evidence, not on `qualified`. `qualified` is false for every
      // domain in this release because the chain has not been walked, so
      // firing on it would tell a correctly signed zone that its DANE is
      // unprotected — a confident verdict with nothing behind it, which is the
      // exact failure this whole release is written to avoid.
      if (tlsa.unauthenticatedHosts.length) {
        issues.push({ key: 'tlsa-published-unsigned', sev: 'warn', args: [tlsa.unauthenticatedHosts.join(', ')] });
      }
      var malformedTlsa = tlsa.hosts.filter(function (h) {
        return h.records.some(function (r) { return !r.valid; });
      }).map(function (h) { return h.host; });
      if (malformedTlsa.length) issues.push({ key: 'tlsa-malformed', sev: 'warn', args: [malformedTlsa.join(', ')] });

      // Only over hosts actually checked — a host whose lookup failed is not
      // evidence of missing coverage.
      var checked = tlsa.hosts.filter(function (h) { return !h.unknown; });
      var covered = checked.filter(function (h) { return h.present; });
      if (covered.length && covered.length < checked.length) {
        issues.push({ key: 'tlsa-partial-coverage', sev: 'info', args: [covered.length, checked.length] });
      }
    }

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
    if (advanced?.mxHealth?.unknown) unverified.push('MX');
    if (advanced?.tlsa?.unknown) unverified.push('TLSA');
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
    else if (advanced.bimi?.declined) { /* the domain said no on purpose — do not sell it */ }
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
    // Every matching record is kept, not just the first. `spfRecord` alone made
    // `spf-multiple-records` an unevidenced accusation: the finding is critical
    // and correct, and the panel beside it showed one perfectly valid record,
    // because the second was discarded here and existed nowhere in the result.
    // An operator could not see which records conflicted or where to look, and
    // the honest conclusion from that screen is that the tool is wrong.
    const spfRecords = spfMatches;
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
    const reportPlan = planReportDestinations(dmarcStatus, dmarcAtDomain, dmarcOrgDomains);
    const externalReportDestinations = reportPlan.external;

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
    let advanced = { bimi: null, mtaSts: null, tlsRpt: null, caa: null, dnssec: null, spfLookups: null, spfSubnets: null, reportAuth: null, mxHealth: null, tlsa: null };
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
      const bimiMatches = leadingVersionMatches(bimiTxt, 'BIMI1');
      const mtaMatches = leadingVersionMatches(mtaStsTxt, 'STSv1');
      const tlsMatches = leadingVersionMatches(tlsRptTxt, 'TLSRPTv1');

      // A sender discards a record that does not BEGIN with the version field,
      // and `present` follows that rule exactly. An auditor must not: the
      // record exists, at an owner name dedicated to this protocol, and
      // "nothing is published" and "what is published is not an active policy"
      // are different facts. Filtering the malformed candidate away before
      // validation is what suppressed the very findings the strict validators
      // were added to raise — `l=…; v=BIMI1` simply vanished.
      const bimiCandidates = versionCandidates(bimiTxt, 'BIMI1');
      const mtaCandidates = versionCandidates(mtaStsTxt, 'STSv1');
      const tlsCandidates = versionCandidates(tlsRptTxt, 'TLSRPTv1');

      // Show the sender-compatible record when there is one, and otherwise the
      // malformed candidate — which is the evidence the operator needs.
      const bimiRecord = bimiMatches[0] || bimiCandidates[0] || '';
      const mtaRecord = mtaMatches[0] || mtaCandidates[0] || '';
      const tlsRecord = tlsMatches[0] || tlsCandidates[0] || '';
      const bimiValidation = validateBimiRecord(bimiRecord);
      const mtaValidation = validateMtaStsRecord(mtaRecord);
      const tlsValidation = validateTlsRptRecord(tlsRecord);

      advanced = {
        // `present` means an indicator is actually asserted. A valid record with
        // an empty `l=` is the draft's explicit declination to publish one —
        // conformant, deliberate, and not a configured BIMI logo. Counting it
        // as present would report an indicator the operator said they do not
        // have; counting it as invalid would report a correct record as broken.
        bimi: { present: bimiMatches.length === 1 && bimiValidation.valid && !bimiValidation.declined, declined: bimiMatches.length === 1 && bimiValidation.declined, advertised: bimiCandidates.length > 0, record: bimiRecord, candidates: bimiCandidates, validation: bimiValidation, multiple: bimiMatches.length > 1, unknown: bimiTxt === null },
        mtaSts: { present: mtaMatches.length === 1 && mtaValidation.valid, advertised: mtaCandidates.length > 0, policyVerified: false, record: mtaRecord, candidates: mtaCandidates, validation: mtaValidation, multiple: mtaMatches.length > 1, unknown: mtaStsTxt === null },
        tlsRpt: { present: tlsMatches.length === 1 && tlsValidation.valid, advertised: tlsCandidates.length > 0, record: tlsRecord, candidates: tlsCandidates, validation: tlsValidation, multiple: tlsMatches.length > 1, unknown: tlsRptTxt === null },
        caa: caaResult,
        dnssec: dnssecResult,
        spfLookups,
        spfSubnets,
        reportAuth,
        mxHealth: null,
        tlsa: null,
      };

      // ── Deep protocol checks ──
      // Gated separately from `advanced` because these are the only checks in
      // the audit whose cost scales with the domain's own configuration: three
      // queries per MX host for the health audit and one more for TLSA, so a
      // five-MX domain adds twenty on its own. Everything above is a fixed
      // handful per domain. See OQ-DEPTH-03 — the interface turns this off
      // above 50 domains, and the engine simply does what it is told.
      //
      // A null MX (RFC 7505) is skipped: the domain has declared it accepts no
      // mail, so there is no host to resolve and nothing to say about TLSA.
      if (opts.deepChecks && mx.length && !isNullMx(mx)) {
        const mxHealth = await optionalCheck(() => auditMxHosts(mx, d, queryOpts),
          () => ({ hosts: [], danglingHosts: [], cnameHosts: [], duplicatePreferences: [], singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: true }));
        const tlsaHosts = mxHealth.hosts.map(h => h.host);
        const tlsa = await optionalCheck(() => checkTlsa(tlsaHosts, queryOpts),
          () => ({ hosts: [], anyPresent: false, qualified: false, unknown: true }));
        advanced.mxHealth = mxHealth;
        advanced.tlsa = tlsa;
      }
    }

    const issues = buildIssues({ emailProvider, spfStatus, spfRecords, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, reportPlan, wildcardApex, wildcardDkim, hosting, advanced, domain: d });
    const suggestions = buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const score = calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const advScore = opts.advanced ? calcAdvScore(advanced) : null;

    return {
      domain: d, ns, mx, txt, aRec, aaaaRec, dnsProvider, emailProvider,
      spfRecord, spfRecords, spfStatus, dmarcRecord, dmarcStatus, dmarcDiscovery, dmarcExistence,
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
    dkimRecordSet,
    analyzeDkimKey,
    validateDkimKeyStructure,
    summarizeDkimKeys,
    parseCaaRecord,
    summarizeCaa,
    parseMxRecord,
    auditMxHosts,
    parseTlsaRecord,
    checkTlsa,
    dnsTypeNum,
    // Exported so the test harness can assert its own type map has not drifted
    // from this one. A fixture keyed for a type the transport cannot query is
    // unreachable; a transport type the harness does not know is answered as
    // TXT and silently mis-keyed. Both are the failure dnsTypeNum() throws to
    // prevent, arriving through the tests instead of through production.
    DNS_TYPES,
    parseDnskey,
    parseDs,
    dnskeyRdata,
    dnskeyKeyTag,
    dnsWireName,
    DNSSEC_ALGORITHMS,
    DNSSEC_ZONE_SIGNING,
    DNSSEC_DIGESTS,
    dnssecAlgorithmEligibility,
    dnskeyStructure,
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
    reportDestinationHosts,
    planReportDestinations,
    parseReportAuthRecord,
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
    checkCAA,
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
