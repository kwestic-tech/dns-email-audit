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

  /* ── DNS-over-HTTPS core ────────────────────────────────────────────── */

  function dnsTypeNum(type) {
    return { NS: 2, A: 1, AAAA: 28, MX: 15, TXT: 16, CNAME: 5, CAA: 257 }[type] ?? 16;
  }

  async function dohFetch(name, type, opts = {}) {
    try {
      const params = new URLSearchParams({ name, type: String(dnsTypeNum(type)) });
      if (opts.dnssec) params.set('do', '1');
      const r = await fetch(`${DOH}?${params}`, { headers: { Accept: 'application/dns-json' } });
      if (!r.ok) return { answers: [], ad: false, status: -1 };
      const j = await r.json();
      return { answers: j.Answer || [], ad: j.AD === true, status: j.Status };
    } catch {
      return { answers: [], ad: false, status: -1 };
    }
  }

  async function dohQuery(name, type) {
    const { answers } = await dohFetch(name, type);
    const num = dnsTypeNum(type);
    return answers.filter(a => a.type === num).map(a => a.data.replace(/^"|"$/g, '').trim());
  }

  async function dohAll(name, type) {
    const { answers } = await dohFetch(name, type);
    return answers.map(a => a.data.replace(/^"|"$/g, '').trim());
  }

  /** Pre-flight: can we reach the resolver at all? */
  async function checkConnectivity() {
    try {
      const r = await fetch(`${DOH}?name=example.com&type=1`, { headers: { Accept: 'application/dns-json' } });
      if (!r.ok) return false;
      const j = await r.json();
      return Array.isArray(j.Answer) || j.Status !== undefined;
    } catch {
      return false;
    }
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

  function detectEmailProvider(mx, domain) {
    if (!mx.length) return '@none';
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
    if (c.includes(domain)) return '@cname-loop';
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
    if (emailProvider === 'Google Workspace' && !spf.includes('_spf.google.com') && !spf.includes('google.com')) warnings.push('spf-missing-google');
    if (emailProvider === 'Apple iCloud' && !spf.includes('icloud')) warnings.push('spf-missing-icloud');
    if (emailProvider === 'Microsoft 365' && !spf.includes('protection.outlook')) warnings.push('spf-missing-microsoft');
    if (spf.includes('+all')) warnings.push('spf-all-permit');
    if (spf.includes('?all')) warnings.push('spf-neutral');
    if (warnings.length) return { status: 'warn', cls: 'warn', warnings };
    if (spf.includes('-all')) return { status: 'ok', cls: 'ok', warnings: [] };
    if (spf.includes('~all')) return { status: 'softfail', cls: 'warn', warnings: ['spf-softfail'] };
    return { status: 'present', cls: 'ok', warnings: [] };
  }

  async function checkDKIM(domain, wildcardBug) {
    const checks = await Promise.all(DKIM_SELECTORS.map(async sel => {
      const [txt, cname] = await Promise.all([
        dohQuery(`${sel}._domainkey.${domain}`, 'TXT'),
        dohAll(`${sel}._domainkey.${domain}`, 'CNAME'),
      ]);
      return { sel, txt, cname };
    }));

    const found = [];
    const duplicated = [];
    for (const { sel, txt, cname } of checks) {
      // Filter to actual DKIM keys rather than taking txt[0] — a selector can
      // carry unrelated TXT records alongside the key.
      const keys = txt.filter(v => startsWithCI(v, 'v=DKIM1'));
      // RFC 6376 §3.6.2.2: key records MUST be unique per selector; with more
      // than one the result is undefined, so verification may fail depending on
      // which verifier looks.
      if (keys.length > 1) duplicated.push(sel);
      if (keys.length) found.push({ sel, type: 'key', value: keys[0] });
      else if (cname.length && cname[0].includes('dkim') && !cname[0].includes('porkbun') && !cname[0].includes('pixie'))
        found.push({ sel, type: 'cname', value: cname[0] });
    }

    if (!found.length) {
      return { found: false, selectors: [], duplicated, note: wildcardBug ? 'noteWildcard' : 'noteNotFound' };
    }
    return { found: true, selectors: found, duplicated, note: '' };
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
    var status = enforcing ? 'ok'
      : (rawPolicy !== null && normalizePolicy(rawPolicy) === null) ? 'present'
        : 'warn';

    return {
      status: status,
      cls: status === 'ok' ? 'ok' : 'warn',
      policy: policy, sp: sp, np: np,
      effectiveSp: effectiveSp, effectiveNp: effectiveNp,
      pct: pct, pctValid: pctValid,
      adkim: adkim, aspf: aspf,
      rua: rua, ruf: ruf, enforcing: enforcing,
    };
  }

  /* ── Advanced checks ────────────────────────────────────────────────── */

  async function checkCAA(domain) {
    // Walk up the domain tree (CAA can be inherited from parent)
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const check = parts.slice(i).join('.');
      const { answers } = await dohFetch(check, 'CAA');
      const caaAnswers = answers.filter(a => a.type === 257);
      if (caaAnswers.length > 0) {
        return { found: true, records: caaAnswers.map(a => a.data), atDomain: check };
      }
    }
    return { found: false, records: [], atDomain: null };
  }

  async function checkDNSSEC(domain) {
    // Check AD (Authenticated Data) flag — true means DNSSEC validates
    const { ad } = await dohFetch(domain, 'NS', { dnssec: true });
    return { signed: ad };
  }

  async function countSpfLookups(spf, domain) {
    // Count top-level lookup mechanisms, then follow one level of includes
    const mxCount = (spf.match(/(?:^|\s)[+\-~?]?mx(?::|$|\s)/g) || []).length;
    const aCount = (spf.match(/(?:^|\s)[+\-~?]?a(?::|$|\s)/g) || []).length;
    const existsCount = (spf.match(/exists:[^\s]+/g) || []).length;
    const includes = (spf.match(/include:[^\s]+/g) || []).map(s => s.replace('include:', ''));
    const redirects = (spf.match(/redirect=[^\s]+/g) || []).map(s => s.replace('redirect=', ''));

    let count = mxCount + aCount + existsCount + includes.length + redirects.length;

    // Follow includes one level deep
    const subCounts = await Promise.all([...includes, ...redirects].map(async inc => {
      const txts = await dohQuery(inc, 'TXT');
      const subSpf = txts.find(v => startsWithCI(v, 'v=spf1')) || '';
      if (!subSpf) return 0;
      const subMx = (subSpf.match(/(?:^|\s)[+\-~?]?mx(?::|$|\s)/g) || []).length;
      const subA = (subSpf.match(/(?:^|\s)[+\-~?]?a(?::|$|\s)/g) || []).length;
      const subEx = (subSpf.match(/exists:[^\s]+/g) || []).length;
      const subInc = (subSpf.match(/include:[^\s]+/g) || []).length;
      return subMx + subA + subEx + subInc;
    }));

    count += subCounts.reduce((a, b) => a + b, 0);
    return { count, warning: count >= 8, error: count >= 10 };
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

  // Parked domains (no MX) are scored on a different rubric: DKIM, BIMI,
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
      adv.mtaSts?.present,
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

    if (!dkimStatus.found && emailProvider !== '@none' && emailProvider !== '@porkbun-forwarding') {
      issues.push({ key: 'dkim-missing', sev: 'warn', noteKey: dkimStatus.note });
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
    if (advanced?.tlsRpt?.multiple) issues.push({ key: 'tls-rpt-multiple-records', sev: 'warn' });
    if (advanced?.bimi?.multiple) issues.push({ key: 'bimi-multiple-records', sev: 'warn' });
    if (dkimStatus?.duplicated?.length) {
      issues.push({ key: 'dkim-multiple-records', sev: 'warn', args: [dkimStatus.duplicated.join(', ')] });
    }

    if (advanced?.spfLookups?.error) {
      issues.push({ key: 'spf-over-limit', sev: 'crit', args: [advanced.spfLookups.count] });
    } else if (advanced?.spfLookups?.warning) {
      issues.push({ key: 'spf-near-limit', sev: 'warn', args: [advanced.spfLookups.count] });
    }

    return issues;
  }

  // `guide` names the Learn more page to link to (see locales → learnMore).
  function buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    const tips = [];
    if (!advanced) return tips;

    const hasEmail = emailProvider !== '@none';
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
    var dmarc = calcDmarcScore(dmarcStatus);

    // ── Parked / no-email domain ────────────────────────────────────────
    // Scored on PARKED_WEIGHTS: a domain that will never send mail is hardened
    // by refusing it outright (null MX + SPF -all + DMARC reject), so it can
    // legitimately reach the A tier. DKIM/BIMI/MTA-STS/TLS-RPT are excluded
    // because they cannot apply.
    if (emailProvider === '@none') {
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
    var pillars = [
      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },
      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },
      { key: 'dkim', pts: dkimStatus && dkimStatus.found ? WEIGHTS.dkim : 0, max: WEIGHTS.dkim },
      { key: 'dnssec', pts: dnssecSigned ? WEIGHTS.dnssec : 0, max: WEIGHTS.dnssec },
      { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? WEIGHTS.caa : 0, max: WEIGHTS.caa },
      { key: 'mtaSts', pts: (advanced && advanced.mtaSts && advanced.mtaSts.present) ? WEIGHTS.mtaSts : 0, max: WEIGHTS.mtaSts },
      { key: 'bimi', pts: (advanced && advanced.bimi && advanced.bimi.present) ? WEIGHTS.bimi : 0, max: WEIGHTS.bimi },
      { key: 'tlsRpt', pts: (advanced && advanced.tlsRpt && advanced.tlsRpt.present) ? WEIGHTS.tlsRpt : 0, max: WEIGHTS.tlsRpt },
    ];

    var pts = pillars.reduce(function (sum, p) { return sum + p.pts; }, 0);
    var graded = gradeFor(pts, dnssecSigned);

    return {
      grade: graded.grade, cls: graded.cls,
      pts: pts, max: 100, parked: false,
      breakdown: { pillars: pillars, dmarc: dmarc.parts },
    };
  }

  /* ── Orchestrated per-domain audit ──────────────────────────────────── */

  async function analyzeDomain(domain, opts) {
    const d = domain.toLowerCase().trim();

    // Probe NS first — NXDOMAIN (Status 3) means the domain isn't registered
    const nsResult = await dohFetch(d, 'NS');
    const ns = nsResult.answers.filter(a => a.type === 2).map(a => a.data.replace(/^"|"$/g, '').trim());
    if (nsResult.status === 3) {
      return { domain: d, unregistered: true, error: false };
    }

    const [mx, txt, aRec] = await Promise.all([
      dohQuery(d, 'MX'),
      dohQuery(d, 'TXT'),
      opts.www ? dohQuery(d, 'A') : Promise.resolve([]),
    ]);

    const dnsProvider = detectDNSProvider(ns, d);
    const emailProvider = detectEmailProvider(mx, d);
    // Count matches rather than .find() — every one of these record types
    // fails closed when more than one exists (see the multiple-record checks
    // in buildIssues), so the count is part of the signal, not noise.
    const spfMatches = txt.filter(v => startsWithCI(v, 'v=spf1'));
    const spfRecord = spfMatches[0] || '';
    const spfMultiple = spfMatches.length > 1;
    const spfStatus = analyzeSpf(spfRecord, emailProvider, spfMultiple);
    const verifications = txt.filter(v => startsWithCI(v, 'google-site-verification') || startsWithCI(v, 'apple-domain'));

    const dmarcTxts = await dohQuery(`_dmarc.${d}`, 'TXT');
    const dmarcMatches = dmarcTxts.filter(v => startsWithCI(v, 'v=DMARC1'));
    const dmarcRecord = dmarcMatches[0] || '';
    const dmarcMultiple = dmarcMatches.length > 1;
    const dmarcStatus = analyzeDmarc(dmarcRecord, dmarcMultiple);

    let wildcardBug = false;
    if (opts.wildcard) {
      const testSub = await dohQuery(`_wildcardtest99xyz.${d}`, 'TXT');
      wildcardBug = testSub.length > 0;
    }

    let dkimStatus = { found: false, selectors: [], note: '' };
    if (opts.dkim && emailProvider !== '@none') {
      dkimStatus = await checkDKIM(d, wildcardBug);
    }

    let hosting = '@dash';
    if (opts.www) {
      const wwwCname = await dohAll(`www.${d}`, 'CNAME');
      hosting = detectHosting(aRec, wwwCname, d);
    }

    // ── Advanced checks ──
    let advanced = { bimi: null, mtaSts: null, tlsRpt: null, caa: null, dnssec: null, spfLookups: null };
    if (opts.advanced) {
      const [bimiTxt, mtaStsTxt, tlsRptTxt, caaResult, dnssecResult, spfLookups] = await Promise.all([
        dohQuery(`default._bimi.${d}`, 'TXT'),
        dohQuery(`_mta-sts.${d}`, 'TXT'),
        dohQuery(`_smtp._tls.${d}`, 'TXT'),
        checkCAA(d),
        checkDNSSEC(d),
        spfRecord ? countSpfLookups(spfRecord, d) : Promise.resolve({ count: 0, warning: false, error: false }),
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

      advanced = {
        bimi: { present: bimiMatches.length === 1, record: bimiRecord, multiple: bimiMatches.length > 1 },
        mtaSts: { present: mtaMatches.length === 1, record: mtaRecord, multiple: mtaMatches.length > 1 },
        tlsRpt: { present: tlsMatches.length === 1, record: tlsRecord, multiple: tlsMatches.length > 1 },
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
      domain: d, ns, mx, txt, aRec, dnsProvider, emailProvider,
      spfRecord, spfStatus, dmarcRecord, dmarcStatus, dkimStatus,
      wildcardBug, hosting, verifications, advanced, advScore,
      issues, suggestions, score,
    };
  }

  global.DnsAudit = {
    DOH,
    DKIM_SELECTORS,
    analyzeDomain,
    checkConnectivity,
    // exported for unit testing / reuse
    detectDNSProvider,
    detectEmailProvider,
    detectHosting,
    analyzeSpf,
    analyzeDmarc,
    parseDmarcTag,
    startsWithCI,
    countSpfLookups,
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
