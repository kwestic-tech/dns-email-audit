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
  function analyzeSpf(spf, emailProvider) {
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
    for (const { sel, txt, cname } of checks) {
      if (txt.some(v => v.startsWith('v=DKIM1'))) found.push({ sel, type: 'key', value: txt[0] });
      else if (cname.length && cname[0].includes('dkim') && !cname[0].includes('porkbun') && !cname[0].includes('pixie'))
        found.push({ sel, type: 'cname', value: cname[0] });
    }

    if (!found.length) {
      return { found: false, selectors: [], note: wildcardBug ? 'noteWildcard' : 'noteNotFound' };
    }
    return { found: true, selectors: found, note: '' };
  }

  function analyzeDmarc(dmarc) {
    if (!dmarc) return { status: 'missing', cls: 'crit', policy: '', rua: false };
    const policyMatch = dmarc.match(/p=([^;]+)/);
    const policy = policyMatch ? policyMatch[1].trim() : 'none';
    const rua = dmarc.includes('rua=');
    if (policy === 'reject') return { status: 'ok', cls: 'ok', policy, rua };
    if (policy === 'quarantine') return { status: 'ok', cls: 'ok', policy, rua };
    if (policy === 'none') return { status: 'warn', cls: 'warn', policy, rua };
    return { status: 'present', cls: 'ok', policy, rua };
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
      const subSpf = txts.find(v => v.startsWith('v=spf1')) || '';
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
    if (spfStatus.status === 'missing') issues.push({ key: 'spf-missing', sev: 'crit' });

    spfStatus.warnings.forEach(key => {
      issues.push({ key, sev: 'warn' });
    });

    if (!dkimStatus.found && emailProvider !== '@none' && emailProvider !== '@porkbun-forwarding') {
      issues.push({ key: 'dkim-missing', sev: 'warn', noteKey: dkimStatus.note });
    }
    if (dmarcStatus.status === 'missing') issues.push({ key: 'dmarc-missing', sev: 'warn' });
    if (dmarcStatus.status === 'warn' && dmarcStatus.policy === 'none') issues.push({ key: 'dmarc-none', sev: 'warn' });
    if (dmarcStatus.status === 'ok' && !dmarcStatus.rua) issues.push({ key: 'dmarc-no-rua', sev: 'info' });
    if (emailProvider === '@porkbun-forwarding') issues.push({ key: 'porkbun-forward', sev: 'warn' });

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

    if (!advanced.bimi?.present && dmarcEnforced && dkimStatus.found) tips.push({ key: 'bimiEligible', guide: 'bimi' });
    else if (!advanced.bimi?.present && hasEmail) tips.push({ key: 'bimiPrereq', guide: 'bimi' });

    if (!advanced.mtaSts?.present && hasEmail) tips.push({ key: 'mta-sts', guide: 'mta-sts' });
    if (!advanced.tlsRpt?.present && hasEmail) tips.push({ key: 'tls-rpt', guide: 'tls-rpt' });
    if (!advanced.caa?.found) tips.push({ key: 'caa', guide: 'caa' });
    if (!advanced.dnssec?.signed) tips.push({ key: 'dnssec', guide: 'dnssec' });

    return tips;
  }

  /* ── Scoring ────────────────────────────────────────────────────────── */

  function calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, wildcardBug, advanced }) {
    if (wildcardBug) return { grade: 'F', cls: 'score-f', pts: 0 };
    let pts = 0;

    // ── Parked / no-email domain ──
    if (emailProvider === '@none') {
      if (spfStatus.status !== 'missing') pts += 2;
      if (dmarcStatus.status === 'ok') pts += 2;
      if (pts >= 4) return { grade: 'B', cls: 'score-b', pts };
      if (pts >= 2) return { grade: 'C', cls: 'score-c', pts };
      if (pts >= 1) return { grade: 'D', cls: 'score-d', pts };
      return { grade: 'F', cls: 'score-f', pts };
    }

    // ── Active email domain ──
    if (spfStatus.status === 'ok') pts += 2;
    else if (['softfail', 'present'].includes(spfStatus.status)) pts += 1;
    if (dkimStatus.found) pts += 3;
    if (dmarcStatus.status === 'ok') { pts += 3; if (dmarcStatus.policy === 'reject') pts += 1; }
    else if (dmarcStatus.status === 'warn') pts += 1;

    if (pts >= 8) {
      // DNSSEC is the hard gate for any A grade
      if (advanced?.dnssec?.signed) {
        const advCount = [
          advanced?.bimi?.present,
          advanced?.mtaSts?.present,
          advanced?.tlsRpt?.present,
          advanced?.caa?.found,
        ].filter(Boolean).length;
        if (advCount >= 4) return { grade: 'A++', cls: 'score-aplusplus', pts };
        if (advCount >= 2) return { grade: 'A+', cls: 'score-aplus', pts };
        return { grade: 'A', cls: 'score-a', pts };
      }
      // High score but DNSSEC absent — capped at B
      return { grade: 'B', cls: 'score-b', pts };
    }
    if (pts >= 5) return { grade: 'B', cls: 'score-b', pts };
    if (pts >= 3) return { grade: 'C', cls: 'score-c', pts };
    if (pts >= 1) return { grade: 'D', cls: 'score-d', pts };
    return { grade: 'F', cls: 'score-f', pts };
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
    const spfRecord = txt.find(v => v.startsWith('v=spf1')) || '';
    const spfStatus = analyzeSpf(spfRecord, emailProvider);
    const verifications = txt.filter(v => v.startsWith('google-site-verification') || v.startsWith('apple-domain'));

    const dmarcTxts = await dohQuery(`_dmarc.${d}`, 'TXT');
    const dmarcRecord = dmarcTxts.find(v => v.startsWith('v=DMARC1')) || '';
    const dmarcStatus = analyzeDmarc(dmarcRecord);

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

      const bimiRecord = bimiTxt.find(v => v.startsWith('v=BIMI1')) || '';
      const mtaRecord = mtaStsTxt.find(v => v.startsWith('v=STSv1')) || '';
      const tlsRecord = tlsRptTxt.find(v => v.startsWith('v=TLSRPTv1')) || '';

      advanced = {
        bimi: { present: !!bimiRecord, record: bimiRecord },
        mtaSts: { present: !!mtaRecord, record: mtaRecord },
        tlsRpt: { present: !!tlsRecord, record: tlsRecord },
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
    countSpfLookups,
    calcScore,
    buildIssues,
    buildSuggestions,
  };
})(window);
