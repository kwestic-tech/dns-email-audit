/* ──────────────────────────────────────────────────────────────────────────
   UI, rendering and orchestration.

   All user-facing text comes from the i18n layer (js/i18n.js → locales/*.json).
   The audit logic lives in js/dns.js and speaks only in stable tokens; this
   file is where tokens become words.
   ────────────────────────────────────────────────────────────────────────── */

(function (global) {
  'use strict';

  var CONCURRENCY = 6;
  var MAX_DOMAINS = 200;
  var MAX_COMPREHENSIVE_DKIM_DOMAINS = 5;

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
    if (dmarcStatus.status === 'permerror') return t('dmarc.permerror');
    if (dmarcStatus.status === 'missing') return t('dmarc.missing');
    // 'present' means receivers cannot act on the record — bad v=, unrecognised
    // p=, or duplicate tags.
    if (dmarcStatus.status === 'present') return t('dmarc.invalid');
    // t=y (RFC 9989): name the published policy AND the fact that it is not
    // being applied. Showing plain "none" here would hide the operator's
    // intent; showing plain "reject" would overstate their protection.
    if (dmarcStatus.testMode && dmarcStatus.policy) return t('dmarc.testMode', dmarcStatus.policy);
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

  function scoreBlockHtml(score) {
    if (!score || !score.breakdown) return '';

    var rows = score.breakdown.pillars.map(function (p) {
      var ratio = p.max ? p.pts / p.max : 0;
      var color = ratio >= 1 ? 'var(--ok)' : ratio > 0 ? 'var(--warn)' : '#cbd5e1';
      return '<div class="sb-row">' +
        '<span class="sb-label">' + esc(t('score.pillar.' + p.key)) + '</span>' +
        '<span class="sb-track"><span class="sb-fill" style="width:' + Math.round(ratio * 100) + '%;background:' + color + ';"></span></span>' +
        '<span class="sb-val">' + num(p.pts) + '<small>/' + p.max + '</small></span>' +
        '</div>';
    }).join('');

    var parts = score.breakdown.dmarc || {};
    var partOrder = ['policy', 'subdomain', 'rua', 'alignment', 'ruf', 'uris'];
    var dmarcParts = partOrder
      .filter(function (k) { return parts[k] !== undefined; })
      .map(function (k) {
        var zero = !parts[k];
        return '<span class="sb-part' + (zero ? ' sb-part-zero' : '') + '">' +
          esc(t('score.dmarcParts.' + k)) + ' <strong>' + num(parts[k]) + '</strong></span>';
      }).join('');

    return '<div class="score-block">' +
      '<div class="score-head">' +
      '<span class="score-total ' + score.cls + '">' + num(score.pts) +
      '<small>/' + score.max + '</small></span>' +
      '<span class="issues-section-label">' + esc(t('score.label')) + '</span>' +
      (score.parked ? '<span class="score-note">' + esc(t('score.parkedNote')) + '</span>' : '') +
      '</div>' +
      '<div class="sb-rows">' + rows + '</div>' +
      (dmarcParts
        ? '<div class="sb-dmarc"><span class="sb-dmarc-label">' + esc(t('score.dmarcParts.label')) + '</span>' + dmarcParts + '</div>'
        : '') +
      '</div>';
  }

  function issueMessage(issue) {
    var args = issue.args ? issue.args.slice() : [];
    if (issue.noteKey) args = [t.apply(null, ['dkim.' + issue.noteKey].concat(issue.noteArgs || []))];
    return t.apply(null, ['issue.' + issue.key + '.msg'].concat(args));
  }

  /* ── Small helpers ──────────────────────────────────────────────────── */

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s === undefined || s === null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function rich(s) { return i18n.sanitizeHTML(s); }

  function badge(text, cls) { return '<span class="badge badge-' + cls + '">' + esc(text) + '</span>'; }

  function emailBadge(provider) {
    var noEmail = provider === '@none' || provider === '@null-mx';
    var cls = provider === '@none' ? 'crit' : provider === '@null-mx' ? 'ok' : provider === '@implicit-mx' ? 'warn' : provider === '@porkbun-forwarding' ? 'warn' : 'info';
    return badge(noEmail ? label(provider) : label(provider), cls);
  }

  function hostCls(h) {
    if (h === '@cname-loop') return 'crit';
    return 'muted';
  }

  function showToast(msg) {
    var el = $('toast');
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(function () { el.classList.remove('show'); }, 3000);
  }

  function log(msg, cls) {
    var el = $('progressLog');
    el.innerHTML += '<span class="log-' + (cls || 'info') + '">' + esc(msg) + '</span>\n';
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

  /* ── Learn more pages ───────────────────────────────────────────────── */

  // Structure and styling live here; every word comes from the locale file
  // under learnMore.<key>.
  var GUIDE_COLORS = {
    'bimi': '#7c3aed',
    'mta-sts': '#0284c7',
    'tls-rpt': '#0284c7',
    'caa': '#16a34a',
    'dnssec': '#d97706',
  };

  function buildLearnMorePage(key) {
    var data = tRaw('learnMore.' + key);
    if (!data) return null;
    var color = GUIDE_COLORS[key] || '#2563eb';

    var sectionHtml = (data.sections || []).map(function (s) {
      var html = '<section><h2>' + esc(s.h) + '</h2><p>' + rich(s.body) + '</p>';
      if (s.code) html += '<pre><code>' + esc(s.code) + '</code></pre>';
      if (s.body2) html += '<p>' + rich(s.body2) + '</p>';
      return html + '</section>';
    }).join('');

    return '<!DOCTYPE html>\n<html lang="' + i18n.lang + '">\n<head>\n' +
      '<meta charset="UTF-8">\n' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
      '<title>' + esc(data.title) + '</title>\n<style>\n' +
      "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n" +
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
      '@media(max-width:600px){.hero{padding:32px 20px 28px}.hero h1{font-size:22px}section{padding:20px 18px}main{padding:24px 12px 60px}}\n' +
      '</style>\n</head>\n<body>\n' +
      '<div class="hero">\n  <div class="tag">' + esc(t('learnMore.badge')) + '</div>\n' +
      '  <h1>' + esc(data.title) + '</h1>\n  <p>' + esc(data.tagline) + '</p>\n</div>\n' +
      '<main>\n  <span class="back">' + esc(t('learnMore.close')) + '</span>\n  ' +
      sectionHtml + '\n</main>\n' +
      '<footer>' + esc(t('learnMore.footer')) + '</footer>\n</body>\n</html>';
  }

  function openLearnMore(key) {
    var html = buildLearnMorePage(key);
    if (!html) return;
    var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    global.open(url, '_blank', 'noopener');
    setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
  }

  /* ── Row rendering ──────────────────────────────────────────────────── */

  function advMiniDots(adv) {
    if (!adv) return t('labels.dash');
    var items = [
      { key: 'BIMI', ok: adv.bimi && adv.bimi.present, dup: adv.bimi && adv.bimi.multiple },
      { key: 'MTA-STS', ok: adv.mtaSts && adv.mtaSts.policyVerified, partial: adv.mtaSts && adv.mtaSts.present, dup: adv.mtaSts && adv.mtaSts.multiple },
      { key: 'TLS-RPT', ok: adv.tlsRpt && adv.tlsRpt.present, dup: adv.tlsRpt && adv.tlsRpt.multiple },
      { key: 'CAA', ok: adv.caa && adv.caa.found },
      { key: 'DNSSEC', ok: adv.dnssec && adv.dnssec.signed },
    ];
    var done = items.filter(function (i) { return i.ok; }).length;
    var dots = items.map(function (i) {
      // A duplicated record is not simply absent — it reads amber so the
      // operator can tell "never set up" from "set up twice, silently off".
      var state = i.ok ? t('adv.configured') : i.partial ? t('adv.unverified') : i.dup ? t('adv.duplicated') : t('adv.notConfigured');
      var color = i.ok ? 'var(--ok)' : (i.partial || i.dup) ? 'var(--warn)' : '#cbd5e1';
      return '<span title="' + i.key + ': ' + esc(state) +
        '" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' +
        color + ';margin-right:2px;"></span>';
    }).join('');
    return '<span style="display:inline-flex;align-items:center;gap:4px;">' + dots +
      '<span style="font-size:10px;color:var(--ink3);margin-left:2px;">' + done + '/5</span></span>';
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
      {
        key: 'DNSSEC', ok: adv.dnssec && adv.dnssec.signed,
        tip: adv.dnssec && adv.dnssec.signed ? t('adv.tip.dnssecOn') : t('adv.tip.dnssecOff'),
      },
    ];
    var dots = items.map(function (i) {
      return '<span class="adv-dot ' + (i.ok ? 'dot-ok' : (i.partial || i.dup) ? 'dot-dup' : 'dot-miss') + '" data-tip="' + esc(i.tip) + '">' +
        '<span class="dot-pip"></span>' + i.key + '</span>';
    }).join('');
    return '<div class="adv-strip"><div class="adv-strip-label">' + esc(t('labels.advanced')) +
      '</div><div class="adv-dots">' + dots + '</div></div>';
  }

  function spfMeterHtml(spfLookups) {
    var count = spfLookups.count;
    var pct = Math.min(100, (count / 10) * 100);
    var color = spfLookups.error ? 'var(--crit)' : spfLookups.warning ? 'var(--warn)' : 'var(--ok)';
    var text = spfLookups.error ? t('spf.meterOver', count)
      : spfLookups.warning ? t('spf.meterNear', count)
        : t('spf.meterOk', count);
    return '<div class="spf-meter" style="margin-top:6px;">' +
      '<div class="spf-meter-bar"><div class="spf-meter-fill" style="width:' + pct + '%;background:' + color + ';"></div></div>' +
      '<span class="spf-meter-label" style="color:' + color + ';">' + esc(text + ' ' + t('spf.meterSuffix')) + '</span></div>';
  }

  function appendRow(r) {
    var tbody = $('tableBody');
    var rowId = 'row-' + r.domain.replace(/\W/g, '-');
    var detailId = 'det-' + r.domain.replace(/\W/g, '-');

    if (r.error) {
      var etr = document.createElement('tr');
      etr.id = rowId;
      etr.dataset.domain = r.domain;
      etr.dataset.overall = 'error';
      etr.innerHTML = '<td></td><td class="domain-cell">' + esc(r.domain) + '</td>' +
        '<td colspan="8">' + badge(t(r.cancelled ? 'badge.cancelled' : 'badge.auditError'), r.cancelled ? 'muted' : 'crit') +
        '<span style="margin-left:8px;color:var(--ink3);font-size:12px">' + esc(r.message || '') + '</span></td>';
      tbody.appendChild(etr);
      return;
    }

    // Unregistered domain — muted row, no detail, no metrics
    if (r.unregistered) {
      var utr = document.createElement('tr');
      utr.id = rowId;
      utr.dataset.domain = r.domain;
      utr.dataset.overall = 'unregistered';
      utr.style.opacity = '0.55';
      utr.innerHTML =
        '<td></td>' +
        '<td class="domain-cell" style="color:var(--ink3);font-style:italic">' + esc(r.domain) + '</td>' +
        '<td data-label="' + esc(t('labels.status')) + '" colspan="8" style="color:var(--ink3);font-size:12px;">' +
        badge(t('badge.notRegistered'), 'muted') + '</td>';
      tbody.appendChild(utr);
      return;
    }

    var spfB = badge(spfLabel(r.spfStatus), r.spfStatus.cls);
    var recognizedDkim = (r.dkimStatus.selectors || []).filter(function (s) { return !s.uncommon; });
    var uncommonDkim = (r.dkimStatus.selectors || []).filter(function (s) { return s.uncommon; });
    var dkimB = r.dkimStatus.found
      ? [
        recognizedDkim.length ? badge('✓ ' + recognizedDkim.map(function (s) { return s.sel; }).join(', '), 'ok') : '',
        uncommonDkim.map(function (s) { return badge(t('badge.dkimUncommon', s.queryName), 'warn'); }).join(' '),
      ].join(' ')
      : r.dkimStatus.confidence === 'sampled'
        ? badge(t('badge.dkimUnverified'), 'warn')
        : badge(t('badge.notChecked'), 'muted');
    var dmarcB = badge(dmarcLabel(r.dmarcStatus), r.dmarcStatus.cls);
    var dnsB = badge(label(r.dnsProvider), r.dnsProvider === 'Cloudflare' ? 'muted' : 'info');
    var emailB = emailBadge(r.emailProvider);
    var hostB = badge(label(r.hosting), hostCls(r.hosting));

    var advCell = r.advScore
      ? advMiniDots(r.advanced)
      : '<span style="color:var(--ink3);font-size:11px;">' + esc(t('labels.dash')) + '</span>';

    var critCount = r.issues.filter(function (i) { return i.sev === 'crit'; }).length;
    var warnCount = r.issues.filter(function (i) { return i.sev === 'warn'; }).length;
    var tipCount = (r.suggestions || []).length;
    var issueTag = [
      critCount ? '<span title="' + esc(tp('rows.critical', critCount)) + '">🔴</span>' : '',
      warnCount ? '<span title="' + esc(tp('rows.warning', warnCount)) + '">🟡</span>' : '',
      tipCount ? '<span title="' + esc(tp('rows.suggestion', tipCount)) + '">💡</span>' : '',
    ].join('');

    var tr = document.createElement('tr');
    tr.id = rowId;
    tr.dataset.domain = r.domain;
    tr.dataset.dmarc = r.dmarcStatus.status !== 'missing' ? 'yes' : 'no';
    tr.dataset.dkim = r.dkimStatus.found ? 'yes' :
      (r.dkimStatus.confidence === 'sampled' || r.dkimStatus.confidence === 'not-checked') ? 'unknown' : 'no';
    tr.dataset.spf = r.spfStatus.status !== 'missing' ? 'yes' : 'no';
    tr.dataset.email = r.emailProvider !== '@none' && r.emailProvider !== '@null-mx' ? 'yes' : 'no';
    tr.dataset.bimi = r.advanced && r.advanced.bimi && r.advanced.bimi.present ? 'yes' : 'no';
    tr.dataset.caa = r.advanced && r.advanced.caa && r.advanced.caa.found ? 'yes' : 'no';
    tr.dataset.dnssec = r.advanced && r.advanced.dnssec && r.advanced.dnssec.signed ? 'yes' : 'no';
    tr.dataset.grade = r.score.grade;
    var hasCrit = r.issues.some(function (i) { return i.sev === 'crit'; });
    var hasWarn = r.issues.some(function (i) { return i.sev === 'warn'; });
    tr.dataset.overall = hasCrit ? 'crit' : hasWarn ? 'warn' : 'ok';

    // A grade standing on a check that could not be verified is marked in the
    // cell itself. The reason is already in the detail panel, but nobody
    // expands 200 rows to find it.
    var unproven = r.score.unproven || [];
    tr.dataset.unproven = unproven.length ? 'yes' : 'no';
    var gradeCls = 'score ' + r.score.cls + (unproven.length ? ' score-unproven' : '');
    var gradeTitle = unproven.length
      ? t('score.unproven', num(r.score.pts), r.score.max,
        unproven.map(function (k) { return t('score.pillar.' + k); }).join(', '))
      : t('score.outOf', num(r.score.pts), r.score.max);
    var gradeText = esc(r.score.grade) + (unproven.length ? '<span class="score-star">*</span>' : '');

    tr.innerHTML =
      '<td><button class="expand-toggle" data-detail-id="' + detailId + '">▶</button></td>' +
      '<td class="domain-cell">' + esc(r.domain) + '<span style="margin-left:5px;font-size:11px;">' + issueTag + '</span></td>' +
      '<td data-label="' + esc(t('th.grade')) + '" style="text-align:center"><span class="' + gradeCls + '" title="' +
      esc(gradeTitle) + '">' + gradeText + '</span></td>' +
      '<td data-label="' + esc(t('th.dns')) + '">' + dnsB + '</td>' +
      '<td data-label="' + esc(t('th.email')) + '">' + emailB + '</td>' +
      '<td data-label="' + esc(t('th.spf')) + '">' + spfB + '</td>' +
      '<td data-label="' + esc(t('th.dkim')) + '">' + dkimB + '</td>' +
      '<td data-label="' + esc(t('th.dmarc')) + '">' + dmarcB + '</td>' +
      '<td data-label="' + esc(t('th.advanced')) + '">' + advCell + '</td>' +
      '<td data-label="' + esc(t('th.hosting')) + '">' + hostB + '</td>';
    tbody.appendChild(tr);

    // ── Detail row ──
    var dkimDetails = (r.dkimStatus.selectors || []).map(function (s) {
      return '<div class="dkim-record">' +
        '<strong>' + (s.uncommon ? esc(t('dkim.uncommon', s.queryName)) : esc(s.sel + ' — ' + s.queryName)) + '</strong>' +
        (s.cname ? '<div><span>' + esc(t('dkim.cnameTarget')) + ':</span> <code>' + esc(s.cname) + '</code></div>' : '') +
        '<div><span>' + esc(t('dkim.txtRecord')) + ':</span> <code class="dkim-record-data">' + esc(s.value) + '</code></div>' +
        '</div>';
    });
    (r.dkimStatus.missingSelectors || []).forEach(function (s) {
      dkimDetails.push('<div class="dkim-record dkim-record-missing"><strong>' +
        esc(t('dkim.noDomainKeyFound', s.queryName)) + '</strong>' +
        (s.cname ? '<div><span>' + esc(t('dkim.cnameTarget')) + ':</span> <code>' + esc(s.cname) + '</code></div>' : '') +
        '</div>');
    });
    if (!dkimDetails.length && r.dkimStatus.note) {
      dkimDetails.push(esc(t(
        'dkim.' + r.dkimStatus.note,
        (r.dkimStatus.testedSelectors || []).length - (r.dkimStatus.failedSelectors || []).length,
        (r.dkimStatus.failedSelectors || []).length
      )));
    }
    var dkimDetail = dkimDetails.join('');

    var spfLookupHtml = (r.advanced && r.advanced.spfLookups && r.spfRecord)
      ? spfMeterHtml(r.advanced.spfLookups) : '';
    var advDotsHtml = r.advanced ? advFullDots(r.advanced) : '';

    var issueHtml = r.issues.map(function (i) {
      var what = tRaw('issue.' + i.key + '.what');
      var fix = tRaw('issue.' + i.key + '.fix');
      var fixCode = tRaw('issue.' + i.key + '.fixCode');
      var showMeHtml = what
        ? '<div class="showme-wrap">' +
          '<button class="showme-btn">' + esc(t('showme.open')) + '</button>' +
          '<div class="showme-content">' +
          '<div class="showme-lbl">' + esc(t('showme.whatItIs')) + '</div>' +
          '<div class="showme-text">' + rich(what) + '</div>' +
          '<div class="showme-lbl">' + esc(t('showme.whatItNeeds')) + '</div>' +
          '<div class="showme-text">' + rich(fix || '') +
          (fixCode ? '<div class="showme-code">' + esc(fixCode) + '</div>' : '') +
          '</div></div></div>'
        : '';
      return '<div class="issue"><span class="icon">' +
        (i.sev === 'crit' ? '🔴' : i.sev === 'warn' ? '⚠️' : 'ℹ️') + '</span>' +
        '<div class="issue-body"><span class="msg">' + esc(issueMessage(i)) + '</span>' + showMeHtml + '</div></div>';
    }).join('');

    var suggestHtml = (r.suggestions && r.suggestions.length)
      ? '<hr class="suggestions-sep"><div class="issues-section-label">' + esc(t('labels.suggestions')) + '</div>' +
        r.suggestions.map(function (s) {
          var guide = s.guide && tRaw('learnMore.' + s.guide);
          return '<div class="issue tip"><span class="icon">💡</span><div class="issue-body">' +
            '<span class="msg">' + esc(t('suggestion.' + s.key)) + '</span>' +
            (guide ? '<button class="learnmore-btn" data-guide="' + esc(s.guide) + '">' + esc(t('btn.learnMore')) + '</button>' : '') +
            '</div></div>';
        }).join('')
      : '';

    var dtr = document.createElement('tr');
    dtr.id = detailId;
    dtr.className = 'detail-row';
    dtr.innerHTML =
      '<td colspan="11"><div class="detail-grid">' +
      detailItem(t('labels.nameservers'), esc(r.ns.join(', ') || t('labels.na'))) +
      detailItem(t('labels.mx'), esc(r.mx.join('\n') || t('labels.none'))) +
      detailItem(
        t('labels.spf') + (spfLookupHtml ? ' · ' + t('labels.spfLookups') : ''),
        esc(r.spfRecord || t('labels.none')) + spfLookupHtml
      ) +
      detailItem(t('labels.dmarc'), esc(r.dmarcRecord || t('labels.none')) +
        (r.dmarcAtDomain && r.dmarcAtDomain !== r.domain ? '<br><small>' + esc(t('dmarc.inheritedFrom', r.dmarcAtDomain)) + '</small>' : '')) +
      detailItem(t('labels.dkim'), dkimDetail) +
      detailItem(t('labels.verifications'), r.verifications.length
        ? r.verifications.map(esc).join('<br>')
        : t('labels.dash')) +
      (r.wildcardDkim || r.wildcardApex
        ? (function () {
            // The two depths get different colours because they mean different
            // things: one degrades DKIM discovery, the other is usually a
            // deliberate anti-spoofing measure and costs nothing.
            var colour = r.wildcardDkim ? 'var(--warn)' : 'var(--info)';
            var suffix = r.wildcardDkim ? 'Dkim' : 'Apex';
            return '<div class="detail-item" style="grid-column:1/-1">' +
              '<div class="di-label" style="color:' + colour + '">' + esc(t('labels.wildcard' + suffix + 'Title')) + '</div>' +
              '<div class="di-value" style="color:' + colour + '">' + esc(t('labels.wildcard' + suffix + 'Text')) + '</div></div>';
          }())
        : '') +
      '</div>' + scoreBlockHtml(r.score) + advDotsHtml +
      (issueHtml || suggestHtml
        ? '<div class="issues-block">' +
          (issueHtml ? '<div class="issues-section-label">' + esc(t('labels.issues')) + '</div>' + issueHtml : '') +
          suggestHtml + '</div>'
        : '') +
      '</td>';
    tbody.appendChild(dtr);
  }

  function detailItem(labelText, valueHtml) {
    return '<div class="detail-item"><div class="di-label">' + esc(labelText) +
      '</div><div class="di-value">' + valueHtml + '</div></div>';
  }

  function toggleDetail(id, btn) {
    var el = $(id);
    btn.textContent = el.classList.toggle('open') ? '▼' : '▶';
  }

  function toggleShowMe(btn) {
    var content = btn.nextElementSibling;
    var open = content.style.display !== 'none' && content.style.display !== '';
    content.style.display = open ? 'none' : 'block';
    btn.textContent = open ? t('showme.open') : t('showme.close');
  }

  /* ── Summary, filter, sort ──────────────────────────────────────────── */

  function tile(n, lbl, cls, denom) {
    var numHtml = (denom !== undefined && denom !== null && denom !== n)
      ? n + '<small style="font-size:17px;font-weight:500;opacity:.5"> (' + denom + ')</small>'
      : n;
    return '<div class="stat-tile"><div class="num ' + cls + '">' + numHtml + '</div><div class="lbl">' + esc(lbl) + '</div></div>';
  }

  function renderSummary() {
    var submitted = results.filter(function (r) { return !r.error; });
    var all = submitted.filter(function (r) { return !r.unregistered; });
    var reg = all.length;
    var tot = submitted.length;
    function count(fn) { return all.filter(fn).length; }

    $('statsGrid').innerHTML =
      tile(reg, t('stat.domains'), 'c-muted', reg < tot ? tot : null) +
      tile(count(function (r) { return r.emailProvider !== '@none' && r.emailProvider !== '@null-mx'; }), t('stat.haveEmail'), 'c-info', reg) +
      tile(count(function (r) { return r.spfStatus && r.spfStatus.status !== 'missing'; }), 'SPF', 'c-ok', reg) +
      tile(count(function (r) { return r.dkimStatus && r.dkimStatus.found; }), 'DKIM', 'c-ok', reg) +
      tile(count(function (r) { return r.dmarcStatus && r.dmarcStatus.status !== 'missing'; }), 'DMARC', 'c-ok', reg) +
      tile(count(function (r) { return r.advanced && r.advanced.bimi && r.advanced.bimi.present; }), 'BIMI', 'c-tip', reg) +
      tile(count(function (r) { return r.advanced && r.advanced.mtaSts && r.advanced.mtaSts.present; }), 'MTA-STS', 'c-tip', reg) +
      tile(count(function (r) { return r.advanced && r.advanced.tlsRpt && r.advanced.tlsRpt.present; }), 'TLS-RPT', 'c-tip', reg) +
      tile(count(function (r) { return r.advanced && r.advanced.caa && r.advanced.caa.found; }), 'CAA', 'c-tip', reg) +
      tile(count(function (r) { return r.advanced && r.advanced.dnssec && r.advanced.dnssec.signed; }), 'DNSSEC', 'c-tip', reg) +
      (count(function (r) { return r.wildcardDkim; })
        ? tile(count(function (r) { return r.wildcardDkim; }), t('stat.wildcardDkim'), 'c-warn')
        : '');
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
      selectors: $('dkimSelectors').value.split(/[\s,]+/).map(function (s) { return s.trim().toLowerCase(); })
        .filter(function (s) { return /^[a-z0-9][a-z0-9_-]{0,62}$/.test(s); }),
    };
    auditController = new AbortController();
    opts.signal = auditController.signal;

    results = new Array(domains.length);
    $('auditBtn').disabled = true;
    $('cancelBtn').style.display = '';
    $('auditBtn').innerHTML = '<span class="spinner"></span> ' + esc(t('btn.auditRunning'));
    ['clearBtn', 'exportCsvBtn', 'exportHtmlBtn'].forEach(function (id) { $(id).style.display = 'none'; });
    ['summarySection', 'resultsSection', 'emptyState'].forEach(function (id) { $(id).style.display = 'none'; });
    $('resultsToolbar').style.display = 'none';
    $('progressSection').style.display = 'block';
    $('tableBody').innerHTML = '';
    $('progressLog').innerHTML = '';
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
    $('auditBtn').innerHTML = esc(t('btn.runAudit'));
    ['clearBtn', 'exportCsvBtn', 'exportHtmlBtn'].forEach(function (id) { $(id).style.display = ''; });
    setTimeout(function () { $('progressSection').style.display = 'none'; }, 1200);

    $('tableBody').innerHTML = '';
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

  function dl(name, type, content) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type: type }));
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function exportCSV() {
    var yes = t('csv.yes');
    var no = t('csv.no');
    var unknown = t('csv.unknown');
    // Header arrays are positional, so a locale that predates a new column
    // would silently misalign every CSV it exports. Backfill per index from
    // English: English defines the column count, translations fill what they
    // have. Never let the header row be shorter than the data row.
    var enCols = (global.__I18N_EN__ && global.__I18N_EN__.csv && global.__I18N_EN__.csv.headers) || [];
    var localeCols = tRaw('csv.headers') || [];
    var cols = (enCols.length ? enCols : localeCols).map(function (h, i) { return localeCols[i] || h; });

    var rows = results.filter(function (r) { return !r.error; }).map(function (r) {
      if (r.unregistered) {
        return [r.domain, no].concat(new Array(cols.length - 2).fill(''));
      }
      return [
        r.domain, yes,
        r.score.grade, r.score.pts,
        label(r.dnsProvider), label(r.emailProvider),
        r.spfStatus.status, r.spfRecord,
        r.dkimStatus.found ? yes : (r.dkimStatus.confidence === 'sampled' || r.dkimStatus.confidence === 'not-checked') ? unknown : no,
        (r.dkimStatus.selectors || []).map(function (s) {
          return (s.uncommon ? t('dkim.uncommon', s.queryName) : s.sel + ' — ' + s.queryName) +
            (s.cname ? ' | CNAME: ' + s.cname : '') + ' | TXT: ' + s.value;
        }).concat((r.dkimStatus.missingSelectors || []).map(function (s) {
          return t('dkim.noDomainKeyFound', s.queryName);
        })).join(' || '),
        r.dmarcStatus.status, r.dmarcStatus.policy || '',
        r.dmarcStatus.testMode ? yes : no,
        r.dmarcStatus.sp || '', r.dmarcStatus.np || '', r.dmarcStatus.pct,
        r.dmarcStatus.adkim, r.dmarcStatus.aspf,
        r.dmarcStatus.rua ? yes : no, r.dmarcStatus.ruf ? yes : no,
        r.advanced?.bimi?.present ? yes : no,
        r.advanced?.mtaSts?.policyVerified ? yes : r.advanced?.mtaSts?.present ? t('csv.txtOnly') : no,
        r.advanced?.tlsRpt?.present ? yes : no,
        r.advanced?.caa?.found ? t('csv.yesAt', r.advanced.caa.atDomain) : no,
        r.advanced?.dnssec?.signed ? yes : r.advanced?.dnssec?.state || no,
        r.advanced?.spfLookups?.count ?? '',
        r.issues.map(issueMessage).join(' | '),
        (r.suggestions || []).map(function (s) { return t('suggestion.' + s.key); }).join(' | '),
      ];
    });

    var csv = [cols].concat(rows)
      .map(function (row) {
        return row.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
      })
      .join('\n');

    // BOM keeps Excel happy with UTF-8 (accents, CJK) on Windows.
    dl('dns-email-audit.csv', 'text/csv;charset=utf-8', '﻿' + csv);
    showToast(t('toast.csvExported'));
  }

  // The app is no longer a single file, so the old
  // `document.documentElement.outerHTML` trick would export a report with
  // dead <link>/<script> references. Instead we build a self-contained,
  // script-free snapshot with the stylesheet inlined.
  async function getStylesheetText() {
    try {
      var r = await fetch('css/style.css');
      if (r.ok) return await r.text();
    } catch (e) { /* file:// or offline — fall through */ }
    try {
      return Array.from(document.styleSheets).map(function (sheet) {
        try {
          return Array.from(sheet.cssRules).map(function (rule) { return rule.cssText; }).join('\n');
        } catch (e) { return ''; }
      }).join('\n');
    } catch (e) { return ''; }
  }

  async function exportHTML() {
    var css = await getStylesheetText();
    if (!css) { showToast(t('toast.htmlExportFailed')); return; }

    var table = $('resultsSection').cloneNode(true);
    // Static report: every detail row open, every explainer expanded, no toggles.
    table.querySelectorAll('.detail-row').forEach(function (el) {
      el.classList.add('open');
      el.style.display = '';
    });
    table.querySelectorAll('tr').forEach(function (el) { el.classList.remove('hidden'); });
    table.querySelectorAll('.expand-toggle, .showme-btn, .learnmore-btn').forEach(function (el) { el.remove(); });
    table.querySelectorAll('.showme-content').forEach(function (el) { el.style.display = 'block'; });

    var generated = new Date().toLocaleString(i18n.lang);
    var counted = results.filter(function (r) { return !r.error; }).length;

    var html = '<!DOCTYPE html>\n<html lang="' + i18n.lang + '">\n<head>\n<meta charset="UTF-8">\n' +
      '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
      '<title>' + esc(t('report.title')) + '</title>\n<style>\n' + css +
      '\n/* static report overrides */\n' +
      '.detail-row{display:table-row!important}.showme-content{display:block!important}\n' +
      'thead th{cursor:default}\n</style>\n</head>\n<body>\n' +
      '<div class="page">\n<h1 style="font-size:20px;margin-bottom:4px">' + esc(t('report.title')) + '</h1>\n' +
      '<p style="font-size:12px;color:var(--ink3);margin-bottom:20px">' +
      esc(t('report.generated', generated, counted)) + '</p>\n' +
      '<div id="summarySection" style="display:block;margin-bottom:24px"><div class="stats-grid">' +
      $('statsGrid').innerHTML + '</div></div>\n' +
      table.innerHTML +
      '\n<div class="app-footer">' + esc(t('report.note')) + '</div>\n</div>\n</body>\n</html>';

    dl('dns-email-audit-report.html', 'text/html', html);
    showToast(t('toast.htmlExported'));
  }

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
    $('tableBody').innerHTML = '';
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
    $('tableBody').innerHTML = '';
    results.filter(function (r) { return !r.error; }).forEach(appendRow);
    renderSummary();
    filterTable();
    showToast(t('toast.langChanged'));
  });

  document.addEventListener('DOMContentLoaded', function () {
    $('auditBtn').addEventListener('click', startAudit);
    $('cancelBtn').addEventListener('click', cancelAudit);
    $('fileInput').addEventListener('change', loadFile);
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
      var learn = event.target.closest('.learnmore-btn');
      if (learn) openLearnMore(learn.dataset.guide);
    });
    i18n.init().then(function () {
      // Surface the sandbox banner immediately if DoH is unreachable.
      DnsAudit.checkConnectivity().then(function (ok) {
        if (!ok) $('netBanner').style.display = 'block';
      });
    });
  });

  // Exposed for the inline onclick handlers in index.html.
  global.startAudit = startAudit;
  global.cancelAudit = cancelAudit;
  global.exportCSV = exportCSV;
  global.exportHTML = exportHTML;
  global.loadFile = loadFile;
  global.loadExample = loadExample;
  global.clearAll = clearAll;
  global.showHelp = showHelp;
  global.setLang = setLang;
  global.filterTable = filterTable;
  global.sortTable = sortTable;
  global.toggleDetail = toggleDetail;
  global.toggleShowMe = toggleShowMe;
  global.openLearnMore = openLearnMore;
})(window);
