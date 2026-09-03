/**
 * The exported artifacts: the CSV and the standalone HTML report. Spec Design
 * §12, implementation Task 5.5.
 *
 * These two files leave the project's control the moment someone emails one,
 * which is why `tools/export.test.mjs` asserts them at the STRING level as
 * well as the tree level, and why the report carries its own restrictive
 * policy rather than inheriting the page's.
 *
 * ── What it formats, and what it must not do ────────────────────────────
 *
 * It formats **completed audit facts** — a finished result's `score.grade`,
 * `spfStatus.status`, `advanced.caa.found` and their siblings — into cells and
 * nodes. It **does not reinterpret protocol records**: every value it writes
 * was decided by a `core/<protocol>/` owner and carried through
 * `audit/issues.js` or `audit/scoring.js`. The same ruling that governs those
 * two governs this: the owner decides what a record MEANS, and this file
 * decides how a meaning is SPELLED for export.
 *
 * ── Dependencies, stated rather than implied ────────────────────────────
 *
 * §12 gives `src/ui/` an edge to `ui/` siblings and `i18n/` only, and says
 * event functions receive audit callbacks as arguments. Everything else is
 * passed, and each of these is a real dependency of the exported bytes:
 *
 * | Dependency | Why the export needs it |
 * | --- | --- |
 * | `i18n` — `t`, `tRaw`, `lang`, and the English bundle | Every header, label and issue message is a locale lookup. `csv.headers` is POSITIONAL, so the English bundle backfills per index; a locale that predates a column would otherwise misalign every row it exports. |
 * | `renderer` (`R`) | The report is built as a detached tree with the same element builder the page uses, and `R.hygieneOf()` produces the record-hygiene column. |
 * | `document` | `implementation.createHTMLDocument()` for the report, `createElement('a')` for the download. Passed, never reached for. |
 * | `platform` | `Blob`, `URL`, `setTimeout`, `fetch` and `formatDateTime`. Spec §11: the composition root owns the window. |
 * | Row formatters — `label`, `issueMessage`, `spfRecordCell`, `dkimKeyBitsCell`, `rowHygieneValues` | The CSV must spell a cell exactly as the table does. These live with the table renderer in `src/main.js` and are passed until that renderer has its own home. |
 * | `getResults` | An ACCESSOR, not the array. `src/main.js` REPLACES `results` on each run (`results = new Array(...)`), so a captured reference would export the previous run. |
 * | `showToast`, `$` | The page feedback and lookup the two entry points use. |
 *
 * ── The report's own policy ─────────────────────────────────────────────
 *
 * `default-src 'none'; style-src 'unsafe-inline'; img-src data:` — asserted
 * twice and unchanged by this move: `tools/csp.test.mjs` §5 reads it out of
 * the source, and `equivalence.validate.mjs` weakens it as a mutation and
 * requires the report surface to move. A standalone file that someone opens
 * from their downloads folder gets no script, no network and no font.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `src/main.js`'s export block, unchanged apart from the two-space dedent, the
 * `export` keywords and the factory wrapper. No column moved, no byte of CSV
 * changed, no policy edited. `serializeDocument` and `styleElement` moved with
 * it and are exported: `buildLearnMorePage()` — still in `src/main.js` — emits
 * a standalone document too, and the `</style>` escape rule must exist once
 * rather than twice.
 */

import { projectReport } from './report-data.js';

export function serializeDocument(doc) {
  return '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
}

// <style> is a raw-text element, so its contents are not entity-escaped by
// any serializer: a `</style>` inside the CSS would end the element early and
// everything after it would be parsed as markup. CSS has no legitimate use
// for '<' at all, so every one is rewritten to the CSS escape `\3c `, which
// renders identically and leaves no character that can open a tag. The
// stylesheet is ours either way; this costs nothing and removes the question.
export function styleElement(D, css) {
  return D.el('style', null, String(css).replace(/</g, '\\3c '));
}


/**
 * Build the export functions over this page's i18n, renderer and platform.
 *
 * Capabilities are destructured in the BODY, not in the parameter list:
 * `platform.test.mjs`'s ambient scan does not recognize a destructured
 * parameter as a declaration, and `document` is one of the names it looks for.
 */
export function createReport(capabilities) {
  const {
    // The page's document and the §11 primitives, both passed.
    document, platform,
    // i18n and the renderer — the two `src/ui/` edges §12 allows.
    i18n, renderer: R,
    // The English bundle, for the positional `csv.headers` backfill.
    englishBundle,
    // Row formatters, still owned by the table renderer in `src/main.js`.
    label, issueMessage, spfRecordCell, dkimKeyBitsCell, rowHygieneValues,
    // Page feedback, and the accessor that keeps `results` fresh.
    showToast, $, getResults, getArtifactSessions, buildArtifactReportContent,
    // 0.9.0's JSON export (report-comparison 1.7 section 3). Each of these is
    // a capability rather than an import because `src/ui/` may reach only
    // `ui/` siblings and `i18n/`: `versions` and `resolver` come from the
    // composition root, and `validSelector` is a protocol rule owned by
    // `src/core/dkim/` that the schema must not restate.
    versions, resolver, validSelector, getRunContext,
  } = capabilities;
  const t = i18n.t;
  const tRaw = i18n.tRaw;
  const { Blob, URL, setTimeout, fetch } = platform;

  function dl(name, type, content) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type: type }));
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  /**
   * Build the CSV rows. Split out from exportCSV so the export tests can
   * assert on the data without a DOM or a download.
   *
   * OQ-SEC-11: the data columns carry the published bytes exactly as received.
   * Rewriting a cell to a sentinel string would break anyone piping this into
   * a script, so the warning goes in its own `record_hygiene` column instead.
   * That column is APPENDED, never inserted, because `csv.headers` is
   * positional and a locale that predates it would otherwise misalign.
   */
  function buildCsvRows(rows) {
    var yes = t('csv.yes');
    var no = t('csv.no');
    var unknown = t('csv.unknown');
    // Header arrays are positional, so a locale that predates a new column
    // would silently misalign every CSV it exports. Backfill per index from
    // English: English defines the column count, translations fill what they
    // have. Never let the header row be shorter than the data row.
    var enCols = (englishBundle && englishBundle.csv && englishBundle.csv.headers) || [];
    var localeCols = tRaw('csv.headers') || [];
    var cols = (enCols.length ? enCols : localeCols).map(function (h, i) { return localeCols[i] || h; });

    var sessions = typeof getArtifactSessions === 'function' ? getArtifactSessions() : {};
    var data = rows.filter(function (r) { return !r.error; }).map(function (r) {
      if (r.unregistered) {
        return [r.domain, no].concat(new Array(cols.length - 2).fill(''));
      }
      var artifactFindings = sessions && sessions[r.domain]
        ? (sessions[r.domain].artifactFindings || []) : [];
      return [
        r.domain, yes,
        r.score.grade, r.score.pts,
        label(r.dnsProvider), label(r.emailProvider),
        r.spfStatus.status, spfRecordCell(r),
        r.dkimStatus.found ? yes : (r.dkimStatus.confidence === 'sampled' || r.dkimStatus.confidence === 'not-checked') ? unknown : no,
        (r.dkimStatus.selectors || []).map(function (s) {
          return (s.uncommon ? t('dkim.uncommon', s.queryName) : s.sel + ' — ' + s.queryName) +
            (s.viaSpf ? ' (' + t('dkim.viaSpf', s.viaSpf) + ')' : '') +
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
        r.issues.map(function (i) { return issueMessage(i, false); }).join(' | '),
        (r.suggestions || []).map(function (s) { return t('suggestion.' + s.key); }).join(' | '),
        // Appended, never inserted, per the positional-header rule above.
        R.hygieneOf(rowHygieneValues(r)).join(' '),
        // Tree Walk provenance (spec §7). Tokens, not prose: `terminated` is
        // the same vocabulary the DMARC walk reports, so a script consuming this
        // column does not have to parse a translated sentence.
        r.dmarcDiscovery && r.dmarcDiscovery.applied ? r.dmarcDiscovery.applied.foundAt : '',
        r.dmarcDiscovery && r.dmarcDiscovery.applied ? r.dmarcDiscovery.applied.labelsUp : '',
        r.dmarcDiscovery ? r.dmarcDiscovery.terminated : '',
        // 0.4.0 protocol depth. Appended, never inserted — `csv.headers` is
        // positional and a consumer's column index must keep meaning what it
        // meant last release.
        (r.dkimStatus?.keyProfile?.algorithms || []).join(', '),
        dkimKeyBitsCell(r.dkimStatus?.keyProfile),
        (r.dkimStatus?.revokedSelectors || []).map(function (x) { return x.sel; }).join(', '),
        (r.advanced?.caa?.issuers || []).join(', '),
        // An absent issuewild set means the issue set governs wildcards. An
        // empty cell here would be read as "wildcards unrestricted", which is
        // the opposite of what the domain published, so it is named instead.
        r.advanced?.caa?.found && r.advanced.caa.parsed
          ? (r.advanced.caa.wildcardBlocked ? t('caa.wildcardBlocked')
            : (r.advanced.caa.wildcardIssuers || []).length ? r.advanced.caa.wildcardIssuers.join(', ')
              : t('caa.wildcardViaIssue'))
          : '',
        // Hosts we could not check are absent from danglingHosts by
        // construction, so this column never accuses a host the audit did not
        // actually resolve.
        r.advanced?.mxHealth ? ((r.advanced.mxHealth.danglingHosts || []).join(', ') || no) : unknown,
        r.advanced?.mxHealth ? (r.advanced.mxHealth.hosts || []).length : unknown,
        r.advanced?.tlsa ? (r.advanced.tlsa.anyPresent ? yes : no) : unknown,
        // 0.7.0 structured findings (findings spec §5). Appended, never
        // inserted — `csv.headers` is positional. Ids and severity tokens, not
        // translated prose, so a consumer reads a stable machine vocabulary;
        // the first remediation step's finding ids show what to fix first.
        (r.findings || []).map(function (f) { return f.id; }).join(' | '),
        (r.findings || []).map(function (f) { return f.severity; }).join(' | '),
        (r.remediationPlan && r.remediationPlan[0] ? r.remediationPlan[0].findings : []).join(' | '),
        // 0.8.0 local artifacts. Three distinct columns, appended after every
        // DNS column: merging these ids into the DNS finding cell would erase
        // the provenance boundary the UI and result model preserve.
        artifactFindings.map(function (f) { return f.id; }).join(' | '),
        artifactFindings.map(function (f) { return f.severity; }).join(' | '),
        artifactFindings.flatMap(function (f) {
          return (f.evidence || []).map(function (e) {
            return [f.source, f.artifact, e.kind, e.location, e.value].join(' :: ');
          });
        }).join(' || '),
      ];
    });

    return [cols].concat(data);
  }

  /**
   * Neutralize a cell a spreadsheet would execute as a formula.
   *
   * A domain controls its SPF, DMARC, DKIM, BIMI and CAA record text, so a
   * value beginning `=`, `+`, `-`, `@`, or a tab/CR/LF becomes an active
   * formula when the downloaded file is opened in Excel or Sheets. RFC 4180
   * quoting does not prevent that — the quotes are stripped before the cell is
   * evaluated.
   *
   * The file is named `.csv` and the button says "Export CSV", which invites
   * exactly that. Spreadsheet safety therefore wins over byte fidelity here,
   * reversing this release's earlier deferral; the change is disclosed by the
   * `formula-leading` token in the `record_hygiene` column rather than applied
   * silently. A leading apostrophe is the standard neutralizer: it makes the
   * spreadsheet read the cell as text rather than a formula. On CSV import it
   * is visible in the cell — an apostrophe is hidden only when it is typed
   * into a cell directly — which is why the change is also named by the
   * `formula-leading` token rather than relying on being invisible.
   */
  function neutralizeCsvCell(value) {
    var text = String(value === undefined || value === null ? '' : value);
    return R.isFormulaLeading(text) ? "'" + text : text;
  }

  function toCsvText(rows) {
    return rows.map(function (row) {
      return row.map(function (c) {
        // Neutralize first, quote second: the quoting is RFC 4180 transport,
        // the neutralization is about what the spreadsheet does after parsing.
        return '"' + neutralizeCsvCell(c).replace(/"/g, '""') + '"';
      }).join(',');
    }).join('\n');
  }

  function exportCSV() {
    var csv = toCsvText(buildCsvRows(getResults()));
    // BOM keeps Excel happy with UTF-8 (accents, CJK) on Windows.
    dl('dns-email-audit.csv', 'text/csv;charset=utf-8', '﻿' + csv);
    showToast(t('toast.csvExported'));
  }

  /**
   * Build the 0.9.0 report body from the current run.
   *
   * Split from `exportJSON()` so the export tests can assert the bytes without
   * a DOM or a download, exactly as `buildCsvRows` is.
   *
   * `generatedAt` is the moment the RUN completed, taken from the run context
   * rather than read from a clock here. That is what makes acceptance criterion
   * 4 testable: two exports of one audit, taken in two languages or ten minutes
   * apart, are byte-identical. A fresh timestamp per export would differ.
   */
  function buildReportJson() {
    var run = typeof getRunContext === 'function' ? getRunContext() : null;
    return projectReport({
      results: getResults(),
      options: (run && run.options) || {},
      generatedAt: (run && run.generatedAt) || '',
      resolver: resolver,
      versions: versions,
      validSelector: validSelector,
    });
  }

  /**
   * Download the report as JSON.
   *
   * The filename carries the run's own UTC date, derived from `generatedAt`
   * rather than from a second clock read, so a file's name and its contents
   * cannot disagree.
   *
   * It is deliberately not UNIQUE. Two exports of one run, or of two runs on
   * the same UTC date, request the same name and the browser disambiguates.
   * A date is readable in a downloads folder, a second-precision timestamp is
   * more identity than the file needs, and the repeat case is rare.
   *
   * Artifact findings are absent by construction: nothing on this path reads
   * `getArtifactSessions()`, so there is no route by which a `user-supplied`
   * finding reaches the file (RQ-CMP-07). The CSV and HTML exports above do
   * carry them, which is the provenance boundary 0.8.0 established.
   */
  function exportJSON() {
    var report = buildReportJson();
    var day = String(report.generatedAt).slice(0, 10) || 'report';
    dl('dns-email-audit-' + day + '.json', 'application/json',
      JSON.stringify(report, null, 2));
    showToast(t('toast.jsonExported'));
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

  /**
   * Build the exported report as a detached tree and serialize once.
   *
   * Split from exportHTML so the export tests can drive it with synthetic
   * nodes rather than a live page. `opts.content` are already-built nodes to
   * adopt into the report document.
   */
  function buildReportDocument(opts) {
    var doc = document.implementation.createHTMLDocument('');
    var D = R.for(doc);

    doc.documentElement.setAttribute('lang', opts.lang || 'en');
    doc.head.appendChild(D.el('meta', { charset: 'UTF-8' }));
    doc.head.appendChild(D.el('meta', {
      name: 'viewport', content: 'width=device-width, initial-scale=1.0',
    }));
    // This file leaves the project's control the moment someone emails it, so
    // it carries its own policy. 'unsafe-inline' for styles is acceptable here
    // and only here: the report inlines the stylesheet by necessity and
    // contains no script at all.
    doc.head.appendChild(D.el('meta', {
      'http-equiv': 'Content-Security-Policy',
      content: "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
    }));
    doc.head.appendChild(D.el('title', null, opts.title));
    doc.head.appendChild(styleElement(D, (opts.css || '') +
      '\n/* static report overrides */\n' +
      '.detail-row{display:table-row!important}.showme-content{display:block!important}\n' +
      '.rv-rest{display:inline!important}.rv-more{display:none!important}\n' +
      'thead th{cursor:default}\n'));

    var page = D.el('div', { className: 'page' }, [
      D.el('h1', { style: 'font-size:20px;margin-bottom:4px' }, opts.title),
      D.el('p', { style: 'font-size:12px;color:var(--ink3);margin-bottom:20px' }, opts.generated),
    ]);

    if (opts.stats) {
      page.appendChild(D.el('div', {
        id: 'summarySection',
        style: 'display:block;margin-bottom:24px',
      }, [D.el('div', { className: 'stats-grid' }, opts.stats)]));
    }
    if (opts.content) page.appendChild(opts.content);
    page.appendChild(D.el('div', { className: 'app-footer' }, opts.note));

    doc.body.appendChild(page);
    return serializeDocument(doc);
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
    table.querySelectorAll('.expand-toggle, .showme-btn, .learnmore-btn, .rv-more').forEach(function (el) { el.remove(); });
    table.querySelectorAll('.showme-content').forEach(function (el) { el.style.display = 'block'; });
    // Display caps never reach the data: the truncated remainder is revealed
    // in the exported report rather than dropped from it.
    table.querySelectorAll('.rv-rest').forEach(function (el) { el.style.display = 'inline'; });

    var generated = platform.formatDateTime(undefined, i18n.lang);
    var counted = getResults().filter(function (r) { return !r.error; }).length;

    var content = document.createDocumentFragment();
    Array.from(table.childNodes).forEach(function (n) { content.appendChild(n); });

    var artifactContent = typeof buildArtifactReportContent === 'function'
      ? buildArtifactReportContent() : null;
    if (artifactContent) {
      artifactContent.querySelectorAll('.showme-btn, .rv-more').forEach(function (el) { el.remove(); });
      artifactContent.querySelectorAll('.showme-content').forEach(function (el) { el.style.display = 'block'; });
      artifactContent.querySelectorAll('.rv-rest').forEach(function (el) { el.style.display = 'inline'; });
      content.appendChild(artifactContent);
    }

    var stats = document.createDocumentFragment();
    Array.from($('statsGrid').cloneNode(true).childNodes).forEach(function (n) { stats.appendChild(n); });

    var html = buildReportDocument({
      lang: i18n.lang,
      css: css,
      title: t('report.title'),
      generated: t('report.generated', generated, counted),
      note: t('report.note'),
      stats: stats,
      content: content,
    });

    dl('dns-email-audit-report.html', 'text/html', html);
    showToast(t('toast.htmlExported'));
  }

  return {
    exportCSV, exportHTML, exportJSON,
    // Reached by `tools/export.test.mjs` through the UI object `createUi()`
    // returns — `loadUi()` composes a runtime and hands it back — so these are
    // driven directly rather than through a live page, and by import rather
    // than through any published name.
    buildCsvRows, toCsvText, neutralizeCsvCell, buildReportDocument,
    buildReportJson,
  };
}
