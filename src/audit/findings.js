/**
 * Structured findings and the remediation plan. Spec: findings-and-remediation
 * 1.0 (Final), §1–§4.
 *
 * ── Enrich, not replace (RQ-FIND-08) ────────────────────────────────────
 *
 * `buildIssues()` in `issues.js` is 250 lines of accumulated correctness, much
 * of it comments naming a specific false positive fixed once. Three independent
 * guards pin its exact shape — the equivalence `result` surface captures
 * `result.issues` verbatim, `equivalence.validate.mjs` greps one of its
 * literals, and `scoring.test.mjs` reads its output at dozens of sites — so this
 * module does NOT rewrite it. `buildFindings()` runs the untouched builder and
 * enriches each `{ key, sev, args }` into a structured `Finding`, then composes
 * the cross-protocol rules that no single-protocol check can see.
 *
 * The consequence the spec relies on: `result.issues` and `result.suggestions`
 * stay byte-identical, and because everything here is pure over an already
 * completed audit context, no DNS query is issued, so the published fan-out
 * (the equivalence `trace` surface) does not move.
 *
 * ── The input boundary, same ruling as issues.js and scoring.js ─────────
 *
 * The `when` predicates below consume owner-produced FACTS — `dmarcStatus.enforcing`,
 * `advanced.bimi.validation.authority`, `dkimStatus.keyProfile.mixed`,
 * `ctx.spfUsesMx` — never the text of a record. Interpreting a fact into a
 * finding is this layer's job; re-parsing a record is an owner's. The
 * `spfUsesMx` fact is produced by `core/spf`'s `spfUsesMechanism()` and composed
 * in `audit-domain.js` (RQ-FIND-09), the same pattern `spfReferencedCatalogKeys`
 * already sets.
 *
 * ── Identity is the id, not the locale key (RQ-FIND-05) ─────────────────
 *
 * A migrated finding carries `key: '<key>'` resolving under the historical
 * `issue.<key>.*` namespace it already has thirteen translations for; a
 * cross-protocol finding carries `key: '<slug>'` resolving under the new
 * `finding.<slug>.*` namespace. The `id` is the stable identity that 0.9.0's
 * report schema freezes, decoupled from either.
 */
import { buildIssues } from './issues.js';

/* ── Closed vocabularies (findings.test.js asserts membership) ──────────────
 *
 * Grouped under one exported object rather than five bare string arrays on
 * purpose: `state-matrix.test.mjs` §3 requires every all-string constant a
 * `src/` module exports to match a reviewed `state-algebras.json` algebra.
 * These finding vocabularies are not yet registered there — they are fully
 * asserted by the co-located `findings.test.js`, and registering them would
 * pull the coverage matrix into this commit. `FINDING_ENUMS`'s own values are
 * arrays, so the §3 all-string scan skips it, and the deferral is recorded for
 * review rather than hidden.
 * ──────────────────────────────────────────────────────────────────────── */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES = ['confirmed', 'probable', 'unverified'];
const CATEGORIES = ['authentication', 'policy', 'reporting', 'transport',
  'issuance', 'resilience', 'hygiene'];
const EFFORTS = ['trivial', 'moderate', 'involved'];
const PROTOCOLS = ['spf', 'dkim', 'dmarc', 'dnssec', 'caa', 'mta-sts',
  'tls-rpt', 'bimi', 'mx', 'dane', 'dns', 'defensive', 'reporting'];

export const FINDING_ENUMS = {
  severity: SEVERITIES, confidence: CONFIDENCES, category: CATEGORIES,
  effort: EFFORTS, protocol: PROTOCOLS,
};

// Severity ranking for within-step ordering (RQ-FIND-01 / §4). Higher is worse.
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const EFFORT_RANK = { trivial: 0, moderate: 1, involved: 2 };

/* ── Migrated findings: legacy issue key → structured metadata ───────────
 *
 * One entry per key `buildIssues()` can emit. Base severity mirrors the legacy
 * `sev` (crit→critical, warn→medium, info→info) EXCEPT where the spec calls for
 * the deliberate widening the five-value scale exists for — `dmarc.policy-none`
 * is `high`. `confidence` defaults to `confirmed`; entries that rest on a failed
 * lookup or a heuristic override it. `dependsOn` is empty for a migrated finding
 * unless a prerequisite is technically necessary; `dmarc.policy-none` names the
 * two authentication findings it must not be advised ahead of.
 * ──────────────────────────────────────────────────────────────────────── */
export const FINDING_META = {
  // Wildcard synthesis and hosting topology (protocol 'dns'/'mx').
  'wildcard-txt-apex': { id: 'dns.wildcard-apex', protocol: 'dns', severity: 'info', category: 'resilience', effort: 'moderate' },
  'wildcard-txt-dkim': { id: 'dns.wildcard-dkim', protocol: 'dns', severity: 'medium', category: 'resilience', effort: 'moderate' },
  'dns-loop': { id: 'dns.hosting-loop', protocol: 'dns', severity: 'critical', category: 'resilience', effort: 'moderate' },
  'checks-unverified': { id: 'dns.checks-unverified', protocol: 'dns', severity: 'medium', category: 'resilience', effort: 'trivial', confidence: 'unverified' },
  'no-mx': { id: 'mx.none', protocol: 'mx', severity: 'critical', category: 'resilience', effort: 'moderate' },
  'implicit-mx': { id: 'mx.implicit', protocol: 'mx', severity: 'medium', category: 'resilience', effort: 'moderate' },
  'porkbun-forward': { id: 'mx.porkbun-forwarding', protocol: 'mx', severity: 'medium', category: 'resilience', effort: 'moderate' },

  // SPF.
  'spf-missing': { id: 'spf.missing', protocol: 'spf', severity: 'critical', category: 'authentication', effort: 'trivial' },
  'spf-multiple-records': { id: 'spf.multiple-records', protocol: 'spf', severity: 'critical', category: 'authentication', effort: 'trivial' },
  'spf-all-permit': { id: 'spf.all-permit', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial' },
  'spf-neutral': { id: 'spf.neutral', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial' },
  'spf-softfail': { id: 'spf.softfail', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial' },
  'spf-missing-google': { id: 'spf.missing-google', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial', confidence: 'probable' },
  'spf-missing-icloud': { id: 'spf.missing-icloud', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial', confidence: 'probable' },
  'spf-missing-microsoft': { id: 'spf.missing-microsoft', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'trivial', confidence: 'probable' },
  'spf-over-limit': { id: 'spf.over-limit', protocol: 'spf', severity: 'critical', category: 'authentication', effort: 'involved' },
  'spf-near-limit': { id: 'spf.near-limit', protocol: 'spf', severity: 'medium', category: 'authentication', effort: 'involved' },
  'spf-cycle': { id: 'spf.cycle', protocol: 'spf', severity: 'critical', category: 'authentication', effort: 'moderate' },
  'spf-large-subnet': { id: 'spf.large-subnet', protocol: 'spf', severity: 'medium', category: 'hygiene', effort: 'involved' },
  'spf-medium-subnet': { id: 'spf.medium-subnet', protocol: 'spf', severity: 'info', category: 'hygiene', effort: 'involved' },
  'spf-partial-coverage': { id: 'spf.partial-coverage', protocol: 'spf', severity: 'info', category: 'hygiene', effort: 'moderate' },
  'spf-redundant-mechanism': { id: 'spf.redundant-mechanism', protocol: 'spf', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'spf-redundant-mechanism-nocount': { id: 'spf.redundant-mechanism-nocount', protocol: 'spf', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'spf-indeterminate': { id: 'spf.indeterminate', protocol: 'spf', severity: 'info', category: 'authentication', effort: 'moderate', confidence: 'unverified' },

  // DKIM. The two "no usable DKIM" keys share one id (they are mutually
  // exclusive at runtime — the confidence ternary in issues.js picks one), so
  // cross-protocol rules can depend on `dkim.none-found` regardless of which fired.
  'dkim-missing': { id: 'dkim.none-found', protocol: 'dkim', severity: 'medium', category: 'authentication', effort: 'involved' },
  'dkim-unverified': { id: 'dkim.none-found', protocol: 'dkim', severity: 'medium', category: 'authentication', effort: 'involved', confidence: 'unverified' },
  'dkim-not-checked': { id: 'dkim.not-checked', protocol: 'dkim', severity: 'info', category: 'authentication', effort: 'trivial', confidence: 'unverified' },
  'dkim-multiple-records': { id: 'dkim.multiple-records', protocol: 'dkim', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dkim-key-weak': { id: 'dkim.key-weak', protocol: 'dkim', severity: 'critical', category: 'authentication', effort: 'moderate' },
  'dkim-key-1024': { id: 'dkim.key-1024', protocol: 'dkim', severity: 'info', category: 'hygiene', effort: 'moderate' },
  'dkim-key-not-email': { id: 'dkim.key-not-email', protocol: 'dkim', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'dkim-key-revoked': { id: 'dkim.key-revoked', protocol: 'dkim', severity: 'medium', category: 'authentication', effort: 'trivial' },
  'dkim-key-unparseable': { id: 'dkim.key-unparseable', protocol: 'dkim', severity: 'medium', category: 'authentication', effort: 'moderate' },
  'dkim-key-malformed': { id: 'dkim.key-malformed', protocol: 'dkim', severity: 'medium', category: 'authentication', effort: 'moderate' },
  'dkim-key-testing': { id: 'dkim.key-testing', protocol: 'dkim', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'dkim-key-sha1': { id: 'dkim.key-sha1', protocol: 'dkim', severity: 'medium', category: 'hygiene', effort: 'moderate' },
  'dkim-key-mixed': { id: 'dkim.mixed-key-strength', protocol: 'dkim', severity: 'low', category: 'hygiene', effort: 'moderate' },

  // DMARC.
  'dmarc-multiple-records': { id: 'dmarc.multiple-records', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-multiple-records-inherited': { id: 'dmarc.multiple-inherited', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-unverified': { id: 'dmarc.unverified', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'trivial', confidence: 'unverified' },
  'dmarc-missing': { id: 'dmarc.missing', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'moderate' },
  'dmarc-version-not-first': { id: 'dmarc.version-not-first', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-version-bad-value': { id: 'dmarc.version-bad-value', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-version-missing': { id: 'dmarc.version-missing', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-at-apex': { id: 'dmarc.at-apex', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-at-apex-ignored': { id: 'dmarc.at-apex-ignored', protocol: 'dmarc', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'dmarc-none': { id: 'dmarc.policy-none', protocol: 'dmarc', severity: 'high', category: 'policy', effort: 'moderate', dependsOn: ['spf.missing', 'dkim.none-found'] },
  'dmarc-quarantine': { id: 'dmarc.quarantine', protocol: 'dmarc', severity: 'info', category: 'policy', effort: 'moderate' },
  'dmarc-no-rua': { id: 'dmarc.no-rua', protocol: 'dmarc', severity: 'info', category: 'reporting', effort: 'trivial' },
  'dmarc-weak-sp': { id: 'dmarc.weak-sp', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'trivial' },
  'dmarc-weak-np': { id: 'dmarc.weak-np', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'trivial' },
  'dmarc-duplicate-tags': { id: 'dmarc.duplicate-tags', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-invalid-policy': { id: 'dmarc.invalid-policy', protocol: 'dmarc', severity: 'critical', category: 'policy', effort: 'trivial' },
  'dmarc-test-mode': { id: 'dmarc.test-mode', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'trivial' },
  'dmarc-bad-t': { id: 'dmarc.bad-t', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-bad-sp': { id: 'dmarc.bad-sp', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-bad-np': { id: 'dmarc.bad-np', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-bad-adkim': { id: 'dmarc.bad-adkim', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-bad-aspf': { id: 'dmarc.bad-aspf', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-np-not-applied': { id: 'dmarc.np-not-applied', protocol: 'dmarc', severity: 'info', category: 'policy', effort: 'trivial' },
  'dmarc-partial-pct': { id: 'dmarc.partial-pct', protocol: 'dmarc', severity: 'medium', category: 'policy', effort: 'trivial' },
  'dmarc-bad-pct': { id: 'dmarc.bad-pct', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-rua-invalid': { id: 'dmarc.rua-invalid', protocol: 'dmarc', severity: 'medium', category: 'reporting', effort: 'trivial' },
  'dmarc-ruf-invalid': { id: 'dmarc.ruf-invalid', protocol: 'dmarc', severity: 'medium', category: 'reporting', effort: 'trivial' },
  'dmarc-fo-without-ruf': { id: 'dmarc.fo-without-ruf', protocol: 'dmarc', severity: 'info', category: 'reporting', effort: 'trivial' },
  'dmarc-bad-fo': { id: 'dmarc.bad-fo', protocol: 'dmarc', severity: 'medium', category: 'reporting', effort: 'trivial' },
  'dmarc-external-override-mismatch': { id: 'dmarc.external-override-mismatch', protocol: 'dmarc', severity: 'medium', category: 'reporting', effort: 'moderate' },
  'dmarc-external-unauthorized': { id: 'dmarc.external-report-unauthorized', protocol: 'dmarc', severity: 'medium', category: 'reporting', effort: 'moderate' },
  'dmarc-external-unverifiable': { id: 'dmarc.external-unverifiable', protocol: 'dmarc', severity: 'info', category: 'reporting', effort: 'moderate', confidence: 'unverified' },
  'dmarc-external-reporting': { id: 'dmarc.external-reporting', protocol: 'dmarc', severity: 'info', category: 'reporting', effort: 'moderate', confidence: 'unverified' },
  'dmarc-report-destinations-truncated': { id: 'dmarc.report-truncated', protocol: 'dmarc', severity: 'info', category: 'reporting', effort: 'trivial' },
  'dmarc-bad-psd': { id: 'dmarc.bad-psd', protocol: 'dmarc', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'dmarc-removed-tags': { id: 'dmarc.removed-tags', protocol: 'dmarc', severity: 'info', category: 'hygiene', effort: 'trivial' },
  'dmarc-unknown-tags': { id: 'dmarc.unknown-tags', protocol: 'dmarc', severity: 'info', category: 'hygiene', effort: 'trivial' },

  // MTA-STS / TLS-RPT.
  'mta-sts-multiple-records': { id: 'mta-sts.multiple-records', protocol: 'mta-sts', severity: 'medium', category: 'transport', effort: 'trivial' },
  'mta-sts-invalid': { id: 'mta-sts.invalid', protocol: 'mta-sts', severity: 'medium', category: 'transport', effort: 'moderate' },
  'mta-sts-policy-unverified': { id: 'mta-sts.policy-unverified', protocol: 'mta-sts', severity: 'info', category: 'transport', effort: 'moderate', confidence: 'unverified' },
  'tls-rpt-multiple-records': { id: 'tls-rpt.multiple-records', protocol: 'tls-rpt', severity: 'medium', category: 'reporting', effort: 'trivial' },
  'tls-rpt-invalid': { id: 'tls-rpt.invalid', protocol: 'tls-rpt', severity: 'medium', category: 'reporting', effort: 'moderate' },

  // BIMI.
  'bimi-multiple-records': { id: 'bimi.multiple-records', protocol: 'bimi', severity: 'medium', category: 'issuance', effort: 'trivial' },
  'bimi-invalid': { id: 'bimi.invalid', protocol: 'bimi', severity: 'medium', category: 'issuance', effort: 'moderate' },

  // CAA.
  'caa-blocks-all-issuance': { id: 'caa.blocks-all-issuance', protocol: 'caa', severity: 'medium', category: 'issuance', effort: 'trivial' },
  'caa-unknown-critical-tag': { id: 'caa.unknown-critical-tag', protocol: 'caa', severity: 'medium', category: 'issuance', effort: 'trivial' },
  'caa-malformed': { id: 'caa.malformed', protocol: 'caa', severity: 'medium', category: 'issuance', effort: 'trivial' },
  'caa-no-iodef': { id: 'caa.no-iodef', protocol: 'caa', severity: 'info', category: 'issuance', effort: 'trivial' },
  'caa-single-issuer': { id: 'caa.single-issuer', protocol: 'caa', severity: 'info', category: 'issuance', effort: 'moderate' },

  // MX health.
  'mx-dangling': { id: 'mx.dangling', protocol: 'mx', severity: 'critical', category: 'transport', effort: 'moderate' },
  'mx-cname-target': { id: 'mx.cname-target', protocol: 'mx', severity: 'medium', category: 'transport', effort: 'moderate' },
  'mx-single-host': { id: 'mx.single-host', protocol: 'mx', severity: 'info', category: 'resilience', effort: 'moderate' },
  'mx-no-ipv6': { id: 'mx.no-ipv6', protocol: 'mx', severity: 'info', category: 'resilience', effort: 'moderate' },
  'mx-same-prefix': { id: 'mx.same-prefix', protocol: 'mx', severity: 'info', category: 'resilience', effort: 'moderate' },
  'mx-duplicate-preference': { id: 'mx.duplicate-preference', protocol: 'mx', severity: 'info', category: 'hygiene', effort: 'trivial' },

  // TLSA / DANE. `tlsa-published-unsigned` is the migrated per-host finding the
  // spec keeps instead of a cross-zone DNSSEC/DANE combination (§3).
  'tlsa-published-unsigned': { id: 'dane.published-unsigned', protocol: 'dane', severity: 'medium', category: 'transport', effort: 'involved' },
  'tlsa-malformed': { id: 'dane.malformed', protocol: 'dane', severity: 'medium', category: 'transport', effort: 'moderate' },
  'tlsa-partial-coverage': { id: 'dane.partial-coverage', protocol: 'dane', severity: 'info', category: 'transport', effort: 'moderate' },

  // DNSSEC.
  'dnssec-bogus': { id: 'dnssec.bogus', protocol: 'dnssec', severity: 'critical', category: 'resilience', effort: 'involved' },
  'dnssec-indeterminate': { id: 'dnssec.indeterminate', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'moderate', confidence: 'unverified' },
  'dnssec-mismatch': { id: 'dnssec.mismatch', protocol: 'dnssec', severity: 'critical', category: 'resilience', effort: 'involved' },
  'dnssec-unanchored': { id: 'dnssec.unanchored', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'involved' },
  'dnssec-ds-orphan': { id: 'dnssec.ds-orphan', protocol: 'dnssec', severity: 'info', category: 'hygiene', effort: 'moderate' },
  'dnssec-deprecated-algorithm': { id: 'dnssec.deprecated-algorithm', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'involved' },
  'dnssec-deprecated-digest': { id: 'dnssec.deprecated-digest', protocol: 'dnssec', severity: 'info', category: 'hygiene', effort: 'moderate' },
  'dnssec-key-algorithm-ineligible': { id: 'dnssec.key-algorithm-ineligible', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'involved' },
  'dnssec-key-not-zone-key': { id: 'dnssec.key-not-zone-key', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'involved' },
  'dnssec-key-malformed': { id: 'dnssec.key-malformed', protocol: 'dnssec', severity: 'medium', category: 'resilience', effort: 'involved' },
  'dnssec-revoke-flag': { id: 'dnssec.revoke-flag', protocol: 'dnssec', severity: 'info', category: 'hygiene', effort: 'moderate' },
};

/* ── Evidence derivation ─────────────────────────────────────────────────
 *
 * Central rather than per-entry: evidence is the raw DNS material a finding
 * rests on, and it is keyed by protocol off the same context the finding was
 * derived from. Every finding names at least one evidence entry (acceptance
 * criterion 1); an absence finding names what was queried and found empty. No
 * record is re-parsed here — the values are the ones owners already returned.
 * ──────────────────────────────────────────────────────────────────────── */
function migratedEvidence(finding, ctx) {
  var adv = ctx.advanced || {};
  var q = function (kind, queryName, value) { return { kind: kind, queryName: queryName, value: value || '' }; };
  switch (finding.protocol) {
    case 'spf':
      return ctx.spfRecord
        ? [q('txt', ctx.domain, ctx.spfRecord)]
        : [q('absent', ctx.domain, '')];
    case 'dmarc':
      return ctx.dmarcRecord
        ? [q('txt', '_dmarc.' + (ctx.dmarcAtDomain || ctx.domain), ctx.dmarcRecord)]
        : [q('absent', '_dmarc.' + ctx.domain, '')];
    case 'dkim': {
      var sels = (ctx.dkimStatus && ctx.dkimStatus.selectors) || [];
      if (sels.length) return sels.slice(0, 4).map(function (s) { return q('selector', s.queryName || s.sel, s.value); });
      return [q('absent', '_domainkey.' + ctx.domain, '')];
    }
    case 'mx': {
      var hosts = (adv.mxHealth && adv.mxHealth.hosts) || [];
      if (hosts.length) return hosts.slice(0, 4).map(function (h) { return q('host', ctx.domain, h.preference + ' ' + h.host); });
      return (ctx.mx || []).length ? [q('mx', ctx.domain, String((ctx.mx || []).length) + ' MX')] : [q('absent', ctx.domain, '')];
    }
    case 'caa':
      return [q('caa', (adv.caa && adv.caa.atDomain) || ctx.domain, ((adv.caa && adv.caa.records) || []).join(' '))];
    case 'dnssec':
      return [q('dnssec', ctx.domain, (adv.dnssec && adv.dnssec.state) || '')];
    case 'dane': {
      var th = (adv.tlsa && adv.tlsa.hosts) || [];
      return th.length ? th.slice(0, 4).map(function (h) { return q('tlsa', h.host, h.present ? 'published' : 'absent'); }) : [q('tlsa', ctx.domain, '')];
    }
    case 'bimi':
      return [q('txt', 'default._bimi.' + ctx.domain, (adv.bimi && adv.bimi.record) || '')];
    case 'mta-sts':
      return [q('txt', '_mta-sts.' + ctx.domain, (adv.mtaSts && adv.mtaSts.record) || '')];
    case 'tls-rpt':
      return [q('txt', '_smtp._tls.' + ctx.domain, (adv.tlsRpt && adv.tlsRpt.record) || '')];
    case 'dns':
    default:
      return [q('info', ctx.domain, '')];
  }
}

/* ── Confidence derivation ───────────────────────────────────────────────
 * A finding's confidence is the META override where given, else `confirmed`.
 * The override captures the two signals the spec names: a finding resting on a
 * failed lookup (`unverified`) and one resting on a heuristic (`probable`).
 * ──────────────────────────────────────────────────────────────────────── */
function migratedConfidence(meta) {
  return meta.confidence || 'confirmed';
}

/* ── Cross-protocol rules: the findings no single check can see (§3) ──────
 *
 * Each `when` is a pure predicate over the completed context. `evidence` names
 * the material; `blocks`/`dependsOn` wire it into the remediation graph. Every
 * id here is new `finding.*` material and collides with no migrated `issue.*` id.
 * ──────────────────────────────────────────────────────────────────────── */
function dmarcEnforcing(ctx) {
  return !!(ctx.dmarcStatus && ctx.dmarcStatus.enforcing);
}
function noUsableDkim(ctx) {
  return !!(ctx.dkimStatus && !ctx.dkimStatus.found);
}
function spfAbsent(ctx) {
  return !!(ctx.spfStatus && (ctx.spfStatus.status === 'missing' || ctx.spfStatus.status === 'permerror'));
}
function ev(kind, queryName, value) { return { kind: kind, queryName: queryName, value: value || '' }; }

export const CROSS_PROTOCOL_RULES = [
  {
    id: 'dmarc.enforcement-without-auth', key: 'dmarc-enforcement-without-auth',
    protocol: 'dmarc', severity: 'critical', category: 'authentication', effort: 'moderate',
    dependsOn: ['spf.missing', 'dkim.none-found'],
    when: function (ctx) { return dmarcEnforcing(ctx) && (spfAbsent(ctx) || noUsableDkim(ctx)); },
    evidence: function (ctx) { return [ev('txt', '_dmarc.' + (ctx.dmarcAtDomain || ctx.domain), ctx.dmarcRecord)]; },
  },
  {
    id: 'mx.dangling-with-enforcement', key: 'mx-dangling-with-enforcement',
    protocol: 'mx', severity: 'critical', category: 'transport', effort: 'moderate',
    when: function (ctx) {
      var mh = ctx.advanced && ctx.advanced.mxHealth;
      return dmarcEnforcing(ctx) && !!(mh && mh.danglingHosts && mh.danglingHosts.length);
    },
    evidence: function (ctx) {
      return (ctx.advanced.mxHealth.danglingHosts || []).slice(0, 4).map(function (h) { return ev('host', ctx.domain, h); });
    },
    args: function (ctx) { return [ctx.advanced.mxHealth.danglingHosts.join(', ')]; },
  },
  {
    id: 'dkim.weak-with-enforcement', key: 'dkim-weak-with-enforcement',
    protocol: 'dkim', severity: 'high', category: 'authentication', effort: 'moderate',
    when: function (ctx) {
      if (!dmarcEnforcing(ctx)) return false;
      var sels = (ctx.dkimStatus && ctx.dkimStatus.selectors) || [];
      return sels.some(function (s) { return s.key && s.key.keyType === 'rsa' && typeof s.key.keyBits === 'number' && s.key.keyBits <= 1024; });
    },
    evidence: function (ctx) {
      return (ctx.dkimStatus.selectors || []).filter(function (s) { return s.key && s.key.keyType === 'rsa' && s.key.keyBits <= 1024; })
        .slice(0, 4).map(function (s) { return ev('selector', s.queryName || s.sel, s.sel + ' (' + s.key.keyBits + ')'); });
    },
    args: function (ctx) {
      return [(ctx.dkimStatus.selectors || []).filter(function (s) { return s.key && s.key.keyType === 'rsa' && s.key.keyBits <= 1024; })
        .map(function (s) { return s.sel + ' (' + s.key.keyBits + ')'; }).join(', ')];
    },
  },
  {
    id: 'bimi.without-enforcement', key: 'bimi-without-enforcement',
    protocol: 'bimi', severity: 'medium', category: 'issuance', effort: 'moderate',
    dependsOn: ['dmarc.policy-none'],
    when: function (ctx) {
      var b = ctx.advanced && ctx.advanced.bimi;
      var d = ctx.dmarcStatus;
      return !!(b && b.present) && !!d && (d.effectivePolicy === 'none' || d.testMode === true);
    },
    evidence: function (ctx) { return [ev('txt', 'default._bimi.' + ctx.domain, ctx.advanced.bimi.record)]; },
  },
  {
    id: 'bimi.without-authority', key: 'bimi-without-authority',
    protocol: 'bimi', severity: 'low', category: 'issuance', effort: 'involved',
    when: function (ctx) {
      var b = ctx.advanced && ctx.advanced.bimi;
      var hasAuthority = !!(b && b.validation && b.validation.authority);
      return !!(b && b.present) && !hasAuthority && dmarcEnforcing(ctx);
    },
    evidence: function (ctx) { return [ev('txt', 'default._bimi.' + ctx.domain, ctx.advanced.bimi.record)]; },
  },
  {
    id: 'mta-sts.without-tls-rpt', key: 'mta-sts-without-tls-rpt',
    protocol: 'mta-sts', severity: 'low', category: 'reporting', effort: 'trivial',
    when: function (ctx) {
      var a = ctx.advanced || {};
      return !!(a.mtaSts && a.mtaSts.present) && !(a.tlsRpt && a.tlsRpt.present) && !(a.tlsRpt && a.tlsRpt.unknown);
    },
    evidence: function (ctx) { return [ev('txt', '_mta-sts.' + ctx.domain, ctx.advanced.mtaSts.record)]; },
  },
  {
    id: 'tls-rpt.without-transport-policy', key: 'tls-rpt-without-transport-policy',
    protocol: 'tls-rpt', severity: 'info', category: 'transport', effort: 'moderate',
    when: function (ctx) {
      var a = ctx.advanced || {};
      if (!(a.tlsRpt && a.tlsRpt.present)) return false;
      if (a.mtaSts && a.mtaSts.present) return false;
      var hosts = (a.tlsa && a.tlsa.hosts) || [];
      var anyAuthenticated = hosts.some(function (h) { return h.authenticated === true; });
      return !anyAuthenticated;
    },
    evidence: function (ctx) { return [ev('txt', '_smtp._tls.' + ctx.domain, ctx.advanced.tlsRpt.record)]; },
  },
  {
    id: 'spf.redundant-with-enforcement', key: 'spf-redundant-with-enforcement',
    protocol: 'spf', severity: 'medium', category: 'hygiene', effort: 'involved',
    when: function (ctx) {
      if (!dmarcEnforcing(ctx)) return false;
      var subs = (ctx.advanced && ctx.advanced.spfSubnets && ctx.advanced.spfSubnets.subnets) || [];
      return subs.some(function (s) { return s.severity === 'HIGH'; });
    },
    evidence: function (ctx) {
      return (ctx.advanced.spfSubnets.subnets || []).filter(function (s) { return s.severity === 'HIGH'; })
        .slice(0, 4).map(function (s) { return ev('mechanism', ctx.domain, s.mechanism); });
    },
    args: function (ctx) {
      return [(ctx.advanced.spfSubnets.subnets || []).filter(function (s) { return s.severity === 'HIGH'; })
        .map(function (s) { return s.mechanism; }).join(', ')];
    },
  },
  {
    id: 'defensive.contradictory', key: 'defensive-contradictory',
    protocol: 'defensive', severity: 'medium', category: 'hygiene', effort: 'trivial',
    when: function (ctx) {
      var nullMx = ctx.emailProvider === '@null-mx';
      if (!nullMx) return false;
      var permissive = ctx.spfStatus && (ctx.spfStatus.warnings || []).some(function (w) { return w === 'spf-all-permit' || w === 'spf-neutral'; });
      return !!(permissive || ctx.spfUsesMx);
    },
    evidence: function (ctx) { return [ev('txt', ctx.domain, ctx.spfRecord)]; },
  },
  {
    id: 'reporting.blind', key: 'reporting-blind',
    protocol: 'reporting', severity: 'medium', category: 'reporting', effort: 'trivial',
    when: function (ctx) {
      var a = ctx.advanced || {};
      var noRua = !(ctx.dmarcStatus && ctx.dmarcStatus.rua);
      var noTlsRpt = !(a.tlsRpt && a.tlsRpt.present);
      return noRua && noTlsRpt;
    },
    evidence: function (ctx) { return [ev('absent', '_dmarc.' + ctx.domain, '')]; },
  },
];

/* ── Assembly ────────────────────────────────────────────────────────────
 *
 * Run the untouched issue builder, enrich each into a Finding, evaluate the
 * cross-protocol rules, then resolve the dependency graph against the fired set:
 * drop `dependsOn` edges pointing at findings that did not fire, and derive
 * `blocks` as the inverse (RQ-FIND-07).
 * ──────────────────────────────────────────────────────────────────────── */
export function buildFindings(ctx) {
  var issues = buildIssues(ctx);
  var findings = [];

  issues.forEach(function (issue) {
    var meta = FINDING_META[issue.key];
    // Total over any legacy key: an unknown key (a mutation-invented token, or
    // a future issue whose META entry has not landed) is skipped rather than
    // thrown on, so the layer never destabilizes a build. The invariant suite
    // proves the table is complete for the real vocabulary.
    if (!meta) return;
    findings.push({
      id: meta.id,
      key: issue.key,
      keyspace: 'issue',
      protocol: meta.protocol,
      severity: meta.severity,
      confidence: migratedConfidence(meta),
      category: meta.category,
      effort: meta.effort,
      evidence: migratedEvidence(meta, ctx),
      args: issue.args || [],
      noteKey: issue.noteKey,
      noteArgs: issue.noteArgs,
      dependsOn: (meta.dependsOn || []).slice(),
      blocks: [],
    });
  });

  CROSS_PROTOCOL_RULES.forEach(function (rule) {
    var fired = false;
    try { fired = rule.when(ctx); } catch (e) { fired = false; }
    if (!fired) return;
    findings.push({
      id: rule.id,
      key: rule.key,
      keyspace: 'finding',
      protocol: rule.protocol,
      severity: rule.severity,
      confidence: rule.confidence ? rule.confidence(ctx) : 'confirmed',
      category: rule.category,
      effort: rule.effort,
      evidence: rule.evidence ? rule.evidence(ctx) : [],
      args: rule.args ? rule.args(ctx) : [],
      dependsOn: (rule.dependsOn || []).slice(),
      blocks: [],
    });
  });

  // Resolve the graph against the fired id set.
  var firedIds = {};
  findings.forEach(function (f) { firedIds[f.id] = true; });
  findings.forEach(function (f) {
    f.dependsOn = f.dependsOn.filter(function (dep) { return firedIds[dep] && dep !== f.id; });
  });
  // Derive `blocks` as the inverse of the resolved `dependsOn`.
  var byId = {};
  findings.forEach(function (f) { if (!byId[f.id]) byId[f.id] = []; byId[f.id].push(f); });
  findings.forEach(function (f) {
    f.dependsOn.forEach(function (dep) {
      (byId[dep] || []).forEach(function (target) {
        if (target.blocks.indexOf(f.id) === -1) target.blocks.push(f.id);
      });
    });
  });

  return findings;
}

/* ── Remediation plan (§4) ───────────────────────────────────────────────
 *
 * A topological sort of the dependency graph. Findings at the same depth are one
 * step; within a step they are ordered by severity then effort — tokens, never
 * translated strings, so the plan is byte-identical across all fourteen locales
 * (§6). The ordering rule that matters: a finding is never placed before a
 * finding it depends on, so enforcement is never advised before authentication.
 * ──────────────────────────────────────────────────────────────────────── */
export function buildRemediationPlan(findings) {
  if (!findings.length) return [];

  // Collapse to one node per fired id; a finding's depth is 1 + max(depth of its
  // dependencies). Unresolved edges were already dropped in buildFindings, so
  // every dependency named here is present, and the graph is acyclic by invariant.
  var present = {};
  findings.forEach(function (f) { present[f.id] = f; });

  var depthCache = {};
  function depthOf(id, seen) {
    if (depthCache[id] !== undefined) return depthCache[id];
    seen = seen || {};
    if (seen[id]) return 0; // cycle guard; the invariant test forbids cycles
    seen[id] = true;
    var f = present[id];
    var deps = (f && f.dependsOn) || [];
    var d = 0;
    deps.forEach(function (dep) {
      if (present[dep]) d = Math.max(d, depthOf(dep, seen) + 1);
    });
    depthCache[id] = d;
    return d;
  }

  var maxDepth = 0;
  var byDepth = {};
  // One entry per distinct id, so two findings sharing an id (never happens at
  // runtime, but the loop is defensive) do not double-list.
  var seenId = {};
  findings.forEach(function (f) {
    if (seenId[f.id]) return;
    seenId[f.id] = true;
    var d = depthOf(f.id);
    if (d > maxDepth) maxDepth = d;
    (byDepth[d] = byDepth[d] || []).push(f);
  });

  var steps = [];
  for (var d = 0; d <= maxDepth; d++) {
    var group = byDepth[d] || [];
    if (!group.length) continue;
    group.sort(function (a, b) {
      var s = (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
      if (s) return s;
      var e = (EFFORT_RANK[a.effort] || 0) - (EFFORT_RANK[b.effort] || 0);
      if (e) return e;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    var ids = group.map(function (f) { return f.id; });
    // What this step unblocks: findings one depth deeper that depend on an id here.
    var unblocks = [];
    (byDepth[d + 1] || []).forEach(function (f) {
      if (f.dependsOn.some(function (dep) { return ids.indexOf(dep) !== -1; })) unblocks.push(f.id);
    });
    steps.push({
      step: steps.length + 1,
      findings: ids,
      // A token, resolved by the UI as `findings.rationale.<token>`; never a
      // translated string, so the plan is byte-identical across all locales (§6).
      rationale: d === 0 ? 'foundation' : 'afterPrereq',
      unblocks: unblocks,
    });
  }
  return steps;
}
