/**
 * Structured findings and the remediation plan. Spec: findings-and-remediation
 * 1.4 (Final), §1–§4.
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
import { tlsaPresentation } from '../core/transport/tlsa.js';

/* ── Closed vocabularies ─────────────────────────────────────────────────
 *
 * Each is a reviewed closed algebra in `tests/state-algebras.json`
 * (`audit.finding.severity` and its siblings), so the `state-matrix.test.mjs`
 * §3 scan MATCHES these exported constants against the registry rather than
 * skipping them, and coverage over the `findings[].*` result paths is checked.
 * `findings.test.js` also pins `audit.finding.id` against the ids these
 * structures produce, the same drift guard `audit.issue.key` carries.
 * ──────────────────────────────────────────────────────────────────────── */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const CONFIDENCES = ['confirmed', 'probable', 'unverified'];
export const CATEGORIES = ['authentication', 'policy', 'reporting', 'transport',
  'issuance', 'resilience', 'hygiene'];
export const EFFORTS = ['trivial', 'moderate', 'involved'];
export const PROTOCOLS = ['spf', 'dkim', 'dmarc', 'dnssec', 'caa', 'mta-sts',
  'tls-rpt', 'bimi', 'mx', 'dane', 'dns', 'defensive', 'reporting'];
export const KEYSPACES = ['issue', 'finding'];
export const RATIONALES = ['foundation', 'afterPrereq', 'cleanup'];

/**
 * The evidence kinds this module produces, and it is CLOSED by construction:
 * every entry is built by the two local helpers below, so the set is exactly
 * what this file writes. Registered as `audit.finding.evidence.kind`.
 *
 * `absent` is the honest form of an absence — a name that was queried and had
 * nothing — and carries an empty value by design (spec §1, amendment 1.2).
 * `info` is the one non-record kind: it carries a finding's own protocol-token
 * arguments, used by `dns.checks-unverified` to name the checks that could not
 * run. Everything else is published DNS material.
 */
export const EVIDENCE_KINDS = ['txt', 'absent', 'selector', 'host', 'mx',
  'address', 'cname', 'caa', 'dnssec', 'tlsa', 'mechanism', 'info'];

const EVIDENCE_KIND_SET = EVIDENCE_KINDS.reduce(function (set, k) { set[k] = true; return set; }, {});

/**
 * The ONE constructor for an evidence entry, and the thing that makes
 * `audit.finding.evidence.kind` closed by CONSTRUCTION rather than by a scan
 * that happens to have swept every branch.
 *
 * An unregistered kind is coerced to `info` rather than thrown: a finding
 * builder that throws takes down the whole audit row, and a mislabelled piece
 * of evidence is not worth that. The co-located suite asserts the coercion
 * never fires in practice — every call site's literal is in the enum, and the
 * enum has no dead members — so this is a floor, not a licence.
 */
export function evidenceEntry(kind, queryName, value) {
  return {
    kind: EVIDENCE_KIND_SET[kind] ? kind : 'info',
    queryName: queryName,
    value: value || '',
  };
}

function completeFields(values) {
  if (values.some(function (v) { return v === undefined || v === null || v === ''; })) return '';
  return values.join(' ');
}

function dsPresentation(record) {
  return completeFields([record.keyTag, record.algorithm, record.digestType, record.digest]);
}

function dnskeyPresentation(record) {
  return completeFields([record.flags, record.protocol, record.algorithm, record.publicKey]);
}

function findingTags(finding) {
  return String((finding.args && finding.args[0]) || '').split(',')
    .map(function (v) { return v.trim(); }).filter(Boolean);
}

function dnssecEvidence(finding, ctx) {
  var dnssec = (ctx.advanced && ctx.advanced.dnssec) || {};
  var ds = dnssec.ds || [];
  var keys = dnssec.keys || [];
  var tags = findingTags(finding);
  var hasTag = function (record) { return !tags.length || tags.indexOf(String(record.keyTag)) !== -1; };
  var selectedDs = [];
  var selectedKeys = [];

  switch (finding.id) {
    case 'dnssec.mismatch':
      selectedDs = ds.filter(function (r) { return r.match === 'digest-mismatch'; });
      break;
    case 'dnssec.ds-orphan':
      selectedDs = ds.filter(function (r) { return hasTag(r); });
      break;
    case 'dnssec.deprecated-digest':
      selectedDs = ds.filter(function (r) { return r.deprecated; });
      break;
    case 'dnssec.deprecated-algorithm':
      selectedDs = ds.filter(function (r) { return r.deprecated; });
      selectedKeys = keys.filter(function (r) { return r.deprecated; });
      break;
    case 'dnssec.key-algorithm-ineligible':
      selectedKeys = keys.filter(function (r) { return hasTag(r) && r.algorithmEligibility === 'ineligible'; });
      break;
    case 'dnssec.key-not-zone-key':
      selectedKeys = keys.filter(function (r) { return hasTag(r) && r.hasZoneFlag === false; });
      break;
    case 'dnssec.key-malformed':
      selectedKeys = keys.filter(function (r) { return hasTag(r) && r.keyStructure === 'invalid'; });
      break;
    case 'dnssec.revoke-flag':
      selectedKeys = keys.filter(function (r) { return hasTag(r) && r.hasRevokeFlag; });
      break;
    default:
      selectedDs = ds;
      selectedKeys = keys;
  }

  var entries = selectedDs.map(function (r) {
    return evidenceEntry('dnssec', ctx.domain, dsPresentation(r));
  }).concat(selectedKeys.map(function (r) {
    return evidenceEntry('dnssec', ctx.domain, dnskeyPresentation(r));
  })).filter(function (e) { return e.value; }).slice(0, 4);

  return entries.length ? entries : [evidenceEntry('absent', ctx.domain, '')];
}

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
  'mx-unroutable': { id: 'mx.unroutable', protocol: 'mx', severity: 'critical', category: 'transport', effort: 'moderate' },
  'mx-partially-routable': { id: 'mx.partially-routable', protocol: 'mx', severity: 'medium', category: 'transport', effort: 'moderate' },
  'mx-address-literal': { id: 'mx.address-literal', protocol: 'mx', severity: 'critical', category: 'transport', effort: 'trivial' },
  'mx-null-conflict': { id: 'mx.null-conflict', protocol: 'mx', severity: 'medium', category: 'hygiene', effort: 'trivial' },
  'mx-invalid-preference': { id: 'mx.invalid-preference', protocol: 'mx', severity: 'info', category: 'hygiene', effort: 'trivial' },

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
  var q = evidenceEntry;

  // ── Finding-specific evidence, where the protocol-generic material would be
  // wrong or too coarse for the record that actually justified THIS finding. ──
  switch (finding.id) {
    case 'spf.multiple-records': {
      // The whole conflicting set, not one record — the count IS the evidence.
      var recs = (ctx.spfRecords && ctx.spfRecords.length) ? ctx.spfRecords : (ctx.spfRecord ? [ctx.spfRecord] : []);
      return recs.length ? recs.map(function (r) { return q('txt', ctx.domain, r); }) : [q('absent', ctx.domain, '')];
    }
    case 'dmarc.multiple-records':
    case 'dmarc.multiple-inherited': {
      // The DUPLICATE records the walk observed, at the name they are at —
      // never the applied record higher in the tree, which is a different fact.
      var dups = ((ctx.dmarcDiscovery && ctx.dmarcDiscovery.observed) || []).filter(function (o) { return o.why === 'multiple-at-step'; });
      return dups.length
        ? dups.map(function (o) { return q('txt', o.queryName || ('_dmarc.' + ctx.domain), o.record || ''); })
        : [q('absent', '_dmarc.' + ctx.domain, '')];
    }
    // The wildcard probes' SYNTHESIZED RECORDS, at the name that was probed.
    // The record is the evidence; an empty set falls back to naming the probe.
    case 'dns.wildcard-apex': {
      var apexName = '_wildcardtest99xyz.' + ctx.domain;
      var apexRecs = ctx.wildcardApexRecords || [];
      return apexRecs.length ? apexRecs.slice(0, 4).map(function (r) { return q('txt', apexName, String(r)); }) : [q('txt', apexName, '')];
    }
    case 'dns.wildcard-dkim': {
      var dkimName = '_wildcardtest99xyz._domainkey.' + ctx.domain;
      var dkimRecs = ctx.wildcardDkimRecords || [];
      return dkimRecs.length ? dkimRecs.slice(0, 4).map(function (r) { return q('txt', dkimName, String(r)); }) : [q('txt', dkimName, '')];
    }
    // The chain that closes the loop, host by host.
    case 'dns.hosting-loop': {
      var chain = ctx.websiteChain || [];
      return chain.length ? chain.slice(0, 8).map(function (h) { return q('cname', 'www.' + ctx.domain, String(h)); }) : [q('cname', 'www.' + ctx.domain, '')];
    }
    case 'dns.checks-unverified': {
      // One entry per control that could not be verified, each carrying that
      // control's bare protocol token. There IS no record to show — the lookups
      // are what failed — so `info` names which control is unproven rather than
      // a comma-joined presentation string standing in for evidence.
      var checks = String((finding.args && finding.args[0]) || '').split(', ').filter(Boolean);
      return checks.length ? checks.map(function (c) { return q('info', ctx.domain, c); }) : [q('info', ctx.domain, '')];
    }
    // An absence: the name that was queried, and nothing. The message says what
    // is missing; the evidence says where it was looked for.
    case 'mx.none':
      return [q('absent', ctx.domain, '')];
    // Implicit MX is selected only when NO MX record exists (providers/detectors),
    // so its evidence is that absence plus the A/AAAA records SMTP would fall
    // back to — the records that actually activate implicit delivery.
    case 'mx.implicit': {
      var addrs = (ctx.aRec || []).concat(ctx.aaaaRec || []);
      return [q('absent', ctx.domain, '')].concat(
        addrs.slice(0, 4).map(function (a) { return q('address', ctx.domain, String(a)); })
      );
    }
    // Both of these are defects in the RECORD, not in a host, and the
    // protocol-generic fallback below would show the resolved hosts instead —
    // which for a null-MX conflict means showing everything except the `0 .`
    // that is the whole finding. The raw records are the evidence.
    case 'mx.null-conflict':
    case 'mx.invalid-preference':
      return (ctx.mx && ctx.mx.length)
        ? ctx.mx.slice(0, 4).map(function (m) { return q('mx', ctx.domain, String(m)); })
        : [q('absent', ctx.domain, '')];
    case 'mx.porkbun-forwarding':
      return (ctx.mx && ctx.mx.length) ? ctx.mx.slice(0, 4).map(function (m) { return q('mx', ctx.domain, String(m)); }) : [q('absent', ctx.domain, '')];
  }

  // ── Protocol-generic fallback. ──
  switch (finding.protocol) {
    case 'spf':
      return ctx.spfRecord ? [q('txt', ctx.domain, ctx.spfRecord)] : [q('absent', ctx.domain, '')];
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
      return (ctx.mx && ctx.mx.length) ? ctx.mx.slice(0, 4).map(function (m) { return q('mx', ctx.domain, String(m)); }) : [q('absent', ctx.domain, '')];
    }
    case 'caa': {
      var caa = (adv.caa && adv.caa.records) || [];
      var caaName = (adv.caa && adv.caa.atDomain) || ctx.domain;
      return caa.length ? caa.slice(0, 4).map(function (r) { return q('caa', caaName, r); }) : [q('absent', caaName, '')];
    }
    // Complete DS or DNSKEY material selected for the finding — never the
    // classifier state, an incomplete DS, or a DS offered for a DNSKEY claim.
    case 'dnssec':
      return dnssecEvidence(finding, ctx);
    // A valid TLSA record is faithfully re-serialized from its wire fields. A
    // malformed one uses the presentation retained by its protocol owner,
    // because fields that did not parse cannot be reconstructed here.
    case 'dane': {
      var th = (adv.tlsa && adv.tlsa.hosts) || [];
      if (!th.length) return [q('absent', ctx.domain, '')];
      var out = [];
      th.slice(0, 4).forEach(function (h) {
        var recs = h.records || [];
        var queryName = h.queryName || ('_25._tcp.' + h.host);
        if (!recs.length) { out.push(q('absent', queryName, '')); return; }
        recs.slice(0, 2).forEach(function (r) {
          var value = r.valid
            ? completeFields([r.usage, r.selector, r.matchingType, r.data])
            : tlsaPresentation(r);
          out.push(value ? q('tlsa', queryName, value) : q('absent', queryName, ''));
        });
      });
      return out;
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
// SPF `missing`, never `permerror` (spec §3 amendment 1.1). A permerror is a
// BROKEN record, not a missing one: it raises its own critical finding
// (spf.multiple-records / spf.over-limit / spf.cycle), and this rule does not
// depend on those. Including permerror here fired the enforcement finding whose
// declared prerequisite `spf.missing` never fired, so the dropped edge left it
// unblocked in step 1 beside the broken-SPF finding — breaking the
// never-enforce-before-authentication guarantee this release exists to keep.
function spfMissing(ctx) {
  return !!(ctx.spfStatus && ctx.spfStatus.status === 'missing');
}
var ev = evidenceEntry;

export const CROSS_PROTOCOL_RULES = [
  {
    id: 'dmarc.enforcement-without-auth', key: 'dmarc-enforcement-without-auth',
    protocol: 'dmarc', severity: 'critical', category: 'authentication', effort: 'moderate',
    dependsOn: ['spf.missing', 'dkim.none-found'],
    when: function (ctx) { return dmarcEnforcing(ctx) && (spfMissing(ctx) || noUsableDkim(ctx)); },
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
    // The published key record itself, not "s1 (1024)" — that presentation form
    // is the message's job and it is already carried in `args` below.
    evidence: function (ctx) {
      return (ctx.dkimStatus.selectors || []).filter(function (s) { return s.key && s.key.keyType === 'rsa' && s.key.keyBits <= 1024; })
        .slice(0, 4).map(function (s) { return ev('selector', s.queryName || s.sel, s.value); });
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
/**
 * Every finding id this build can produce.
 *
 * Exposed so the interface can tell an id it knows from one it does not, and
 * say so: report-comparison 1.9 section 4 requires an unrecognized id to be
 * "displayed by id with a note that this build has no description for it,
 * rather than being dropped". `src/ui/` may not import this module, so the
 * catalog crosses the composition boundary as data, the same route the DKIM
 * selector grammar takes.
 */
export function findingCatalogIds() {
  var ids = Object.keys(FINDING_META).map(function (k) { return FINDING_META[k].id; })
    .concat(CROSS_PROTOCOL_RULES.map(function (r) { return r.id; }));
  return Object.keys(ids.reduce(function (set, id) { set[id] = true; return set; },
    Object.create(null))).sort();
}

export function buildFindings(ctx, issuesOverride) {
  // `issuesOverride` exists so the suite can feed a fabricated issue array —
  // including an unknown key — to exercise the skip branch directly. Production
  // and every ordinary caller pass one argument and get buildIssues(ctx).
  var issues = issuesOverride || buildIssues(ctx);
  var findings = [];

  issues.forEach(function (issue) {
    var meta = FINDING_META[issue.key];
    // Total over any legacy key: an unknown key (a mutation-invented token, or
    // a future issue whose META entry has not landed) is skipped rather than
    // thrown on, so the layer never destabilizes a build. The invariant suite
    // proves the table is complete for the real vocabulary.
    if (!meta) return;
    var f = {
      id: meta.id,
      key: issue.key,
      keyspace: 'issue',
      protocol: meta.protocol,
      severity: meta.severity,
      confidence: migratedConfidence(meta),
      category: meta.category,
      effort: meta.effort,
      args: issue.args || [],
      noteKey: issue.noteKey,
      noteArgs: issue.noteArgs,
      dependsOn: (meta.dependsOn || []).slice(),
      blocks: [],
    };
    // Evidence is computed from the finished finding so the id-specific cases
    // can read its `args` (e.g. dns.checks-unverified names its own checks).
    f.evidence = migratedEvidence(f, ctx);
    findings.push(f);
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

  // One node per distinct fired id (two findings never share an id at runtime,
  // but the reduction is defensive). Unresolved edges were dropped in
  // buildFindings, so every dependency named here is present; the graph is
  // acyclic by invariant.
  var present = {};
  var ids = [];
  findings.forEach(function (f) { if (!present[f.id]) { present[f.id] = f; ids.push(f.id); } });

  // An id "has a dependent" when another fired finding depends on it.
  var hasDependent = {};
  ids.forEach(function (id) {
    (present[id].dependsOn || []).forEach(function (dep) { if (present[dep]) hasDependent[dep] = true; });
  });

  // Isolated findings — no prerequisites AND no dependents — carry no ordering
  // constraint, so they gather in a single FINAL step (spec §4, amendment 1.1),
  // never in step 1 beside a blocking finding. Depth grouping governs only the
  // connected findings; a finding with dependencies but no dependents (e.g.
  // dmarc.enforcement-without-auth) is connected and stays at its depth.
  var connected = [];
  var isolated = [];
  ids.forEach(function (id) {
    var deps = (present[id].dependsOn || []).filter(function (d) { return present[d]; });
    if (deps.length === 0 && !hasDependent[id]) isolated.push(id);
    else connected.push(id);
  });

  var depthCache = {};
  function depthOf(id, seen) {
    if (depthCache[id] !== undefined) return depthCache[id];
    seen = seen || {};
    if (seen[id]) return 0; // cycle guard; the invariant test forbids cycles
    seen[id] = true;
    var deps = (present[id] && present[id].dependsOn) || [];
    var d = 0;
    deps.forEach(function (dep) { if (present[dep]) d = Math.max(d, depthOf(dep, seen) + 1); });
    depthCache[id] = d;
    return d;
  }

  var byDepth = {};
  var maxDepth = 0;
  connected.forEach(function (id) {
    var d = depthOf(id);
    if (d > maxDepth) maxDepth = d;
    (byDepth[d] = byDepth[d] || []).push(present[id]);
  });

  // Tokens, never translated strings, so the plan is byte-identical across all
  // fourteen locales (§6): severity, then effort, then id.
  var withinStep = function (a, b) {
    var s = (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
    if (s) return s;
    var e = (EFFORT_RANK[a.effort] || 0) - (EFFORT_RANK[b.effort] || 0);
    if (e) return e;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  };

  var steps = [];
  for (var d = 0; d <= maxDepth; d++) {
    var group = (byDepth[d] || []).slice();
    if (!group.length) continue;
    group.sort(withinStep);
    var stepIds = group.map(function (f) { return f.id; });
    // What this step unblocks: findings one depth deeper that depend on an id here.
    var unblocks = [];
    (byDepth[d + 1] || []).forEach(function (f) {
      if (f.dependsOn.some(function (dep) { return stepIds.indexOf(dep) !== -1; })) unblocks.push(f.id);
    });
    steps.push({
      step: steps.length + 1,
      findings: stepIds,
      rationale: d === 0 ? 'foundation' : 'afterPrereq',
      unblocks: unblocks,
    });
  }

  // The final step collects the isolated findings, where hygiene gathers.
  if (isolated.length) {
    var isoGroup = isolated.map(function (id) { return present[id]; }).sort(withinStep);
    steps.push({
      step: steps.length + 1,
      findings: isoGroup.map(function (f) { return f.id; }),
      rationale: 'cleanup',
      unblocks: [],
    });
  }

  return steps;
}
