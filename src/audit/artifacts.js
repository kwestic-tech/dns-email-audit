/**
 * The cross-protocol composer for user-supplied artifacts.
 *
 * Two protocol owners validate the material — `core/transport/mta-sts-policy.js`
 * for a policy body, `core/bimi/svg.js` for an indicator SVG — and neither may
 * import the other or emit a finding. This module is the only place their
 * results meet, and the only place artifact findings are constructed.
 *
 * ── Three boundaries this file exists to hold ────────────────────────────
 *
 * 1. **Artifact findings never merge into the DNS findings array.** They are
 *    returned separately, they carry `source: 'user-supplied'`, and their
 *    evidence uses its own `kind` vocabulary. The DNS-only
 *    `audit.finding.evidence.kind` algebra and its `queryName` contract are
 *    untouched: a line of pasted text was not queried from DNS and must never
 *    render as though it were.
 * 2. **Nothing here fetches anything.** No policy URL, no `l=` URL, no `a=`
 *    URL, no proxy. The validators are pure and this composer holds no
 *    capability that could reach the network.
 * 3. **Nothing here scores.** `calcScore()` never sees an artifact finding, so
 *    a public-DNS grade stays reproducible from public DNS.
 *
 * ── Delivery candidates are not MX records ───────────────────────────────
 *
 * The MX cross-check is the release's headline, and the fact it compares
 * against is the domain's DELIVERY CANDIDATES. RFC 5321 §5.1: "If an empty
 * list of MXs is returned, the address is treated as if it was associated with
 * an implicit MX RR, with a preference of 0, pointing to that host", and that
 * rule "applies only if there are no MX records present". So a domain with no
 * MX and a usable address record has exactly one candidate — itself — and a
 * policy naming it is correct rather than stale.
 *
 * `advanced.mxHealth` is deliberately NOT the source: its `hosts` are audit
 * objects rather than names, and it is `null` whenever deep checks are off,
 * which the interface does above 50 domains. See `core/transport/API.md`.
 */

import {
  validateMtaStsPolicy, compareMtaStsMx, policyFindingScope,
} from '../core/transport/mta-sts-policy.js';
import { validateBimiSvg } from '../core/bimi/svg.js';
import { isNullMx, parseMxRecord } from '../core/mx/mx.js';

/** Every artifact kind this release accepts. VMC is not one — see the spec. */
export const ARTIFACT_KINDS = Object.freeze(['mta-sts-policy', 'bimi-svg']);

/**
 * Provenance. One member today, and it is still a closed vocabulary rather
 * than a boolean: the reason a finding is separated from DNS findings is that
 * somebody supplied it, and that reason has to be nameable in an export.
 */
export const ARTIFACT_SOURCES = Object.freeze(['user-supplied']);

/**
 * Artifact evidence kinds, and they are NOT the DNS ones. A `line` is a line
 * of a pasted document, an `element` is a node name from a parsed tree, and
 * `input` is the artifact as a whole — what a document-level error like a
 * missing field is located by.
 */
export const ARTIFACT_EVIDENCE_KINDS = Object.freeze(['line', 'element', 'input']);

/** How much supplied material any one evidence entry may carry into a report. */
export const MAX_EVIDENCE_CHARS = 200;

const KIND_SET = ARTIFACT_EVIDENCE_KINDS.reduce(function (set, k) { set[k] = true; return set; }, {});

/**
 * The ONE constructor for artifact evidence, so the kind vocabulary is closed
 * by construction rather than by a scan that happened to sweep every branch —
 * the same rule `findings.js` holds for DNS evidence.
 *
 * The value is bounded here rather than in the renderer. This material is
 * attacker-influenced when a third party's artifact is being audited, and it
 * travels into the CSV and the HTML report; a cap at the source is one fewer
 * place for it to arrive unbounded.
 */
function bounded(value) {
  // Code POINTS, not UTF-16 indexes. `.slice(0, 200)` through an astral
  // character leaves a lone high surrogate, and `tools/export.test.mjs` §10
  // exists because that has already been a defect in this project once. A
  // bound applied at the source must not manufacture malformed Unicode before
  // the renderer or the export sees it.
  var points = Array.from(String(value == null ? '' : value));
  return points.length > MAX_EVIDENCE_CHARS
    ? points.slice(0, MAX_EVIDENCE_CHARS).join('') : points.join('');
}

export function artifactEvidence(kind, location, value) {
  return {
    kind: KIND_SET[kind] ? kind : 'input',
    location: bounded(location),
    value: bounded(value),
  };
}

/**
 * Every artifact finding id, frozen and exported.
 *
 * `audit.finding.id` is the DNS contract and stays narrow; this is its
 * artifact counterpart, and it is a closed algebra for the same reason: the
 * catalog below constructs every published id, so an unregistered table would
 * be twelve identities drifting outside the guard every other vocabulary in
 * this repository has. The co-located suite pins the catalog against it.
 */
export const ARTIFACT_FINDING_IDS = Object.freeze([
  'mta-sts.policy-invalid',
  'mta-sts.policy-hygiene',
  'mta-sts.policy-mx-mismatch',
  'mta-sts.policy-mx-unused',
  'mta-sts.policy-on-null-mx',
  'mta-sts.policy-mx-unknown',
  'mta-sts.mode-testing',
  'mta-sts.mode-none',
  'mta-sts.max-age-short',
  'bimi.svg-rejected',
  'bimi.svg-profile',
  'bimi.svg-valid',
]);

/* ── The finding catalog ──────────────────────────────────────────────────
 *
 * Same metadata shape as `findings.js`'s DNS catalog so the existing renderer
 * can present these, but a separate table: an artifact finding is not a DNS
 * finding with a flag on it, and merging the catalogs would be the first step
 * toward merging the arrays. */
const ARTIFACT_FINDINGS = Object.freeze({
  // MTA-STS policy body.
  'mta-sts-policy-invalid': {
    id: 'mta-sts.policy-invalid', protocol: 'mta-sts',
    severity: 'high', category: 'transport', effort: 'moderate',
  },
  'mta-sts-policy-hygiene': {
    id: 'mta-sts.policy-hygiene', protocol: 'mta-sts',
    severity: 'info', category: 'hygiene', effort: 'trivial',
  },
  'mta-sts-policy-mx-mismatch': {
    id: 'mta-sts.policy-mx-mismatch', protocol: 'mta-sts',
    severity: 'critical', category: 'transport', effort: 'moderate',
  },
  'mta-sts-policy-mx-unused': {
    id: 'mta-sts.policy-mx-unused', protocol: 'mta-sts',
    severity: 'medium', category: 'transport', effort: 'moderate',
  },
  'mta-sts-policy-on-null-mx': {
    id: 'mta-sts.policy-on-null-mx', protocol: 'mta-sts',
    severity: 'medium', category: 'transport', effort: 'moderate',
  },
  'mta-sts-policy-mx-unknown': {
    id: 'mta-sts.policy-mx-unknown', protocol: 'mta-sts',
    severity: 'info', category: 'transport', effort: 'moderate',
    confidence: 'unverified',
  },
  'mta-sts-mode-testing': {
    id: 'mta-sts.mode-testing', protocol: 'mta-sts',
    severity: 'medium', category: 'transport', effort: 'trivial',
  },
  'mta-sts-mode-none': {
    id: 'mta-sts.mode-none', protocol: 'mta-sts',
    severity: 'high', category: 'transport', effort: 'trivial',
  },
  'mta-sts-max-age-short': {
    id: 'mta-sts.max-age-short', protocol: 'mta-sts',
    severity: 'medium', category: 'transport', effort: 'trivial',
  },
  // BIMI indicator SVG.
  'bimi-svg-rejected': {
    id: 'bimi.svg-rejected', protocol: 'bimi',
    severity: 'high', category: 'issuance', effort: 'moderate',
  },
  'bimi-svg-profile': {
    id: 'bimi.svg-profile', protocol: 'bimi',
    severity: 'medium', category: 'issuance', effort: 'moderate',
  },
  'bimi-svg-valid': {
    id: 'bimi.svg-valid', protocol: 'bimi',
    severity: 'info', category: 'issuance', effort: 'trivial',
  },
});

/** RFC 8461 §8.3's removal procedure publishes a small max_age on purpose. */
const SHORT_MAX_AGE = 86400;

function finding(key, artifact, args, evidence) {
  var meta = ARTIFACT_FINDINGS[key];
  if (!meta) return null;
  return {
    id: meta.id,
    key: key,
    keyspace: 'finding',
    protocol: meta.protocol,
    severity: meta.severity,
    confidence: meta.confidence || 'confirmed',
    category: meta.category,
    effort: meta.effort,
    args: args || [],
    noteKey: undefined,
    noteArgs: undefined,
    dependsOn: [],
    blocks: [],
    source: 'user-supplied',
    artifact: artifact,
    evidence: evidence || [],
  };
}

/**
 * The domain's delivery candidates, as a fact `compareMtaStsMx()` can use.
 *
 * Takes `{ mx, addresses, domain, unknown }`. `mx` is the raw MX record set
 * from the base lookup — presentation strings like `10 mail.example.com`, not
 * the deep-check audit objects. `addresses` is whatever A/AAAA answers the
 * audit already holds, and it decides only whether an implicit MX exists.
 */
export function deliveryCandidates(input) {
  var supplied = input || {};
  if (supplied.unknown) return { hosts: [], unknown: true };

  var records = Array.isArray(supplied.mx) ? supplied.mx : [];
  if (isNullMx(records)) return { hosts: [], nullMx: true };

  if (records.length) {
    var hosts = [];
    for (var i = 0; i < records.length; i++) {
      var parsed = parseMxRecord(records[i]);
      // Fail closed on ANY unparseable record. A partially read MX set cannot
      // tell a stale policy pattern from an unread one, so half an answer is
      // worse than no answer: it would be reported with confidence.
      if (!parsed || !parsed.host) return { hosts: [], unknown: true };
      if (hosts.indexOf(parsed.host) === -1) hosts.push(parsed.host);
    }
    return { hosts: hosts, unknown: false };
  }

  // RFC 5321 §5.1: no MX and a usable address record means one implicit
  // candidate, the domain itself. No address record means no candidate at all.
  var addrs = Array.isArray(supplied.addresses) ? supplied.addresses.filter(Boolean) : [];
  var domain = String(supplied.domain == null ? '' : supplied.domain).trim().toLowerCase();
  if (addrs.length && domain) return { hosts: [domain], unknown: false, implicit: true };
  return { hosts: [], unknown: true };
}

/** Convert one validated MTA-STS policy body into artifact findings. */
export function mtaStsPolicyFindings(text, mxFact) {
  var policy = validateMtaStsPolicy(text);
  var scope = policyFindingScope(policy);
  var out = [];

  /**
   * One evidence entry per DIAGNOSTIC OCCURRENCE, carrying the offending line
   * itself as the value.
   *
   * Two things were wrong before. The value was the diagnostic TOKEN, but the
   * token is already the finding's `args` — spec §5 defines `value` as "the
   * bounded user-supplied material that caused it", and an operator cannot act
   * on `blank-line` without being shown which line. And occurrences were
   * grouped by token and then read `lines[0]`, so two blank lines both pointed
   * at the first.
   *
   * A `missing-*` error is raised against the document and has no diagnostic
   * entry, so it takes the `input` variant rather than inventing a line.
   */
  var located = {};
  (policy.diagnostics || []).forEach(function (d) {
    if (!located[d.token]) located[d.token] = [];
    located[d.token].push(d);
  });
  var evidenceFor = function (tokens) {
    var out2 = [];
    // Unique TOKENS, every OCCURRENCE. The parser reports a repeated token
    // once per occurrence, so iterating the raw list emitted the cross product
    // — two blank lines produced four evidence entries.
    var unique = tokens.filter(function (t, i) { return tokens.indexOf(t) === i; });
    unique.forEach(function (token) {
      var sites = located[token];
      if (!sites || !sites.length) {
        out2.push(artifactEvidence('input', 'policy', token));
        return;
      }
      sites.forEach(function (d) {
        out2.push(artifactEvidence('line', 'line ' + d.line, d.text));
      });
    });
    return out2;
  };

  // The parser's own diagnostics come first, and they are the ONLY thing an
  // invalid policy produces. Everything below reads fields that a document no
  // sender will honour cannot be trusted to have set meaningfully.
  if (policy.errors.length) {
    out.push(finding('mta-sts-policy-invalid', 'mta-sts-policy',
      policy.errors.slice(), evidenceFor(policy.errors)));
  }
  if (policy.warnings.length) {
    out.push(finding('mta-sts-policy-hygiene', 'mta-sts-policy',
      policy.warnings.slice(), evidenceFor(policy.warnings)));
  }

  if (scope.modeFinding && policy.mode === 'testing') {
    out.push(finding('mta-sts-mode-testing', 'mta-sts-policy', [],
      [artifactEvidence('input', 'mode', 'testing')]));
  }
  if (scope.modeFinding && policy.mode === 'none') {
    out.push(finding('mta-sts-mode-none', 'mta-sts-policy', [],
      [artifactEvidence('input', 'mode', 'none')]));
  }
  if (scope.maxAgeFinding && policy.maxAge !== null && policy.maxAge < SHORT_MAX_AGE) {
    out.push(finding('mta-sts-max-age-short', 'mta-sts-policy',
      [String(policy.maxAge)],
      [artifactEvidence('input', 'max_age', String(policy.maxAge))]));
  }

  if (scope.mxComparison) {
    var comparison = compareMtaStsMx(policy.mx, mxFact);
    if (comparison.state === 'null-mx' && scope.nullMxConflict) {
      out.push(finding('mta-sts-policy-on-null-mx', 'mta-sts-policy', [],
        [artifactEvidence('input', 'mx', policy.mx.join(' '))]));
    } else if (comparison.state === 'unknown') {
      // Said out loud rather than silently skipped. The headline check not
      // running is a fact about the audit the operator should see.
      out.push(finding('mta-sts-policy-mx-unknown', 'mta-sts-policy', [],
        [artifactEvidence('input', 'mx', policy.mx.join(' '))]));
    } else if (comparison.state === 'compared') {
      if (comparison.unmatchedHosts.length) {
        out.push(finding('mta-sts-policy-mx-mismatch', 'mta-sts-policy',
          comparison.unmatchedHosts.slice(),
          comparison.unmatchedHosts.map(function (host) {
            return artifactEvidence('input', 'mx', host);
          })));
      }
      if (comparison.unusedPatterns.length) {
        out.push(finding('mta-sts-policy-mx-unused', 'mta-sts-policy',
          comparison.unusedPatterns.slice(),
          comparison.unusedPatterns.map(function (pattern) {
            return artifactEvidence('input', 'mx', pattern);
          })));
      }
    }
  }

  return { policy: policy, scope: scope, findings: out.filter(Boolean) };
}

/** Convert one screened BIMI indicator SVG into artifact findings. */
export function bimiSvgFindings(text, parseSvg) {
  var svg = validateBimiSvg(text, parseSvg);
  var out = [];

  /**
   * Evidence comes from the validator's `sites`, one per occurrence, so it
   * names the OFFENDING element and the material that made it offending.
   * Mapping the token arrays instead located every rejection at the root and
   * put the token where the supplied material belongs.
   */
  var sitesFor = function (tokens) {
    var entries = (svg.sites || []).filter(function (site) {
      return tokens.indexOf(site.token) !== -1;
    }).map(function (site) {
      return artifactEvidence('element',
        site.element || (svg.root ? '<' + svg.root + '>' : 'logo'), site.value);
    });
    // A token with no site — `bad-root` and `malformed-xml` are raised before
    // any element exists — still has to be evidenced.
    if (!entries.length) {
      return [artifactEvidence('input', 'logo', svg.root ? '<' + svg.root + '>' : '')];
    }
    return entries;
  };

  if (svg.rejections.length) {
    out.push(finding('bimi-svg-rejected', 'bimi-svg', svg.rejections.slice(),
      sitesFor(svg.rejections)));
  } else if (svg.diagnostics.length) {
    out.push(finding('bimi-svg-profile', 'bimi-svg', svg.diagnostics.slice(),
      sitesFor(svg.diagnostics)));
  } else {
    // Deliberately a finding rather than silence: the panel's whole purpose is
    // to answer a question, and "nothing was wrong with what you supplied" is
    // an answer. Its message must not claim mailbox-provider acceptance.
    out.push(finding('bimi-svg-valid', 'bimi-svg', [],
      [artifactEvidence('element', '<title>', svg.title)]));
  }

  return { svg: svg, findings: out.filter(Boolean) };
}

/**
 * Analyse whatever the user supplied for one domain.
 *
 * Returns `artifactFindings` — a separate array, never merged into the audit's
 * DNS findings, and never seen by `calcScore()`.
 */
export function analyzeArtifacts(input) {
  var supplied = input || {};
  var findings = [];

  /**
   * The fact is DERIVED here, from the fields the audit actually holds.
   *
   * An earlier version took a ready-made `mxFact`, which nothing in the audit
   * produces — `audit-domain.js` holds `mx`, `aRec` and `aaaaRec`. The result
   * was that `deliveryCandidates()` was correct, its unit tests were green,
   * the composer's tests were green against a hand-built fact, and the public
   * entry point reported `policy-mx-unknown` for a domain whose MX matched
   * perfectly. Two green halves proving nothing about the join between them.
   */
  var mxFact = deliveryCandidates({
    mx: supplied.mx,
    addresses: [].concat(supplied.aRec || [], supplied.aaaaRec || []),
    domain: supplied.domain,
    unknown: supplied.mxUnknown,
  });

  var result = {
    domain: String(supplied.domain || ''),
    artifactFindings: findings,
    mxFact: mxFact,
    mtaStsPolicy: null,
    bimiSvg: null,
  };

  if (typeof supplied.mtaStsPolicyText === 'string' && supplied.mtaStsPolicyText) {
    var policy = mtaStsPolicyFindings(supplied.mtaStsPolicyText, mxFact);
    result.mtaStsPolicy = { result: policy.policy, scope: policy.scope };
    policy.findings.forEach(function (f) { findings.push(f); });
  }

  if (typeof supplied.bimiSvgText === 'string' && supplied.bimiSvgText) {
    var svg = bimiSvgFindings(supplied.bimiSvgText, supplied.parseSvg);
    result.bimiSvg = { result: svg.svg };
    svg.findings.forEach(function (f) { findings.push(f); });
  }

  return result;
}
