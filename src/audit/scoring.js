/**
 * The scoring model. Spec Design §5 and §12, implementation Task 5.3.
 *
 * One weighted 0–100 rubric, its grade tiers, and the two functions that turn
 * a domain's protocol facts into points. **Byte-identical to `v0.5.0`** — Gate
 * 5's first condition, verified by an explicit diff against the tag rather
 * than by assumption, and pinned here by `scoring.test.js`.
 *
 * ── What scoring is allowed to read ─────────────────────────────────────
 *
 * Its inputs are **protocol FACTS produced by an owner**, never records.
 * `calcSpfScore()` reads `spfStatus.status` and `spfStatus.warnings`;
 * `calcDmarcScore()` reads the parsed DMARC status; `calcScore()` reads
 * `advanced.caa.found`, `advanced.mtaSts.present` and their siblings. Every
 * one of those is a value a `core/<protocol>/` owner computed and returned.
 *
 * **That is not a parsing rule and must not be mistaken for one.** The owner
 * decides what a record MEANS; scoring decides what a meaning is WORTH. Reading
 * `spfStatus.warnings` is the second of those — the tokens are SPF's, and this
 * module neither produces nor interprets the record they came from. The line
 * scoring may not cross is re-deriving a fact from a record: if a number here
 * ever needs something no owner reports, the owner grows the fact, not this
 * file. `scoring.test.js` §5 asserts that boundary directly.
 *
 * Ruled at Task 5.3, and deliberately NOT added to
 * `dns-transport.test.mjs` §3b: that inventory protects one specific
 * regression — parsing and selection leaking back into the coordinator — and a
 * weight table is not a parsing rule. Widening it to mean "anything that reads
 * a protocol value" would leave it protecting nothing in particular.
 *
 * ── Two pillars are deliberately asymmetric ─────────────────────────────
 *
 * DMARC carries the most weight — it is the richest signal available and the
 * only one that makes SPF and DKIM enforceable. DNSSEC counts for points AND
 * gates the A tier: an unsigned zone means every record above it can be
 * spoofed, so it is not merely additive.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s two scoring blocks, unchanged apart from the two-space dedent
 * and the `export` keywords. No weight, no threshold, no rounding and no
 * branch moved with them. `POLICY_RANK` is NOT here: it went to
 * `core/dmarc/record.js` at Task 4.6, which is its owner — the implementation
 * plan lists it under this task because it was still in `js/dns.js` when the
 * plan was written.
 */
import { POLICY_RANK } from '../core/dmarc/record.js';

/* ── Scoring model ──────────────────────────────────────────────────────
   One weighted 0–100 rubric. Weights live here as data so they can be
   inspected, tested and tuned without touching the logic.

   Two pillars are deliberately asymmetric:
    • DMARC carries the most weight — it is the richest signal available and
      the only one that makes SPF and DKIM enforceable.
    • DNSSEC counts for points AND gates the A tier. An unsigned zone means
      every record above it can be spoofed, so it is not merely additive.
   ───────────────────────────────────────────────────────────────────────── */

/**
 * The analysis version, frozen into every exported 0.9.0 report.
 * Spec: report-comparison 1.6 (Final), §2.
 *
 * It gates the SCORE DELTA of a comparison and nothing else. The finding diff
 * always runs, on 0.7.0's stable ids, because a version that blocked the whole
 * comparison would fail the feature's commonest case — audit in March, audit
 * again in September after two releases.
 *
 * That diff is not thereby a claim about improvement. Spec §5 qualifies it:
 * when `generator.version` differs, `findingSemanticsMatch` is false, the id
 * diff is labelled "baseline only"/"current only" and the domain status is
 * `changed` — never `improved` or `regressed`. Stable ids establish IDENTITY,
 * not that the detector behaved the same; 0.4.0 added twenty-one advisory
 * findings with zero score movement, so a clean domain can gain findings by
 * the tool getting more thorough.
 *
 * **Bump it in the same commit as anything that can move a score.** That is
 * broader than the rubric below, and the broadness is the point:
 *
 *  - `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`, `calcDmarcScore()`,
 *    `calcSpfScore()`, `calcAdvScore()`, `calcScore()`; and
 *  - any DISCOVERY change that moves a score without touching those. 0.3.0 is
 *    the confirmed instance: replacing the Public Suffix List with the RFC 9989
 *    Tree Walk moved scores with all three constants untouched.
 *
 * `scoring.test.js` hashes the rubric and fails when it changes without a bump.
 * That guard catches only the first bullet — a hash of this file cannot see a
 * Tree Walk landing in `src/core/dmarc/`. The second bullet is caught by the
 * standing backtest rule in `AGENTS.md`: a backtest that shows grade or score
 * movement requires a bump here in the same release.
 */
export const ANALYSIS_VERSION = 1;

export const WEIGHTS = {
  dmarc: 30, spf: 15, dkim: 15, dnssec: 15,
  caa: 10, mtaSts: 8, bimi: 4, tlsRpt: 3,
};

// Parked domains (an explicit null MX) are scored on a different rubric: DKIM, BIMI,
// MTA-STS and TLS-RPT are meaningless without mail flow, so the weight
// redistributes onto the checks that actually harden an unused domain.
export const PARKED_WEIGHTS = { spf: 30, dmarc: 30, dnssec: 25, caa: 15 };

export const GRADE_THRESHOLDS = [
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
export function calcDmarcScore(d) {
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
export function calcSpfScore(spfStatus, advanced) {
  if (!spfStatus || spfStatus.status === 'missing' || spfStatus.status === 'permerror') return 0;
  if (advanced && advanced.spfLookups && advanced.spfLookups.error) return 0;

  var warnings = spfStatus.warnings || [];
  var worthless = warnings.indexOf('spf-all-permit') !== -1 || warnings.indexOf('spf-neutral') !== -1;
  if (worthless) return 0;

  if (spfStatus.status === 'ok') return WEIGHTS.spf;        // -all
  if (spfStatus.status === 'softfail') return 10;           // ~all
  return 8;                                                 // present, or missing include
}

export function gradeFor(pts, dnssecSigned) {
  for (var i = 0; i < GRADE_THRESHOLDS.length; i++) {
    var tier = GRADE_THRESHOLDS[i];
    if (pts < tier.min) continue;
    if (tier.requiresDnssec && !dnssecSigned) continue;
    return { grade: tier.grade, cls: tier.cls };
  }
  return { grade: 'F', cls: 'score-f' };
}

export function calcAdvScore(adv) {
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

export function calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
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
