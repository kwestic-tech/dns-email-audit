/**
 * Per-protocol observability. Spec: report-comparison 1.4 (Final), §1 and §5.
 *
 * ── What this answers, and why it is an audit fact ──────────────────────
 *
 * 0.9.0 compares two reports. A finding present in the baseline and absent
 * from the current report has two possible causes: it was fixed, or the tool
 * never looked. Calling the second one `resolved` tells someone a problem is
 * gone when nobody checked, which is the failure `RQ-CMP-08` exists to
 * prevent.
 *
 * The distinction cannot be reconstructed downstream, which is why this lives
 * here rather than in `src/ui/`:
 *
 *  - `dns.checks-unverified` carries `protocol: 'dns'` while naming MX and
 *    TLSA in its own `args`/evidence. Reading the finding's protocol marks
 *    `dns` incomparable and leaves `mx` and `dane` falsely comparable — the
 *    exact controls that failed.
 *  - `dmarc.external-unverifiable` is `confidence: 'unverified'` on
 *    `protocol: 'dmarc'`, but it reports one external-authorization sub-check.
 *    Reading confidence would discard a perfectly good DMARC policy diff.
 *
 * So observability is projected from the OPTIONS in force and the FINISHED
 * FACTS, never inferred from finding text or confidence.
 *
 * ── The three states ────────────────────────────────────────────────────
 *
 * | State | Meaning |
 * | --- | --- |
 * | `observed` | The checks for this protocol ran and completed. |
 * | `unproven` | They were enabled and ran, but a lookup failed or returned nothing conclusive. |
 * | `not-run` | The option gating them was off, so nothing was attempted. |
 *
 * `not-run` is deliberately NOT treated as comparable-because-both-sides-agree.
 * Two runs with DKIM switched off both report no DKIM findings, and that is
 * still not evidence that DKIM is clean. §5 makes anything other than
 * `observed` incomparable on either side.
 *
 * ── The option-to-protocol mapping is the spec's, applied literally ─────
 *
 * §5: "`selectors` affect `dkim`; `deepChecks` affects `mx` and `dane`;
 * `wildcard` affects `dns` and `dkim`; `www` affects `dns`; and `advanced`
 * affects every advanced protocol."
 *
 * Two consequences of reading that literally, both intended:
 *
 *  - `dkim` needs `wildcard` as well as `dkim`. A wildcard TXT record answers
 *    every `_domainkey` probe, so without the wildcard probe the audit cannot
 *    prove a selector is genuinely absent. `wildcard-txt-dkim` exists because
 *    of exactly that.
 *  - `spf` and `dmarc` are never `not-run`, because their records are core
 *    queries that always happen. But they are not `observed` either unless
 *    their `advanced`-gated SUB-audits ran. `audit-domain.js` defaults
 *    `spfLookups`, `spfSubnets` and `reportAuth` to `null` and fills them only
 *    inside `if (ctx.options.advanced)`, and NINE finding ids depend on them —
 *    eight on `protocol: 'spf'` (`spf.over-limit`, `near-limit`, `cycle`,
 *    `large-subnet`, `medium-subnet`, `redundant-mechanism`,
 *    `partial-coverage`, `indeterminate`) and `dmarc.external-unverifiable`.
 *    Reporting `observed` with `advanced` off would let a comparison across an
 *    `advanced` mismatch call all eight SPF findings RESOLVED, which is the
 *    precise harm `RQ-CMP-08` exists to prevent. Spec 1.2 extends §5's mapping
 *    to say so; 1.1 named only the five dedicated advanced protocols.
 *
 * Note what this does NOT do: an external-authorization result that ran and
 * came back uncertain leaves `dmarc` `observed`. The distinction is whether the
 * check RAN, never how confident its finding was — that is §5's rule, and
 * section 4 of the co-located suite pins both halves of it.
 */
import { PROTOCOLS } from './findings.js';

/**
 * Registered as `audit.observability.state` in `tests/state-algebras.json`, so
 * the §3 constant scan in `state-matrix.test.mjs` matches it against the
 * registry rather than reporting an unknown closed vocabulary.
 */
export const OBSERVABILITY_STATES = ['observed', 'unproven', 'not-run'];

/**
 * One protocol's verdict. `ran` is the option gate; `unproven` is whether the
 * checks that did run reached a conclusion.
 */
function verdict(ran, unproven) {
  if (!ran) return 'not-run';
  return unproven ? 'unproven' : 'observed';
}

/**
 * Combine component verdicts for a cross-protocol token, worst-first.
 *
 * `not-run` outranks `unproven` because a check that never ran is a stronger
 * statement of ignorance than one that ran and failed.
 */
function worst(states) {
  if (states.indexOf('not-run') !== -1) return 'not-run';
  if (states.indexOf('unproven') !== -1) return 'unproven';
  return 'observed';
}

/**
 * Build the total observability map over `PROTOCOLS`.
 *
 * Every member of `PROTOCOLS` is present in the returned object — §1 requires
 * a TOTAL map, so a protocol this function forgot would be a missing key
 * rather than a silently optimistic `observed`. The final loop asserts that
 * by construction.
 *
 * Called only for an audited domain: §1 gives an `unregistered` or `error`
 * domain no `observability` at all.
 */
export function buildObservability(facts) {
  const options = (facts && facts.options) || {};
  const advanced = (facts && facts.advanced) || {};
  const dkimStatus = (facts && facts.dkimStatus) || {};
  const dmarcDiscovery = facts && facts.dmarcDiscovery;

  const adv = !!options.advanced;
  const deep = adv && !!options.deepChecks;

  // A summary carries `unknown: true` when its lookup failed, as distinct from
  // the record being absent. `mxHealth` and `tlsa` stay null when the deep
  // checks did not run at all, or when a null MX means there is no host to
  // resolve — nothing to observe either way.
  const unknownOf = (summary) => !summary || !!summary.unknown;

  const map = {
    // Core record, plus the `advanced`-gated sub-audits. `unknownOf` covers
    // both causes with one rule: the fact is `null` when `advanced` was off and
    // carries `unknown: true` when the lookup ran and failed. Either way the
    // SPF observation is incomplete.
    spf: verdict(true, unknownOf(advanced.spfLookups) || unknownOf(advanced.spfSubnets)),
    // The Tree Walk records its own failure; a walk that errored did not
    // establish which policy applies. External report authorization is
    // `advanced`-gated the same way SPF's sub-audits are, and
    // `dmarc.external-unverifiable` cannot fire without it.
    dmarc: verdict(true, !!(dmarcDiscovery && dmarcDiscovery.error)
      || unknownOf(advanced.reportAuth)),

    // `confidence` is the DKIM owner's own verdict: `observed` means selectors
    // were found, `sampled` means the scan completed without proving absence.
    dkim: verdict(!!options.dkim && !!options.wildcard, dkimStatus.confidence !== 'observed'),

    // Advanced-gated protocols.
    dnssec: verdict(adv, !advanced.dnssec || advanced.dnssec.state === 'indeterminate'),
    caa: verdict(adv, unknownOf(advanced.caa)),
    'mta-sts': verdict(adv, unknownOf(advanced.mtaSts)),
    'tls-rpt': verdict(adv, unknownOf(advanced.tlsRpt)),
    bimi: verdict(adv, unknownOf(advanced.bimi)),

    // Deep-check-gated protocols.
    mx: verdict(deep, unknownOf(advanced.mxHealth)),
    dane: verdict(deep, unknownOf(advanced.tlsa)),

    // The wildcard and website probes are what the `dns` findings are built
    // from: `dns.wildcard-apex`, `dns.wildcard-dkim` and `dns.hosting-loop`.
    dns: verdict(!!options.www && !!options.wildcard, false),
  };

  // Cross-protocol tokens, conservative per §1.
  map.defensive = worst([map.mx, map.spf]);
  map.reporting = worst([map.dmarc, map['tls-rpt']]);

  // Totality is the contract, so it is enforced rather than trusted. A
  // protocol added to `PROTOCOLS` without a rule here lands as `not-run`,
  // which is the safe direction: it makes the comparison refuse to claim a
  // resolution rather than quietly assert one.
  PROTOCOLS.forEach(function (protocol) {
    if (!Object.prototype.hasOwnProperty.call(map, protocol)) map[protocol] = 'not-run';
  });

  return map;
}
