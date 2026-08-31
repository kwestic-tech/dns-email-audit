/**
 * The RFC 9989 DNS Tree Walk. Spec Design §4 and §12, Task 4.6.
 *
 * Discovery only. No parsing, no scoring, no English — the walk locates the
 * policy record and says how it got there; `record.js` says what it means.
 *
 * ── A named raw-kind reader ─────────────────────────────────────────────
 *
 * `discoverDmarc()` is one of spec §3's six allowed raw-kind readers, moved
 * here from `js/dns.js` by Task 4.6. It records each step's kind and
 * distinguishes a FAILED WALK from an absence — two things that look identical
 * after normalization and mean opposite things to an operator.
 *
 * It **inlines the usability gate** rather than calling `requireUsable()`.
 * That is deliberate and unchanged: the walk needs the kind of every step,
 * including the steps that failed, and layer 2 throws those away. Leave it
 * behaviourally as it is.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s Tree Walk block and the inheritance rules, unchanged apart
 * from the two-space dedent, the `export` keywords, and `discoverDmarc`
 * becoming the body of a factory that names its three resolver capabilities.
 * Every step, its order and its termination state are byte-identical.
 */

import { validateDmarcVersion, parseDmarcTag, POLICY_RANK } from './record.js';

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

export function domainLabels(name) {
  return String(name || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
}

/**
 * The ordered list of subject names a Tree Walk queries, per §4.10 steps
 * 3, 4 and 7. Exported for testing because the label arithmetic is the part
 * of this release most likely to be subtly wrong.
 */
export function dmarcWalkTargets(domain) {
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
export function isDmarcPolicyRecord(txt) {
  return validateDmarcVersion(txt).valid;
}

/**
 * Explain a TXT string that failed the strict pass but was probably meant
 * to be a DMARC record. Diagnosis only: nothing here ever becomes a policy.
 *
 * The point is the difference between "you have no DMARC record" and "you
 * have a DMARC record that no receiver will read, and here is why".
 */
export function diagnoseDmarcRecord(txt) {
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
export function oneLabelBelow(subject, ancestor) {
  var subjectLabels = domainLabels(subject);
  var depth = domainLabels(ancestor).length + 1;
  if (depth > subjectLabels.length) return null;
  return subjectLabels.slice(subjectLabels.length - depth).join('.');
}

/**
 * The walk, over a passed resolver.
 *
 * Three capabilities, all arguments: §12 gives a protocol directory no edge to
 * `core/dns/`. `dohFetch` is the RAW handle, because the walk records the kind
 * of every step including the failed ones; `dnsError` to raise a cancellation
 * with the name that was being queried; `cleanAnswerData` because this module
 * does layer 3's cleaning itself, on the TXT answers it kept.
 */
export function createDmarcDiscovery({ dohFetch, dnsError, cleanAnswerData }) {
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

  return discoverDmarc;
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
export function selectOrganizationalDomain(subject, collected) {
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
export function selectAppliedRecord(subject, collected, organizationalDomain) {
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
export function applyInheritance(dmarcStatus, discovery, existence) {
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

export function weakerPolicy(a, b) {
  var ra = POLICY_RANK[a], rb = POLICY_RANK[b];
  if (ra === undefined) return b;
  if (rb === undefined) return a;
  return ra <= rb ? a : b;
}
