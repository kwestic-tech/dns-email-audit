/**
 * The organizational domain, from the Public Suffix List. Spec §12, Task 4.6.
 *
 * **The PSL is generated data and is PASSED**, never imported: §12 gives a
 * protocol directory no edge to `src/data/`, and the fixture-identity probes
 * in `legacy-shapes.test.mjs` work by handing this a four-rule list and
 * watching the answer change. A module that reached for the real table could
 * not be given a fixture one.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s three PSL sets and `getOrganizationalDomain`, unchanged apart
 * from the two-space dedent and becoming the body of a factory. The rule sets
 * are built once per factory call, exactly as they were built once per engine.
 */

/**
 * Build the organizational-domain reader over one public suffix list.
 *
 * One call, one set of rules. Two factories over two lists share nothing,
 * which is the isolation half of the fixture-identity invariant.
 */
export function createOrgDomain({ publicSuffixRules }) {

  var PSL_EXACT = new Set();
  var PSL_WILDCARD = new Set();
  var PSL_EXCEPTION = new Set();
  (publicSuffixRules || []).forEach(function (rule) {
    if (rule[0] === '!') PSL_EXCEPTION.add(rule.slice(1));
    else if (rule.startsWith('*.')) PSL_WILDCARD.add(rule.slice(2));
    else PSL_EXACT.add(rule);
  });

  function getOrganizationalDomain(domain) {
    var labels = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
    if (labels.length < 2) return labels.join('.');
    var suffixLength = 1; // prevailing "*" rule when the PSL has no match
    for (var i = 0; i < labels.length; i++) {
      var candidate = labels.slice(i).join('.');
      if (PSL_EXCEPTION.has(candidate)) {
        suffixLength = Math.max(1, labels.length - i - 1);
        break;
      }
      if (PSL_EXACT.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i);
      if (i > 0 && PSL_WILDCARD.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i + 1);
    }
    if (labels.length <= suffixLength) return labels.join('.');
    return labels.slice(-(suffixLength + 1)).join('.');
  }

  return getOrganizationalDomain;
}
