/**
 * Behavioural fingerprints for the three injected generated-data bindings.
 * Spec §11, implementation Task 0.7.
 *
 * The spike settled why these exist rather than a count or a length check:
 * bundling `js/public-suffixes.js` into the scoring sandbox replaced a
 * four-rule fixture with the real 10,239-rule list and the suite still
 * reported `1535 passed, 0 failed`, byte-identical to the correct baseline.
 *
 * It also settled why the FIRST attempt at a probe did not work. `a.b.ck`
 * against `*.ck`/`!www.ck` uses two rules that are both in the real PSL, so
 * fixture and production agree and the probe passes under the exact
 * substitution it exists to catch. Measured here, not argued:
 *
 *     getOrganizationalDomain('a.b.ck')          fixture a.b.ck   real a.b.ck
 *     getOrganizationalDomain('a.www.ck')        fixture www.ck   real www.ck
 *     getOrganizationalDomain('foo.blogspot.com') fixture blogspot.com
 *                                                 real    foo.blogspot.com
 *
 * `blogspot.com` is a private-section PSL rule the fixture does not carry, so
 * the two lists disagree. That divergence is the whole probe.
 *
 * Each binding gets its OWN divergent fingerprint. A suite that substitutes one
 * binding while leaving the other two correct must still fail its own probe.
 */

/** The four-rule table every v0.5.0 suite injects. Not the real list. */
export const FIXTURE_PSL_RULES = ['com', 'co.uk', '*.ck', '!www.ck'];

/** A selector no production catalog entry contributes. */
export const FIXTURE_DKIM_SELECTOR = 'fixtureselector999';

/** The value the fixture English bundle puts at doc.title. */
export const FIXTURE_ENGLISH_TITLE = '__fixture_english_title__';

/**
 * A probe asserts in ONE of two directions, and the suite says which.
 *
 * `'fixture'` — this suite supplies the fixture binding.
 * `'production'` — this suite supplies the shipped generated data.
 *
 * Both directions matter. The v0.5.0 suites inject a four-rule PSL while
 * loading the REAL `js/dkim-selectors.js`, so a probe API that could only
 * express "everything is a fixture" would force a suite to declare a profile
 * it does not have. That is not a smaller lie than the one the probes exist to
 * catch, and it was caught here by running the probe rather than by reasoning
 * about it.
 */
function probe(name, expectation, fixtureValue, productionValue, actual, note) {
  const fixture = expectation === 'fixture';
  return {
    name,
    expectation,
    expected: fixture ? fixtureValue : productionValue,
    counterResult: fixture ? productionValue : fixtureValue,
    actual,
    note,
  };
}

/**
 * The public suffix table in force.
 *
 * Divergent by construction: the real list contains the private rule
 * `blogspot.com` and resolves the probe one label deeper than a fixture that
 * does not carry it.
 */
export function probePublicSuffixRules(getOrganizationalDomain, expectation = 'fixture') {
  return probe('PSL', expectation,
    'blogspot.com', 'foo.blogspot.com',
    getOrganizationalDomain('foo.blogspot.com'),
    'the real PSL carries the private blogspot.com rule');
}

/**
 * The DKIM selector catalog in force.
 *
 * Divergent by construction: the production catalog has ten providers and none
 * of them contributes this selector.
 */
export function probeDkimCatalog(isRecognizedDkimSelector, expectation = 'fixture') {
  return probe('DKIM catalog', expectation,
    true, false,
    isRecognizedDkimSelector(FIXTURE_DKIM_SELECTOR),
    'only a fixture catalog contributes ' + FIXTURE_DKIM_SELECTOR);
}

/**
 * The English bundle in force.
 *
 * Divergent by construction: the shipped bundle's doc.title is the product
 * name, which no fixture would coincidentally produce.
 */
export function probeEnglishBundle(t, expectation = 'fixture') {
  return probe('English bundle', expectation,
    FIXTURE_ENGLISH_TITLE,
    'DNS & Email Security Auditor — Free SPF, DKIM, DMARC & DNSSEC Checker',
    t('doc.title'),
    'the shipped bundle returns the product name');
}

/**
 * Run the probes a suite declares, before any other assertion.
 *
 * Throws rather than returning a verdict: a suite testing against the wrong
 * generated data must not be allowed to report a count at all, which is
 * precisely the failure the spike demonstrated — 1,535 assertions passed
 * against a silently substituted public suffix list.
 */
export function assertFixtureIdentity(probes) {
  for (const p of probes) {
    if (p.actual === p.expected) continue;
    const substituted = p.actual === p.counterResult;
    const other = p.expectation === 'fixture' ? 'production' : 'fixture';
    throw new Error(
      `fixture identity: the ${p.name} binding in force is not the ${p.expectation} one.\n` +
      `  expected ${JSON.stringify(p.expected)}\n` +
      `  actual   ${JSON.stringify(p.actual)}\n` +
      (substituted
        ? `  this is exactly the ${other} value — ${p.note}\n`
        : `  this is neither the fixture nor the production value\n`)
    );
  }
}
