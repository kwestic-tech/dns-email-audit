/**
 * The hand-rolled assertion style the v0.5.0 suites use, extracted so the new
 * cross-cutting suites under `tests/` print the same "N passed, M failed"
 * signal `tools/run-tests.mjs` will later sum.
 *
 * Deliberately not `node:test`. Migrating the harness is a schema change
 * wearing a tooling costume — spec Design §9, cost 3 — and it is not part of
 * this release.
 */

export function createSuite() {
  let pass = 0, fail = 0;
  // BigInt has no JSON representation and the SPF subnet helpers return one.
  const show = v => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? `${x}n` : x));

  const eq = (label, actual, expected) => {
    const a = show(actual), e = show(expected);
    if (a === e) { pass++; return; }
    fail++;
    console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
  };

  /** Asserts the thunk throws, and that the thrown value satisfies `check`. */
  const throws = (label, thunk, check) => {
    let error = null;
    try { thunk(); } catch (e) { error = e; }
    if (error === null) { fail++; console.log(`  ✗ ${label}\n      expected a throw, nothing was thrown`); return; }
    eq(label, check(error), true);
  };

  /** Same, for an async thunk. */
  const rejects = async (label, thunk, check) => {
    let error = null;
    try { await thunk(); } catch (e) { error = e; }
    if (error === null) { fail++; console.log(`  ✗ ${label}\n      expected a rejection, none happened`); return; }
    eq(label, check(error), true);
  };

  const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

  const report = () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${pass} passed, ${fail} failed`);
    if (fail) process.exit(1);
  };

  return { eq, throws, rejects, section, report, counts: () => ({ pass, fail }) };
}
