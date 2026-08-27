/**
 * Extract, from real equivalence runs, which registry members the corpus
 * actually reaches.
 *
 * The alternative was assigning `tests/state-matrix.json`'s `fixtures` column
 * by hand from a reading of the fixtures, and a hand-assigned coverage claim is
 * exactly the kind of thing this project has already been bitten by: a suite
 * reported 1,535 passing assertions while testing against the wrong public
 * suffix list, and nothing in it was lying — the claim had simply never been
 * checked against what ran.
 *
 * So coverage is measured. `resultPaths` in the registry says where an
 * algebra's members appear in an `analyzeDomain()` result; this walks a run's
 * results along those paths and reports the values it found. A member with no
 * corpus case is then a fact about the corpus rather than an opinion about it.
 */

/**
 * Read every value at a path pattern.
 *
 * Pattern syntax is deliberately tiny: dots for properties, `[]` for "every
 * element of this array". Anything richer would be a query language nobody
 * needs and everybody would have to learn to review the registry.
 *
 * Absence and presence-with-undefined are distinguished, because the registry
 * distinguishes them: `dnssec.error` is SET to `undefined` on a determinate
 * result while the not-checked DKIM shape omits its properties outright, and a
 * reader that folded the two together would report coverage for a state the
 * corpus never reached.
 */
export function readPath(value, pattern) {
  const segments = pattern.split('.');
  let cursor = [{ value, present: true }];
  for (const segment of segments) {
    const next = [];
    const isArray = segment.endsWith('[]');
    const key = isArray ? segment.slice(0, -2) : segment;
    for (const entry of cursor) {
      if (!entry.present || entry.value === null || typeof entry.value !== 'object') continue;
      if (!Object.prototype.hasOwnProperty.call(entry.value, key)) continue;
      const child = entry.value[key];
      if (isArray) {
        if (Array.isArray(child)) for (const item of child) next.push({ value: item, present: true });
      } else {
        next.push({ value: child, present: true });
      }
    }
    cursor = next;
  }
  return cursor.map(entry => entry.value);
}

/**
 * How an observed value is written in the registry.
 *
 * The registry lists members as strings — `'null'`, `'true'`, `'undefined'`,
 * `''` — because it is a reviewed JSON document a person reads. This is the one
 * place that mapping lives.
 */
function asMember(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (value === true) return 'true';
  if (value === false) return 'false';
  // The canonical encoder tags a present-but-undefined property.
  if (value && typeof value === 'object' && value.$undefined === true) return 'undefined';
  return String(value);
}

/**
 * Which members of which algebras a set of audit results reaches.
 *
 * `results` is the runner's `audits` array — `{ domain, outcome, result }` —
 * so a thrown audit contributes nothing, which is correct: it produced no
 * result for a member to appear in.
 */
export function observedMembers(registry, audits) {
  const observed = new Map();
  for (const algebra of registry.algebras) {
    if (!algebra.resultPaths || !algebra.resultPaths.length) continue;
    const found = new Set();
    for (const audit of audits) {
      if (audit.outcome !== 'result' || !audit.result) continue;
      for (const pattern of algebra.resultPaths) {
        for (const value of readPath(audit.result, pattern)) {
          const member = asMember(value);
          if (algebra.members.includes(member)) found.add(member);
        }
      }
    }
    if (found.size) observed.set(algebra.id, found);
  }
  return observed;
}

/**
 * Merge per-case observations into `{ "<algebra> <member>": [caseId, ...] }`.
 */
export function mergeCoverage(perCase) {
  const coverage = new Map();
  for (const [caseId, observed] of perCase) {
    for (const [algebraId, members] of observed) {
      for (const member of members) {
        const key = `${algebraId} ${member}`;
        if (!coverage.has(key)) coverage.set(key, []);
        coverage.get(key).push(caseId);
      }
    }
  }
  return coverage;
}
