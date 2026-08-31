#!/usr/bin/env node
/**
 * The RFC 9989 DNS Tree Walk. Task 4.6.
 *
 * Two properties this suite exists to hold still.
 *
 * **The budget is eight queries, reached by SHORTENING rather than aborting.**
 * §4.10 step 4 cuts a name with eight or more labels back to seven, so a
 * thirteen-label name walks one label at a time from there and lands on the
 * TLD on query eight exactly. There is deliberately no `query-limit`
 * termination state, because running out of queries before running out of
 * labels cannot happen.
 *
 * **A failed walk is not an absence.** `discoverDmarc()` is a named raw-kind
 * reader precisely so those two stay distinguishable, and it inlines the
 * usability gate rather than calling `requireUsable()` because layer 2 throws
 * away the kinds it needs.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { dnsError } from '../dns/errors.js';
import {
  createDmarcDiscovery, dmarcWalkTargets, domainLabels, isDmarcPolicyRecord,
  diagnoseDmarcRecord, oneLabelBelow, selectOrganizationalDomain,
  selectAppliedRecord, applyInheritance, weakerPolicy,
} from './tree-walk.js';
import { analyzeDmarc } from './record.js';

const { eq, section, report } = createSuite();

/* ── 1. Labels and targets ────────────────────────────────────────────── */
section('1. dmarcWalkTargets');

eq('labels are lowercased and the trailing dot dropped',
  domainLabels('A.B.Test.'), ['a', 'b', 'test']);
eq('empty labels are dropped', domainLabels('a..test'), ['a', 'test']);

// Targets are DOMAIN names; `discoverDmarc()` prefixes `_dmarc.` when it
// queries. Keeping the prefix out of the target list is what lets the same
// list be compared against an organizational domain.
eq('a two-label name walks two targets',
  dmarcWalkTargets('example.test'), ['example.test', 'test']);
eq('a three-label name walks three',
  dmarcWalkTargets('a.example.test').length, 3);
eq('and the last target is the TLD',
  dmarcWalkTargets('a.b.c.example.test').slice(-1), ['test']);

/**
 * §4.10 step 4: "If x >= 8, remove the left-most labels until 7 labels
 * remain." Shortening, not aborting — which is why eight queries always
 * suffice and no query-limit state exists.
 */
const long = dmarcWalkTargets('a.b.c.d.e.f.g.h.i.j.k.example.test');
eq('a thirteen-label name walks exactly eight targets', long.length, 8);
eq('and it still ends at the TLD', long.slice(-1), ['test']);
// The subject itself is queried first, THEN the shortening applies: the second
// target is the seven-label form, not the twelve-label one a plain
// one-label-at-a-time walk would give.
eq('the first target is the subject, all thirteen labels',
  domainLabels(long[0]).length, 13);
eq('and the second is shortened to seven, not twelve',
  domainLabels(long[1]).length, 7);
eq('so the walk lands on the TLD on query eight exactly, never running out',
  long.length, 8);
eq('a single-label name walks once', dmarcWalkTargets('test'), ['test']);
eq('an empty name walks nowhere', dmarcWalkTargets(''), []);

eq('one label below an ancestor', oneLabelBelow('a.b.example.test', 'example.test'), 'b.example.test');
eq('the subject itself when already one below',
  oneLabelBelow('b.example.test', 'example.test'), 'b.example.test');
eq('null when the ancestor is not one', oneLabelBelow('a.test', 'other.test'), null);

/* ── 2. Recognizing a policy record ───────────────────────────────────── */
section('2. isDmarcPolicyRecord and diagnoseDmarcRecord');

eq('a conforming record is one', isDmarcPolicyRecord('v=DMARC1; p=none'), true);
// Recognition is case-insensitive on the tag name; the VALUE is exact.
eq('V=DMARC1 is recognized', isDmarcPolicyRecord('V=DMARC1; p=none'), true);
eq('v=dmarc1 is not — the value is case-sensitive',
  isDmarcPolicyRecord('v=dmarc1; p=none'), false);
eq('a record with the version second is not one',
  isDmarcPolicyRecord('p=none; v=DMARC1'), false);
eq('an SPF record is not one', isDmarcPolicyRecord('v=spf1 -all'), false);
eq('an empty string is not one', isDmarcPolicyRecord(''), false);

// null means "nothing to say about this one"; a string is the specific reason
// a record that LOOKS like DMARC was not treated as one. Silence and a
// diagnosis are different answers.
eq('a good record diagnoses to nothing', diagnoseDmarcRecord('v=DMARC1; p=none'), null);
eq('a version-second record is diagnosed, not silently dropped',
  diagnoseDmarcRecord('p=none; v=DMARC1'), 'version-not-first');
eq('and a mis-cased version gets its own reason',
  diagnoseDmarcRecord('v=dmarc1; p=none'), 'version-bad-case');

/* ── 3. Policy comparison ─────────────────────────────────────────────── */
section('3. weakerPolicy');

eq('none is weaker than reject', weakerPolicy('none', 'reject'), 'none');
eq('quarantine is weaker than reject', weakerPolicy('reject', 'quarantine'), 'quarantine');
eq('equal policies return the first', weakerPolicy('none', 'none'), 'none');
eq('an unknown first falls back to the second', weakerPolicy('bogus', 'reject'), 'reject');
eq('an unknown second falls back to the first', weakerPolicy('reject', 'bogus'), 'reject');

/* ── 4. The walk, over a passed resolver ──────────────────────────────── */
section('4. createDmarcDiscovery');

function transport(table) {
  const asked = [];
  return {
    asked,
    dohFetch: async name => {
      asked.push(name);
      const spec = table[name];
      if (!spec) return { kind: 'nodata', answers: [] };
      if (typeof spec === 'string') return { kind: spec, answers: [] };
      return { kind: 'success', answers: spec.map(data => ({ type: 16, data })) };
    },
  };
}
const discovery = table => {
  const t = transport(table);
  return {
    run: createDmarcDiscovery({
      dohFetch: t.dohFetch, dnsError, cleanAnswerData: d => String(d),
    }),
    asked: t.asked,
  };
};

const atApex = discovery({ '_dmarc.example.test': ['v=DMARC1; p=reject'] });
const found = await atApex.run('example.test');
eq('a record at the apex is found', found.applied.record, 'v=DMARC1; p=reject');
eq('and it says where', found.applied.foundAt, 'example.test');
eq('zero labels up, so nothing was inherited',
  [found.applied.labelsUp, found.applied.inherited], [0, false]);
/**
 * The walk does NOT stop at the first record. It queries every target and
 * selects afterwards, which is what makes the organizational domain and the
 * inheritance rules computable at all — the shortest collected name is not
 * knowable until the walk has finished.
 */
eq('the walk continues past a match rather than stopping',
  atApex.asked, ['_dmarc.example.test', '_dmarc.test']);
eq('and every step records its kind and counts',
  found.steps[0], { queryName: '_dmarc.example.test', kind: 'success', txtCount: 1, dmarcCount: 1, selected: true });
eq('the unselected step is marked so', found.steps[1].selected, false);
eq('termination is stated, not inferred', found.terminated, 'root');
eq('and the query count is reported', found.queries, 2);

const inherited = discovery({ '_dmarc.example.test': ['v=DMARC1; p=reject'] });
const child = await inherited.run('a.b.example.test');
eq('a parent record is inherited', child.applied.inherited, true);
eq('two labels up', child.applied.labelsUp, 2);
eq('and it names where it was found', child.applied.foundAt, 'example.test');
eq('the walk queried every target', inherited.asked.length, 4);

const nothing = await discovery({}).run('example.test');
// `applied` is NULL, not an empty record: there is no applied policy at all,
// and an empty-string record would read as "a record that says nothing".
eq('no record anywhere leaves no applied record', nothing.applied, null);
eq('and that is an absence, not an error', nothing.error, null);
eq('the steps still record what was asked', nothing.steps.length, 2);

/**
 * The distinction the raw-kind read exists for. A walk that FAILED is not a
 * walk that found nothing — after normalization both are an empty array, and
 * an operator told "no DMARC record" when the resolver was down would go and
 * publish one they already have.
 */
const broken = await discovery({ '_dmarc.example.test': 'servfail' }).run('example.test');
eq('a failed step is recorded with its kind', broken.steps[0].kind, 'servfail');
eq('and the walk reports an error', broken.error, 'servfail');
eq('which is NOT the same as not found', broken.error === nothing.error, false);

// nxdomain is an answer: the name does not exist, and the walk continues.
const absent = await discovery({
  '_dmarc.a.example.test': 'nxdomain',
  '_dmarc.example.test': ['v=DMARC1; p=none'],
}).run('a.example.test');
eq('an nxdomain step does not stop the walk', absent.applied.record, 'v=DMARC1; p=none');
eq('and it is not an error', absent.error, null);
eq('while its kind is still recorded', absent.steps[0].kind, 'nxdomain');

// §4.10 step 2: more than one policy record at a name discards them ALL and
// the walk CONTINUES — the opposite of the report-authorization rule, which
// takes the first valid record of several.
const duplicated = await discovery({
  '_dmarc.a.example.test': ['v=DMARC1; p=reject', 'v=DMARC1; p=none'],
  '_dmarc.example.test': ['v=DMARC1; p=quarantine'],
}).run('a.example.test');
eq('duplicate records at a name are discarded and the walk continues',
  duplicated.applied.foundAt, 'example.test');
eq('and the duplication is visible in the step',
  duplicated.steps[0].dmarcCount, 2);
eq('while that step was not selected', duplicated.steps[0].selected, false);

// A cancelled query throws rather than being recorded as a step.
let threw = null;
try {
  await discovery({ '_dmarc.example.test': 'cancelled' }).run('example.test');
} catch (e) { threw = e; }
eq('a cancelled walk throws', threw !== null, true);
eq('and it is named AbortError so optionalCheck rethrows it',
  threw && threw.name, 'AbortError');

/* ── 5. Selection and inheritance ─────────────────────────────────────── */
section('5. selectAppliedRecord and applyInheritance');

// Collected entries carry the DOMAIN, not the `_dmarc.` query name — the same
// convention `dmarcWalkTargets()` uses, which is what lets a collected name be
// compared against an organizational domain directly.
const collected = [
  { name: 'a.example.test', record: 'v=DMARC1; p=reject' },
  { name: 'example.test', record: 'v=DMARC1; p=none' },
];
eq('the organizational domain is the shortest collected name',
  selectOrganizationalDomain('a.example.test', collected), 'example.test');
// With nothing collected the subject IS its own organizational domain — the
// walk found no boundary, so there is nothing above it to inherit from.
eq('and with nothing collected the subject is its own',
  selectOrganizationalDomain('a.example.test', []), 'a.example.test');
// The applied record is the LOWEST match, not the organizational one: a
// subdomain's own record wins over its parent's.
eq('the applied record is the subject\'s own when it has one',
  selectAppliedRecord('a.example.test', collected, 'example.test').name, 'a.example.test');
eq('and the parent\'s when it does not',
  selectAppliedRecord('a.example.test', [collected[1]], 'example.test').name, 'example.test');

// RFC 9989 §4.10.1: an inherited record's `sp` becomes the applied policy for
// a subdomain, which is what makes `sp` more than documentation.
const parent = analyzeDmarc('v=DMARC1; p=reject; sp=none');
const applied = applyInheritance(parent,
  { applied: { found: true, name: '_dmarc.example.test', inherited: true } }, 'yes');
eq('an inherited record applies its sp to the subdomain',
  applied.effectivePolicy, 'none');
eq('while the parent record itself is unchanged', parent.effectivePolicy, 'reject');
eq('and the result is a NEW object', applied === parent, false);

report();
