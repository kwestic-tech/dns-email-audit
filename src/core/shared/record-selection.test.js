#!/usr/bin/env node
/**
 * Record selection. Task 5.2a.
 *
 * Selection is not validation, and the assertions worth holding are the ones
 * where the difference decides what an operator sees: a record that announces
 * the right protocol and is malformed must still be SELECTED, or the finding
 * about it never has anything to point at.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { startsWithCI, versionCandidates, leadingVersionMatches } from './record-selection.js';

const { eq, section, report } = createSuite();

/* ── 1. startsWithCI ──────────────────────────────────────────────────── */
section('1. startsWithCI');

eq('an upper-case version field is recognized', startsWithCI('V=SPF1 -all', 'v=spf1'), true);
eq('a mixed-case one is too', startsWithCI('V=dkim1; k=rsa', 'v=DKIM1'), true);
eq('a non-match is rejected', startsWithCI('x=DMARC1', 'v=DMARC1'), false);
eq('an empty record is safe', startsWithCI('', 'v=DMARC1'), false);
eq('and so is a null one', startsWithCI(null, 'v=DMARC1'), false);
// Prefix, not equality: the rest of the record follows.
eq('the prefix does not have to be the whole record',
  startsWithCI('google-site-verification=abc123', 'google-site-verification'), true);

/* ── 2. versionCandidates ─────────────────────────────────────────────── */
section('2. versionCandidates — recognizable, not yet valid');

eq('a conforming record is a candidate',
  versionCandidates(['v=BIMI1; l=https://e.test/l.svg'], 'BIMI1').length, 1);
// THE case this exists for. A sender discards a record whose version field is
// not first; an auditor must not, because "nothing is published" and "what is
// published is not an active policy" are different facts, and filtering the
// malformed candidate away is what suppressed the findings the strict
// validators were added to raise.
eq('a record whose version field is not first is still a candidate',
  versionCandidates(['l=https://e.test/l.svg; v=BIMI1'], 'BIMI1').length, 1);
eq('recognition is case-insensitive', versionCandidates(['V=BIMI1; l='], 'BIMI1').length, 1);
eq('and tolerant of whitespace around the tag', versionCandidates([' v = BIMI1 ; l='], 'BIMI1').length, 1);
eq('another protocol\'s record is not a candidate', versionCandidates(['v=spf1 -all'], 'BIMI1'), []);
eq('a null record set is empty, not a throw', versionCandidates(null, 'BIMI1'), []);
eq('and a null entry inside one is skipped', versionCandidates([null], 'BIMI1'), []);

/* ── 3. leadingVersionMatches ─────────────────────────────────────────── */
section('3. leadingVersionMatches — what a sender keeps');

eq('a conforming record leads with its version',
  leadingVersionMatches(['v=STSv1; id=20260101'], 'STSv1').length, 1);
// The delimiter is `*WSP ";" *WSP`, so whitespace before the semicolon must
// not make a sender-compatible record disappear from the effective set.
eq('whitespace before the delimiter is allowed',
  leadingVersionMatches(['v=STSv1 ; id=20260101'], 'STSv1').length, 1);
eq('a tab is whitespace too', leadingVersionMatches(['v=STSv1\t;id=1'], 'STSv1').length, 1);
eq('the version alone is a whole record', leadingVersionMatches(['v=TLSRPTv1'], 'TLSRPTv1').length, 1);
// The version literal itself is exact, unlike recognition.
eq('the version literal is case-SENSITIVE here',
  leadingVersionMatches(['V=STSv1; id=1'], 'STSv1'), []);
eq('a version field that is not first is not kept',
  leadingVersionMatches(['id=1; v=STSv1'], 'STSv1'), []);
eq('and a null record set is empty', leadingVersionMatches(null, 'STSv1'), []);

/* ── 4. The two are not the same question ─────────────────────────────── */
section('4. Selection and sender-compatibility differ, deliberately');

// The pair that carries the whole design: one record, recognized by an auditor
// and discarded by a sender. Collapsing these two functions would lose exactly
// this case, which is the one the strict validators exist to report.
const trailing = ['l=https://e.test/l.svg; v=BIMI1'];
eq('an auditor recognizes the malformed record', versionCandidates(trailing, 'BIMI1').length, 1);
eq('while a sender discards it', leadingVersionMatches(trailing, 'BIMI1').length, 0);

report();
