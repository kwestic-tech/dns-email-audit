/**
 * Source-text normalization, for checks that read a module's own code.
 *
 * It lives in `tests/lib/` because TWO suites need it and a second copy is a
 * second thing to get wrong. `scoring.test.js` fingerprints the rubric;
 * `src/ui/report-data.test.js` asserts a pure module reaches for no ambient
 * primitive. Both are the case the framework rule in `AGENTS.md` names -- a
 * check over source text "must strip comments, because the file most likely to
 * discuss a thing is the one that just stopped doing it." A module that
 * explains why it avoids `TextEncoder` would otherwise read as one that uses it.
 *
 * The behaviour and its negative controls are asserted in
 * `src/audit/scoring.test.js`, where the fingerprint that depends on it lives.
 */

/**
 * Normalize a function's source for fingerprinting: remove `//` and block
 * comments, and collapse whitespace runs — both only OUTSIDE string literals.
 *
 * Whitespace has to go too, and that is not tidiness. A comment occupies its
 * own line, so stripping the comment while keeping the newline it arrived on
 * still moves the fingerprint, and the guard would fire on a comment after all.
 * Collapsing only outside strings is what makes that safe: a literal's own
 * spacing is code and is preserved, so there is no blind spot to argue about.
 *
 * Hand-written because the runtime is dependency-free and this runs over four
 * known functions rather than arbitrary input. Its one remaining blind spot is
 * a regex literal containing a comment sequence; the section below proves that
 * absent from what it is actually asked to normalize rather than assuming it.
 */
export function stripComments(source) {
  let out = '';
  let quote = null;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      out += c;
      if (c === '\\') { out += source[++i] || ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; out += c; continue; }
    if (c === '/' && source[i + 1] === '/') {
      // Advance to the character BEFORE the newline and let the loop emit the
      // newline itself. Consuming it here would split the surrounding
      // whitespace run in two, and pass 2 would collapse it to two spaces
      // rather than one — which is how a comment moved the fingerprint on the
      // first attempt at this guard.
      while (i < source.length && source[i] !== '\n') i++;
      i--;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i++;
      i++;
      continue;
    }
    out += c;
  }
  return out;
}

/** Pass 2: collapse whitespace runs, outside string literals only. */
export function collapseWhitespace(source) {
  let out = '';
  let quote = null;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      out += c;
      if (c === '\\') { out += source[++i] || ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; out += c; continue; }
    if (/\s/.test(c)) {
      while (i + 1 < source.length && /\s/.test(source[i + 1])) i++;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}

export const normalizeSource = (src) => collapseWhitespace(stripComments(src)).trim();
