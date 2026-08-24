# Spec: Rendering correctness and malformed-record robustness

| Field | Value |
| --- | --- |
| Spec version | 1.1 (Final, amended during implementation) |
| Target release | 0.2.3 |
| Status | Final — approved for implementation |
| Depends on | Nothing. This is the first release after 0.2.2. |
| Blocks | Every later release extends the rendering path. |
| Slug for open questions | `SEC` |
| Last updated | 2026-08-24 |

## Threat model for this release

The general threat model is stated once in [`README.md`](README.md) and is not
restated per spec. The part that governs this release: there is no session, no
credential, no stored user data and no privileged action, so script execution on
this origin yields an attacker nothing to steal. What remains is **output
integrity**. This is a security assessment tool, and the failure that matters is
a domain owner being able to make it display a false result, suppress a finding,
or render a record so that a reader draws the wrong conclusion.

That reframing changes what this release does. The original 0.1 draft was written
as CSP hardening and has been cut back to the parts that survive on their own
merit: rendering correctness, which is an engineering argument, and robustness
against malformed DNS data, which is an output-integrity argument.

## Problem

Four concrete defects, none of which is a vulnerability and all of which are
worth fixing before six more releases extend the same code.

**Placeholder interpolation is sequential.** `interpolate()` at
[`js/i18n.js:54`](../../js/i18n.js) loops `i` from 0 upward and replaces
`{i}` by string split and join. An argument substituted at `i=0` becomes part of
the string that `i=1` then scans, so a value containing `{1}` causes the second
argument to be interpolated into a position the translator never wrote. Every
current multi-argument message takes an internal value first, so nothing reachable
exploits this today. [dmarcbis-tree-walk](dmarcbis-tree-walk.md) and
[dns-protocol-depth](dns-protocol-depth.md) both add messages whose first
argument is a DNS-derived name, which makes it reachable.

**The progress log is quadratic.** `log()` at
[`js/app.js:156`](../../js/app.js) does `el.innerHTML +=`, which serializes and
reparses the entire log on every append. A 200-domain run appends at least 200
times and reparses a growing document each time.

**`esc()` does not escape single quotes.** [`js/app.js:128`](../../js/app.js)
handles `&`, `<`, `>` and `"`. That is correct only because every generated
attribute in the file happens to use double quotes. It is a property maintained
by consistent habit across twenty-odd concatenation sites, not by construction,
and the next four releases add more of them.

**Sanitized rich text round-trips through a string.**
`sanitizeHTML()` at [`js/i18n.js:96`](../../js/i18n.js) parses into a
`<template>`, walks and strips, then returns `template.innerHTML`. The caller
reparses that string. Serializing a sanitized tree and reparsing it is the shape
mutation XSS exploits. The content here is our own locale files rather than DNS
data, so the threat is a translator or a bad merge rather than an attacker, but
the fix is ten lines.

Separately, nothing in the codebase decides what to do with a DNS record that is
hostile in the *display* sense rather than the execution sense: 40 KB of TXT data
in a table cell, a bidirectional override that visually reverses a hostname, C0
control characters, or 400 MX records at one name. Section 4 is the detailed
review of that, which is the substantive half of this release.

Finally, [`README.md:283`](../../README.md) claims 174 assertions. The suite runs
489.

## Scope

1. Replace HTML string construction in `js/app.js` with DOM node building.
2. Rebuild the two document builders to construct trees and serialize once, so
   no escape helper remains anywhere in the codebase.
3. Fix `interpolate()` to a single pass.
4. Return a `DocumentFragment` from the rich-text sanitizer.
5. Decide and implement handling for every malformed-record class in section 4.
6. Add a dependency-free DOM shim, a markup-sink setter trap, and hostile-value
   regression suites for both rendering and export.
7. Narrow `img-src`, replace the JSON-LD nonce with a hash, give the exported
   report its own policy.
8. Correct the assertion count and the security wording in `README.md`.

## Non-goals

These were in the 0.1 draft and are cut. Each is recorded with its reason so the
decision does not have to be re-argued.

- **`style-src 'unsafe-inline'` stays.** Removing it means rewriting every inline
  style in `js/app.js` and editing `index.html`, to defend against an attacker
  who can already inject markup. If that state is reachable, the directive is not
  what saves you.
- **No `frame-ancestors`, no hosting migration.** Clickjacking a tool with no
  state and no destructive action is worth approximately nothing, and a
  meta-delivered CSP cannot express the directive anyway. GitHub Pages stays.
- **No Trusted Types.** It is Chromium-only platform enforcement for a rule the
  shim's setter trap already enforces in every browser, because after this
  release there is no markup sink left for it to guard.
- **The learn-more guides are unchanged.** The 0.1 draft converted them to an
  in-page dialog only because removing `style-src 'unsafe-inline'` would have
  broken the Blob-rendered documents. That constraint is gone, so the guides stay
  as they are. Converting them is a user-experience change and belongs in a
  user-experience release.
- **No change to `js/dns.js`.** No audit logic, no scoring, no grades. A grade
  computed at `v0.2.2` is identical at `v0.2.3`.
- **No new network destinations.** `connect-src` is unchanged.

## Design

### 1. Node-building renderer

New file `js/render.js`, loaded after `js/i18n.js` and before `js/app.js`,
exposing a small factory on `window.R`:

```js
R.el(tag, props, children)   // → HTMLElement
R.frag(children)             // → DocumentFragment
R.text(value)                // → Text node
R.rich(translatedString)     // → DocumentFragment, the only rich-text path
```

`props` accepts `textContent`, `className`, `title`, `dataset` and a named
attribute allowlist. It refuses an `innerHTML` prop and throws. `href` is set
only when the value matches `^https://`. Everything else is `setAttribute` after
an allowlist check.

Functions in `js/app.js` that change from returning strings to returning nodes:

| Function | Line | Note |
| --- | --- | --- |
| `log()` | 156 | Appends one `<span>`; fixes the quadratic rebuild |
| `badge()` | 136 | Returns a `<span>` |
| `scoreBlockHtml()` → `scoreBlock()` | 81 | Returns a fragment |
| `advMiniDots()` / `advFullDots()` | 247 / 270 | Return fragments |
| `spfMeterHtml()` → `spfMeter()` | 308 | Returns a node |
| `detailItem()` | 522 | Takes `(labelText, valueNode)` |
| `appendRow()` | 320 | Builds `<tr>` and `<td>` directly |
| `tile()` | 541 | Returns a node; `renderSummary()` appends |

`esc()` is deleted rather than kept, with no private replacement anywhere.
Leaving an escape helper available invites reuse and reintroduces the string
path.

Inline `style` attributes are kept. Where the rewrite touches a static one
anyway, moving it to a class in `css/style.css` is free and welcome, but the
release is not gated on any of them and the CSP directive does not change.

### 1a. Document builders: build a tree, then serialize

`buildLearnMorePage()` at [`js/app.js:195`](../../js/app.js) and `exportHTML()`
at [`js/app.js:811`](../../js/app.js) both produce a complete HTML document, one
for a Blob and one for a download. In the 0.2 draft they were allowlisted as
legitimate string builders, which does not compose with deleting `esc()`, since
`buildLearnMorePage()` is its largest consumer.

Both are rebuilt to construct a DOM tree with `R.el` in a detached document from
`document.implementation.createHTMLDocument()`, then serialize once:

```js
var out = '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
```

That establishes the rule the rest of this spec enforces, and it is a cleaner
rule than the one it replaces:

> **Reading `outerHTML` is permitted. Writing `innerHTML` or `outerHTML` is
> never permitted.**

Serialization of a node-built tree is safe by construction, because a text node
containing `<script>` serializes to `&lt;script&gt;` and reparses back to the same
text node. The markup-sink allowlist therefore drops to **zero entries**.

The only literal strings remaining in either builder are the doctype, the CSS
text from `css/style.css`, and the language code, all of which are ours.

The exported report also regains its own policy, which was cut during the 0.2
rescope and should not have been. That file leaves this project's control the
moment a user emails it to someone, so it carries:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
```

`style-src 'unsafe-inline'` is acceptable here and only here, because the report
inlines the stylesheet by necessity and contains no script at all.

### 2. Single-pass interpolation

```js
function interpolate(str, args) {
  return String(str).replace(/\{(\d+)\}/g, function (match, digits) {
    var i = Number(digits);
    return i < args.length ? String(args[i]) : match;
  });
}
```

One pass over the template, so a value substituted at `{0}` is never rescanned.
An index with no corresponding argument is left as written rather than becoming
`undefined`, which makes a locale file with a stray `{3}` visible instead of
silently wrong.

### 3. Rich text without the round trip

`sanitizeHTML(html) → string` becomes `sanitizeFragment(html) → DocumentFragment`.
Nothing reparses a sanitized tree.

**Amended at 1.1.** The 1.0 text said to keep the existing `<template>` parse
and return `template.content` instead of `template.innerHTML`. That cannot be
built: `template.innerHTML = html` is an assignment to a markup sink in
`js/i18n.js`, which section 5 puts inside the static scan and acceptance
criterion 2 forbids outright, with an allowlist the same two places require to
be empty. As specified, the implementation would have failed the test the spec
itself mandates.

Resolved by building nodes instead of parsing a string: `sanitizeFragment` is a
small fail-closed tokenizer over the same twelve-tag allowlist. It recognizes
an allowlisted tag, an `href` matching `^https://` on an `A`, and a fixed set
of entities; **anything else — a `<script>`, a malformed `<`, a stray close
tag — is emitted as literal text**, so it renders visibly as itself and
serializes back to `&lt;script&gt;`. Nothing is silently dropped, which is the
same rule section 4 applies to invisible characters, and the markup-sink
allowlist stays honestly empty.

The input is our own locale file and `tools/check-locales.mjs` now fails the
build on any tag outside the allowlist (below), so the fail-closed branch is a
backstop rather than a routine path. `tools/render.test.mjs` asserts the
author-time allowlist and the runtime tokenizer agree tag for tag, so the two
cannot drift.

`applyTranslations()` at [`js/i18n.js:188`](../../js/i18n.js) changes from
`el.innerHTML = sanitizeHTML(...)` to `el.replaceChildren(sanitizeFragment(...))`.

The allowlist is unchanged: `A, BR, STRONG, CODE, EM, B, I, SMALL, UL, OL, LI, P`,
with `A` stripped of every attribute and given back an `href` only when it matches
`^https://`, plus `target="_blank"` and `rel="noopener noreferrer"`.

Because locale content is ours rather than a stranger's, add a static check to
`tools/check-locales.mjs`: any tag in a locale string outside the allowlist fails
the build. That closes the same gap at author time, with no parser and no
dependency.

### 4. Malformed-record handling

This is the part you asked to review in detail. Each row states what the code
does today and what it should do. All of these are display and interpretation
problems, not execution problems.

Two rules govern the whole table and are stated once here.

**Nothing invisible is silently dropped.** Every DNS-derived character that
renders as nothing, or that changes how neighbouring characters are ordered, is
replaced at its exact position by a visible sentinel such as `‹RLO›`, `‹ZWSP›` or
`‹U+0007›`, styled as a marker rather than as content. Stripping would neutralize
the display attack while hiding the technique, which is the wrong trade for a
tool whose job is to show you what a domain published. Replacing achieves both:
the character is genuinely gone from the text run, so no reordering survives, and
the marker sits where it was, so the reader can see it.

CSS alone cannot achieve this. `unicode-bidi: isolate` prevents a value from
reordering its *neighbours*, not its own contents, so an override embedded in an
SPF `include:` host still reverses the rest of that value inside its own element.
The isolation is applied anyway, on the value container, because it is free and
contains anything residual, but the sentinel substitution is what does the work.

**Display caps never reach the data.** Truncation and record caps apply to what is
painted. The full value stays in the result object, in the CSV, in the HTML
report and behind the disclosure control.

| Class | Today | Proposed |
| --- | --- | --- |
| **Oversized TXT** (a 40 KB DKIM or SPF value) | Rendered whole into a table cell | Display the first 1024 characters, then a disclosure control that reveals the rest. 1024 clears a 4096-bit RSA DKIM key, which runs to roughly 760 characters with its tags; the 512 in the 0.2 draft would have truncated a legitimate key. |
| **Large RRset** (400 MX records, 200 TXT strings at one name) | `r.mx.join('\n')` renders all of them | Render the first 20 with a count of the remainder. This cap and the 1024-character cap are independent and both apply. Analysis reads everything; only display is capped. |
| **Bidirectional overrides** (U+202A–202E, U+2066–2069, U+200E, U+200F) | Passed through to the DOM | Sentinel substitution per the rule above, plus `unicode-bidi: isolate` on the container, plus a record-hygiene note. This is the malformation that is a genuine output-integrity attack: an override inside an SPF `include:` host visually reverses the name, so a reader checks the wrong domain while the escaping was entirely correct. |
| **C0 and C1 control characters** | May pass through `cleanAnswerData()` | Sentinel substitution naming the code point, and a record-hygiene note. |
| **Zero-width characters** (U+200B–200D, U+FEFF) | Passed through | Sentinel substitution. Two hostnames differing only by a zero-width joiner render identically today. |
| **Lone surrogates and invalid UTF-8** | `JSON.parse` may produce them; `cleanAnswerData()` falls back to the raw chunk on a parse failure | Normalize to U+FFFD. Confirm the fallback path at [`js/dns.js:201`](../../js/dns.js) does not silently produce a differently-decoded string from the success path. |
| **Punycode names in responses** (`xn--` MX or CNAME targets) | Displayed verbatim | Keep displaying verbatim. Decoding to Unicode would reintroduce homoglyph confusion. Note the `xn--` prefix in the interface rather than hiding it. |
| **Very long single label** in a CNAME or MX target | Unbounded | Truncate for display at 253 characters with the same disclosure control. |
| **Unbounded DoH cache** at [`js/dns.js:65`](../../js/dns.js) | `Map` grows for the page's lifetime | Cap at a fixed entry count with least-recently-used eviction. A long session auditing several batches currently retains every answer. |
| **Records that look like templates** (a value containing `{0}`) | Sequential interpolation substitutes it | Fixed by section 2. |
| **Empty and whitespace-only values** | Rendered as an empty cell | Render the existing `labels.none` token so an empty record is distinguishable from a lookup that returned nothing. |

Three pathologies are already handled correctly and are listed so a reviewer can
confirm rather than rediscover: CNAME loops are bounded by a visited set and a
depth of 12 at [`js/dns.js:923`](../../js/dns.js); SPF include cycles are bounded
at depth 20 at [`js/dns.js:973`](../../js/dns.js); duplicate versioned records
fail closed at [`js/dns.js:1949`](../../js/dns.js).

### 5. Dependency-free test harness

The zero-dependency constraint is satisfiable here specifically because of the
rewrite. A DOM shim cannot reproduce mutation XSS, which is why the 0.1 draft
proposed `jsdom`. After section 1 the renderer never parses a string into markup:
it calls `createElement`, sets `textContent`, and calls `setAttribute` against an
allowlist. The property under test becomes "does every untrusted value land in a
text node or an allowlisted attribute", and a shim answers that exactly, because
no parser is involved.

New file `tools/lib/dom-shim.mjs`, roughly 200 lines, implementing only what the
render path uses: `document.createElement`, `createTextNode`,
`createDocumentFragment`, `getElementById`,
`document.implementation.createHTMLDocument`, and on elements `appendChild`,
`replaceChildren`, `setAttribute`, `getAttribute`, `textContent`, `className`,
`classList`, `dataset`, `style.setProperty` and a serializing `outerHTML`
**getter**. Tests walk the resulting tree directly, so no selector engine is
needed.

The shim's boundary must be stated in its header comment. It proves the renderer
puts untrusted values only in text nodes and allowlisted attributes. It does not
prove a browser renders that safely, and it does not need to: a text node is not
markup by definition of the DOM, not by grace of the shim.

**Enforcement is primarily a runtime trap, not a grep.** The shim defines
`innerHTML` and `outerHTML` as accessor properties whose **setters throw**.
Any assignment fails the test that exercises it, including
`el['inner' + 'HTML'] = x` and `Object.assign(el, { innerHTML: x })`, which a
static pattern would miss entirely. The `outerHTML` getter works normally, since
section 1a makes reading it the supported way to serialize a document.

A static check backs it up for code paths no test reaches. `npm test` scans
`js/app.js`, `js/render.js` and `js/i18n.js` for **assignment only**,
`/\.(inner|outer)HTML\s*=[^=]/`, plus any use of `insertAdjacentHTML` or
`document.write`, and fails on any hit. The allowlist is **empty**, which is what
makes the check reliable: an empty allowlist has no judgment calls in it, and the
0.2 draft's two entries were exactly where a reviewer would have to trust rather
than verify.

Neither mechanism alone is sufficient and both are cheap. The trap catches what
the tests run; the scan catches what they do not.

### 6. CSP touch-ups

Two small changes, no restructuring.

`img-src` becomes `'self' data:`. Nothing loads a remote image and nothing
planned will. One token, no cost.

The `nonce-dns-audit-static` token is replaced by a SHA-256 hash of the JSON-LD
block at [`index.html:29`](../../index.html). The reason is not secrecy; a public
nonce leaks nothing. The reason is that a nonce whose value is fixed and published
authorizes any injected script bearing the same attribute, so the policy claims a
control it does not have. A hash is the same length and is true.
`tools/csp.test.mjs` recomputes the digest with `node:crypto` and fails if the two
drift, which also makes the eventual structured-data edit self-correcting.

Everything else in the policy at [`index.html:7`](../../index.html) is unchanged.

### 7. Documentation

- `README.md:283`: the assertion count becomes correct, and `CONTRIBUTING.md`
  gains a release-checklist line so it is read from a test run at each cut rather
  than typed from memory.
- `README.md` security section: "DNS-derived output is escaped" becomes
  "DNS-derived output is inserted as text nodes and never parsed as markup".
- `SECURITY.md`: state the threat model in two sentences, including the part that
  says what is deliberately not defended, so a reporter knows what counts.

## Localization impact

Minimal. The malformation handling in section 4 adds a small number of keys: a
disclosure control label, a truncation indicator, a remainder count for capped
record lists, and record-hygiene notes naming what a record contained. Estimate
8 to 12 keys.

The sentinel markers themselves are **not** translated. `‹RLO›`, `‹ZWSP›` and
`‹U+0007›` name Unicode code points, which are the same in every language, and a
translated marker would break the property that two auditors reading the same
record in different languages see the same evidence. They join the never-translate
list in [`AGENTS.md`](../../AGENTS.md) alongside record types and tag names.

All thirteen locales translated in the same change, `npm run build:fallback`
after the `locales/en.json` edit, `npm run locale:gate` reporting 13/13 before
the pull request opens.

## Testing

`tools/interpolate.test.mjs`, pure, no DOM:

- `t('k', 'a {1} b', 'X')` where the template has `{0}` and `{1}`, asserting the
  injected `{1}` survives as literal text.
- A stray `{5}` with three arguments stays literal rather than becoming
  `undefined`.
- Existing placeholder behavior is unchanged for every current message.

`tools/render.test.mjs`, using the shim, asserting for each fixture that the
produced tree contains only element nodes the renderer created, that every
DNS-derived value is in a text node or an allowlisted attribute, and that no
attribute name begins with `on`:

| Fixture | Value |
| --- | --- |
| Tag injection | `v=spf1 <script>alert(1)</script> -all` |
| Attribute breakout | `rua=mailto:"><img src=x onerror=alert(1)>@e.com` |
| Single-quote breakout | A value containing `'` in every rendered position |
| SVG payload | DKIM `p=` containing `<svg onload=alert(1)>` |
| Encoded entities | `&lt;script&gt;` and `&#60;script&#62;` |
| Template injection | An SPF record containing `{0}` and `{1}` |
| Bidi override | An SPF `include:` host containing U+202E |
| Zero-width | Two MX hosts differing only by U+200B |
| Control characters | A TXT value containing U+0000 through U+001F |
| Oversized | A 64 KB TXT record, asserting truncation and no hang |
| Large RRset | 400 MX records, asserting the display cap |
| Lone surrogate | An unpaired high surrogate in a TXT value |
| Empty value | An empty TXT string |

`tools/export.test.mjs`, covering the two document builders from section 1a. The
exported file leaves this project's control, so it is asserted at the string
level as well as the tree level, and string assertions need no DOM:

- Every fixture above is rendered, exported, and the resulting string is scanned
  for `<script`, `<iframe`, `<object` and `<embed`. All must be absent: an
  element can only exist if its `<` was not escaped.

  **Amended at 1.1.** ` on\w+\s*=` and `javascript:` are scanned against the
  **tag regions** of the output (`/<[^>]*>/g`), not the whole string. Escaping
  a value neutralizes `<` and `>` but leaves the substring ` onerror=` intact
  inside the resulting text node, so a whole-string scan reports a false
  positive on the spec's own attribute-breakout fixture
  (`rua=mailto:"><img src=x onerror=alert(1)>@e.com`) — a record the tool is
  required to display faithfully. The naive scan is therefore unsatisfiable
  while also rendering the record, and the tag-region scan tests the property
  that actually matters: no event handler and no `javascript:` URL exists as
  markup. A fixture publishing `javascript:` additionally asserts it is shown
  to the reader as text and never as an `href`.
- The exported document contains the CSP meta tag from section 1a.
- Round trip: the serialized string reparsed yields a tree with the same text
  content as the tree that produced it, confirming serialization is idempotent
  for the node types the renderer emits.
- `buildLearnMorePage()` output is asserted the same way, with a locale fixture
  containing markup outside the rich-text allowlist.
- The sentinel substitution from section 4 survives into both exports, so a
  record containing an override is visibly marked in a report handed to a third
  party rather than silently reordered in their browser.

`tools/export.test.mjs` additionally asserts the inlined stylesheet survives
serialization byte for byte. `<style>` is a raw-text element, so its contents
must **not** be entity-escaped — `css/style.css` contains both `&` and a `>`
child combinator, and escaping either would silently break the exported
report's layout. Conversely a `<` inside the CSS could open a tag, so every
`<` is rewritten to the CSS escape `\3c `, which renders identically and
leaves no character that can terminate the element early.

`tools/csp.test.mjs`, dependency-free: no `nonce-` token in `script-src`, the
JSON-LD hash matches, `connect-src` is exactly `'self' https://cloudflare-dns.com`,
`img-src` is exactly `'self' data:`, and the markup-sink scan passes with an empty allowlist.

`tools/check-locales.mjs` gains the tag-allowlist check from section 3.

Existing coverage does not regress: at least 489 assertions plus the new ones, and
13/13 locales.

## Acceptance criteria

1. No fixture in `tools/render.test.mjs` places a DNS-derived value anywhere but
   a text node or an allowlisted attribute.
2. No file under `js/` assigns to `innerHTML` or `outerHTML`. The allowlist is
   empty, enforced by both the shim setter trap and the static scan.
3. A DNS value containing `{1}` cannot cause a second argument to be interpolated.
4. Every malformation class in section 4 has a decided, tested behavior, and no
   invisible character is silently dropped from displayed output.
5. Every export fixture produces a document containing no script element, no
   event-handler attribute and no `javascript:` URL, asserted at the string
   level, and carrying its own CSP meta tag.
6. Grades and scores for a fixed input set are byte-identical to `v0.2.2`,
   verified by diffing `node tools/backtest.mjs --json` across the two tags.
7. The 200-domain progress log does not rebuild on each append.
8. `README.md` states the correct assertion count.
9. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**Visual regression.** The rewrite touches every rendered cell in a responsive
table with `data-label` mobile fallbacks. Mitigation: screenshots at three
viewport widths before and after; the output is required to be identical, so any
visible difference is a defect.

**Truncation hides real data.** Capping display could hide the tail of a long but
legitimate SPF or DKIM value, which is the opposite of what an audit tool should
do. Mitigation: 1024 characters clears a 4096-bit RSA key with headroom, the
disclosure control is one click, and the full value is in both exports and in the
result object.

**Sentinel substitution alters legitimate text.** A domain legitimately using a
right-to-left script in a TXT value would see markers appear. Mitigation:
substitute only the directional *control* characters and the invisible set, never
script characters, which reorder correctly on their own and need no intervention.
A record hygiene note says which characters were found, so the change is
disclosed rather than silent.

**The shim diverges from a browser.** Mitigation: the shim only has to be right
about node identity and attribute storage. The setter trap and the static scan
together guarantee no parsing path exists for it to be wrong about, and the
export tests assert on real serialized strings rather than on the shim's model.

## Open questions

None. `OQ-SEC-11` and `OQ-SEC-12` were the last two outstanding and were
resolved on 2026-08-24; see **Resolved questions** below. Every numbered
question raised against this spec now has a recorded verdict, which is the
condition `docs/specs/README.md` sets for `1.0 (Final)`.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| OQ-SEC-01 | How do we get a DOM for security tests? | A dependency-free shim in `tools/lib/dom-shim.mjs`, viable because the rewrite removes every string-to-markup path from the render code, with a static grep enforcing that it stays removed. No `jsdom`, no Playwright, no devDependency. | 0.2 |
| OQ-SEC-03 | Should `require-trusted-types-for 'script'` be added? | No. Platform enforcement for a rule a grep enforces, and Chromium-only. | 0.2 |
| OQ-SEC-04 | Do the learn-more guides become a dialog? | No. The only reason to change them was the `style-src` removal, which is cut. They stay as Blob-rendered documents. Converting them is a user-experience decision for a later release. | 0.2 |
| OQ-SEC-05 | Do we need real response headers, and does that mean leaving GitHub Pages? | No. Clickjacking a stateless tool with no destructive action is not worth a hosting migration, and nothing else under `kwestic.com` shares trust with this origin. GitHub Pages stays. | 0.2 |
| OQ-SEC-07 | Should `esc()` be deleted or kept? | Deleted, so no new string-concatenation site can appear. | 0.2 |
| OQ-SEC-02 | Is `i18n.sanitizeHTML` public API? | Delete it. `js/i18n.js` is not published as a package; `package.json` declares no `main`, `exports` or `files`, so there is no external consumer to break. Keeping a deprecated wrapper would preserve the string sink for no benefit. | 0.3 |
| OQ-SEC-06 | Does `img-src` need to anticipate BIMI logo previews? | No. `'self' data:` stays permanently. Local assets and provider iconography are covered by `'self'`, inline artwork by `data:`, and the only thing the directive forbids is fetching an image from a remote host, which would disclose the auditor's address to a server named in a stranger's record. A logo is only ever rendered from a file the user supplied locally. | 0.3 |
| OQ-SEC-08 | Display truncation threshold and unit? | 1024 characters, per value. A 4096-bit RSA DKIM key runs to roughly 760 characters with its tags, so 512 would truncate a legitimate key. The 20-record cap per cell is a separate, independent limit and both apply. | 0.3 |
| OQ-SEC-09 | Strip bidirectional controls, or render them inert? | Neither. Replace each invisible character with a visible sentinel at its exact position. CSS cannot do this: `unicode-bidi: isolate` stops a value reordering its neighbours, not its own contents, so an override inside an SPF `include:` host still reverses that value. Substitution removes the character from the text run, which actually neutralizes it, while the marker keeps the technique visible. Isolation is applied to the container as well, since it is free. | 0.3 |
| OQ-SEC-10 | Should the markup-sink check be a test or a lint? | A blocking test, and a runtime trap first. The shim defines `innerHTML` and `outerHTML` setters that throw, catching computed and destructured access a static pattern misses; an assignment-only scan backs it up for untested paths. The allowlist is empty, because section 1a makes both document builders construct trees and read `outerHTML` rather than write it. | 0.3 |
| OQ-SEC-11 | Do sentinels appear in the CSV export, or only in the interface and the HTML report? | Raw characters stay in the CSV data column; a separate `record_hygiene` column names what was found (e.g. `bidi-override`). The CSV is the machine-readable export people pipe into other tools, so rewriting a cell's bytes to a sentinel string breaks programmatic parsing, while the new column still warns a human who opens it in a spreadsheet. Consistent with this spec's own "display caps never reach the data" rule: the interface is annotated and capped, the export stays faithful. The column is **appended, never inserted**, per the positional-header backfill rule at [`js/app.js:744`](../../js/app.js). The interface and the HTML report keep the visible sentinels of section 4. | 1.0 |
| OQ-SEC-12 | Do record-hygiene observations become findings, or stay display annotations? | They stay display annotations in 0.2.3, explicitly deferred to [findings-and-remediation](findings-and-remediation.md) (0.6.0). This release's non-goals rule out a scoring change and any edit to `js/dns.js` for grading purposes; promoting a hygiene observation to a finding would require a severity and so smuggle a scope change into a release whose entire point is rendering correctness. 0.6.0 is where severity is modelled properly. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft, framed as CSP and XSS hardening. |
| 0.2 | 2026-08-20 | Rescoped after review. Threat model corrected: no session or stored data means the risk is output integrity, not compromise. Cut `style-src` removal, `frame-ancestors`, hosting migration, Trusted Types and the learn-more dialog. Promoted malformed-record handling to the centre of the release. Added the sequential-interpolation defect. Resolved five open questions; added three. Renamed from `security-boundary.md`. |
| 0.3 | 2026-08-20 | Revised after Gemini review. Document builders now construct DOM trees and serialize, which removes the last escape helper and empties the markup-sink allowlist; exported report regains its own CSP. Enforcement moved from a grep to a shim setter trap with an assignment-only scan as backup. Truncation raised to 1024 per value. Invisible-character handling changed from stripping to visible sentinel substitution, correcting the reviewer's `unicode-bidi: isolate` proposal, which does not neutralize reordering within an element. Added `tools/export.test.mjs`. Resolved the five remaining open questions; added two. |
| 1.0 | 2026-08-24 | Final. Resolved the last two open questions: `OQ-SEC-11` (raw bytes stay in the CSV data column, a separate appended `record_hygiene` column names what was found) and `OQ-SEC-12` (record-hygiene observations stay display annotations in 0.2.3, deferred to `findings-and-remediation` (0.6.0)). No change to Design, Scope, Non-goals, Testing or Acceptance criteria beyond the `record_hygiene` CSV column those resolutions add. Approved for implementation. |
| 1.1 | 2026-08-24 | Amended during implementation, per the "amend rather than quietly diverge" rule in `docs/specs/README.md`. Two defects in the 1.0 text: (a) §3 kept the `<template>` parse, which is an `innerHTML` assignment in `js/i18n.js` that §5 and acceptance criterion 2 forbid with an empty allowlist — replaced by a fail-closed tokenizer that builds nodes, so no markup sink remains under `js/`; (b) the export scan for ` on\w+\s*=` and `javascript:` was specified against the whole output string, which false-positives on the spec's own attribute-breakout fixture because escaping `<` leaves ` onerror=` intact in the text node — now scanned against tag regions only. Added the `<style>` raw-text serialization rule the export builder depends on, and the `tools/check-locales.mjs` tag-allowlist check promised by §3. No change to Scope, Non-goals, or the acceptance criteria themselves. |
