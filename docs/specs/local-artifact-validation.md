# Spec: Private local validation of MTA-STS policies and BIMI artifacts

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.7.0 |
| Status | Awaiting review |
| Depends on | [rendering-and-robustness](implemented/rendering-and-robustness.md), whose rendering boundary this release relies on absolutely |
| Blocks | Nothing |
| Slug for open questions | `ART` |
| Last updated | 2026-08-20 |

## Problem

Two of the eight controls the tool scores cannot be fully evaluated from DNS.

MTA-STS publishes a TXT record at `_mta-sts.<domain>` that says only "a policy
exists, and here is its version id". The policy itself, which contains the mode,
the permitted MX patterns and the max age, lives at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. The tool validates the TXT
record's syntax in `validateMtaStsRecord()` at
`js/dns.js:896` and sets `policyVerified: false`
unconditionally at `js/dns.js:1962`. `calcScore()` at
`js/dns.js:1795` therefore awards half the MTA-STS pillar,
four points out of eight, to every domain that publishes a syntactically valid
TXT record. `README.md` states the reason honestly under Known limitations:
browser CORS restrictions prevent reliable policy retrieval.

BIMI has the same shape. `validateBimiRecord()` at
`js/dns.js:910` confirms the `l=` and `a=` values are HTTPS
URLs and stops there. Whether the SVG at `l=` conforms to the SVG Portable/Secure
profile, which is what determines whether mailbox providers actually display the
logo, is unknown.

Fetching either artifact is not an option. It would send the auditor's IP address
and a request pattern to a host chosen by the domain being investigated, which is
the precise thing that keeps item 8 of the roadmap deferred past 1.0. It would
also require widening `connect-src` from a single documented destination to
"any host named in a stranger's DNS record", which would end the tool's privacy
claim outright.

The middle path is to let the user supply the artifact. Someone auditing their
own domain has the policy file and the logo. Someone auditing a third party can
fetch the artifact themselves, by whatever means they consider appropriate, and
paste it in. The tool then validates locally, in memory, with no network access
of any kind.

## Scope

1. A visually and structurally separate local-analysis panel.
2. MTA-STS policy text accepted by paste or file selection, validated against
   RFC 8461 §3.2.
3. BIMI SVG accepted by paste or file selection, validated against the SVG
   Portable/Secure profile.
4. Optional VMC material accepted, with structural inspection only.
5. Strict size and type limits, enforced before parsing.
6. Rejection of DTDs, entity declarations, scripts, event handlers, external
   references and unsupported features.
7. User-supplied SVG never injected into the application DOM.
8. No automatic fetching of any MTA-STS, BIMI or VMC URL.
9. Every artifact-derived finding labelled "user supplied".

## Non-goals

- **No fetching.** Not of `.well-known/mta-sts.txt`, not of the BIMI `l=` URL,
  not of the VMC `a=` URL, not through a proxy, not with the user's permission,
  not behind a flag. `connect-src` remains `'self' https://cloudflare-dns.com`
  and the CSP test from 0.2.3 enforces it.
- **No rendering of the supplied logo.** See `OQ-ART-03`.
- **No certificate chain validation for VMC.** The browser has no access to the
  trust store used for VMC issuance and could not validate a chain if it did.
- **No persistence.** Supplied artifacts live in a JavaScript variable for the
  lifetime of the page. Nothing is written to `localStorage`, `IndexedDB`, a
  cookie, or a cache.
- **No scoring change.** A verified MTA-STS policy does not turn the existing
  half-credit into full credit in this release. See `OQ-ART-05`.

## Design

### 1. Panel separation

A collapsed section below the results table, opened explicitly, labelled to make
the distinction unmissable: everything above the line came from DNS and is
attributable to the audited domain; everything below the line came from a file
the user provided and is attributable to nobody but the user.

The panel is scoped to one domain at a time, selected from the audited set. Bulk
artifact validation across 200 domains has no plausible workflow, since each
artifact would have to be supplied individually.

Inputs, per artifact type:

- A `<textarea>` for pasted text.
- A `<input type="file">` accepting `.txt` for MTA-STS and `.svg` for BIMI.

Both read into a string with `FileReader`, following the existing upload pattern
at [`js/app.js:848`](../../src/main.js), which already enforces a 1 MB cap through
`MAX_UPLOAD_BYTES`.

### 2. Limits, enforced before parsing

| Artifact | Byte limit | Accepted type | Rationale |
| --- | --- | --- | --- |
| MTA-STS policy | 64 KB | `text/plain` | A conformant policy is a few hundred bytes |
| BIMI SVG | 32 KB | `image/svg+xml` | The BIMI specification's own recommended ceiling |
| VMC | 64 KB | `application/x-pem-file`, `text/plain` | A PEM certificate with a logotype extension |

The declared MIME type from the file picker is advisory and is checked, but the
byte limit and the content inspection are what actually enforce the boundary. A
`.svg` file containing HTML is rejected by the parser, not by its extension.

Limits are checked on the string length before any parse call, so a hostile file
never reaches a parser at all.

### 3. MTA-STS policy validation

RFC 8461 §3.2 defines the policy as a sequence of `key: value` lines with CRLF
line endings.

```js
function validateMtaStsPolicy(text) → {
  valid: boolean,
  version: string,                     // must be 'STSv1'
  mode: 'enforce' | 'testing' | 'none' | null,
  mx: string[],                        // patterns, one per line, '*.' allowed
  maxAge: number | null,               // seconds
  duplicateKeys: string[],
  unknownKeys: string[],
  lineEndings: 'crlf' | 'lf' | 'mixed',
  errors: string[],                    // tokens
  warnings: string[],
}
```

Validation rules:

- `version: STSv1` must be present. RFC 8461 requires it first.
- `mode` must be exactly one of `enforce`, `testing`, `none`.
- `max_age` must be a positive integer not exceeding 31557600.
- At least one `mx` line is required unless `mode: none`.
- `mx` patterns permit a single leading `*.` wildcard and nothing else.
- Duplicate keys other than `mx` are an error.
- LF-only line endings are a warning, not an error. Real implementations vary in
  strictness and the tool should say which risk the operator is taking rather
  than declare a working policy invalid.

Cross-checks against DNS data already held, which is where the value is:

| Check | Condition |
| --- | --- |
| `mta-sts.policy-mx-mismatch` | An MX host from DNS matches no `mx` pattern in the policy. This breaks mail delivery in `enforce` mode. |
| `mta-sts.policy-mx-unused` | An `mx` pattern matches none of the domain's MX hosts. Usually a stale policy after a provider migration. |
| `mta-sts.mode-testing` | `mode: testing` provides no enforcement. |
| `mta-sts.mode-none` | `mode: none` actively withdraws a previously published policy. |
| `mta-sts.max-age-short` | `max_age` under 86400 seconds weakens the protection substantially. |
| `mta-sts.id-mismatch` | Reported only if the policy carries an id and it differs from the TXT record's `id=`. Note the policy format has no id field, so this applies only if `OQ-ART-01` resolves toward accepting an HTTP response body with headers. |

The MX cross-check is the headline feature. A policy whose `mx` patterns do not
cover the domain's actual MX hosts causes conformant senders in `enforce` mode to
refuse delivery, and it is invisible to every check the tool currently performs.

### 4. BIMI SVG validation

Parsing is the entire security surface, so the parse call is specified exactly:

```js
const doc = new DOMParser().parseFromString(text, 'image/svg+xml');
```

`DOMParser` produces a detached document. Scripts in it do not execute, external
references in it are not fetched, and event handler attributes in it are inert,
provided no node from it is ever adopted into the rendered document. That
provision is the load-bearing rule of this release: **no node from the parsed
artifact document is ever passed to `appendChild`, `replaceChildren`,
`adoptNode`, `importNode`, or any other insertion path.** The validator reads
attributes and element names and produces tokens. It never produces nodes.

The `R.el` factory from 0.2.3 already refuses an `innerHTML` prop. The artifact
validator additionally lives in its own file, `js/artifact.js`, which imports
nothing from the renderer, so a future maintainer cannot casually wire the two
together.

Rejection rules, each producing a distinct error token:

| Rejected | Token |
| --- | --- |
| Any `<!DOCTYPE>` | `doctype-present` |
| Any `<!ENTITY>` declaration | `entity-declaration` |
| `<script>` anywhere | `script-element` |
| Any attribute matching `/^on/i` | `event-handler` |
| `<foreignObject>` | `foreign-object` |
| `<image>` or `<use>` | `external-reference-element` |
| `href` or `xlink:href` whose value is not a same-document fragment | `external-reference` |
| `<a>` with any target | `link-element` |
| `<style>` containing `@import` or `url(` | `external-style` |
| `<animate>`, `<animateTransform>`, `<set>`, `<animateMotion>` | `animation` |
| A parser error node | `malformed-xml` |
| Anything other than `<svg>` as the root | `bad-root` |

Profile conformance checks, which are findings rather than security rejections:

| Check | Requirement |
| --- | --- |
| `baseProfile="tiny-ps"` | Required by the SVG P/S profile |
| `version="1.2"` | Required |
| `<title>` present and non-empty | Required |
| `viewBox` present, square aspect ratio | Required |
| No `x` or `y` on the root | Required |
| Single root element | Required |
| No raster data URI in a fill or a `<style>` | Required |

Every one of these is reported with the specification requirement it comes from,
because "your logo will not display" is useless without "and here is the line to
change".

### 5. VMC

Structural inspection only: confirm PEM framing, decode base64 to DER, confirm
the DER parses as an X.509 certificate, extract subject, issuer, validity dates
and whether a logotype extension is present. Report expiry. Explicitly state that
the chain is not validated and that the tool cannot determine whether the
certificate would be accepted by any mailbox provider.

If DER parsing turns out to need a library, it is dropped rather than depended
on. See `OQ-ART-04`.

### 6. Result and export handling

Artifact findings live in a separate array from DNS findings:

```js
artifactFindings: [{
  …Finding shape from 0.6.0…,
  source: 'user-supplied',
  artifact: 'mta-sts-policy' | 'bimi-svg' | 'vmc',
}]
```

`source: 'user-supplied'` is rendered on every one of them, and it survives into
the CSV and HTML exports. The reason is provenance: a report handed to a third
party must not blur the line between what the tool observed in public DNS and
what someone typed into a text box.

Artifact findings do not enter `calcScore()`. See `OQ-ART-05`.

## Localization impact

Roughly 45 to 60 new keys: panel headings and instructions, the MTA-STS policy
checks, the SVG rejection tokens, the SVG profile checks, VMC fields, the
"user supplied" label, and the limit and type error messages.

Never translated: `STSv1`, `enforce`, `testing`, `none`, `max_age`, `mx`,
`baseProfile`, `tiny-ps`, `viewBox`, `<title>`, `xlink:href`, `foreignObject`,
`PEM`, `X.509`, and file extensions. Always translated: "user supplied",
"policy", "logo", "certificate", "rejected", "not fetched", and every explanatory
sentence.

The privacy statement in the panel is the most important string in the release
and should be reviewed as copy, not only as translation.

## Testing

`validateMtaStsPolicy()` is pure and tests in the existing sandbox.

The SVG validator is the problem. 0.2.3 resolved `OQ-SEC-01` in favor of a
dependency-free DOM shim, which is sufficient there precisely because the
renderer stops parsing strings into markup. This release does the opposite: its
whole job is to parse a hostile XML string, so a shim cannot test it, and there
is no `DOMParser` in Node without a dependency. That is a hard conflict between
this release and the project's zero-dependency rule, and it is not resolvable by
being clever about the design. See `OQ-ART-08`, which is now the question that
decides whether this release is buildable as specified.

MTA-STS fixtures: a conformant `enforce` policy; `mode: testing`; `mode: none`;
missing `version`; `version` not first; duplicate `mode`; `max_age` of 0, of
31557601, and non-numeric; wildcard `mx` patterns matching and not matching the
DNS MX set; LF-only line endings; CRLF; mixed; a 64 KB policy accepted and a
65 KB one rejected before parsing; a policy containing null bytes.

SVG fixtures, each asserting rejection with the right token and, critically,
asserting that no network request occurred and no node was inserted:

| Fixture | Expectation |
| --- | --- |
| Conformant tiny-ps logo | Valid |
| `<script>alert(1)</script>` inside the SVG | `script-element` |
| `onload="alert(1)"` on the root | `event-handler` |
| Billion laughs entity expansion | `entity-declaration`, and no hang |
| External DTD reference | `doctype-present`, and no fetch |
| `<image href="https://evil.example/x.png">` | `external-reference-element` |
| `<use xlink:href="https://evil.example/x#a">` | `external-reference` |
| `<style>@import url(https://evil.example/x.css)</style>` | `external-style` |
| `<foreignObject><iframe>` | `foreign-object` |
| HTML content with an `.svg` extension | `bad-root` |
| Truncated XML | `malformed-xml` |
| Missing `baseProfile` | Profile finding, not a rejection |
| Non-square `viewBox` | Profile finding |
| 33 KB SVG | Rejected on size before parsing |
| Data URI raster in a fill | Profile finding |

The network assertion is the important one and needs a mechanism: stub `fetch`
and `XMLHttpRequest` in the test environment to throw, run every fixture, and
assert nothing threw. In the browser, the CSP is the real enforcement and the
0.2.3 CSP test is what guarantees it.

## Acceptance criteria

1. Every artifact is processed entirely in memory. No fixture produces a network
   request, a storage write, or an inserted DOM node.
2. `connect-src` in `index.html` is unchanged and the 0.2.3 CSP test still
   passes.
3. No MTA-STS, BIMI or VMC URL is fetched under any code path, verified by
   grepping `js/artifact.js` for `fetch`, `XMLHttpRequest`, `Image`, `import(`
   and `<img`.
4. Every artifact-derived finding carries `source: 'user-supplied'` in the
   interface and in both exports.
5. Reloading the page discards every supplied artifact.
6. `calcScore()` output is unaffected by artifact input.
7. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**SVG is a hostile format and this release accepts it from strangers.** The
entire mitigation is that the parsed document is never inserted anywhere, which
is a rule enforced by convention plus a file boundary plus a test. Mitigation:
`js/artifact.js` has no dependency on the renderer, the validator's public API
returns only tokens and primitives, and the test suite asserts no insertion.

**Users will expect the tool to fetch the file for them.** The panel is more
work than a button that says "check my policy", and the reason for the extra work
is invisible to someone who has not read `PRIVACY.md`. Mitigation: state the
reason in the panel in one sentence, and link to the privacy document.

**Scope creep toward rendering the logo.** Displaying the supplied SVG is an
obvious next request and would reintroduce every risk this design removes.
Mitigation: `OQ-ART-03` decides it explicitly rather than leaving it to a future
maintainer's judgment.

**The panel dilutes the tool's identity.** Everything else in the application is
a bulk DNS auditor. This is a single-domain file inspector. Mitigation: the panel
is collapsed by default and clearly subordinate.

## Open questions

**OQ-ART-01: Does the MTA-STS validator accept a saved HTTP response, or only
the body?**
Some MTA-STS failures are HTTP-layer failures: the wrong `Content-Type`, a
redirect, a missing certificate. A user who saved the response with headers
could have those checked too. Accepting a raw HTTP response adds a parsing mode
and a plausible-looking way for someone to paste something confusing. This draft
accepts the body only. Worth the extra mode?

**OQ-ART-02: Which DOMParser MIME type?**
`image/svg+xml` gives XML parsing with SVG semantics and correct namespace
handling. `text/xml` gives XML parsing with no SVG semantics at all, which is
slightly more inert and slightly less accurate for profile checks that depend on
namespace resolution. `application/xml` behaves as `text/xml`. This draft uses
`image/svg+xml` on the grounds that a detached document is inert either way and
the namespace handling matters for correctness. Confirm.

**OQ-ART-03: Is the supplied logo ever displayed?**
Never displaying it is safest and means a user validating their own logo cannot
see whether it looks right. Displaying it through a `blob:` URL in an `<img>`
would keep the SVG out of the DOM tree and render it as an image, which blocks
scripts by the image sandbox, at the cost of widening `img-src` to include
`blob:`. A third option renders it only after validation passes, on the argument
that a validated tiny-ps SVG has already had every dangerous construct rejected.
This draft displays nothing. This is the single most likely feature request after
release, so decide it now.

**OQ-ART-04: Is VMC in scope at all?**
Structural PEM and DER inspection without chain validation tells the user the
subject, the issuer and the expiry date, which they can also get from any
certificate viewer. The genuinely useful check, whether a mailbox provider would
accept it, is impossible here. Dropping VMC removes a parser, a set of locale
keys and a maintenance burden. This draft includes it at minimum depth. Cut it?

**OQ-ART-05: Does a verified MTA-STS policy earn the other four points?**
`calcScore()` awards half the MTA-STS pillar when the TXT record is present and
`policyVerified` is false, which it always is. A user-supplied, validated
`enforce` policy is real evidence that the control works. Awarding the full eight
points for it would mean a domain's grade depends on what the user typed, which
makes grades non-reproducible from public data and unsound in an exported report.
This draft awards nothing and reports the finding. The alternative is a clearly
marked second score. Which?

**OQ-ART-06: Should the panel accept a directory or multiple files at once?**
Someone auditing their own estate has thirty policy files. Accepting a batch with
filename-to-domain matching would make the panel genuinely useful at scale, and
would add a filename-parsing surface and a matching heuristic. Out of scope for
0.7.0 in this draft. Note it as a possible follow-up or reject it.

**OQ-ART-07: What happens to artifact findings in the 0.8.0 report export?**
0.8.0 defines a versioned JSON report for comparison across time. A report
containing user-supplied findings is not reproducible from DNS, so comparing two
of them compares two different kinds of claim. Options: exclude artifact findings
from the exported report entirely; include them flagged, and have the comparison
ignore them; include and compare them like any other finding. This draft excludes
them, and flags the decision here so 0.8.0's schema accounts for it.

**OQ-ART-08: How is a hostile-SVG parser tested without a dependency?**
This is now the question that decides whether the release is buildable as
specified. The zero-dependency rule holds elsewhere because nothing else in the
project parses untrusted markup. This release exists to parse untrusted markup,
and an XML parser cannot be shimmed the way a DOM renderer can: the fixtures that
matter are entity expansion, DTD handling and malformed-XML recovery, which are
properties of the parser itself. Four ways out, in rough order of preference:

1. **Drop the SVG validator.** Ship MTA-STS policy validation alone, which is
   pure string parsing, needs no dependency, and carries most of the release's
   value through the MX cross-check. Revisit BIMI separately.
2. **Accept a devDependency for tests only.** The shipped site stays
   dependency-free; `npm test` requires an install. Contradicts the rule as
   stated but not the property users care about.
3. **Validate the SVG without a parser.** A tokenizer that rejects on any
   `<!DOCTYPE`, `<!ENTITY`, `<script`, `on*=` or external reference, and refuses
   anything it cannot tokenize unambiguously. Testable with no dependency, and
   strictly more conservative than a parser, at the cost of rejecting some
   conformant logos it cannot confidently read.
4. **Browser-only tests.** A manual test page, not run in CI. Rejected in this
   draft as untestable in practice.

Option 3 is the one that preserves both the feature and the rule, and it inverts
the usual risk: a tokenizer that fails closed on anything ambiguous is safer than
a parser, just less accurate. Which?

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 0.1 | 2026-08-20 | Not a version bump. Recorded a downstream consequence of the 0.2.3 rescope: `OQ-SEC-01` resolved to a dependency-free DOM shim, which cannot test this release's XML parsing. Added `OQ-ART-08`. |
