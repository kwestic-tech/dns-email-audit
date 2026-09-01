# Spec: Private local validation of MTA-STS policies and BIMI artifacts

| Field | Value |
| --- | --- |
| Spec version | 1.1 (Final) |
| Target release | 0.8.0 |
| Status | Final; approved for implementation |
| Depends on | [rendering-and-robustness](implemented/rendering-and-robustness.md), the 0.6.0 module boundaries, and [findings-and-remediation](implemented/findings-and-remediation.md) for the final `Finding` shape |
| Blocks | [report-comparison](report-comparison.md), which must decide whether user-supplied findings enter a DNS report |
| Slug for open questions | `ART` |
| Last updated | 2026-09-01 |

## Problem

Two of the eight controls the tool scores cannot be fully evaluated from DNS.

MTA-STS publishes a TXT record at `_mta-sts.<domain>` that says only "a policy
exists, and here is its version id". The policy itself, which contains the mode,
the permitted MX patterns and the max age, lives at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. The tool validates the TXT
record's syntax in `validateMtaStsRecord()` in
[`src/core/transport/mta-sts.js`](../../src/core/transport/mta-sts.js) and sets
`policyVerified: false` in the DNS-only result. `calcScore()` in
[`src/audit/scoring.js`](../../src/audit/scoring.js) therefore awards half the MTA-STS pillar,
four points out of eight, to every domain that publishes a syntactically valid
TXT record. `README.md` states the reason honestly under Known limitations:
browser CORS restrictions prevent reliable policy retrieval.

BIMI has the same shape. `validateBimiRecord()` in
[`src/core/bimi/bimi.js`](../../src/core/bimi/bimi.js) confirms the `l=` and
`a=` values are HTTPS
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
3. BIMI SVG accepted by paste or file selection and inspected against the
   security-critical and operator-actionable SVG Portable/Secure requirements.
   The result is diagnostic, not a claim of complete RNC-schema conformance.
4. Strict size and type limits, enforced before parsing.
5. Rejection of DTDs, entity declarations, scripts, event handlers, external
   references and unsupported features.
6. User-supplied SVG never injected into the application DOM.
7. No automatic fetching of any MTA-STS, BIMI or VMC URL.
8. Every artifact-derived finding labelled "user supplied".

## Non-goals

- **No fetching.** Not of `.well-known/mta-sts.txt`, not of the BIMI `l=` URL,
  not of the VMC `a=` URL, not through a proxy, not with the user's permission,
  not behind a flag. `connect-src` remains `'self' https://cloudflare-dns.com`
  and the CSP test from 0.2.3 enforces it.
- **No rendering of the supplied logo.** The result describes the SVG; no image
  preview, parsed node or `blob:` URL is created.
- **No VMC inspection.** Structural PEM details without chain validation do not
  answer whether a mailbox provider will accept the certificate. The existing
  DNS result continues to report the `a=` URL without fetching it.
- **No persistence.** Supplied artifacts live in a JavaScript variable for the
  lifetime of the page. Nothing is written to `localStorage`, `IndexedDB`, a
  cookie, or a cache.
- **No scoring change.** A user-supplied MTA-STS policy does not turn the
  existing half-credit into full credit. Public-DNS grades remain reproducible.

## Design

### 0. Architecture and implementation boundary

The pre-refactor proposal for one `js/artifact.js` is withdrawn. Artifact
validation crosses two protocol owners and a UI, so the shipped allowed-edge
matrix determines the split:

| Responsibility | Owner |
| --- | --- |
| MTA-STS policy grammar and MX-pattern comparison | `src/core/transport/mta-sts-policy.js` |
| BIMI SVG security screening and P/S diagnostics | `src/core/bimi/` siblings |
| Converting validator results into 0.7.0 findings and attaching provenance | `src/audit/artifacts.js` |
| File/paste controls and token-only rendering | `src/ui/events.js` and `src/ui/render.js` |
| Constructing one artifact-analysis capability, including the injected XML parser, and passing it to the UI | `src/runtime.js` |

The protocol validators are deterministic over their inputs: strings,
already-audited MX facts and an injected `parseSvg` callback in; tokens and
primitives out. `DOMParser` is added to the platform capability set and is
constructed by `src/runtime.js`; no protocol owner reads an ambient browser
global. The validators import only permitted siblings or `core/shared/`.
`src/audit/artifacts.js` is the only cross-protocol composer. `src/ui/` receives
an injected callback and imports neither protocol owner. This adds no allowed
edge. Implementation is divided into directory-bound commits so a protocol-rule
change is never combined with a UI behavior change.

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
in `src/ui/events.js`, which already enforces a 1 MB cap through
`MAX_UPLOAD_BYTES`.

### 2. Limits, enforced before parsing

| Artifact | Byte limit | Accepted type | Rationale |
| --- | --- | --- | --- |
| MTA-STS policy | 64 KB | `text/plain` | A conformant policy is a few hundred bytes |
| BIMI SVG | 32 KB | `image/svg+xml` | The BIMI specification's own recommended ceiling |

The declared MIME type from the file picker is advisory and is checked, but the
byte limit and the content inspection are what actually enforce the boundary. A
`.svg` file containing HTML is rejected by the parser, not by its extension.

For selected files, `File.size` is checked before `FileReader` runs. For pasted
text, the UTF-8 byte length is measured with the already-injected `Blob`
capability. JavaScript string length is not a byte count and MUST NOT enforce
either limit. Oversized input never reaches a protocol parser.

### 3. MTA-STS policy validation

RFC 8461 §3.2 defines the policy as a sequence of `key: value` lines. Its prose
describes CRLF-separated fields, while its normative ABNF permits either LF or
CRLF for each terminator. Both forms, including a mixture, are valid.

```js
function validateMtaStsPolicy(text) → {
  valid: boolean,
  version: string,                     // must be 'STSv1'
  mode: 'enforce' | 'testing' | 'none' | null,
  mx: string[],                        // patterns, one per line, '*.' allowed
  maxAge: number | null,               // seconds
  duplicateKeys: string[],
  unknownKeys: string[],
  lineEndings: 'crlf' | 'lf' | 'mixed' | 'none',
  errors: string[],                    // tokens
  warnings: string[],
  diagnostics: [{ token: string, line: number }],
}
```

Validation rules:

- `version: STSv1` must be present. Unlike the DNS TXT record, the policy ABNF
  does not require the version field to come first.
- `mode` must be exactly one of `enforce`, `testing`, `none`.
- `max_age` must be a non-negative integer not exceeding 31557600. Zero is
  valid and is also reported by the short-lifetime diagnostic.
- At least one `mx` line is required unless `mode: none`.
- `mx` patterns permit a single leading `*.` wildcard and nothing else. The
  wildcard matches exactly one left-most label: `*.example.com` matches
  `mail.example.com`, not `example.com` or `a.b.example.com`.
- Later duplicates of a non-`mx` field are ignored, as RFC 8461 requires. They
  are reported as hygiene diagnostics rather than making the policy invalid.
- Unknown syntactically valid extension fields are retained in `unknownKeys`
  for display and ignored for validity. The module header and tests preserve
  that policy extension values may contain `=` and `;`, even though the DNS
  TXT record parser's different ABNF refuses those characters.
- A leading UTF-8 BOM is removed before field parsing and reported as the
  `bom-present` hygiene warning. Blank lines are invalid and produce
  `blank-line`; other lines that cannot be parsed produce `malformed-line`.
  Neither condition discards diagnostics already collected from other lines.
- Field names and registered values are case-sensitive. A case-insensitive
  spelling of a registered field produces `wrong-case-field` at that line,
  rather than being presented only as an unknown extension.
- LF, CRLF and mixed terminators are recorded as evidence but produce no error
  or warning. `none` records an input with no terminator; it is part of the
  parser's result vocabulary even though such an input cannot contain every
  required policy field.
- `errors`, `warnings`, `lineEndings` and the MX comparison state are frozen,
  exported vocabularies registered in `tests/state-algebras.json` and covered
  in `tests/state-matrix.json`. The SVG rejection and diagnostic vocabularies
  receive the same treatment when their validators are added.

Cross-checks against DNS data already held, which is where the value is:

| Check | Precondition and condition |
| --- | --- |
| `mta-sts.policy-mx-mismatch` | Only when the DNS MX result is known and is not null MX: an MX host from DNS matches no `mx` pattern in the policy. This breaks mail delivery in `enforce` mode. |
| `mta-sts.policy-mx-unused` | Only when the DNS MX result is known and is not null MX: an `mx` pattern matches none of the domain's MX hosts. Usually a stale policy after a provider migration. |
| `mta-sts.policy-on-null-mx` | The domain publishes RFC 7505 null MX while the supplied policy advertises mail handling. This is distinct from an MX mismatch. |
| `mta-sts.mode-testing` | `mode: testing` provides no enforcement. |
| `mta-sts.mode-none` | `mode: none` actively withdraws a previously published policy. |
| `mta-sts.max-age-short` | `max_age` under 86400 seconds weakens the protection substantially. |

The MX cross-check is the headline feature. A policy whose `mx` patterns do not
cover the domain's actual MX hosts causes conformant senders in `enforce` mode to
refuse delivery, and it is invisible to every check the tool currently performs.
The comparator therefore accepts the audit's MX fact as
`{ hosts, unknown, nullMx }` and returns a closed state of `compared`, `unknown`
or `null-mx`. In either non-compared state, both mismatch arrays are empty.

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
validators additionally live outside `src/ui/` and return no nodes, so the
import graph prevents a future maintainer from casually wiring parsed material
into the renderer.

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

Profile diagnostics, which are findings rather than security rejections:

| Check | Requirement |
| --- | --- |
| SVG namespace is `http://www.w3.org/2000/svg` | Required by the document definition |
| `baseProfile="tiny-ps"` | Required by the SVG P/S profile |
| `version="1.2"` | Required |
| Exactly one direct-child `<title>`, present and non-empty | Required |
| A non-empty `<desc>`, when present | Required |
| `viewBox` present, square aspect ratio | Operator compatibility diagnostic |
| No `x` or `y` on the root | Required |
| Single root element | Required |
| No raster data URI in a fill or a `<style>` | Required |
| `zoomAndPan`, `externalResourcesRequired`, `focusable`, `snapshotTime`, `playbackOrder` and `timelineBegin` absent or set to their permitted inert values | Required when present |

Every one of these is reported with the requirement it comes from, because "your
logo may not display" is useless without "and here is the line to change". The
panel says explicitly that it does not run the full SVG P/S RNC schema and does
not certify mailbox-provider acceptance.

### 5. Result and export handling

Artifact findings live in a separate array from DNS findings:

```js
artifactFindings: [{
  // The 0.7.0 identity, display, severity, confidence, dependency, effort and
  // category fields. keyspace remains 'finding'.
  id, key, keyspace, protocol, severity, confidence,
  args, noteKey, noteArgs, dependsOn, blocks, effort, category,
  source: 'user-supplied',
  artifact: 'mta-sts-policy' | 'bimi-svg',
  evidence: [{
    kind: 'line' | 'element' | 'input',
    location: string, // e.g. 'line 3', '<svg>', or the artifact label
    value: string,    // the bounded user-supplied material that caused it
  }],
}]
```

`artifactFindings` is never merged into the DNS-derived `findings` array. Its
`source`, `artifact` and evidence `kind` fields each have their own closed
vocabulary and constructor in `src/audit/artifacts.js`; the DNS-only
`audit.finding.evidence.kind` algebra and its `queryName` contract do not widen.
The shared metadata shape does not make DNS evidence rendering reusable. The
artifact branch in `src/ui/events.js` renders `location` as bounded text/code
and `value` through the existing value renderer; it never calls `R.host()` and
never maps `location` into `queryName`. This named branch preserves the DNS
evidence contract while showing both halves of an actionable artifact result.

`source: 'user-supplied'` is rendered on every artifact finding, and it survives
into the CSV and HTML exports. The reason is provenance: a report handed to a
third party must not blur the line between what the tool observed in public DNS
and what someone typed into a text box.

Artifact findings do not enter `calcScore()`. CSV appends three columns after
all existing columns: artifact finding ids, artifact severities and artifact
evidence with its user-supplied provenance. It does not append artifact ids to
the existing DNS findings cell. Static HTML renders a separate artifact section
with the same provenance. These are presentations of the current session.
The versioned JSON report introduced by 0.9.0 excludes them so a comparison
continues to describe reproducible public-DNS observations.

The existing `mta-sts.policy-unverified` copy is revised to say that the
DNS-only audit did not fetch the HTTPS policy and to point the user to the local
artifact panel. It must not say the policy cannot be checked once a supplied
policy has been analyzed.

## Localization impact

Budget 95 to 145 new English leaf keys: panel headings and instructions, the
MTA-STS policy checks, SVG rejection tokens, SVG profile diagnostics, the
"user supplied" label, limit and type errors, export headings and privacy copy.
The range is based on the existing finding metadata rate rather than counting
conditions as though each needed one string. Rejection-token findings may share
a parameterized message whose `{0}` is the untranslated token, but their
actionable explanation and remediation still have to be represented honestly.
Against the current 732-key English corpus, all new keys must be translated
across all 13 tracked locales in the same change.

Never translated: `STSv1`, `enforce`, `testing`, `none`, `max_age`, `mx`,
`baseProfile`, `tiny-ps`, `viewBox`, `<title>`, `xlink:href`, `foreignObject`
and file extensions. Always translated: "user supplied", "policy", "logo",
"rejected", "not fetched", and every explanatory sentence.

The privacy statement in the panel is the most important string in the release
and should be reviewed as copy, not only as translation.

## Testing

`validateMtaStsPolicy()` is pure and tests in the existing sandbox.

The SVG parser is tested in a real Chromium-family engine through the existing
dependency-free DevTools Protocol harness used by
`tests/build/file-url.test.mjs`. The new suite is named
`tests/build/local-input-security.test.mjs` to avoid collision with the existing
deployment `artifact.test.mjs`. It is invoked by
`npm run test:local-input-security` and a required CI job named
`Local input security (real browser)`; it is not hidden behind `npm test`, whose
supported environments do not all provide a browser. The test drives the production bundle and the
real panel, records `Network.requestWillBeSent`, instruments storage writes, and
wraps DOM insertion methods to fail if a node whose `ownerDocument` is the
parsed artifact document enters the application document. This tests the parser
the browser actually ships rather than substituting a Node XML implementation.

The browser suite's instrument is proved before it is trusted: a deliberately
unsafe local fixture attempts one network request, one storage write and one
foreign-document insertion, and the harness must detect all three. Removing
each detector in a temporary negative run must make its corresponding assertion
fail. This is the resolved `OQ-ART-08` mechanism and adds no dependency.

MTA-STS fixtures: a conformant `enforce` policy; `mode: testing`; `mode: none`;
missing `version`; version not first and still valid; duplicate `mode` with the
first value retained; `max_age` of 0 and valid, of 31557601 and invalid, and
non-numeric; wildcard `mx` patterns matching exactly one label and not matching
the apex or two labels; LF-only, CRLF and mixed line endings all valid; a 64 KB
policy accepted and a 65 KB one rejected before parsing; a policy containing
null bytes; a leading BOM warning; interior and extra trailing blank lines with
line numbers; a malformed line that does not erase a separate invalid field;
wrong-case registered names; extension punctuation; an unknown MX result that
emits no mismatch; and a null-MX result that emits only its dedicated finding.

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

The browser run is the behavioral proof that parsing causes no request,
persistence or foreign-node insertion. The unchanged CSP and its existing
source test remain independent defense in depth.

## Acceptance criteria

1. Every artifact is processed entirely in memory. No fixture produces a network
   request, a storage write, or an inserted DOM node.
2. `connect-src` in `index.html` is unchanged and the 0.2.3 CSP test still
   passes.
3. No MTA-STS, BIMI or VMC URL is fetched under any code path, verified by the
   import graph plus source scans over `src/core/transport/mta-sts-policy.js`,
   the new `src/core/bimi/` validators and `src/audit/artifacts.js` for network,
   platform and markup sinks.
4. Every artifact-derived finding carries `source: 'user-supplied'` in the
   interface and in both exports.
5. Reloading the page discards every supplied artifact.
6. `calcScore()` output is unaffected by artifact input.
7. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.
8. `npm run test:local-input-security` passes, its deliberate unsafe instrument
   is shown to fail when each detector is removed, and the required
   `Local input security (real browser)` CI job invokes that script.

## Risks

**SVG is a hostile format and this release accepts it from strangers.** The
entire mitigation is that the parsed document is never inserted anywhere, which
is a rule enforced by convention plus a file boundary plus a test. Mitigation:
the protocol validators have no dependency on the renderer, their public APIs
return only tokens and primitives, and the test suite asserts no insertion.

**Users will expect the tool to fetch the file for them.** The panel is more
work than a button that says "check my policy", and the reason for the extra work
is invisible to someone who has not read `PRIVACY.md`. Mitigation: state the
reason in the panel in one sentence, and link to the privacy document.

**Scope creep toward rendering the logo.** Displaying the supplied SVG is an
obvious next request and would reintroduce every risk this design removes.
Mitigation: 0.8.0 explicitly ships no preview and keeps `img-src` unchanged.

**The panel dilutes the tool's identity.** Everything else in the application is
a bulk DNS auditor. This is a single-domain file inspector. Mitigation: the panel
is collapsed by default and clearly subordinate.

## Resolved questions

| Question | Decision | Reasoning |
| --- | --- | --- |
| `OQ-ART-01` | Accept the policy body only. | HTTP status, redirects, certificate validation and response media type cannot be established faithfully from pasted headers. A second ambiguous input mode would appear to validate evidence it did not observe. |
| `OQ-ART-02` | Parse with `image/svg+xml`. | Correct SVG namespace semantics matter to the diagnostics. The document remains detached, no parsed node may cross into the application document, and the real-browser hostile-fixture suite verifies inert behavior. |
| `OQ-ART-03` | Never display the logo. | A preview is not validation and would require a new image-loading path plus a CSP change. Tokens and primitives are the only validator outputs. |
| `OQ-ART-04` | Drop VMC inspection from 0.8.0. | Without trust-chain and mailbox-provider validation, decoded certificate metadata does not answer the useful question and adds a DER parser and maintenance surface. |
| `OQ-ART-05` | User-supplied artifacts never affect the score. | A public-DNS grade must not depend on unverified text supplied by the person running the audit. No second score is introduced. |
| `OQ-ART-06` | One domain and one artifact of each type at a time. | Batch filename-to-domain inference is a separate workflow and an avoidable matching surface. It may be proposed later with its own spec. |
| `OQ-ART-07` | Exclude artifact findings from 0.9.0's versioned JSON comparison report. | CSV and static HTML may present the current session with explicit provenance, but longitudinal comparison remains reproducible from public observations alone. |
| `OQ-ART-08` | Use the existing automated Chromium/CDP harness; add no parser dependency. | It exercises the production bundle with the browser's real `DOMParser`, records network activity, storage writes and foreign-document insertion, and includes a deliberate unsafe instrument proving each detector can fail. A Node parser substitute would test different behavior. |

### Review corrections made before Final

Review against RFC 8461 corrected four draft rules: `max_age` is non-negative
and therefore permits zero; LF and CRLF are both valid policy terminators;
later duplicate non-`mx` fields are ignored rather than fatal; and the policy
version field, unlike the TXT version field, is not required to come first.
Wildcard MX matching is also stated as exactly one left-most label.

Review against the current SVG Tiny PS draft bounded the product claim. The
panel performs security rejection and named high-value profile diagnostics; it
does not implement the complete RNC schema and must not label an SVG fully
conformant or accepted by a mailbox provider. UTF-8 byte limits replace the
draft's incorrect JavaScript string-length check.

### Review round after 1.0 Final

Every claim in this round was reproduced against the repository before the spec
was amended.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| Localization estimate | Accepted | Counting conditions understated the existing finding key shape by roughly two to three times. The budget is now 95–145 leaf keys, with parameterization allowed only where it preserves actionable copy. |
| Unknown and null-MX comparison | Accepted | An empty host list previously reported every pattern as unused. Comparison now has explicit `unknown` and `null-mx` states; null MX receives its own finding. |
| Unregistered vocabularies | Accepted | Policy error, warning, line-ending and comparison tokens, and later SVG tokens, are frozen exports registered in both state files. |
| Undeclared `none` line ending | Accepted | The parser already returns it for unterminated input, so the public result vocabulary now declares and tests it. |
| Artifact evidence renderer mismatch | Accepted | The DNS renderer ignores `location`; a named artifact branch renders `location` and `value` without widening `queryName`. |
| Malformed-line diagnostic loss | Accepted | BOM, blank lines and generic malformed lines are distinguished, carry line numbers, and no longer erase other errors. |
| Case-sensitive field diagnostic | Accepted | RFC case sensitivity remains strict, with a dedicated wrong-case error instead of only an unknown-extension presentation. |
| DNS-only unverified copy | Accepted | The copy will distinguish no automatic fetch from local user-supplied validation and point to the panel. |
| CSV artifact shape | Accepted | Three artifact-only columns are appended; DNS finding columns retain their meaning and position. |
| Browser-suite invocation | Accepted | The spec now names the script, file and required CI job explicitly. |
| Policy module absent from the bundle at its first commit | Declined as a defect | A directory-bound pure-module commit is intentionally test-first and browser-working. The module enters the single delivery artifact when the audit composer is added; state registration covers source contracts, not bundle reachability. |
| `artifact` naming collision | Accepted | The browser suite is named `local-input-security`; `src/audit/artifacts.js` remains the domain composer, and the existing deployment artifact test keeps its established name. |
| Extension-value asymmetry | Accepted | It follows different RFC productions and is now documented and pinned by a test so it is not normalized to the TXT parser later. |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.1 | 2026-09-01 | Amended Final after reproducing the first implementation review. Added explicit unknown and null-MX comparison states; registered closed vocabularies; declared `lineEndings: none`; preserved per-line malformed diagnostics; added BOM, blank-line and wrong-case decisions; named the artifact evidence renderer branch, export columns, unverified-policy copy change, browser script and CI job; renamed the browser suite; documented policy extension punctuation; and replaced the low localization estimate with a measured 95–145-key budget. Recorded all accepted and declined review outcomes. |
| 1.0 | 2026-09-01 | Final. Resolved all eight open questions: body-only MTA-STS input; `image/svg+xml` parsing; no logo rendering; VMC removed; no scoring; single-artifact workflow; artifact findings excluded from 0.9.0 JSON comparison; and real-browser hostile-SVG verification through the existing Chromium/CDP harness. Corrected the RFC 8461 rules for zero `max_age`, line endings, duplicate fields, version ordering and one-label wildcard matching. Bounded SVG output to security rejection and named profile diagnostics rather than unsupported full-schema certification, and replaced string length with UTF-8 byte measurement. |
| 0.2 | 2026-08-31 | Renumbered the target to 0.8.0 and rebased the design onto the 0.6.0 allowed-edge matrix. Replaced the proposed `js/artifact.js` monolith with pure validators under the existing MTA-STS and BIMI protocol owners, composition in `src/audit/`, injected UI capabilities through `src/runtime.js`, and directory-bound implementation commits. Added the now-sequential dependency on 0.7.0's final finding shape and updated the report dependency to 0.9.0. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
| 0.1 | 2026-08-20 | Not a version bump. Recorded a downstream consequence of the 0.2.3 rescope: `OQ-SEC-01` resolved to a dependency-free DOM shim, which cannot test this release's XML parsing. Added `OQ-ART-08`. |
