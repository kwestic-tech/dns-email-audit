# Spec: Private local validation of MTA-STS policies and BIMI artifacts

| Field | Value |
| --- | --- |
| Spec version | 1.11 (Implemented, amended) |
| Target release | 0.8.0 |
| Status | Released as `v0.8.0` |
| Depends on | [rendering-and-robustness](rendering-and-robustness.md), the 0.6.0 module boundaries, and [findings-and-remediation](findings-and-remediation.md) for the final `Finding` shape |
| Blocks | [report-comparison](../report-comparison.md), which must decide whether user-supplied findings enter a DNS report |
| Slug for open questions | `ART` |
| Last updated | 2026-09-03 |

## Problem

Two of the eight controls the tool scores cannot be fully evaluated from DNS.

MTA-STS publishes a TXT record at `_mta-sts.<domain>` that says only "a policy
exists, and here is its version id". The policy itself, which contains the mode,
the permitted MX patterns and the max age, lives at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. The tool validates the TXT
record's syntax in `validateMtaStsRecord()` in
[`src/core/transport/mta-sts.js`](../../../src/core/transport/mta-sts.js) and sets
`policyVerified: false` in the DNS-only result. `calcScore()` in
[`src/audit/scoring.js`](../../../src/audit/scoring.js) therefore awards half the MTA-STS pillar,
four points out of eight, to every domain that publishes a syntactically valid
TXT record. `README.md` states the reason honestly under Known limitations:
browser CORS restrictions prevent reliable policy retrieval.

BIMI has the same shape. `validateBimiRecord()` in
[`src/core/bimi/bimi.js`](../../../src/core/bimi/bimi.js) confirms the `l=` and
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
- At least one `mx` line is required when `mode` is `enforce` or `testing`.
  When `mode` is absent or invalid the requirement is not established, so no
  `missing-mx` is claimed and the mode error carries the invalidity on its own.
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
  spelling of a registered field produces the `wrong-case-field` **warning** at
  that line, rather than being presented only as an unknown extension. It is a
  warning and not an error because `sts-policy-ext-name` permits `Mode`, and
  §3.2 says unknown fields SHALL be ignored: a conformant policy may carry a
  case-variant extension and must not be reported invalid. Where the operator
  did mean the registered field, the resulting `missing-*` error already
  carries the invalidity and this token only explains it. The warning does not
  short-circuit the field: a case variant is retained in `unknownKeys` and
  takes the ordinary non-`mx` duplicate rule, exactly like any other
  extension, because that is what it is.
- `diagnostics` is a line index, not a mirror of `errors` + `warnings`. Every
  token raised against a line appears in both. The four `missing-*` errors are
  raised against the document and have no line, so they appear in `errors`
  only and take the `kind: 'input'` evidence variant, located by the artifact
  label rather than a line.
- LF, CRLF and mixed terminators are recorded as evidence but produce no error
  or warning. `none` records an input with no terminator; it is part of the
  parser's result vocabulary even though such an input cannot contain every
  required policy field.
- `errors`, `warnings`, `lineEndings` and the MX comparison state are frozen,
  exported vocabularies registered in `tests/state-algebras.json` and covered
  in `tests/state-matrix.json`. The SVG rejection and diagnostic vocabularies
  receive the same treatment when their validators are added.

Cross-checks against DNS data already held, which is where the value is.

#### The semantic-finding matrix

Parsing says what a document contains. It does not say which readings of it are
honest, and **every** semantic finding has a policy state in which it becomes a
lie — not just the two mismatch classes. `policyFindingScope(policy)` is the one
place that decision lives; `src/audit/artifacts.js` reads its flags and does not
re-derive them.

| Policy state | Semantic findings allowed |
| --- | --- |
| **Invalid** | Parser and profile diagnostics, and hygiene, only. No mode, max-age, null-MX or mismatch interpretation — each would be built from the fields that happened to survive parsing, describing a document no sender will honour. |
| **Valid `none`** (withdrawal) | `mta-sts.mode-none` and hygiene. No max-age-short, no null-MX conflict, no mismatch findings. |
| **Valid `testing`** | `mta-sts.mode-testing`; max-age-short when applicable; and either the null-MX conflict or the gated MX comparison. |
| **Valid `enforce`** | Max-age-short when applicable; and either the null-MX conflict or the gated MX comparison. No mode finding — `enforce` is the intended state. |

The withdrawal row is the one with teeth. RFC 8461 §8.3's removal procedure is
*"Publish a new policy with 'mode' equal to 'none' and a small 'max_age' (e.g.,
one day)."* One day is exactly the `max-age-short` threshold, so emitting that
finding against a conforming withdrawal document tells the operator to work
against the protocol's own removal steps.

The individual checks, each gated by the matrix above:

| Check | Precondition and condition |
| --- | --- |
| `mta-sts.policy-mx-mismatch` | Scope allows `mxComparison`, **and** `compareMtaStsMx()` returned `compared`: a delivery candidate matches no `mx` pattern in the policy. This breaks mail delivery in `enforce` mode. |
| `mta-sts.policy-mx-unused` | Same two conditions: an `mx` pattern matches none of the domain's delivery candidates. Usually a stale policy after a provider migration. |
| `mta-sts.policy-on-null-mx` | Scope allows `nullMxConflict`, **and** the comparator returned `null-mx`. Arrives with the composer. The domain publishes RFC 7505 null MX while the supplied policy advertises mail handling. Distinct from an MX mismatch. |
| `mta-sts.mode-testing` | Scope is `testing`. `mode: testing` provides no enforcement. |
| `mta-sts.mode-none` | Scope is `withdrawal`. `mode: none` actively withdraws a previously published policy. |
| `mta-sts.max-age-short` | Scope allows `maxAgeFinding`, i.e. never on a withdrawal or an invalid policy: `max_age` under 86400 seconds weakens the protection substantially. |

#### Why the policy-side preconditions exist

Without them the composer produces confident false findings from documents that
are not defects at all. All are executed in `mta-sts.test.js`:

- A **valid `mode: none`** policy legitimately carries no `mx` at all, because
  it withdraws enforcement. `compareMtaStsMx([], { hosts: ['mail.example.test'] })`
  reports `unmatchedHosts: ['mail.example.test']` — a `policy-mx-mismatch` on a
  policy that is deliberately inactive. `mta-sts.mode-none` is the finding that
  case deserves.
- An **invalid** policy still exposes whichever `mx` lines happened to parse, so
  comparing that partial list reports mismatches and unused patterns derived
  from a document no sender will honour.

- A **valid `mode: none`** policy with `max_age: 3600` is RFC 8461 §8.3's own
  removal document. `max-age-short` on it is advice to break the removal
  procedure, so the withdrawal scope suppresses it — while the same `max_age`
  under `enforce` still raises it.

The composer therefore emits the parser's own diagnostics first, then consults
`policyFindingScope(policy)` before every semantic finding. `mxComparisonApplies`
remains available as the named view of that matrix's `mxComparison` row and
delegates to it, so the rule has exactly one implementation.

#### The comparator's contract, now and at the end state

The MX cross-check is the headline feature. A policy whose `mx` patterns do not
cover the domain's delivery candidates causes conformant senders in `enforce`
mode to refuse delivery, and it is invisible to every check the tool currently
performs. The contract is deliberately different before and after the composer,
and the transition is atomic rather than gradual:

| | Fact accepted | States returned |
| --- | --- | --- |
| **Current protocol commit** | `{ hosts: string[], unknown }` | `compared`, `unknown` |
| **Composer / end-state commit** | `{ hosts: string[], unknown, nullMx }` | `compared`, `unknown`, `null-mx` |

`nullMx` and the `null-mx` state are added to the constant, both state files and
this table **in the same commit as `src/audit/artifacts.js`**, which is their
only producer. Until then a null-MX domain reaches the comparator as an empty
host list and degrades to `unknown`. In every non-`compared` state, both
mismatch arrays are empty.

**`src/audit/artifacts.js` builds that fact from the domain's delivery
candidates, and never from `advanced.mxHealth`.** No such `{ hosts, unknown }`
object exists in the audit result today; the composer constructs it. Three
reasons for excluding `mxHealth`, each independently sufficient:

1. `mxHealth.hosts` holds audit objects, not hostnames. `audit-domain.js`
   already writes `mxHealth.hosts.map(h => h.host)` to get names out of it.
   Passing the raw shape stringifies each entry to `[object Object]`, so a
   correctly configured domain reports a mismatch against nothing.
2. `advanced.mxHealth` is initialised to `null` and replaced only when deep
   checks are on, the domain has MX records, and it is not a null MX. The
   interface disables deep checks above 50 domains, so on the largest audits
   the fact is absent for every row.
3. MTA-STS `mx` patterns describe which exchanges the policy permits, which the
   base MX lookup answers for every domain. Binding the headline check to a
   cost-gated resolution-health artifact would switch it off silently.

#### Delivery candidates are not MX records

RFC 5321 §5.1: *"If an empty list of MXs is returned, the address is treated as
if it was associated with an implicit MX RR, with a preference of 0, pointing
to that host"*, and that rule *"applies only if there are no MX records
present"*. RFC 7505 exists to distinguish "no explicit MX" from "accepts no
mail". A domain with no MX and a usable address record therefore has exactly
one delivery candidate — itself — and a policy publishing `mx: example.com`
covers it correctly. Building `hosts` from published MX records alone would
report that policy stale.

The composer MUST distinguish four cases:

| Domain state | Fact |
| --- | --- |
| Explicit null MX (RFC 7505 `0 .`) | the `null-mx` non-comparison state |
| Explicit MX records, all parseable | `hosts` = their parsed exchange hostnames |
| No MX, plus a usable A or AAAA record | `hosts` = the audited domain itself, the RFC 5321 §5.1 implicit MX |
| No established candidate, an unusable input, or any MX record that fails to parse | `unknown` |

The last row is a fail-closed rule, not a convenience: a partially parsed MX
set cannot distinguish a stale pattern from an unread one, so the composer
fails the whole comparison rather than silently filtering the entry out.

There is deliberately **no "the lookup failed" input**. A base MX failure
rejects `analyzeDomain()`, so no completed audit result carries such a flag and
nothing could set one. `unknown` today means what the data says: no candidate
established, or a record that would not parse. The input arrives with its
producer, if a runtime ever gains one — the same rule that kept `null-mx` out
of the comparison vocabulary until `deliveryCandidates()` existed to derive it.

#### Fail-closed rules the comparator enforces today

An empty or silently-filtered host list compares as "every pattern is unused",
so an absent fact read as an empty one turns a healthy policy into a
stale-policy claim. The comparator returns `unknown` on:

- an absent, non-object fact, or one carrying `unknown`;
- a missing or non-array `hosts`;
- an **empty** `hosts` array — no delivery candidate is established;
- any entry that is not a string, or that is not a valid hostname after
  normalisation, including `''`, whitespace-only and a bare `.`.

A single invalid entry fails the whole comparison. Each guard ships with a
negative run proving it fails when removed.

#### `null-mx` is not a member yet

`MTA_STS_MX_COMPARE_STATES` is `['compared', 'unknown']`. Nothing in the tree
produces a `nullMx` fact — null MX exists as `isNullMx()` and the `@null-mx`
provider token — and a registered state the fixture corpus cannot reach is a
stop under the agent contract, with a hand-built `{ nullMx: true }` in a unit
test being exactly the invented response shape that rule names. The member is
added to the constant, `tests/state-algebras.json` and `tests/state-matrix.json`
in the **same reviewed step** as the composer that produces it. Until then a
null-MX domain arrives as an empty host list and degrades to `unknown`, which
claims nothing untrue.

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
| Any attribute value containing a `url(` whose argument is not a same-document fragment | `external-reference` |
| `<a>` with any target | `link-element` |
| `<style>` text containing `@import`, or a `url(` whose argument is not a same-document fragment | `external-style` |
| `<animate>`, `<animateTransform>`, `<set>`, `<animateMotion>` | `animation` |
| A parser error node | `malformed-xml` |
| Anything other than `<svg>` as the root | `bad-root` |

#### One `url()` matcher, applied in both positions

Amendment 1.10. The rule stated above replaces two rules that were each wrong
in a different direction, and the correction is one matcher used twice rather
than a widening of the existing one.

**Attributes were under-screened.** SVG permits a paint server, a filter, a
mask, a clip path and a marker to be named with `url()` in a presentation
attribute or in a `style` attribute, and that argument may point at another
document. Through 1.9 the screen tested `href` and `xlink:href` only, so an
external reference in any other attribute reached a `bimi.svg-valid` verdict.
Measured against the shipped `validateBimiSvg()`:

```text
VALID     fill="url(https://evil.example/p.svg#g)"
VALID     style="fill:url(https://evil.example/p.svg#g)"
VALID     style="filter:url(https://evil.example/f.svg#blur)"
```

Nothing is fetched — the parsed document never enters the page and the
validator produces tokens, never nodes — but the tool told an operator that a
logo which would beacon from a mail client, and which SVG Tiny PS forbids, had
passed. The heading of the rule it passed was "external reference".

**`<style>` was over-screened, and this is the half that changes a verdict for
a conformant logo.** The 1.9 matcher was `/@import|url\s*\(/i`, which rejects
*every* `url(`, including a purely local one. A logo that defines a gradient and
refers to it from a stylesheet — ordinary, conformant SVG — was rejected as
`external-style`:

```text
REJECTED  <style>.a{fill:url(#localGradient)}</style>  -> external-style
```

Widening that matcher to every attribute, which is what the review first
proposed, would have propagated the false positive across the whole element
tree rather than fixing anything.

**The corrected rule.** One matcher: a `url(` whose argument, after optional
whitespace and optional quoting, does not begin with `#` is an external
reference. `@import` remains an unconditional rejection in `<style>` text. The
matcher is applied to `<style>` text and to every attribute value — every
attribute, not a list of the ones that take paint, because SVG accepts a
`url()` in `fill`, `stroke`, `filter`, `mask`, `clip-path`, `marker-*` and
`style`, and an attribute allowlist would need revisiting for each of them.
The `<style>` position keeps its `external-style` token and the attribute
position takes `external-reference`, because those tokens are already
registered in the closed vocabulary and an operator reading a rejection needs
to know which construct was refused, not only that a `url()` was.

Two arguments are neither an ordinary fragment nor an ordinary external
reference, and the rule names both:

| Argument | Verdict | Why |
| --- | --- | --- |
| `url()`, empty | `external-reference` | It addresses nothing and is not a fragment. The screen fails closed. |
| `url(data:…)` | `data-uri-reference`, a **diagnostic** | SVG Tiny 1.2's reference-restrictions table permits `fill` and `stroke` to name a category A local fragment only; a `data:` IRI is category E and is not permitted there. So this is a profile violation and must be reported. It is not a security refusal: the URI carries its own bytes, so it requires no network fetch and cannot beacon, and there is nothing to refuse. See below. |

#### Why `data:` is a diagnostic and not a rejection

Amendment 1.11, after review pushed back on 1.10 letting a `data:` paint
reference pass silently. The review was right that the construct is
non-conformant and wrong about where it belongs, and the distinction is the
one this file is built on.

`valid` is a **security** verdict. Spec 1.0 bounded this screen to "security
rejection and named profile diagnostics rather than unsupported full-schema
certification", and the two exported vocabularies say the same thing in code:
`BIMI_SVG_REJECTIONS` refuses a document outright, `BIMI_SVG_DIAGNOSTICS`
describes why a mailbox provider may decline to display it. Non-conformance
with SVG Tiny PS does not make a document invalid here, and never has:
`base-profile-not-tiny-ps`, `version-not-1-2`, `viewbox-not-square` and
`raster-data-uri` are all profile violations on documents this screen reports
as valid.

A `data:` URI requires no network fetch and cannot beacon, which is the
property `external-reference` exists to catch. It does still resolve to a
document distinct from the owner document — SVG Tiny 1.2 says so, and that is
precisely why the profile forbids it in a paint position — but "a distinct
document" and "a document fetched from somewhere else" are different claims,
and only the second is a refusal here. Putting it in the rejection vocabulary
would make one profile rule refuse a document while the four beside it do not,
and would reverse the shipped 0.8.0 verdict for a self-contained logo carrying
an embedded bitmap.

What 1.10 got wrong is that it reported nothing at all for the **vector** case.
`url(data:image/png…)` at least raised `raster-data-uri`, because a bitmap is
outside a vector-only profile; `url(data:image/svg+xml,…)` embeds no bitmap and
so reached `bimi.svg-valid` with no signal. The reference position is a
separate rule from the payload, and 1.11 gives it its own token. The two are
independent and can both fire: a raster `data:` in a `fill` now raises
`data-uri-reference` and `raster-data-uri`.

The matcher extracts the argument and tests it rather than deciding inside one
pattern. A single regex with optional quoting and optional whitespace
backtracks: the first attempt at this rule passed `url( #local )` — a local
reference with a space — as external, because `\s*` matched nothing and the
lookahead then saw the space instead of the `#`.

Both positions carry a `url(#fragment)` control asserting the document stays
valid. A fix that only adds the three hostile fixtures would pass while
preserving the false positive.

Profile diagnostics, which are findings rather than security rejections:

| Check | Requirement |
| --- | --- |
| SVG namespace is `http://www.w3.org/2000/svg` | Required by the document definition |
| `baseProfile="tiny-ps"` | Required by the SVG P/S profile |
| `version="1.2"` | Required |
| Exactly one direct-child `<title>`, present and non-empty | Required |
| A non-empty `<desc>`, when present | Required |
| `viewBox` present, square, and both extents greater than zero | Operator compatibility diagnostic |
| No `x` or `y` on the root | Required |
| No raster data URI in a fill or a `<style>` | Required |
| The six constrained attributes carry their permitted value when present | Required when present |

**The "single root element" row is withdrawn.** XML makes a second root a parse
error — measured in Chrome — so the condition arrives as `malformed-xml`, a
rejection. A diagnostic for it would be a state no fixture can reach.

**The six constrained attributes have enumerated values**, quoted from
[draft-svg-tiny-ps-abrotman-12 §2.3](https://datatracker.ietf.org/doc/html/draft-svg-tiny-ps-abrotman-12#section-2.3),
which says of each that it "SHOULD NOT be present in an SVG Tiny PS document.
If it is present, it MUST be set to" the value below:

| Attribute | Permitted value |
| --- | --- |
| `zoomAndPan` | `disable` |
| `externalResourcesRequired` | `false` |
| `focusable` | `false` |
| `snapshotTime` | `none` |
| `playbackOrder` | `all` |
| `timelineBegin` | `onLoad` |

`unsupported-attribute` means present with a value outside this table. Reporting
mere presence diagnosed the draft's own conformant example.

**Profile names are matched exactly; the security screen is not.** XML is
case-sensitive and the SVG Tiny PS schema names `svg`, `baseProfile`, `viewBox`
and `title` exactly, so folding case would tell an operator that a
nonconformant document conforms. Security screening deliberately keeps folding
case, because there the dangerous direction is missing a `<SCRIPT>`. The
asymmetry is intentional and each half is wrong in the safe direction for its
own job.

**A `viewBox` needs usable extents.** SVG Tiny 1.2 makes a negative width or
height an error and zero disables rendering, so comparing width to height alone
called `0 0 0 0` and `0 0 -64 -64` square. Both are `viewbox-missing`.

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
    location: string, // e.g. 'line 3', '<use>', or the artifact label
    value: string,    // the bounded user-supplied material that caused it
  }],
}]
```

**`value` is the supplied material, never the diagnostic token.** The token is
already the finding's `args`; repeating it as evidence tells an operator
nothing they did not have. `value` carries the offending policy line, the
offending attribute pair, or the offending URL.

**`location` names the offending construct, not the document.** An SVG
rejection is located at the element that caused it — `<use>`, `<script>` — not
at the root. A `line` location is the line the parser saw the token on, and a
repeated token produces ONE evidence entry PER OCCURRENCE at its own line.
`input` is for a condition raised against the whole document, such as a missing
required field, which has no line to point at.

**The owner validators supply this, and `src/audit/` never reparses.** The
composer may not re-split a policy body to recover line text, nor re-walk an
SVG to find an element: a second copy of a parser's own position handling would
diverge silently. `validateMtaStsPolicy().diagnostics` carries
`{ token, line, text }` and `validateBimiSvg().sites` carries
`{ token, element, value }`, one entry per occurrence.

**A condition with no position takes the `input` variant with an EMPTY value.**
A missing required field has no offending line and a pre-parse rejection has no
element, so neither may borrow the token as its material — the token is already
`args`, and repeating it says nothing. Several missing fields are one entry,
because they point at the same place. A pre-parse rejection still carries the
refused declaration itself, which is material rather than a token.

**Bounds are applied in code points.** `String.slice` through an astral
character leaves a lone surrogate; `tools/export.test.mjs` §10 exists because
that has already been a defect in this project once, and a bound applied at the
source must not manufacture malformed Unicode ahead of the renderer.

#### The artifact finding catalog

Twelve ids, frozen and exported as `ARTIFACT_FINDING_IDS`, registered as the
closed algebra `audit.artifact.finding.id`. It is deliberately separate from
`audit.finding.id`, which stays the DNS contract.

| Id | Severity | When |
| --- | --- | --- |
| `mta-sts.policy-invalid` | high | the parser reported any error |
| `mta-sts.policy-hygiene` | info | the parser reported only warnings |
| `mta-sts.policy-mx-mismatch` | critical | a delivery candidate no pattern covers — this breaks delivery under `enforce` |
| `mta-sts.policy-mx-unused` | medium | a pattern covering no candidate |
| `mta-sts.policy-on-null-mx` | medium | a mail-handling policy on an RFC 7505 null-MX domain |
| `mta-sts.policy-mx-unknown` | info, unverified | the MX fact could not be established, so the headline check did not run |
| `mta-sts.mode-testing` | medium | `mode: testing` |
| `mta-sts.mode-none` | high | `mode: none` withdraws the control |
| `mta-sts.max-age-short` | medium | `max_age` under 86400, where the scope permits the finding |
| `bimi.svg-rejected` | high | any security rejection |
| `bimi.svg-profile` | medium | profile diagnostics with no rejection |
| `bimi.svg-valid` | info | neither — the panel answers the question it was asked |

Two of these are outcomes the earlier check tables did not name, and both are
deliberate. **`policy-mx-unknown` is reported rather than skipped**: above the
50-domain deep-check threshold a user who supplied a policy would otherwise see
nothing and be unable to tell "no problem" from "not checked". **`bimi.svg-valid`
is reported for the same reason** — the panel exists to answer a question — and
its copy must not imply mailbox-provider acceptance.

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
Against the current **837-key** English corpus, all new keys must be translated
across all 13 tracked locales in the same change. 837 is what
`npm run locale:gate` counts and is the operative figure: `flatten()` in
`tools/lib/locale-utils.mjs` expands array values by index and drops `meta.*`,
so a naive count of JSON leaf objects reports 732 and understates the work by
105 keys.

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
wrong-case registered names as warnings that leave a conformant policy valid;
extension punctuation; an unknown MX result that emits no mismatch; a null-MX
result that emits only its dedicated finding; the fail-closed comparator
inputs — an absent fact, a fact with no `hosts` array, and the raw `mxHealth`
audit shape — each asserted not to produce the every-pattern-is-stale answer;
and the four finding scopes, each reachable from a real parser result, with the
§8.3 withdrawal document proven not to raise `max-age-short` while the same
`max_age` under `enforce` does.

Composer fixtures, when `src/audit/artifacts.js` lands, must prove **suppression
rather than absence** for at least: a valid `mode: none` policy with a small
`max_age`; a valid `mode: none` policy on a null-MX domain; and an invalid
policy carrying fields that would otherwise trigger mode, max-age and mismatch
findings. Asserting only that parsing failed would pass without the matrix.

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
| `<style>.a{fill:url(https://evil.example/p.svg#g)}</style>` | `external-style` |
| `<style>.a{fill:url(#localGradient)}</style>` | **Valid.** The 1.9 over-screening control |
| `fill="url(https://evil.example/p.svg#g)"` | `external-reference` |
| `style="fill:url(https://evil.example/p.svg#g)"` | `external-reference` |
| `style="filter:url(https://evil.example/f.svg#blur)"` | `external-reference` |
| `fill="url(#local)"` | **Valid.** The attribute-side under-screening control |
| `fill="url( #local )"`, `url("#local")`, `url('#local')` | **Valid.** Whitespace and quoting controls |
| `style="fill:url(#a);stroke:url(#b)"` | **Valid.** Two local references in one value |
| `style="fill:url(#a);stroke:url(https://evil.example/b#c)"` | `external-reference`. One external reference among local ones is still found |
| `stroke="url(//evil.example/p.svg#g)"` | `external-reference`. Scheme-relative is not a fragment |
| `fill="url()"` | `external-reference` |
| `fill="url(data:image/png;base64,…)"` | **Valid**, with `data-uri-reference` and `raster-data-uri`, and no rejection |
| `fill="url(data:image/svg+xml,…)"` | **Valid**, with `data-uri-reference` only — no bitmap, and through 1.10 no signal at all |
| `style="fill:url(data:image/png;base64,…)"` and the same inside `<style>` | **Valid**, with `data-uri-reference` |
| `fill="url(https://data.example/p.svg#g)"` | `external-reference`. A host called `data` is not a `data:` URI |
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

## As implemented

The release follows the final architecture: protocol parsing remains in the
MTA-STS and BIMI owners, `src/audit/artifacts.js` is the only cross-protocol
composer, `src/runtime.js` supplies the browser's XML parser, and the UI receives
one injected analysis callback. Artifact findings remain separate from DNS
findings and scoring while carrying explicit `user-supplied` provenance into
the panel, three appended CSV columns, and a separate static-report section.

Implementation and review sharpened seven details beyond the original 1.0 text:

1. The MTA-STS comparator consumes delivery candidates derived from the base MX
   and address facts, including implicit and null MX behavior. It never consumes
   the deep-check-only `advanced.mxHealth` objects.
2. Parser diagnostics retain every occurrence and its bounded supplied source.
   Missing fields use document-level evidence, and all evidence bounds preserve
   Unicode code points rather than slicing UTF-16 units.
3. The BIMI screen rejects DTD/entity, active-content and external-reference
   paths before profile diagnostics. It parses with the real browser
   `DOMParser`, never renders the logo, and claims a named screen rather than
   complete RNC certification or mailbox-provider acceptance.
4. The collapsed panel is enabled only by a completed DNS audit. Selected files
   are checked by `File.size` and declared MIME before `FileReader`; pasted text
   is measured as UTF-8 bytes with `Blob`. Any replacement input, including a
   rejected file, retires the previous per-domain result so stale findings
   cannot remain visible or exportable.
5. The production-browser security suite grew from method wrappers into a
   behavioral instrument: browser-external storage mutation events, network
   events and tagged-node observation prove that analysis performs no request,
   persistence or insertion. Its unsafe fixture and detector-removal runs prove
   each signal can fail. The same suite drives hostile SVG, policy paste, file
   size/MIME boundaries and successful file reading through the shipped panel.
6. The English bundle gained 106 leaf keys and all thirteen other locales ship
   complete. Token and protocol spellings remain literal; user-facing policy,
   logo, provenance, error, privacy and remediation prose is translated.
7. Finding cards explicitly separate live and static-report rendering, so
   array callback indexes cannot silently open later cards or remove their
   disclosure controls. File reads use per-artifact generations so an earlier
   read cannot overwrite a newer selection or paste. A finished 0.8.0
   five-surface baseline pins the resulting UI and export boundary exactly,
   while the release-compatibility suite bounds every intentional 0.7.0 delta.

No score, weight, threshold, DNS query path, `connect-src` destination, storage
contract or public `DnsAudit` facade member changed. The release adds one local,
session-only input surface and no automatic artifact retrieval.

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

### Review round after 1.1

Every claim in this round was reproduced by executing the module before the
spec was amended.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| Comparator fact contract matched no fact the audit produces | Accepted | `mxHealth.hosts` holds audit objects, so a healthy domain compared against `[object Object]` and reported every pattern stale. `advanced.mxHealth` is also `null` for null MX, for no MX, and whenever deep checks are off, all of which read as an empty host list. The fact source is now the published MX records, the comparator fails closed to `unknown`, and both guards have negative runs. |
| `null-mx` registered but unreachable | Accepted | No producer sets a `nullMx` field; null MX exists as `isNullMx()` and the `@null-mx` provider token. The member stays registered with the composer named as its future producer, recorded in `tests/state-matrix.json` rather than implied. |
| `wrong-case-field` rejected conformant policies | Accepted | `sts-policy-ext-name` permits `Mode`, and §3.2 ignores unknown fields, so a conformant policy carrying a case-variant extension was being marked invalid. The token moved to `warnings`; the `missing-*` error still carries invalidity in the real-mistake case, which also removes the doubled six-errors-for-three-lines output. |
| `diagnostics` not a mirror of `errors` | Accepted | Correct as built — a missing field has no line — but undocumented against the promised `evidence[].location`. The line-less rule and its `kind: 'input'` variant are now stated. |
| Spec and code disagreed on `missing-mx` | Accepted | The code had narrowed to `enforce`/`testing` without a written rule. That reading is the better one and is now the spec's: with no established mode the requirement is not established either. |

### Review round after 1.2

Both factual claims were verified from source before amendment: RFC 5321 §5.1
was read from `rfc-editor.org`, and the 837-vs-732 key gap was traced to
`flatten()` expanding arrays.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| `null-mx` registered with no producer | Accepted | The honest note was not a permitted exemption. The member is removed from the constant and both state files until `src/audit/artifacts.js` lands, and is added in the same reviewed step as its producer. A null-MX domain meanwhile degrades to `unknown`. |
| Published MX records omit the RFC 5321 implicit MX | Accepted | Verified against §5.1. A domain with no MX and a usable address record has one delivery candidate — itself — so a policy naming it is correct, not stale. The composer contract is now four enumerated cases over delivery candidates rather than MX records, with unparseable input failing the whole comparison. |
| Case-variant extensions not retained | Accepted | The warning short-circuited the field, so it left `unknownKeys` and escaped the duplicate rule, contradicting the retained-extension rule stated two bullets above it. The warning no longer short-circuits. |
| The host guard accepted empty strings | Accepted | `typeof h === 'string'` passed `''` and `'   '`, which normalised away under `filter(Boolean)` into a confident empty comparison — the same stale-policy claim in a different costume. Entries are now validated after normalisation and a single bad entry fails the comparison. |
| Stale 732-key localisation baseline | Accepted | 837 is what the gate counts. The gap is `flatten()` expanding array values by index; the spec now states the measured figure and why a leaf count disagrees. |

### Review round after 1.3

Both findings were reproduced by executing the two pure functions before the
spec was amended.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| Two incompatible comparator contracts in one Final spec | Accepted | The 1.3 amendment rewrote the fail-closed block but left the paragraph above it describing `{ hosts, unknown, nullMx }` and a `null-mx` state the same document withdraws 60 lines later. Replaced with an explicit current-vs-end-state table, and the cross-check table and prose moved from "DNS MX hosts" to delivery candidates. |
| No policy-validity or mode precondition on the composer | Accepted | Reproduced exactly as reported: a valid `mode: none` policy has `mx: []`, and comparing it against a real MX host returns `unmatchedHosts: ['mail.example.test']` — a false `policy-mx-mismatch` on a deliberately inactive policy. An invalid policy's surviving partial `mx` list produces both mismatch classes. Rather than leave the rule as composer prose nothing enforces, `mxComparisonApplies(policy)` is now an exported pure predicate in the protocol owner, because it is a statement about RFC 8461 mode semantics. Its suite pins both counterexamples, not just the predicate. |

### Review round after 1.4

The RFC 8461 §8.3 claim was read from `rfc-editor.org` before the spec was
amended.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| The semantic-finding precondition is incomplete | Accepted | 1.4 gated only the two mismatch classes, leaving `max-age-short`, the mode findings and the null-MX conflict ungated. Verified verbatim against §8.3: *"Publish a new policy with 'mode' equal to 'none' and a small 'max_age' (e.g., one day)"* — one day being exactly the `max-age-short` threshold, so the finding would advise breaking the protocol's removal procedure. Replaced the one-off precondition with a four-state matrix, made it executable as `policyFindingScope()` with a registered closed algebra, and had `mxComparisonApplies` delegate to it so the rule has one implementation. |

### Review round after 1.5

Every finding reproduced by execution, and both cited sources read directly.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| Unreachable "single root element" row | Accepted | Withdrawn from the profile table. Measured: a second XML root is a parse error, so the condition is `malformed-xml`. |
| "Permitted inert values" were enumerable all along | Accepted | I flagged this as an open standards question rather than fetching the draft, and the draft answers it in §2.3 for all six attributes. Verified verbatim from `datatracker.ietf.org`. The validator reported any presence as unsupported, so it diagnosed the draft's own conformant example. |
| The instrument enumerated APIs instead of observing behaviour | Accepted | Both reported bypasses reproduced: `Range.insertNode` inserted an SVG with the wrapper count at 0, and a named-property write stored a value with the wrapper count at 0. Detection is now behavioural — a `MutationObserver` over tagged parser output, and a storage state comparison — and the unsafe fixture commits each violation by both routes. |
| Case-insensitive profile matching | Accepted | `baseprofile`, `viewbox`, `VERSION`, `<SVG>` and `<TITLE>` all satisfied requirements they do not meet. Profile checks are exact; the security screen stays case-insensitive by design, and the asymmetry is now written down. |
| Degenerate `viewBox` passed the square check | Accepted | `0 0 0 0` and `0 0 -64 -64` compared equal. Both extents must now exceed zero. |

### Review round after the composer

Every finding reproduced by execution before the spec was amended.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| `analyzeArtifacts()` never composed the fact | Accepted | Reproduced: the public entry reported `policy-mx-unknown` for a domain whose MX matched perfectly, because it took a ready-made `mxFact` that nothing in the audit produces. `deliveryCandidates()` and the composition path each had green tests; the join between them had none. The entry point now derives from `mx`/`aRec`/`aaaaRec`/`domain`, and every case is driven through the public entry. |
| Evidence carried tokens, not material | Accepted | The token is already `args`. The owner validators now return `{token, line, text}` and `{token, element, value}` so the composer can build honest evidence without reparsing protocol input in `src/audit/`. |
| The twelve finding ids were unregistered | Accepted | Exported, frozen, registered as `audit.artifact.finding.id`, and pinned against the catalog by the co-located suite. |
| New outcomes and severities outran the spec | Accepted | `policy-mx-unknown`, `bimi.svg-valid` and the full severity table are recorded above. Labelling them judgement calls in a handoff is exactly why they needed to be in the spec, not a review document. |
| Repeated diagnostics pointed at the first line | Accepted | Occurrences are consumed in order; two blank lines produce two entries at lines 2 and 3. |
| The evidence cap split astral characters | Accepted | Bounds are in code points in all three places that apply one. |

### Review round after spec 1.7

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| Site-less paths still carried the token as evidence | Accepted | Document-level policy errors and every pre-parse, parser and root SVG rejection now route through the located-site constructor. Two distinct pre-parse rejections had been collapsing into one blank entry. The suite section that claimed "every token records its site" covered only tree-walk tokens and is renamed. |
| The clean-logo title split astral characters | Accepted | `result.title` was the one bound still slicing UTF-16, and `bimi.svg-valid` used the already-damaged value, so the evidence constructor could not repair it. |
| The catalog pin was one-way | Accepted | It covered seven of twelve ids and could not see an unused registry member. Replaced with exact equality in both directions — catalog to constant, constant to registry — plus a disjointness check against `audit.finding.id`, matching the guard `findings.test.js` already has. |
| `mxUnknown` had no producer | Accepted | Removed rather than documented. Inventing a field and calling it current audit data is the mistake `null-mx` already taught; `unknown` now comes only from the data. |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.11 | 2026-09-03 | Amended after review checked the primary standard. SVG Tiny 1.2's reference-restrictions table permits `fill` and `stroke` to name a category A local fragment only, and a `data:` IRI is category E — so 1.10 was wrong to let a `data:` paint reference pass with no report, and the vector case reached `bimi.svg-valid` with no signal at all. Added `data-uri-reference` to the frozen `BIMI_SVG_DIAGNOSTICS` vocabulary, registered in both state files, raised in every reference position, and independent of `raster-data-uri` so a raster `data:` fill now raises both. Kept it out of `BIMI_SVG_REJECTIONS`: `valid` is bounded by spec 1.0 to security refusal rather than profile conformance, a `data:` URI requires no network fetch, and the four profile violations beside it already leave a document valid. The URI does resolve to a distinct document, which is why the profile forbids it and why the diagnostic exists; it is not a refusal because nothing is fetched. One new locale key, translated into all thirteen. |
| 1.10 | 2026-09-03 | Amended after the Fable 5.1 review of `v0.8.0`, which found the `url()` screen wrong in **both** directions. Attributes were under-screened: the rule tested `href` and `xlink:href` only, so `fill="url(https://…)"`, `style="fill:url(https://…)"` and `style="filter:url(https://…)"` all reached `bimi.svg-valid`. `<style>` was over-screened: the `/@import|url\s*\(/i` matcher rejected a conformant local paint server, so `<style>.a{fill:url(#localGradient)}</style>` was refused as `external-style`. Both reproduced against the shipped validator. Replaced the two rules with one matcher — a `url(` whose argument does not begin with `#` — applied to `<style>` text and to every attribute value, keeping `external-style` in the first position and `external-reference` in the second, and required a `url(#fragment)` control in each so a fix cannot close the under-screening while preserving the false positive. Named the two arguments that are neither a fragment nor external: an empty `url()` fails closed as `external-reference`, and a `data:` URI is self-contained and keeps its existing `raster-data-uri` diagnostic rather than becoming a rejection. Specified the matcher as extract-then-test rather than one pattern, after a backtracking version passed `url( #local )` as external. No token was added to or removed from the closed rejection vocabulary. |
| 1.9 | 2026-09-03 | Implemented and released as `v0.8.0`. Recorded the delivery-candidate composition, occurrence-preserving evidence, real-browser SVG boundary, separate provenance-aware panel and exports, pre-read byte/MIME limits, stale-result invalidation, latest-input-wins file ordering, live/static finding-card separation, behavioral security instrument, finished five-surface baseline and complete 14-language surface. No score, DNS fan-out, persistence, CSP destination or public facade change. |
| 1.8 | 2026-09-01 | Amended Final after the evidence-contract review. Required every diagnostic path — document-level, pre-parse, parser and root — to produce located evidence, and defined the `input` variant as an empty value rather than the token. Removed the producer-less failed-lookup input from the delivery-candidate contract. |
| 1.7 | 2026-09-01 | Amended Final after the composer review. Defined the evidence contract precisely — supplied material rather than the diagnostic token, the offending construct rather than the document, one entry per occurrence, code-point bounds — and required the owner validators to supply the located material so `src/audit/` never reparses. Recorded the twelve-id artifact finding catalog with its severities as a registered closed algebra separate from `audit.finding.id`, including the two outcomes (`policy-mx-unknown`, `bimi.svg-valid`) that earlier tables did not name. |
| 1.6 | 2026-09-01 | Amended Final after the SVG review. Withdrew the unreachable "single root element" diagnostic; enumerated the six SVG Tiny PS constrained attributes and their permitted values from draft-svg-tiny-ps-abrotman-12 §2.3, redefining `unsupported-attribute` as a value outside that table; required exact XML name matching for profile conformance while keeping the security screen case-insensitive, and stated why the two differ; and required a `viewBox` to have extents greater than zero before it can be square. |
| 1.5 | 2026-09-01 | Amended Final after the third follow-up review. Replaced the mismatch-only precondition with a four-state semantic-finding matrix covering every policy finding, keyed on RFC 8461 §8.3's withdrawal procedure; made it executable as the exported `policyFindingScope()` with `transport.mtaStsPolicy.findingScope` registered as a closed algebra in both state files; had `mxComparisonApplies` delegate to that matrix rather than re-derive it; and required composer fixtures that prove suppression rather than absence. |
| 1.4 | 2026-09-01 | Amended Final after the second follow-up review. Replaced the contradictory comparator paragraph with an explicit current-commit vs composer-commit contract table and moved the cross-check table and surrounding prose to delivery-candidate terminology. Added the policy-side precondition — both MX mismatch classes now require `mxComparisonApplies(policy)`, a new exported predicate requiring a valid policy in `enforce` or `testing` mode — with both false-finding counterexamples pinned by fixtures. |
| 1.3 | 2026-09-01 | Amended Final after the follow-up review. Replaced the published-MX-records fact source with a four-case delivery-candidate contract covering the RFC 5321 §5.1 implicit MX and RFC 7505 null MX; removed `null-mx` from the comparison vocabulary and both state files until its composer exists; extended the fail-closed rules to an empty host list and to any entry that is not a valid hostname after normalisation; made a case-variant extension retained and duplicate-checked rather than short-circuited; and corrected the localisation baseline from 732 to the gate-measured 837. |
| 1.2 | 2026-09-01 | Amended Final after executing the 1.1 implementation. Named the published MX records as the comparator's fact source and forbade `advanced.mxHealth`; made the comparator fail closed to `unknown` on any fact that is not an established list of hostname strings; recorded `null-mx` as having no producer until `src/audit/artifacts.js` lands; moved `wrong-case-field` from `errors` to `warnings` so a conformant case-variant extension stays valid; stated the `diagnostics` line-index rule and the line-less evidence variant; and aligned the `missing-mx` rule with the mode-conditioned reading. |
| 1.1 | 2026-09-01 | Amended Final after reproducing the first implementation review. Added explicit unknown and null-MX comparison states; registered closed vocabularies; declared `lineEndings: none`; preserved per-line malformed diagnostics; added BOM, blank-line and wrong-case decisions; named the artifact evidence renderer branch, export columns, unverified-policy copy change, browser script and CI job; renamed the browser suite; documented policy extension punctuation; and replaced the low localization estimate with a measured 95–145-key budget. Recorded all accepted and declined review outcomes. |
| 1.0 | 2026-09-01 | Final. Resolved all eight open questions: body-only MTA-STS input; `image/svg+xml` parsing; no logo rendering; VMC removed; no scoring; single-artifact workflow; artifact findings excluded from 0.9.0 JSON comparison; and real-browser hostile-SVG verification through the existing Chromium/CDP harness. Corrected the RFC 8461 rules for zero `max_age`, line endings, duplicate fields, version ordering and one-label wildcard matching. Bounded SVG output to security rejection and named profile diagnostics rather than unsupported full-schema certification, and replaced string length with UTF-8 byte measurement. |
| 0.2 | 2026-08-31 | Renumbered the target to 0.8.0 and rebased the design onto the 0.6.0 allowed-edge matrix. Replaced the proposed `js/artifact.js` monolith with pure validators under the existing MTA-STS and BIMI protocol owners, composition in `src/audit/`, injected UI capabilities through `src/runtime.js`, and directory-bound implementation commits. Added the now-sequential dependency on 0.7.0's final finding shape and updated the report dependency to 0.9.0. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
| 0.1 | 2026-08-20 | Not a version bump. Recorded a downstream consequence of the 0.2.3 rescope: `OQ-SEC-01` resolved to a dependency-free DOM shim, which cannot test this release's XML parsing. Added `OQ-ART-08`. |
