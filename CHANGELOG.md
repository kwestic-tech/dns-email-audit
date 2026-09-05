# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **A note for translators while the project is at 0.x:** the key structure in
> `locales/en.json` is not frozen yet. Keys may be renamed or restructured
> between minor releases as the first translations reveal what needs splitting
> or merging. `npm run check` will flag any of your keys that no longer exist
> upstream after you pull. From 1.0.0 onward, a key rename will be treated as a
> breaking change and will only happen in a major release.

## [Unreleased]

Nothing yet.

## [0.9.1] — 2026-09-05

### Added

- **MX hosts are read for what they resolve to, not only for whether they
  resolve.** A host answering `127.0.0.1`, `10.0.0.4` or `::1` resolved
  successfully, raised nothing, and read in the interface exactly like a
  healthy mail domain — while no sending server on the internet could deliver
  to it. Every resolved address is now classified against the IANA
  special-purpose registries, and a host whose addresses are all unreachable is
  reported as a critical finding. A host with both routable and unreachable
  addresses gets its own finding: mail still arrives, for whichever senders
  happen to pick a routable address, and stalls for the rest.
- **An address written where a hostname belongs is named for what it is.**
  `MX 10 203.0.113.10` was diagnosed as a host that does not resolve, which is
  the right alarm attached to advice that cannot be followed — no address
  record can exist for a name that is an address. It now reports its own
  finding, suppresses the dangling one, and skips the three lookups that were
  spent proving what the record already stated.
- **A null MX published beside a real MX record is reported.** RFC 7505 §3
  requires `0 .` to be the only MX record in the set; a domain publishing both
  has declared that it accepts mail and that it accepts none, and which
  declaration a given sender honours is not something the domain controls.
  This was previously reported nowhere at all: the parser rejects `0 .` before
  any lookup, so the contradiction reached neither a finding nor a query.

### Notes

- **No new DNS query, and no score or grade movement.** The three findings are
  read from answers the audit already had. Deterministic replay across the
  32-case corpus shows byte-identical query traces and unchanged scores and
  grades on every domain; the only rendered movement is in the one fixture that
  publishes deliberately unreachable MX hosts.
- **A preference-range check was specified and withdrawn before release.** RFC
  1035 §3.3.9 encodes the MX preference as an unsigned 16-bit integer, so a
  larger value cannot survive a real response and the check could only ever be
  exercised by feeding the parser a string no resolver produces.

## [0.9.0] — 2026-09-04

### Added

- **A versioned JSON report.** **Export JSON** writes the finished run as a
  named projection of the audit rather than the result object: normalized
  records, findings with their nine comparable fields and source-bound
  evidence, the per-domain score in its real `pts`/pillar shape, the options
  that were in force, the resolver used, and the analysis version that scored
  it. Display state, locale routing and the query trace are excluded by
  decision, and the exclusion table is published in the spec.
- **Comparison of two reports, entirely in memory.** Import a saved report
  while results are on screen to compare it against the current run, or import
  two with no audit running. Each domain gets a verdict — new, removed,
  improved, regressed, changed, unchanged or not comparable — decided in a
  fixed precedence, with the finding ids that appeared or resolved, the record
  deltas paired baseline against current, and the score movement. The
  comparison overlays the existing table rather than replacing it, and leaving
  the mode or reloading discards both reports.
- **Per-protocol observability, so nothing is reported as fixed that was never
  looked at.** Every audit now carries a total map over the thirteen protocols
  with one of three values: observed, unproven, or not run. A comparison
  refuses to call a finding resolved on a protocol either report did not
  observe; it marks the protocol instead, with the side that lacked it and
  whether it was checked without result or never checked. This is what makes
  a comparison across an options change safe: turning off advanced checks
  would otherwise have reported eight SPF findings and DMARC report
  authorization as resolved.
- **`analysisVersion`, gating the score delta only.** Two reports scored by
  different rubric versions still show their finding and record movement; only
  the number is withheld, because that is the only part the rubric decides.
  A rubric fingerprint test fails if the weights or thresholds move without the
  version moving with them.

### Changed

- Imported reports are validated strictly and fail closed. Every known field is
  type- and range-checked against published limits — 8 MB, 200 domains, 200
  findings and 20 evidence entries per domain, 8 levels of nesting — and a
  malformed file is refused whole rather than coerced into a comparable-looking
  one. Refusals carry a code from a closed six-member set plus the literal
  schema path that failed, so the message is translated while the diagnostic
  stays exact.
- Every value from an imported report is rendered as a text node, on the same
  path a DNS record takes. A finding id this build does not recognize is shown
  with a note saying so rather than dropped, so a diff across tool versions
  stays complete.
- Added 56 English locale leaves and the same interface, comparison, refusal
  and per-protocol surface across all thirteen other locales. Protocol tokens,
  schema paths and finding ids remain literal.
- Pinned the finished 0.9.0 browser boundary across audit results, DNS traces,
  CSV, HTML reports and rendered DOM. The release-compatibility suite bounds
  the delta from 0.8.0 to exactly two authorized changes — the added
  observability map and 632 bytes of comparison styles — and proves query
  traces, CSV and DOM byte-identical: comparison is a second mode over an
  already-rendered table and issues no query of its own.
- The verification inventory reports 280 checks and 5,491 assertions. The
  locale gate reports 13/13 at 100%, and the Content Security Policy retains
  its existing connection destinations.

### Fixed

- Completed the Polish `render.moreRecords` plural with its reachable `few`
  and `many` forms, so counts such as 3 and 5 use the correct grammatical case
  instead of falling through to the English-shaped `other` form.

## [0.8.1] — 2026-09-03

A patch release. Five defects found by an external review of `v0.8.0`, one
reported by a user, and the documentation drift the review catalogued. No
scoring, DNS fan-out, cache scope, persistence, CSP destination or public
facade change; the deterministic corpus replays across 32 cases and five
surfaces with zero differences.

### Fixed

- **One hostile nameserver label no longer discards the whole run.** A DNS
  label of `__proto__` in an audited domain's NS record produced the provider
  string `__proto__`, which resolved through `Object.prototype` in the token
  table, handed the renderer an object, and threw inside the per-row loop —
  losing every domain in the batch, not only the hostile one, with the Run
  Audit button already re-enabled so the page looked as though nothing had
  happened. Underscores are legal in owner names, so any domain in a list
  could do this to whoever was auditing it. The token table is prototype-free,
  and a row that fails to render is now contained to that row: its partial
  markup is removed and replaced with a row that names a *display* failure,
  distinct from an audit error, in all fourteen languages. The cleanup removes
  what that render call appended, by position: row ids come from a lossy
  `\W`-to-dash mapping under which `a-b.com` and `a.b-com` collide, so removing
  by id would have deleted a different domain's finished result while claiming
  the others were unaffected.
- **Two clicks on Run Audit no longer start two audits.** The re-entry guard
  was read before `await checkConnectivity()` and not set until after it, so a
  second click inside the probe window started a second run: both replaced the
  results, both reset the progress log, and whichever finished first re-enabled
  the button while the other was still querying, so Cancel could not reach it.
  Measured at two runs and 111 DoH queries for one double click on two domains,
  against a published fan-out of one probe per run. The guard is now claimed in
  the same synchronous step it is read, and every early return releases it.
- **The DNS-provider badge is sentinelised.** It was the one DNS-derived string
  reaching the display without passing `R.value()` or `R.sentinelText()`, so a
  bidirectional override inside a nameserver name reordered the table cell —
  while the nameserver list two rows below showed the same record with its
  `‹RLO›` marker. Substitution happens on the derived branch of `label()`, so
  translated provider names are untouched.
- **i18n keys and named entities resolve through own properties only.** The
  bundle walk and the entity table both reached `Object.prototype`, so
  `artifact.token.constructor` returned a function and `&constructor;` in a
  locale string rendered `function Object() { [native code] }` into the page.
  0.8.0 already routed user-supplied text into the first of these through the
  MTA-STS artifact panel.
- **The BIMI SVG screen's `url()` rule was wrong in both directions.**
  Attributes were screened for `href` only, so `fill="url(https://…)"`,
  `style="fill:url(https://…)"` and `style="filter:url(https://…)"` reached
  `bimi.svg-valid`. `<style>` was screened by a matcher that rejected *every*
  `url(`, so a conformant logo painting with a local gradient was refused as
  `external-style`. One matcher now runs in both positions, and a `data:` URI
  in a reference position raises the new `data-uri-reference` **diagnostic**:
  SVG Tiny 1.2 permits paint references to local fragments only, but a `data:`
  URI needs no network fetch, so it is a profile complaint rather than a
  refusal. The vector case previously passed with no signal at all.
- **The footer separators render.** All fourteen locales write `&bull;` in the
  footer and about text, which the rich-text tokenizer left as literal text
  because the entity was not in its allowlist — the footer read
  "Cloudflare &bull; No data sent to Kwestic". 69 occurrences.

### Changed

- `PRIVACY.md` attributed the stylesheet fetch to `src/main.js`; it has been
  `src/ui/report.js` since 0.6.0. `SECURITY.md`'s scope named `js/` paths
  deleted in the same release. `index.html` declared two languages in its
  structured data and one Open Graph alternate while fourteen locales ship.
  `src/audit/context.js` documented a `BigInt` in the audit result that is not
  there and never was — the committed equivalence baseline serialises the full
  result for all 32 cases, which could not exist if one were. `README.md` and
  `src/ui/report.js` said a leading apostrophe "is not displayed by the
  spreadsheet"; on CSV import it is visible, which is why the change is also
  named by the `formula-leading` token.

### Notes

- The verification inventory reports 270 checks and 5,100 assertions, up from
  265 and 5,004. `dist/app.min.js` is 507,030 bytes raw; gzip is about 150.5 KB
  and varies by a few bytes with the zlib build, so only the raw figure is
  quoted exactly.
- `npm run equivalence` reports zero differences against the `v0.8.0` baseline
  across result, query trace, CSV, HTML and DOM.
- One new locale key pair for the display-failure row and one for the new SVG
  diagnostic, translated into all thirteen languages; the gate passes 13/13
  strict.

## [0.8.0] — 2026-09-03

### Added

- **Private local artifact validation.** A separate collapsed panel accepts an
  MTA-STS policy body or BIMI SVG by paste or file selection and analyzes it
  entirely in browser memory. It never fetches a domain-controlled URL,
  uploads or persists supplied material, renders the logo, or changes the DNS
  score.
- **RFC 8461 policy diagnostics and delivery-host comparison.** The policy
  parser reports line-specific syntax and hygiene findings, mode and cache-age
  posture, and compares `mx` patterns with the audited domain's real delivery
  candidates, including implicit and null MX behavior. Missing or incomplete
  facts produce an explicit unverified result rather than a false mismatch.
- **A deliberately narrow BIMI SVG screen.** DTDs, entity declarations,
  scripts, event handlers, foreign content, external references, links and
  animation are rejected; named SVG Tiny PS profile requirements are reported
  separately. The positive result states the screen that passed without
  claiming full RNC-schema certification or mailbox-provider acceptance.
- **Artifact-aware exports.** CSV appends finding ids, severities and bounded
  user-supplied evidence after every existing DNS column. The script-free HTML
  report adds a separate artifact section. Both preserve the provenance line;
  artifact findings never enter the DNS findings array or remediation score.

### Changed

- The MTA-STS DNS-only finding now says the application did not automatically
  retrieve the HTTPS policy and points operators to the local panel instead of
  implying the policy cannot be checked.
- Added 106 English locale leaves and completed the same interface, diagnostic,
  evidence, privacy and remediation surface across all thirteen other locales.
  Protocol, field, profile and element names remain literal.
- Added a required real-browser security job that drives the shipped panel and
  real XML parser while observing browser-external network and storage events
  plus tagged-node insertion. Its unsafe fixture and detector-removal controls
  prove the instrument can see the prohibited behavior before the complete
  94-assertion browser suite passes.
- Pinned the finished 0.8.0 browser boundary across audit results, DNS traces,
  CSV, HTML reports and rendered DOM. The release-compatibility suite proves
  results and traces are byte-identical to 0.7.0 and bounds the visible delta
  to the three artifact columns, one MTA-STS wording update and the artifact
  styles. Live finding disclosures are separately pinned so static-report mode
  cannot remove their controls or force them open.
- The verification inventory reports 265 checks and 5,004 assertions. The
  `test:file-url` suite passes 22 assertions, the local-input security suite
  passes 94, the locale gate reports 13/13 at 100%, and the Content Security
  Policy retains its existing connection destinations.

### Fixed

- **Only the first finding in each severity group had a working "show me"
  disclosure.** `findingCard` takes a `staticMode` flag as its second argument,
  and the severity and low-information lists passed it straight to
  `Array.prototype.map`, which supplies the element index there. Every card
  after the first therefore rendered in the static form used by the exported
  report: its explanation was permanently expanded and its toggle button was
  omitted entirely. Present since 0.8.0's finding cards were introduced in
  0.7.0, and covered now by a rendering regression test.

## [0.7.0] — 2026-09-01

### Added

- **Structured findings alongside the existing issue list.** Every finding has a
  stable protocol-qualified id, five-level severity, confidence, category,
  effort, localized message key, source-bound evidence and explicit prerequisite
  relationships. The legacy `result.issues`, suggestions, scores and grades are
  unchanged; `findings` and `remediationPlan` are additive result fields.
- **Ten cross-protocol findings** for conditions a single protocol owner cannot
  judge alone, including DMARC enforcement without complete authentication,
  weak DKIM or fragile MX under enforcement, BIMI without enforcement,
  MTA-STS without TLS-RPT, TLS-RPT without a transport policy, contradictory
  parked-domain controls and blind reporting.
- **A dependency-ordered remediation plan.** Prerequisites are fixed before the
  findings they block; independent cleanup collects in a final step. The detail
  panel can switch between severity groups and remediation steps, and visibly
  marks a finding that is waiting on another one.
- **Finding-aware exports.** CSV adds finding ids, severities and the first
  remediation step without moving any existing column. The HTML report renders
  the same two-view findings block as the application.

### Changed

- Evidence now carries the material an operator can verify rather than authored
  descriptions or classifier verdicts: complete DS or DNSKEY records selected
  for DNSSEC claims, actual TLSA query owners and malformed source text,
  individual CAA records, conflicting SPF/DMARC records, wildcard responses,
  CNAME chains, implicit-MX addresses and explicit empty absences.
- Finding ids, keys, severities, confidence levels, categories, effort levels,
  protocols, keyspaces, evidence kinds and remediation rationales are registered
  reviewed algebras. The state matrix contains 719 covered rows.
- Added 65 English finding/remediation keys and 845 translated units across all
  thirteen non-English locales. Finding and remediation order is measured
  byte-identical in all fourteen interfaces.
- The verification inventory now reports 255 checks and 4,643 assertions. The
  deterministic 32-case DNS trace is unchanged, and concurrent 40-domain
  backtests with deep checks both off and on show zero grade or point movement
  from 0.6.0.
- Added a finished 0.7.0 five-surface baseline for exact result, trace, CSV,
  report and DOM gating. A separate release-compatibility suite keeps the
  historical v0.5.0 baseline meaningful by proving the 0.7.0 delta is limited to
  the two additive result fields, three appended CSV cells and the reviewed UI;
  trace and every legacy result field remain byte-identical. Each bounded rule
  has a negative control.
- Repaired the live backtest's request counter after the 0.6.0 composition moved
  the engine around its counted fetch. A negative control pins the wiring; the
  restored measurements remain about 34 queries per domain with deep checks off
  and 41 with them on, matching `PRIVACY.md`.

## [0.6.0] — 2026-08-30

### Changed

- **The application is ES modules under `src/`, bundled to one artifact.** The
  engine was a single 5,704-line IIFE, `js/dns.js`, loaded beside six other
  scripts in an order the page could not state a reason for. Separate files
  could only reach each other through `window`, and **twenty-four top-level
  globals** was the surface that arrangement left behind — some of it
  load-bearing between files, some of it published alongside a purely
  internal function. Either way, all of it was reachable by anything on the
  page.

  There are now **thirteen owning directories** under `src/` — `audit/`, eight
  protocol owners, `core/dns/`, `core/shared/`, `providers/` and `ui/` — each
  with a checked-in `API.md`, and **30 co-located test modules** sitting beside
  the code they test. `src/ui/` is the one owning directory with no co-located
  test: it keeps its established coverage in `tools/render.test.mjs` and
  `tools/export.test.mjs`. Imports are explicit, so load order is derived
  rather than declared. The only application-created browser global is
  `DnsAudit`, with the two facade members described below.

- **`index.html` loads one script instead of seven.** `dist/app.min.js`, built
  by esbuild, is the single delivery boundary: 437 KB raw and 131 KB gzipped,
  down from 719 KB raw and 213 KB gzipped across the seven separately-fetched
  files it replaces.

- **`window.DnsAudit` is the supported browser API, and it has two members** —
  `analyzeDomain` and `checkConnectivity`. The bundle publishes **one top-level
  global** where 0.5.0 published twenty-four, and that one global carries two
  members. A contract test asserts the artifact creates exactly that one name,
  and that its members match the entry module's exports exactly in both
  directions, so neither a second global nor a third member can appear by
  accident.

  **This is a breaking change for anything that drove the page from outside
  it.** Three groups went:

  - `DnsAudit` itself carried the entire 95-member engine; it now carries the
    two members above — the only two the application itself ever called. Of
    the other 93, this repository's own tools reached 81 (77 in the scoring
    suite, four in the backtest) and now import the modules directly; the
    remaining twelve had no consumer here at all.
  - The fourteen `js/app.js` UI function globals — `startAudit`,
    `cancelAudit`, `clearAll`, `exportCSV`, `exportHTML`, `filterTable`,
    `loadExample`, `loadFile`, `openLearnMore`, `setLang`, `showHelp`,
    `sortTable`, `toggleDetail`, `toggleShowMe`. **The functions themselves
    were doing the work** — the page wired them to its controls with
    `addEventListener` and called them from its own handlers. What went is the
    published `window` binding beside each one, which nothing reached through:
    `index.html` has no inline handlers, because its CSP carries no
    `unsafe-inline`. Drive the controls by clicking them.
  - The wiring and generated-data names — `i18n`, `t`, `tp`, `tRaw`, `R`,
    `__APP_TEST__`, `__PUBLIC_SUFFIX_RULES__`, `__DKIM_SELECTOR_CATALOG__`,
    `__I18N_EN__`. Every module now takes its renderer and translator as an
    argument, and the generated tables live inside the bundle's closure.

  A search of this repository found no consumer for any of them outside the
  suites that moved. That is the basis for removing them, and it is worth
  stating precisely: **it proves no repository consumer, not no consumer.** A
  static site can be driven from a console or an embedding page that is not in
  this checkout.

- **Opening `index.html` from disk still works, and is still tested.** The
  bundle is emitted as a classic script rather than `type="module"` — a module
  script is blocked by CORS under `file://` — and the English locale is inlined
  into the artifact rather than fetched. `npm run test:file-url` drives a real
  Chrome over `file://` and asserts it. Other languages still need the app
  served over HTTP, unchanged from 0.5.0.

### Added

- **A reproducible build with one direct development dependency.**
  `package.json` declares
  exactly one: esbuild `0.28.2`, exact-pinned, as a dev dependency — no
  framework, and still nothing at runtime.

  The developer and command-line tooling floor is now **Node.js 20**. The
  browser application has no Node.js runtime requirement. The release review
  tested the previous `>=18` declaration directly; Node 18 reaches the suite
  but lacks the global Web Crypto API used by the production modules and
  tools, so the old declaration promised support the project did not provide.

  What that resolves to is worth stating separately, because "one dependency"
  and "one package" are different claims. On a given platform `npm ci`
  installs **two packages**: `esbuild` and the one `@esbuild/*` binary for
  your architecture, out of 26 declared optional platform packages of which 25
  go unmet. esbuild declares a `postinstall` script, and
  **`package.json`'s `allowScripts` gate sets `esbuild: false`, so it does not
  run** — the optional platform package supplies the binary directly. The
  install runs no scripts at all, and that is a recorded decision rather than
  a default.

  `npm test` builds first, because several suites assert against the artifact
  and a source-only run would be testing something the browser never sees.
  A clean checkout therefore runs `npm ci` and `npm run build` before
  `npm start`; `dist/` remains generated and untracked.

- **An allowed-import matrix that a test enforces.** `AGENTS.md` carries the
  edges the architecture permits, and
  `tests/contract/dns-transport.test.mjs` checks them against the real import
  graph: **an edge absent from the matrix is a test failure, not a judgement
  call.** Adding or widening a row is an architectural change and takes the
  same review as any other.

- **A five-surface equivalence oracle.** `npm run equivalence` replays 32
  corpus cases and compares the result object, the DNS query trace, the CSV
  export, the HTML report and the rendered DOM against a baseline captured
  from `v0.5.0`. It also validates itself: `npm run equivalence:validate`
  mutates each surface in turn and fails if a mutation is *not* caught, so the
  oracle cannot pass by reaching nothing.

- **An assertion inventory.** `npm run inventory` runs every suite as a
  subprocess and compares each one's count against `tests/inventory.json`. It
  fails in both directions — a silent decrease is coverage leaving, a silent
  increase is work nobody recorded.

- **Contract suites for the seams the unit tests cannot see**: the transport
  kinds each layer may use, the closed issue-token vocabulary, the browser
  namespace, the platform boundary, and source-to-bundle parity.

### Removed

- **`js/` is deleted** — `dns.js`, `app.js`, `render.js`, `i18n.js` and the
  three generated data files. Forks or self-hosted copies that reference those
  paths should load `dist/app.min.js` instead. The generated tables now live in
  `src/data/` and are still never hand-edited; `npm run build:fallback`
  regenerates the inlined English bundle.

### Verification

**No behaviour changed across the five equivalence surfaces** — the result
object, the DNS query trace, the CSV export, the HTML report and the rendered
DOM — and that is a measured claim rather than an intention. The oracle reports
**32 cases, 5 surfaces, 0 differences** against the `v0.5.0` baseline, covering
**430 of 430** registry rows. The browser compatibility surface — the global
namespace described above — **did change, deliberately**; it is observed by
none of the five, which is why it is documented rather than diffed. `WEIGHTS`,
`PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are byte-identical to `v0.5.0`.

`tools/scoring.test.mjs` still reaches the engine's 95-member surface by name,
and passes the **same 1,535 assertions** it passed before the refactor, with
**the count unmoved through all six phases**. It was not rewritten to match
the new structure — that would have retired the instrument measuring the
refactor. What did change in it is the loading
mechanism (a `node:vm` sandbox cannot evaluate an ES module) and three DNSSEC
tests that used to reassign `sandbox.crypto` between calls; a platform is fixed
for the life of a runtime now, so "a runtime without crypto" is expressed by
building one. No assertion's subject or expectation moved.

`npm test` passes **4,451 assertions across 46 suites**, up from 2,121 at
0.5.0; the increase is the new contract, build and co-located unit suites, not
new behaviour. `npm run inventory` passes 240, `npm run test:file-url` passes
22, and `npm run locale:gate` passes 13/13 at 771/771 keys.

## [0.5.0] — 2026-08-26

### Added

- **DNSSEC is six states rather than a boolean, and the two new ones are the
  point.** The chain state came from one bit: the resolver's authenticated-data
  flag on an `NS` probe, plus a `cd=1` re-query to tell a bogus chain from an
  unsigned one. A zone that is signed but has no `DS` record at its parent, and
  a zone whose `DS` and `DNSKEY` have drifted apart during a key rollover, both
  rendered identically to a zone that had never been signed — telling an
  operator who had done the work that they had not.

  `checkDNSSEC()` now queries the child's `DNSKEY` set and the parent's `DS` set
  alongside the existing probe, and classifies through an ordered six-rule
  table: `bogus`, `indeterminate`, `secure`, `unanchored`, `mismatch`,
  `insecure`. The order is normative — `dnssec-failed.org` satisfies three of
  those rules at once.

  Measured on the 40-domain backtest sample, `atlassian.com` is signed with no
  `DS` at its parent and had been reported as having no DNSSEC.

- **The `DS` records are matched against the `DNSKEY` set locally, with Web
  Crypto.** RFC 4034 §5.1.4's digest over the canonical owner name and the
  DNSKEY RDATA, with the RFC 4034 Appendix B key tag — and RFC 6840 §5.5 for
  algorithm 1, whose calculation Appendix B states incorrectly. Verified against
  RFC 4034 §5.4, RFC 4509 §2.3 and RFC 6605 §§6.1–6.2's published vectors.

- **Nine findings, each naming what to do.** `dnssec-unanchored` (warn),
  `dnssec-mismatch` (crit), `dnssec-ds-orphan` (info),
  `dnssec-deprecated-algorithm` (warn), `dnssec-deprecated-digest` (info),
  `dnssec-revoke-flag` (info), and three that report a `DS` confirming a key
  that cannot anchor a delegation. The generic "enable DNSSEC" suggestion no
  longer fires on a zone that is already signed, where it contradicted the
  finding printed directly above it.

- **A detail panel that says where each part of the verdict came from.** The
  keys, the `DS` records with their match verdicts, and an evidence list in
  which every line is attributed either to the resolver or to computation done
  in the browser. It also names the single link that was checked, because
  showing one link of a chain without naming it implies the tool walked the
  whole thing to the root, which it does not.

- **`node tools/backtest.mjs --dnssec-states`**, a live check of one named
  domain per state against the classifier. The 40-domain `SAMPLE` is untouched:
  it is a longitudinal score baseline, and mixing deliberately-broken test zones
  into it would change what its histogram means.

### Changed

- **`checkTlsa()`'s `qualified` flag is retired rather than completed.** 0.4.0
  introduced it as the stronger claim that the chain had been walked and
  verified, expecting this release to supply it. A TLSA record lives at
  `_25._tcp.<host>`, usually in a zone unrelated to the audited domain, so the
  audited domain's chain evidence says nothing about it — and local
  `DS`-to-`DNSKEY` matching never validates signatures, so it can never exceed
  the per-host authenticated-data bit already recorded. A second field that can
  only ever equal the first is a claim rather than a distinction. Each TLSA host
  reports `authenticated: true | false | null` and nothing more.

- **The DNSSEC dot tells the truth in every state.** Its tooltip read "Not
  detected — enable DNSSEC in your DNS provider" for every non-signed state,
  which is false for a signed-but-unanchored zone and worse than false for one
  whose validation is failing. `unanchored` and `mismatch` also read amber,
  matching the existing treatment for a duplicated record.

- **The IANA algorithm and DS digest registries are current**, including
  algorithms 17, 18 and 23 and digest types 5 and 6, with deprecation following
  RFC 9905 and RFC 9906 rather than the superseded RFC 8624. A one-octet SM3
  digest previously parsed as a valid record with no name.

- **`DNSKEY` records are validated against their algorithm's key grammar.**
  `257 3 15 AA==` — a one-octet Ed25519 key — parsed as valid and computed a key
  tag. Structure is now reported separately from whether the record parsed, with
  `unknown` reserved for algorithms whose key format this build does not
  implement, so a zone signed to a newer specification is never called broken.

- **Fan-out rises by exactly two queries per domain.** `PRIVACY.md` carries the
  re-measured figures: about 41 per domain with the default options and 61 for
  `cloudflare.com`, or about 34 and 45 with the deep protocol checks off.

### Fixed

- **A genuinely bogus zone now reaches its own critical finding.** A validating
  resolver returns SERVFAIL for the core NS probe when DNSSEC validation fails,
  so the audit previously threw before `checkDNSSEC()` could report `bogus`.
  The integrated path now retains the validating verdict and uses `cd=1` only
  to retrieve the diagnostic records needed to render the row. Ordinary core
  lookup failures remain fatal.

- **A DNSSEC verdict can no longer be assembled from local evidence alone.**
  `servfail.nl` publishes a `DS` that confirms its `DNSKEY` by SHA-256 and a
  full key set, and the zone is bogus. The resolver's flag remains the
  validation signal; the local arithmetic explains the parent-to-child
  relationship and nothing more.

- **A key tag matching nothing is not a broken chain.** `paypal.com` publishes
  one `DS` that confirms its key and one that matches nothing, and validates
  perfectly — RFC 6840 §5.11 permits exactly that. An earlier design would have
  reported it as a mismatch, costing it 15 points and the A tier.

### Verification

`npm test` passes 2,121 assertions, up from 1,813 at 0.4.0. `npm run
locale:gate` passes 13/13 at 771/771 keys. The backtest against `v0.4.0` shows
**zero grade, score and `dnssec.signed` movement** across the 40-domain sample,
with `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` byte-identical — the
classifier reaches its new states only when the resolver's flag is already
false, so `signed` is unchanged by construction rather than by measurement.

## [0.4.0] — 2026-08-25

### Added

- **DKIM public keys are decoded rather than just displayed.** A found selector
  used to produce only the raw TXT string, leaving the single most actionable
  fact about the key — its size — sitting decoded-but-unread. `analyzeDkimKey()`
  now reports algorithm, RSA modulus size, Ed25519 detection, revocation, and
  the `h=`, `s=`, `t=` and `n=` service tags.

  The modulus size comes from a synchronous DER length walk rather than from Web
  Crypto, because `crypto.subtle` needs a secure context and `README.md`
  advertises that opening `index.html` from disk works. The walk accepts both
  encodings RFC 6376 §3.6.1 and its errata permit — a bare PKCS#1
  `RSAPublicKey` and one wrapped in a `SubjectPublicKeyInfo` — and the two
  exports of the same key are asserted to agree on its size.

  Web Crypto is confirmation only, and only for what it can express. It takes
  `spki` and not `pkcs1`, so a conformant bare key is recorded as "not checked"
  and stays valid with its size intact; an SPKI key that fails to import is
  recorded as `key-structure-invalid`, again with the size untouched. The DER
  walk is authoritative throughout: an implementation's input formats must not
  decide what the protocol permits, or a perfectly good published key gets
  reported as unparseable.

  Bare PKCS#1 has fixture coverage and no real-world sample: all 39 keys found
  across a 15-domain slice — Microsoft, Apple, PayPal, Stripe, NASA, Harvard,
  Mozilla, the EFF among them — are SPKI. That is the argument for accepting it
  rather than against: the encoding is conformant and rare, which is exactly the
  shape of a bug that ships and then misreports one operator's working key with
  nothing in the sample to catch it.

  The base64 decode is hand-rolled for the same reason — reaching for `atob`
  would have meant reporting every key on every domain as unparseable in any
  environment lacking it, which is an assertion about our own runtime dressed up
  as one about the operator's DNS.

  New findings: `dkim-key-weak` (crit), `dkim-key-1024` (**info**),
  `dkim-key-revoked`, `dkim-key-unparseable`, `dkim-key-sha1`,
  `dkim-key-testing`, `dkim-key-mixed`, `dkim-key-not-email`,
  `dkim-key-malformed`.

  `dkim-key-1024` is informational rather than a warning, and that was settled
  by counting instead of arguing. Across the 40-domain backtest sample, 35 of
  66 keys are RSA-1024, on 21 of the 27 domains that publish DKIM at all —
  Microsoft, GitHub, Apple, PayPal, Stripe and the EFF among them. A warning
  firing on roughly 78% of audited domains is not a signal. Zero sub-1024 keys
  were found, which is why `dkim-key-weak` stays critical and stays meaningful.

- **A revoked DKIM selector is reported as revoked, not as absent.** RFC 6376
  §3.6.1 defines an empty `p=` as key revocation, and the discovery filter
  discarded exactly those records — so a selector the operator had deliberately
  retired read as one they had never set up. The two questions are now answered
  separately rather than by loosening the filter, which would have let a revoked
  key satisfy "DKIM is present".

- **CAA is parsed into a policy instead of a boolean.** A domain publishing
  `0 issue ";"` has locked out every certificate authority and one publishing
  `0 issuewild ";"` has locked out wildcards only; both used to render as the
  same green dot. `parseCaaRecord()` and the extended `checkCAA()` report
  issuers, wildcard issuers, `iodef` destinations, unknown critical properties
  and malformed records. Two semantics are encoded explicitly because both are
  easy to invert: an `issue` value of `;` forbids all issuance, and an **absent**
  `issuewild` set means wildcards are governed by `issue` — not that they are
  unrestricted. Findings: `caa-blocks-all-issuance`, `caa-unknown-critical-tag`,
  `caa-malformed`, `caa-no-iodef`, `caa-single-issuer`.

- **MX health, from DNS alone.** `auditMxHosts()` resolves every MX target and
  reports dangling hosts, `CNAME` targets, single points of failure, IPv6
  coverage, address-block concentration and duplicate preferences. An MX host
  that does not resolve is a total inbound mail outage and used to read exactly
  like a healthy mail domain. Nothing connects to port 25 — every conclusion is
  inferred from DNS. Findings: `mx-dangling` (crit), `mx-cname-target`,
  `mx-single-host`, `mx-no-ipv6`, `mx-same-prefix`, `mx-duplicate-preference`.

  A host whose lookup fails degrades to `unknown` and is deliberately excluded
  from `danglingHosts`: a resolver hiccup must never be reported as an outage.

- **TLSA lookup and syntax validation, labelled as published rather than
  active.** `checkTlsa()` queries `_25._tcp.<mx-host>` and validates usage,
  selector, matching type and association-data length. `qualified` is hardcoded
  `false` — DANE is only meaningful behind a validated DNSSEC chain, and this
  release does not walk one, so nothing in the interface says anything
  resembling "DANE enabled". Findings: `tlsa-published-unsigned`,
  `tlsa-malformed`, `tlsa-partial-coverage`.

  The unsigned finding is gated on the AD bit the validating resolver returns
  for that exact name, not on `qualified`. Gating it on `qualified` would have
  fired on every domain in the release, telling a correctly signed zone that its
  DANE was unprotected — a confident verdict with nothing behind it. The AD bit
  costs no extra query and is read for the MX host's own name, because an MX
  host usually lives in someone else's zone and the audited domain's DNSSEC
  status says nothing about it.

- **A "deep protocol checks" toggle, on by default, that turns itself off above
  50 domains.** MX health and TLSA are the only checks whose cost scales with
  the audited domain's own configuration, so they are the only ones behind a
  switch. Above the threshold the box clears itself and an inline notice says
  why, naming both the limit and the size of the run — deliberately not a toast,
  because a toast is gone in three seconds and this explains a checkbox the user
  last saw ticked. Ticking it again runs them anyway, and that choice is
  remembered **for the browser tab's session only**: persisting it would need a
  second `localStorage` key, and `PRIVACY.md` states the app writes exactly one
  value and calls that the entire footprint. A reload restores the default.

- **The detail panel reports what was found.** Each DKIM selector gains a key
  line (`RSA 2048-bit`, `Ed25519`, `revoked`, `does not decode`); CAA gains a
  parsed policy block; the MX list is annotated per host with its addresses, or
  with "does not resolve" or "not checked"; and TLSA gains a block whose first
  line is "Published, not yet qualified". A key Web Crypto never examined says
  nothing at all, because "we did not check" is not a finding and must not look
  like one.

- **Eight CSV columns, appended after the Tree Walk columns**: `DKIM Key Type`,
  `DKIM Key Bits`, `DKIM Revoked Selectors`, `CAA Issuers`,
  `CAA Wildcard Issuers`, `MX Dangling`, `MX Host Count`, `TLSA Present`. Every
  column that existed before 0.4.0 is still at the index it was at, and the
  export tests now assert that by index rather than by "last" — pinning the tail
  is what made them fire on this release. With the deep checks off, the MX and
  TLSA columns say `Unknown` rather than `No`: a domain whose MX hosts were
  never resolved has no dangling hosts *reported*, which is not the same as
  having none. An absent `issuewild` set is named as governed by `issue` rather
  than left blank, since a blank cell reads as "wildcards unrestricted" — the
  opposite of what the domain published.

### Fixed

- **Protocol-looking TXT is separated from sender-effective policy.** BIMI,
  MTA-STS and TLS-RPT now retain every recognizable candidate as evidence while
  counting only records with an exact, leading version field for multiplicity
  and activation. A valid record beside a malformed, wrong-order candidate no
  longer disables the valid policy or raises a false multiple-record finding.

- **DKIM validation now covers the complete tag-list boundary without treating
  unrelated wildcard TXT as a key.** Illegal tag syntax, folding, base64 pad
  bits, `k=`, `n=`, missing `p=` and version placement all reach an explicit
  malformed finding, including on revoked or service-scoped records. At the
  same time, a TXT record that explicitly declares another protocol is ignored:
  a live check found `gov.uk` synthesizing `v=DMARC1; p=reject` at every tested
  selector, which the intermediate implementation counted as ten DKIM keys and
  incorrectly awarded the full 15-point pillar.

- **URI validation follows the imported grammar rather than a dotted-host
  approximation.** TLS-RPT and CAA `iodef` accept valid IPv6/IPvFuture hosts,
  quoted and percent-encoded mailboxes, UTF-8 domain names and structured
  mailto header fields, while rejecting malformed IPv6 placement, invalid
  percent encoding and forbidden component characters. BIMI keeps its own
  stricter HTTPS/FQDN profile and enforces DNS label lengths.

- **JSON backtests flush before exiting.** The 0.4.0 selector evidence pushes a
  40-domain report beyond 64 KiB; an immediate `process.exit()` truncated the
  piped JSON and made the release's score-diff gate unparsable.

- **DKIM key sizes are the modulus's bit length, not its encoded byte width.**
  The two differ whenever the leading significant octet is below `0x80`, and the
  difference lands across this release's own threshold: a conformant 128-byte
  modulus beginning `0x01` is a 1017-bit key, and reporting it as 1024 both
  printed a false number and swapped the critical `dkim-key-weak` finding for
  the informational 1024-bit one. Every real RSA key has the top bit of its
  modulus set, so all 26 keys across a live ten-domain check are unaffected —
  which is why this needed constructed keys to find rather than captured ones.

- **The SPKI path now applies the same structural guards as the bare PKCS#1
  path.** Both envelopes go through one `RSAPublicKey` reader that requires a
  modulus, a `publicExponent` that ends its sequence, and exact container
  boundaries at every nesting level, plus an `rsaEncryption` algorithm
  identifier. Previously the SPKI branch checked only that a modulus INTEGER
  existed, so a key whose exponent tag had been altered walked cleanly and
  returned a size — leaving Web Crypto as the only thing that would reject
  malformed DER, in a walk this release documents as authoritative without it.

- **A domain with more than one SPF record now shows the records it conflicts
  over.** Reported from the field against `splunk.com`, which really does
  publish two `v=spf1` records. The `permerror` was correct — RFC 7208 §4.5, and
  receivers neither merge the records nor pick the stricter one — but only the
  first match was ever kept, so the panel beside a critical finding showed one
  perfectly valid record and the second existed nowhere in the result. The
  reasonable conclusion from that screen was that the tool was wrong, and it was
  reported as exactly that.

  `analyzeDomain()` now returns `spfRecords` with every match, the detail panel
  renders the whole conflicting set under "N conflicting records — none of them
  applies", and the finding names the count the way `dkim-multiple-records`
  already names its selectors. The lookup meter is withheld from a conflicting
  set: it is computed from the first record, and shown beside all of them it
  would attribute one record's lookup count to the rest.

  The `SPF Record` CSV column carries the whole set for the same reason. A count
  in the `Issues` column says how many records conflict; the records themselves
  are the evidence, and exporting only the first reproduced the same misleading
  presentation outside the interface. The column keeps its index, a domain with
  one record produces a byte-for-byte identical cell, and multiple records are
  joined with newlines in resolver order — every cell is already quoted
  unconditionally with embedded quotes doubled, so a newline inside the field is
  RFC 4180 §2.6 transport and the serializer needed no change.

  `rowHygieneValues()` scans the whole set too. The data columns carry the
  published bytes verbatim by design, so the `Record Hygiene` column is the only
  place a bidi override or zero-width character is named — and scanning only the
  first record let a marker in the second reach the export unannounced.

  Pre-dates this release — the single-match selection has been there since
  `29f1bbe` — but it is the same defect class 0.4.0 is about, a claim shown
  without the evidence that supports it, so it is fixed here rather than
  deferred. Single-record domains are unaffected.

### Changed

- **`dnsTypeNum()` throws on an unknown record type instead of returning the TXT
  type number.** The old `?? 16` fallback made the function total, and the cost
  of that totality was the worst answer this codebase can produce: a caller
  asking for `DS` issued a TXT query, filtered the answers for type 16, found
  none, and received a plausible-looking empty array — no error, and a confident
  "nothing published" about a type that was never asked for. `PTR`, `DS`,
  `DNSKEY` and `TLSA` are added. Every existing call site passes a supported
  literal, so this is behaviour-preserving for the code that exists and
  fail-fast for the code that comes next.

  The throw is resolved before the concurrency slot and re-thrown by
  `optionalCheck()`. Both matter: `fetchDohOnce()`'s own catch would otherwise
  have reported it as `network-error`, and `optionalCheck()` would have degraded
  it to a stated "unknown" — either of which restores the silent wrong answer in
  a different costume.

### Notes

- **No scoring changes.** `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are
  byte-identical to 0.3.0, and every observation above is advisory. Measured
  across the 40-domain backtest: **zero grade movement and zero score movement**,
  with the deep checks both off and on. Unlike 0.3.0, where movement was
  expected and explained, here there should be none and there is none.

- **A domain that was clean did not get worse; the tool got more thorough.**
  Twenty-one new findings can read as a regression on a domain that previously
  showed nothing. None of them changes a grade.

- **Query fan-out is measured, and `PRIVACY.md` is updated with the real
  numbers.** MX health and TLSA cost three queries per MX host plus one more
  each, so they sit behind a toggle. **That toggle ships on**, and turning it off
  is what returns the fan-out to 0.3.0's — `cloudflare.com` issues
  exactly 43 queries on both releases. With them on, the 40-domain sample goes
  from 31.9 to 39.1 queries per domain. `node tools/backtest.mjs --deep`
  reproduces it.

## [0.3.0] — 2026-08-25

### Changed

- **DMARC discovery follows the RFC 9989 DNS Tree Walk instead of the Public
  Suffix List.** Previously the audit made at most two DMARC queries: one at
  `_dmarc.<domain>`, and on a miss one more at the name a bundled Public Suffix
  List picked. That approximation reaches the wrong name whenever a domain's
  real DMARC boundary differs from its PSL boundary, cannot see a policy
  published at an intermediate level, and cannot honour `psd=` — the tag that
  exists precisely so the boundary comes from DNS rather than from a list
  maintained elsewhere. `discoverDmarc()` now walks from the audited name up to
  the top-level domain, capped at eight queries by RFC 9989 §4.10's shortening
  rule, stopping early at a `psd=y` or `psd=n` boundary.

  **This moves some grades, and no scoring rule changed to do it.** `WEIGHTS`,
  `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are byte-identical to 0.2.3. A domain
  moves only because a different record is now found. Measured across two
  40-domain backtests: no DMARC-pillar movement at all on apex domains, and one
  move on a subdomain list — `www.gov.uk`, F → D. `gov.uk` is a PSL public
  suffix, so the old code never looked above it; the Tree Walk queries
  `_dmarc.gov.uk` and finds a real `p=reject; sp=none; np=reject` record.

  The vendored PSL file stays, but no DMARC decision consults it any more — the
  external-report authorization check in RFC 9990 §4 is defined against
  organizational domains, and those now come from the walk on both sides. The
  list is retained only for the hosting and provider heuristics.

- **Duplicate DMARC records no longer mean "no DMARC policy".** RFC 9989 §4.10
  discards every record when a name returns more than one and then *keeps
  walking*, so a valid record higher in the tree still governs. The finding
  stays critical — two records at one name is a real misconfiguration that makes
  every receiver ignore both — but it no longer claims that nothing applies when
  something does. There are two messages now: one that names the governing
  policy, and one for when there is genuinely nothing above.

- **External report authorization is checked against the name the applied
  record was found at**, and follows RFC 9990 §4 as written. One query is
  issued, at the single name the RFC constructs — a Report Consumer's wildcard
  authorization is synthesized by the resolver while answering it, so there is
  no second lookup to make and querying the asterisk owner directly was never
  the algorithm. That mattered beyond the saved query: wildcard synthesis is
  suppressed when the queried name already exists, so a destination whose exact
  name holds unrelated data is not authorized, where the old fallback found the
  wildcard beside it and authorized anyway. Records are now parsed in full
  rather than accepted on the version tag alone (§4 step 6 requires both), the
  `v=DMARC1` tag is validated rather than prefix-matched so `v=DMARC1x`
  authorizes nothing, and a destination publishing several records is authorized
  when at least one **complete** record parses (§4 step 8).

  A destination that authorizes your reports and then redirects them to a
  different host is now reported as unusable rather than as authorized. RFC 9990
  §4 says receivers must send to neither the original nor the override address
  in that case, so "authorized" would have meant reports were flowing when
  nothing was being sent at all. A merely malformed override is still ignored
  and the authorization stands, per §3.5.

- **The number of report destinations one audit will follow is capped at ten**,
  in the order the record gives them, and the audit says so when it stops short.
  Every destination outside your organizational domain costs a tree walk plus an
  authorization query, and the count is set by the audited record itself — RFC
  9990 §3.5 anticipates this, delivering to each URI "up to the Receiver's
  limits on supported URIs".

### Added

- **A failed DMARC lookup is reported as unverified, not as missing.** The walk
  issues up to eight queries where the old code issued one or two, so a
  transient resolver failure is correspondingly more likely — and "we could not
  check" and "you have no DMARC record" are very different things to tell
  someone about their production domain. A walk that ends in a DNS error now
  yields an `unknown` status with its own badge and finding, and the DMARC
  pillar is marked as unproven rather than silently scored as absent. The score
  is still zero, per the existing rule for controls this audit cannot prove.

- **A misplaced or miscased DMARC record is diagnosed instead of reported as
  missing.** `p=reject; v=DMARC1` (version not first), `v=dmarc1; p=reject`
  (wrong case — the value is case-sensitive), a record with no `v=` at all, and
  a record published on the domain's own TXT set instead of under `_dmarc` each
  produce a specific finding naming the actual problem. The last of these is
  common and previously indistinguishable from having no record: `zoom.us`
  publishes a complete, correct DMARC record where no receiver will ever read
  it. Where a working policy exists as well, the apex copy is reported as an
  ignored leftover rather than a critical defect — the same rule the duplicate
  finding follows, that a message must never claim no policy applies when one
  does. Each diagnosis names the DNS name the broken record is actually at,
  which matters now that the walk visits names the operator may not control.

- **Discovery evidence in the interface and the export.** The DMARC detail line
  names the name the policy was found at and how many lookups it took, and the
  step-by-step walk is shown when it did something worth seeing — an inherited
  policy or an early stop — and is behind a disclosure control otherwise. Three
  CSV columns are appended: `DMARC Found At`, `DMARC Labels Up` and
  `DMARC Discovery Terminated`.

- **`np=` is applied only to names that do not exist.** RFC 9989 §4.10.1 takes
  the inherited policy from `sp=` when the audited name exists and from `np=`
  when it does not; existence was never tested before. Where a record publishes
  an `np=` that does not govern the audited name, that is now stated rather than
  left to look like an inconsistency.

- **Stricter DMARC tag validation.** An `sp=`, `np=`, `adkim=` or `aspf=` value
  that is not one the RFC defines is reported and the written value named.
  Receiver behaviour is unchanged — these still fall back exactly as before —
  but `adkim=strict` relaxes alignment while reading as strict, and that is
  worth saying out loud.

- `tools/backtest.mjs` now reports the DNS query fan-out of every run, so the
  figure `PRIVACY.md` publishes is measured rather than estimated.

### Removed

- **The `dmarc-psd-invalid` finding.** It asked the bundled Public Suffix List
  whether a `psd=y` declaration was justified — the last place a DMARC decision
  consulted that list — and it asked about the audited name rather than the name
  carrying the applied record. A domain inheriting the real `_dmarc.gov` PSD
  policy is its own PSL organizational domain, so the check fired and called
  that correct declaration invalid: a false positive on the very case this
  release adds support for. There is no DNS-only test that disproves a `psd=`
  declaration, which is the whole reason the tag exists. `dmarc-bad-psd`
  remains, checking the value vocabulary the RFC actually defines.

### Fixed

- Corrected the RFC section cited in nine user-facing findings and nineteen code
  comments. The `v=` tag rules are RFC 9989 **§4.7** (DMARC Policy Record
  Format), not §5.4 (Policy Enforcement Considerations), and RFC 9990's
  external-destination procedure is **§4**, which has no subsections. Five of
  these citations predate this release.

- `tools/lib/doh-fixture.mjs`, a programmable DoH resolver for the test sandbox.
  No production code gained a test seam: the sandbox's own `fetch` is replaced,
  so fixtures exercise the real URL building, JSON parsing, cache, concurrency
  limiter and retry loop. Unmatched queries default to NXDOMAIN so a fixture
  cannot silently depend on a live lookup.

### Documentation

- `PRIVACY.md`'s query fan-out is updated from the measurement: roughly 32
  queries for a typical domain, up from roughly 30, and 46 for `cloudflare.com`
  with default options. The Tree Walk's own cost and the walk over each report
  destination are both described, because both add query names that were not
  sent before.

## [0.2.3] — 2026-08-24

No grade or score changes: a grade computed at `v0.2.2` is identical here,
verified by diffing `node tools/backtest.mjs --json` across the two.

### Changed

- **The interface is built from DOM nodes instead of HTML strings.** Every
  rendered cell, badge, score block and detail row is now constructed with
  `createElement`/`textContent` through a new `js/render.js`, and the escape
  helper `esc()` is deleted rather than kept — leaving one available invites the
  next concatenation site. Both document builders (the learn-more guides and the
  exported HTML report) construct a detached tree and serialize once, which
  establishes the rule the release enforces: reading `outerHTML` is permitted,
  writing `innerHTML` or `outerHTML` never is. Nothing under `js/` assigns to
  either, and the allowlist for that rule is empty, enforced by a runtime setter
  trap in the test DOM and a static scan in `npm test`.

  The visible output is unchanged. Record separators, spacing and every cell's
  appearance match 0.2.2 exactly; only how they are built changed.

- **The progress log no longer rebuilds on every line.** `log()` appended with
  `el.innerHTML +=`, which serialized and reparsed the whole log on each of a
  200-domain run's 200-plus appends. It now appends one node.

- **The CSV export is spreadsheet-safe.** A domain controls its own record text,
  and a cell beginning `=`, `+`, `-`, `@`, or a tab/newline is executed as a
  formula when a CSV is opened in Excel or Google Sheets — RFC 4180 quoting does
  not prevent this, because the quotes are stripped before the cell is
  evaluated. Any such cell is now prefixed with an apostrophe, which
  spreadsheets treat as literal text and do not display, and the row is marked
  `formula-leading` in the new `Record Hygiene` column.

  This is the only place the CSV departs from the published bytes; every other
  character, including invisible ones, is exported exactly as received. The
  prefix is a display-time mitigation: OWASP notes Excel may drop it if the file
  is re-saved as CSV from inside Excel and reopened, and that no single strategy
  is safe across every spreadsheet application. Read the HTML report or the
  results table if you need the bytes exactly as published.

### Added

- **Malformed records are shown, not silently rendered.** A record can be
  hostile in the *display* sense without being hostile in the execution sense: a
  bidirectional override inside an SPF `include:` host visually reverses the
  hostname, so a reader checks the wrong domain while the escaping was entirely
  correct. Every character Unicode marks `Default_Ignorable`, plus C0/C1
  controls, is now replaced at its exact position by a visible marker naming the
  code point — `‹RLO›`, `‹ZWSP›`, `‹U+0007›`. The character is genuinely gone
  from the text run, so no reordering survives, and the marker sits where it was,
  so the technique stays visible. Stripping would have neutralized the attack
  while hiding it.

  Variation selectors, and shorthand and musical notation format controls, are
  exempt as legitimate content, so emoji render normally. Script-format
  characters such as the Arabic number signs are not default-ignorable at all,
  so Arabic, Syriac and Egyptian text is untouched.

- **Display caps that never reach the data.** A value is painted up to 1,024
  characters — code points, so an emoji at the boundary is not split — with a
  disclosure control revealing the rest; a record list is painted 20 deep with a
  counted remainder. 1,024 clears a 4096-bit RSA DKIM key with headroom. The
  full value stays in the result object, in the CSV and in the HTML report.

- **A `Record Hygiene` column in the CSV**, appended rather than inserted so a
  locale predating it cannot misalign. It names what a record contained —
  `bidi-override`, `zero-width`, `control-char`, `lone-surrogate`, `punycode`,
  `formula-leading` — while the data columns keep the published bytes.

- **The exported HTML report carries its own Content-Security-Policy**
  (`default-src 'none'; style-src 'unsafe-inline'; img-src data:`). That file
  leaves this project's control the moment someone emails it.

- **Four dependency-free test suites and a DOM shim.** `tools/lib/dom-shim.mjs`
  implements only what the render path uses, with `innerHTML`/`outerHTML`
  setters that throw — catching computed and destructured assignment a static
  pattern misses. `npm test` now runs 972 assertions, up from 489, across
  scoring, interpolation, rendering, export and CSP.

### Fixed

- **Placeholder interpolation was sequential.** `interpolate()` replaced `{0}`,
  then rescanned the result for `{1}`, so a value substituted at `{0}` that
  itself contained `{1}` pulled the second argument into a position the
  translator never wrote. Nothing reachable exploited it, because every current
  message takes an internal value first — but the next two releases both add
  messages whose first argument is a DNS-derived name. It is now a single pass,
  and an index with no corresponding argument is left as written rather than
  becoming `undefined`.

- **Sanitized rich text round-tripped through a string.** The locale sanitizer
  parsed into a `<template>`, walked it, then returned `innerHTML` for the
  caller to reparse — serializing a sanitized tree and reparsing it is the shape
  mutation XSS exploits. It is now a fail-closed tokenizer that builds nodes
  directly; anything outside the twelve-tag allowlist is emitted as literal
  text, and `npm run check` fails the build on any such tag in a locale file.

- **`esc()` did not escape single quotes.** Correct only because every generated
  attribute happened to use double quotes — a property maintained by habit
  across twenty-odd concatenation sites rather than by construction. The helper
  is gone.

- **The DNS-over-HTTPS cache grew without bound** for the lifetime of the page,
  so a long session auditing several batches retained every answer it had ever
  seen. It is now capped at 4,096 entries with least-recently-used eviction.

- **`README.md` claimed 174 assertions.** `CONTRIBUTING.md` gains two
  release-checklist entries: read the figure out of a test run at each cut
  rather than typing it from memory, and re-check `CHANGELOG.md`, the pull
  request description and `README.md` on every push to an open pull request —
  adding a commit updates none of them, and nothing fails when they go stale.
  `AGENTS.md` gains the matching convention for the description itself: review
  rounds are appended below a `---` separator with what was addressed, what was
  declined and why, and whether each reviewer claim held up against the code —
  never overwritten, so what a pull request originally claimed stays legible.

### Security

- `img-src` narrowed to `'self' data:`. The only thing this forbids is fetching
  an image from a host named in a stranger's record, which would disclose the
  auditor's address to that host.
- The fixed, published `nonce-dns-audit-static` is replaced by a SHA-256 hash of
  the structured-data block. A nonce whose value is published authorizes any
  injected script bearing the same attribute, so the policy claimed a control it
  did not have. `tools/csp.test.mjs` recomputes the digest, so a future edit to
  that block is self-correcting.
- `connect-src` is unchanged at `'self' https://cloudflare-dns.com`, and there
  is still no persistence beyond the single `dns-email-audit-lang` key.

## [0.2.2] — 2026-08-20

### Added

- **DKIM selectors for the services your SPF record names.** A normal
  (non-Comprehensive) scan tests the selectors of the provider detected from
  MX. That only ever names one provider, so a helpdesk or ESP that signs part
  of your mail stayed invisible unless you ran a 1,677-selector Comprehensive
  scan. An `include:` is the domain stating that a vendor sends mail for it —
  the same claim MX makes about the inbound provider — so provider-aware mode
  now also tests the selectors of any catalog vendor named by an `include:` or
  `redirect=` in the domain's own SPF record. `slack.com` is the live example:
  MX says Google Workspace, SPF names Zendesk, and `zendesk1`/`zendesk2` are
  published — a normal scan now finds both, taking the domain from B (60) to
  A+ (75), at 22 selectors tested instead of 1,677.

  Only the literal hostnames in the domain's own record are matched; the
  included records are not walked, and no extra DNS lookups are made beyond
  the selector probes themselves. A domain whose SPF names no known vendor
  scans exactly as it did before.

  Each such finding is tagged with the vendor SPF pointed at — *via SPF:
  Zendesk* — in both the detail view and the CSV export, so a selector that
  belongs to neither the MX provider nor anything you typed explains itself.
  Selectors that would have been tested anyway are not tagged. Translated into
  all thirteen locales.

## [0.2.1] — 2026-08-20

### Added

- **XLIFF-based locale pipeline.** `locales/translation-status.json` tracks
  every key in every locale using the XLIFF 2.1 `state` vocabulary verbatim —
  `initial`, `translated`, `reviewed`, `final` — plus a namespaced `subState`
  (`kwestic:mt` for machine-translated, `kwestic:stale` for a translation whose
  English moved underneath it, the same idea as gettext's `fuzzy`). State is
  derived from the files by fingerprinting both sides, not trusted from the
  database, so editing either the English or a translation is detected on the
  next `locale:sync`.

  Four new commands drive it: `locale:sync` scaffolds and recomputes state,
  `locale:todo` emits a per-locale work order (as JSON, carrying the target
  language by name, the English source, and the placeholders and inline tags
  that must survive), `locale:set` applies a patch file and **refuses any unit
  whose `{0}`/`{1}` placeholders or `<code>`/`<em>`/`<strong>` tags do not
  match the English**, and `locale:gate` blocks a PR while any key is still
  `initial`. `pr-readiness.mjs` summarizes the state for a PR description.

  This replaces a Markdown-packet round-trip that never named the target
  language, was lossy for values containing newlines and DNS record syntax, and
  could only record whether a key was present or absent.

- **Five new languages: Brazilian Portuguese, Polish, Turkish, Indonesian and
  Dutch.** Polish carries 543 keys rather than 533 because CLDR gives it
  `one`/`few`/`many`/`other` where English has two plural categories; the
  tooling preserves categories English does not have.

- **`AGENTS.md`** — one contract shared by every coding agent working in the
  repo, covering the translation loop, the terminology that must stay literal
  (record types, tag names, example domains, `fixCode` record syntax), register
  per language, and the CLDR plural rule. `CLAUDE.md` points at it so both
  toolchains read the same rules.

### Changed

- **Every locale is now complete.** The eight existing translations went from
  409–413 keys to 533 — **988 previously untranslated keys filled** — and the
  five new locales landed complete, for 3,663 new translations in total. A
  missing translation is invisible at runtime because the UI silently falls
  back to English, which is how a 124-key gap sat in seven locales for months.
- `check-locales.mjs` reworked to validate against the state database, with a
  `--strict` mode behind `locale:gate`.

### Notes

- Arabic and Hindi were considered and deliberately deferred. Arabic is a
  layout problem rather than a translation one: 140 strings carry DNS syntax
  that reorders visually under RTL, and blocks meant to be copied into a DNS
  panel must not read scrambled. Hindi was deferred on editorial grounds — DNS
  terminology has little settled Hindi convention.
- No runtime code changes: `js/`, `css/`, `index.html` and `locales/en.json`
  are unchanged by this release.

## [0.2.0] — 2026-08-20

### Added

- **SPF authorized-range size audit.** Every `ip4:`/`ip6:` block in a record is
  classified by how much address space it authorizes. IPv4 is judged on host
  count — a `/24` is 256 addresses that can all send as you. IPv6 is judged on
  allocation tier and deliberately does *not* reuse the IPv4 table: RFC 4291
  §2.5.4 makes `/64` the standard single-subnet allocation, frequently one mail
  server, and the `2^n` reasoning that makes an IPv4 `/24` worth a look would
  rate that same `/64` as eighteen quintillion hosts and flag it hardest of all.
  `nih.gov` publishes four of them and they are unremarkable. Single-host blocks
  are classified but never surfaced as findings — `stanford.edu` publishes 15
  `ip4:` mechanisms, 13 of them `/32`, and a line each saying "this is one host"
  buries everything worth reading.
- **SPF redundancy audit.** An `a` or `mx` mechanism spends one of the 10
  permitted DNS lookups. When every address it resolves to already sits inside
  an `ip4:`/`ip6:` block written into the same record, that lookup buys no
  authorization and can be reclaimed. `python.org` is a live example: its `mx`
  resolves to exactly the two addresses its own `ip4:`/`ip6:` mechanisms list,
  and removing it takes the record from 8 lookups to 7 — out of the near-limit
  warning band — with no change to which servers can send.

  Removal is only ever recommended when **both** address families are fully
  covered. A hostname with an `AAAA` record, in a record carrying no `ip6:`
  mechanism, is never flagged: the IPv4 side looks fully covered, and acting on
  that would silently drop IPv6 authorization. Partial coverage is reported as
  an informational note instead, so the finding is not lost and the mechanism
  is not deleted while it is still doing real work.

  Both checks are advisory and feed no part of the weighted rubric — verified
  by a before/after back-test showing no grade or score movement across the
  40-domain sample. They cost no DNS lookups at all on records with no
  `ip4:`/`ip6:` block, which is most of them.
- **`PRIVACY.md` and `SECURITY.md`,** linked from the options row, the "How it
  works" callout and the page footer in all nine shipped locales, with the link
  labels translated like every other string in the app. `PRIVACY.md` documents
  the whole footprint: one `localStorage` key (`dns-email-audit-lang`, written
  only when the language selector is used), no cookies, no analytics, no
  backend. It also states what the app does *not* hide — one audit is roughly
  30 DNS queries, not one, and because the SPF `include:` chain is resolved,
  the query pattern reveals which email and SaaS vendors the audited domain
  uses, not merely that someone looked it up. Documentation only; nothing about
  what the app stores or transmits changed.

### Fixed

- **A failed optional DNS lookup no longer discards the whole audit.** Every
  check behind `www`, `wildcard` and the advanced set threw on SERVFAIL, and
  because nothing caught the throw the entire result was dropped — SPF, DKIM,
  DMARC, MX and all — for a domain whose core records had resolved perfectly.
  A transient resolver failure on website-hosting detection was enough to
  delete a complete email-security audit. Across a 200-domain run that is close
  to certain to hit someone. Optional checks now degrade to a stated unknown
  and the audit completes.
- **A failed optional lookup is named instead of passed over.** CAA, MTA-STS,
  BIMI, TLS-RPT and the SPF lookup count each record whether their lookup
  actually answered, and any that did not are listed in the results by name so
  a re-run can settle them. They are scored as unconfigured — see the grading
  change below.
- **A failed wildcard probe is no longer read as "no wildcard".** Each depth
  stays explicitly false until its own probe answers.
- **The wildcard TXT check no longer fails domains it cannot be harming.** The
  probe asked one label deep, at `_wildcardtest99xyz.<domain>`, but inferred
  harm to DKIM discovery, which happens two labels deep at
  `<selector>._domainkey.<domain>`. It measured at a depth that does not
  predict the harm. `apple.com` and `ibm.com` both scored F (0/100) on the
  strength of an apex wildcard that never reaches DKIM — Apple's is a
  deliberate anti-spoofing measure, `*.apple.com IN TXT "v=spf1
  redirect=_spf.apple.com"`, so that mail from an invented subdomain meets a
  real SPF policy instead of finding none. Two of the three F verdicts in a
  15-domain survey were wrong. The probe now runs at both depths and the
  verdict follows the one that was actually measured.
- **No "you have not configured this" advice for checks that never ran.**
  The CAA, MTA-STS, TLS-RPT, BIMI and DNSSEC recommendations are suppressed
  when the corresponding lookup did not complete.
- **DKIM issue notes interpolate their counts.** `dkim-unverified` and
  `dkim-missing` rendered the literal `{0}` and `{1}` placeholders because the
  selector counts were never passed to the renderer. This note becomes far more
  common once failed lookups stop aborting the audit.

### Added

- A `checks-unverified` finding naming exactly which checks could not be
  completed, so a gap in the audit is stated rather than silently omitted.
- A `@dns-error` hosting state ("Lookup failed") distinct from a domain that
  genuinely has no web presence.
- `optionalCheck()`, the single wrapper all optional checks route through. It
  converts a DNS failure into a declared fallback and deliberately re-throws
  `AbortError`, so cancelling an audit is never mistaken for an unknown result.
- 32 new assertions, including a simulated resolver in which only the core
  records answer and every optional lookup returns SERVFAIL.

### Unchanged

- Core lookups stay fail-closed. With no usable NS response there is nothing to
  audit, and reporting a failure remains better than inventing a result.

### Changed

- **Grades are always a single letter — the floor–ceiling range is gone.** An
  unverifiable control used to be left unscored, which produced a two-letter
  grade like `C–B`, or `B–A+` in the worst case observed. Across a 40-domain
  live sample, 9 domains (22.5%) displayed one. A range reads as an error
  rather than a result and told nobody what to do next. Unproven controls now
  score zero, exactly like the parked-domain rubric has always scored them, and
  `grade`, `pts` and `cls` are the only score fields the UI reads
  (`gradeMin`, `gradeMax`, `maxPossible` and `uncertain` are removed).
- **A grade resting on an unverified check is marked in the results table.**
  The circle is drawn with a dashed border in its own tier colour and the
  letter carries an asterisk — `B*` rather than `B` — so a recoverable check is
  visible while scanning a 200-domain table, without expanding a row. The
  marker is display-only: `pts`, `grade` and `cls` are untouched, and the score
  object carries a new `unproven` array naming the pillars behind it. It covers
  DKIM (sampled or not checked), indeterminate DNSSEC, and any failed CAA,
  MTA-STS, BIMI or TLS-RPT lookup. It deliberately does not read as a warning:
  the tier colour is kept, because the grade is the real grade.
- **Every unproven control now states what it cost and how to recover it.**
  Because uncertainty is no longer free, `dkim-unverified` and
  `dnssec-indeterminate` are warnings rather than notes: the first names the
  **Additional DKIM selectors** field, the second asks for a re-run first and
  then gives the evidence a GitHub issue needs. `checks-unverified` likewise
  warns and says a re-run recovers the points. A new `dkim-not-checked` note
  covers the domain audited with DKIM checking switched off, which would
  otherwise have dropped 15 points in silence.
- **A wildcard TXT record no longer scores an instant F.** Even where the
  wildcard genuinely does cover `_domainkey` — `netflix.com` is the one case in
  the survey where it does — F=0 was the wrong answer. A poisoned `_domainkey`
  makes DKIM *absence* unverifiable; it leaves SPF, DMARC, DNSSEC and CAA
  perfectly measurable, and selectors that are published still resolve and
  still verify. DKIM now routes into the existing confidence machinery
  (`sampled` confidence, `noteWildcard`, `dkim-unverified`) and the remaining
  pillars stand on their own, which is how every other uncertainty in this
  project is already handled.
- **The two wildcard depths are reported separately.** A wildcard only the apex
  probe sees is an informational finding with no score effect
  (`wildcard-txt-apex`); one that reaches `_domainkey` is a warning
  (`wildcard-txt-dkim`). The old blanket `wildcard-txt` critical issue is gone.
- **A value synthesized by a `_domainkey` wildcard is no longer accepted as a
  DKIM key.** A wildcard whose value happens to parse as a key would otherwise
  report DKIM present at every selector tried, which is worse than reporting
  none. Such values are discarded by content.
- **DMARC is now evaluated against RFC 9989 (DMARCbis, May 2026)** instead of
  RFC 7489 + RFC 9091, which it obsoletes. The parser accepts the complete
  RFC 9989 tag set — `v`, `p`, `sp`, `np`, `adkim`, `aspf`, `fo`, `rua`, `ruf`,
  `psd`, `t` — and classifies anything else as removed (`pct`, `rf`, `ri`) or
  unknown.
- **`pct=` no longer contributes to the score.** RFC 9989 removed the tag, so a
  conformant receiver ignores it; scoring it meant grading against an obsolete
  spec. It is still parsed and surfaced: any record carrying `pct=` now gets a
  **recommendation** to remove it, naming RFC 9989 and its May 2026
  ratification, with a "Learn more" guide covering the migration. Advice to
  drop an obsolete tag is guidance rather than a defect, so it sits in
  Recommendations rather than Issues — but a `pct=` below 100 has a live
  consequence (receivers that have not migrated still honour it, so
  enforcement differs from one receiver to the next) and keeps its own
  warning-level finding.
- **The DMARC sub-score redistributes those 4 points.** New split: policy 12
  (was 10), effective subdomain coverage 6, aggregate reports 6 (was 5), strict
  alignment 3, forensic reports 2, and a new 1-point component for report
  destinations that can actually be delivered to. The total is unchanged at 30.
  Backtested over the 40-domain live sample: 29 domains scored identically, 11
  moved by 1–3 points, and **no domain changed letter grade**.
- The score breakdown now shows a "Report destinations" component in place of
  "Enforcement rate (pct=)".
- CSV export gains a `DMARC Test Mode (t=)` column (inserted after
  `DMARC Policy`). The header row is now backfilled per-index from English, so
  a locale whose header array predates a new column can no longer misalign the
  export.

### Added

- **`t=` (test mode) support.** `t=y` tells receivers not to apply the policy,
  so `p=reject; t=y` is scored at the `none` tier and badged as
  "reject (test mode, not applied)" rather than as enforcement. This was
  previously invisible: the record would have graded as full enforcement.
- **`psd=` parsing and validation**, including a warning when a domain that is
  not a public suffix declares `psd=y`.
- **Strict `v=` validation.** RFC 9989 requires `v=` to be the first tag with
  the case-sensitive value `DMARC1`; a record failing either test must be
  ignored entirely. `v=dmarc1` and a misplaced `v=` are now reported as
  critical findings rather than parsed as valid.
- **Report-URI parsing for `rua=`/`ruf=`**, covering the comma-separated list
  form, the `!` size-limit suffix, and unsupported schemes. A published but
  undeliverable destination is now a finding instead of a silent monitoring gap.
- **External report-destination detection and verification.** Reports sent
  outside the organizational domain require the destination to publish an
  authorization record (RFC 9990 §4.3). The audit now queries
  `<policy-domain>._report._dmarc.<destination>` and falls back to the
  wildcard form `*._report._dmarc.<destination>` that most reporting vendors
  publish, then reports a verdict per destination:
  - **authorized** — no finding at all. A correctly-configured domain hears
    nothing, which is the point: the previous blanket "verify this" notice
    fired on every external destination and was a false positive on every
    properly set-up domain (cloudflare.com and paypal.com both included).
  - **unauthorized** — a warning naming only the destinations that are
    actually being discarded.
  - **unverifiable** — an informational note when the DNS lookup itself
    failed. A timeout is missing evidence, not evidence of a missing record.

  Authorization is evaluated per URI, matching the RFC, so a record mixing an
  in-house mailbox with a vendor address is scored and reported correctly: the
  record stays valid, and only the unauthorized destination is flagged. When
  the advanced checks are off, the previous advisory notice remains as a
  fallback.
- **`fo=` validation**, plus a notice when `fo=` is present with no `ruf=`,
  where receivers must ignore it.
- Duplicate DMARC tags now report as their own finding rather than as
  "invalid p=".
- **A `dmarc-rfc9989` "Learn more" guide** explaining what DMARCbis changed:
  the RFC 9989/9990/9991 split, why `pct=` was removed, how `t=` replaces it
  for staged rollout, the complete eleven-tag vocabulary, and external report
  authorization.
- 119 new assertions covering the above (`npm run test:scoring`), including
  checks that every recommendation has translated text and that no
  recommendation links to a guide that does not exist.

### Changed

- **Scoring is now a single weighted 0–100 rubric** instead of an additive
  points-to-grade shortcut. Pillars: DMARC 30, SPF 15, DKIM 15, DNSSEC 15,
  CAA 10, MTA-STS 8, BIMI 4, TLS-RPT 3. DNSSEC still gates the A tier — an
  unsigned zone caps the grade at B regardless of everything else.
- TLS-RPT now contributes to the score. Previously it was displayed in the
  advanced strip but had no effect on the grade.
- The `A` grade is reachable again. Thresholds are 85 (A++), 75 (A+), 65 (A),
  50 (B), 30 (C), 10 (D), all A tiers requiring DNSSEC.
- Parked domains (no MX) are scored on their own rubric — SPF 30, DMARC 30,
  DNSSEC 25, CAA 15 — since DKIM, BIMI, MTA-STS and TLS-RPT cannot apply to a
  domain with no mail flow. A fully hardened parked domain can now reach the
  A tier rather than being capped at B.
- CSV export gained Grade, Score, and the full DMARC tag set (`sp`, `np`,
  `pct`, `adkim`, `aspf`, `ruf`). The grade was previously absent entirely.

### Added

- Full DMARC tag parsing per RFC 7489 and RFC 9091: `sp`, `np`, `pct`,
  `adkim`, `aspf`, `ruf`, with the documented inheritance chain
  (`np` → `sp` → `p`) resolved into `effectiveSp` / `effectiveNp`.
- Per-pillar score breakdown in each domain's detail row, including the DMARC
  sub-score components, so a grade can be explained rather than just asserted.
- New checks: `dmarc-quarantine` (harden to reject), `dmarc-weak-sp`,
  `dmarc-weak-np`, `dmarc-partial-pct`, `dmarc-bad-pct`,
  `dmarc-invalid-policy` — each with a full explainer and example records.
- Duplicate-record detection for all six record types that fail closed with
  more than one record: SPF (RFC 7208 §4.5), DMARC (RFC 7489 §6.6.3), MTA-STS
  (RFC 8461 §3.1), TLS-RPT (RFC 8460 §3), BIMI (draft §7.2) and DKIM keys per
  selector (RFC 6376 §3.6.2.2). Each scores zero for its pillar and raises a
  dedicated issue with merge instructions — previously the first record was
  silently used and the domain scored as if correctly configured. CAA and MX are
  excluded: multiple records there are legitimate.
- `npm run test:scoring` — 125 assertions over the parser, sub-scores, grade
  ladder, rubric integrity, duplicate-record handling and issue detection.
- `tools/backtest.mjs` — runs the real scoring code against live domains and
  prints the grade distribution, score percentiles and per-pillar adoption, for
  validating threshold changes.

### Fixed

- DMARC records were selected with a case-sensitive prefix match, so a valid
  `V=DMARC1` record was reported as **missing** and the domain scored as having
  no DMARC at all. Same bug affected SPF, DKIM, BIMI, MTA-STS and TLS-RPT
  record selection.
- A `pct=` value that wasn't a number produced `NaN`, which propagated through
  the total and silently graded the domain **F**. Out-of-range values are now
  clamped and flagged.
- An unrecognised `p=` value (typo, unsupported keyword) was treated as
  `p=none` and earned partial credit. Receivers cannot act on it, so it now
  scores zero and raises a critical issue.
- Subdomain policy was previously unscored: `p=reject` with no `sp` tag is
  fully protective via inheritance, but any rubric keyed on tag *presence*
  penalises it. Scoring now uses the effective policy, so explicit and
  inherited protection score equally and only genuine weakening (`sp=none`)
  costs points.
- An SPF record exceeding the 10-lookup limit evaluates to `permerror` and
  never passes, but scored full marks for a strict `-all`. It now scores zero.
- `+all` and `?all` no longer earn partial SPF credit, while a missing provider
  include — a real record one line short — still does.
- DKIM key extraction took `txt[0]` after testing whether *any* record at the
  selector was a key, so an unrelated TXT record sharing the selector name could
  be reported as the DKIM key. It now filters to `v=DKIM1` records first.
- "Not configured" recommendations for MTA-STS, TLS-RPT and BIMI are suppressed
  when the record exists but is duplicated — telling someone to publish a record
  they already have twice is actively misleading.

## [0.1.0] — 2026-08-17

First public release.

### Added

- Audits SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC for up to 200
  domains per run, entirely client-side via Cloudflare DNS-over-HTTPS.
- Detects DNS provider, email provider and website hosting from NS, MX, A and
  CNAME records, including self-hosted setups and ccSLD domains.
- SPF lookup-depth analysis that follows `include:` and `redirect=` one level
  deep and warns before the hard 10-lookup limit.
- Wildcard TXT detection — catches a `* TXT` record silently breaking DKIM and
  DMARC on every subdomain.
- Letter grading (A++ through F) with DNSSEC as a hard gate on any A grade, and
  a separate scoring path for parked domains with no email.
- Plain-language explanation and copy-paste DNS records for every issue found,
  behind a "Show me" toggle.
- Long-form guides for BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC, opened in a new
  tab as self-contained pages.
- CSV export and a self-contained, script-free HTML report.
- Filter, search and sort across results; per-domain detail rows.
- Internationalization: English and Spanish, with a dependency-free JSON
  translation layer. Missing keys fall back to English, so partial translations
  are usable.
- `npm run check` validates every locale against `en.json` — placeholder
  mismatches and stale keys fail CI, missing keys only warn.
- GitHub Actions workflows for Pages deployment and locale validation.

### Notes

- Spanish ships at roughly 40% coverage; the remainder falls back to English.
- No backend, no build step, no runtime dependencies. Opening `index.html`
  directly from disk works in English — browsers block `fetch()` of local JSON
  over `file://`, so other languages need the app served over HTTP.

[Unreleased]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kwestic-tech/dns-email-audit/releases/tag/v0.1.0
