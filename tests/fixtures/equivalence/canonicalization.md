# Canonicalization rules

**Status:** Checked in **before** the corpus, per spec Design §8 and
implementation Task 0.4.b. These rules are not derived from the corpus and must
not be widened to make a captured baseline pass.

**Implementation:** [`tests/lib/canonical.mjs`](../../lib/canonical.mjs). Every
rule below names the function that carries it.

**Proof:** [`tests/contract/canonicalization.test.mjs`](../../contract/canonicalization.test.mjs)
asserts each rule *and* the negative case that proves the rule can fail. A
canonicalizer nobody has watched reject a difference is not an instrument.

---

## The governing constraint

> A canonicalizer loose enough to never cry wolf is loose enough to absorb a
> real regression.

These rules are strict enough that inconsequential differences will surface.
That is deliberate and it is spec Design §8's final ruling after review round 3.
**Each tolerance added must name the difference class it admits and why that
class cannot carry a defect.** A tolerance whose admitted class cannot be
bounded is framework §6 trigger 2 — stop and write a Codex review.

Time and locale are controlled **inputs**, supplied through the platform
binding, not excluded outputs. There is no timestamp wildcard.

---

## 1. Result — `encode()` / `canonicalResult()`

The whole `analyzeDomain()` return value, not the grade. The Non-goals promise
"same statuses, findings, severities, scores **and explanations**".

| Rule | Why |
| --- | --- |
| **Recursively sort object keys.** The only sort applied to the result. | Key order is not observable behaviour. |
| **Preserve array order.** Never sorted, never deduplicated. | Several arrays are semantically ordered: the DMARC walk `steps`, the DNSSEC `chain` claims, the scoring `pillars`, `issues`, `suggestions`. Sorting them erases the behaviour under test. |
| **An absent property and a property present with `undefined` are different.** Absent keys stay absent; `undefined` encodes to `{"$undefined":true}`. | `checkDNSSEC()` sets `error` to `undefined` on a determinate result ([`js/dns.js:4128`](../../../js/dns.js)) while the not-checked DKIM shape omits six properties outright ([`js/dns.js:5470`](../../../js/dns.js)). A refactor turning one into the other is a real change. |
| **Tag non-JSON primitives, never coerce.** `BigInt` → `{"$bigint":"…"}`; `NaN` / `±Infinity` / `-0` → `{"$number":"…"}`. | The SPF subnet arithmetic is `BigInt` throughout ([`js/dns.js:4213`](../../../js/dns.js)). `JSON.stringify` throws on one and silently turns `NaN` into `null` and `-0` into `0`. |
| **Tag `Map`, `Set`, `Date`, `Error` and typed arrays** rather than serializing them to `{}`. | Nothing in the v0.5.0 result carries one. Tagging makes that a fact the runner reports rather than an assumption it rests on. |
| **Refuse a function, a symbol or a cycle.** Throws, naming the path. | Any of the three reaching the result surface is a defect, not a formatting problem. |
| **No blanket removal of empty values.** `[]`, `''`, `0`, `false` and `null` are all preserved and all distinct. | `caa.issuers === []` means "this policy authorizes nobody" — RFC 8659 §4.2. Dropping it inverts the finding. |
| **No float rounding.** | A number that changed is a change. |

Serialization is `JSON.stringify(value, null, 2)` plus a trailing newline —
stable, because `encode()` already fixed key order, and diffable, because the
baseline is a committed file a human has to read.

## 2. Query trace — `canonicalQueryTrace()` / `orderedSubsequence()`

| Gated on | Not gated on |
| --- | --- |
| The **multiset** of `(name, type, do, cd)` with occurrence counts | Global chronology |
| Total and distinct query counts | Which independent branch finished first |
| Maximum observed concurrency and batch size | |

Global chronology is excluded for a stated reason, and it is the one exclusion
in this document: independent `Promise.all` branches may interleave differently
between two runs of **identical** code. Gating on that produces failures that
carry no information, and a surface that cries wolf is a surface people learn
to ignore. The admitted difference class is exactly "the relative order of
concurrent, independent branches", and it cannot carry a defect because the
multiset, the counts and the concurrency ceiling are all still compared.

**Order is asserted separately and explicitly for the two algorithms where the
sequence is the behaviour:**

- the **DMARC tree walk** — RFC 9989 §4.10 fixes the order of subject names,
  and `dmarcWalkTargets()` ([`js/dns.js:1900`](../../../js/dns.js)) is the part
  of the release most likely to be subtly wrong;
- **SPF recursive evaluation** — `countSpfLookups()`
  ([`js/dns.js:4147`](../../../js/dns.js)) walks `include:`/`redirect=` depth
  first, and the cycle and void-lookup counts depend on that order.

This surface exists because a lost cache hit is **invisible in the result** and
changes a published figure: [`PRIVACY.md:30-33`](../../../PRIVACY.md) states
"roughly 41 queries for a typical domain" and 61 for `cloudflare.com`. A
query-trace diff with an identical result is still a stop.

## 3. CSV — `canonicalCsv()`

**Exact bytes.** No canonicalization at all, and the function exists to say so
and to fail loudly if a caller hands it anything but text.

Included in the comparison: the UTF-8 BOM, the header row, column order, the
`\r\n` line ending that `toCsvText()` writes, and every quoted and escaped
field including the formula-neutralization prefix.

The columns are positional — [`js/app.js:1452`](../../../src/main.js) backfills a
short translated header from English **by index** — so a reordered column
silently breaks anyone parsing the file while every value in it stays correct.

## 4. HTML report — `canonicalDom()` + `reportByteRegions()`

The parsed tree is canonicalized as in §5 below. Two regions are additionally
compared as **exact bytes**, because they are precisely what a tree
canonicalizer would be allowed to normalize away:

- the embedded policy
  `default-src 'none'; style-src 'unsafe-inline'; img-src data:` — the report
  leaves the project's control the moment someone emails it and carries its own
  security policy, asserted at [`tools/csp.test.mjs`](../../../tools/csp.test.mjs) §5;
- the **inlined stylesheet**, byte for byte and by byte length.

The stylesheet is read from the subject root's own `css/style.css`. A baseline
run must never pair v0.5.0 JavaScript with current-branch CSS.

## 5. DOM — `canonicalDom()`

| Rule | Why |
| --- | --- |
| **Ordered node and child structure**, arrays never sorted | Document order is behaviour. |
| **Exact text.** Whitespace text nodes are not normalized away and text is not trimmed. | The hygiene sentinels `‹RLO›` and `‹ZWSP›` are exact text, and so is the astral character at the display cap that `tools/export.test.mjs` pins. |
| **Attributes as a sorted name/value map**, `dataset` folded in as `data-*` | Attribute order is not observable and a DOM shim need not preserve it. |
| **Non-attribute properties compared explicitly**: `value`, `checked`, `disabled`, `hidden`, `selected` | `#optDeepChecks` is a real checkbox whose `.checked` the code reads and writes, and that state never appears in the markup. |

## 6. Exclusions — `applyExclusions()`

**One manifest entry per excluded field, each with a stated reason.**
**No wildcard field classes** — a path containing `*` is refused, not expanded.
An exclusion nobody can enumerate is a hole nobody can review.

The manifest is expected to stay **empty**. If an entry is ever needed, it names
the difference class it admits and why that class cannot carry a defect, and
adding it is a framework §6 trigger 2 review.

Time and locale are not exclusions. They are inputs: the runner supplies a
fixed instant and a fixed locale formatter through the platform binding, so
`report.generated` contains the same formatted timestamp in the baseline,
source and bundle runs.

## 7. What binds a comparison

Per spec Design §8, a baseline is only meaningful with its subject pinned. The
manifest records, for every subject root:

- the commit or tag, and the resolved subject-root path;
- Node and ICU versions, the fixed instant, and the locale;
- **SHA-256 of every loaded HTML, CSS, locale and script input**.

Each subject is a **complete root**. The runner loads that root's own
`index.html`, stylesheet, generated English bundle and JavaScript, and may not
pair baseline JavaScript with current-branch assets.
