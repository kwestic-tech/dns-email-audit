# `src/core/dns/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Obtaining DNS information, and nothing else. This directory
emits no finding, severity, score, locale key or protocol verdict. Spec §3:
"`src/core/dns/` owns obtaining DNS information and nothing else."

## Allowed edges

| May import | May not |
| --- | --- |
| `core/dns/` siblings, `core/shared/` | anything else — `ui/`, `audit/`, `data/`, a protocol directory, the platform module |

The platform and the cache are **passed**, never imported. Generated data never
reaches this directory at all.

## Public exports

### `doh.js` — layer 1, raw transport (Task 3.1)

| Export | Kind | Contract |
| --- | --- | --- |
| `createDohTransport({ platform, cache, dnsError, dnsTypeNum, … })` | factory | Returns `{ dohFetch }`. One transport per runtime; it owns the concurrency limiter's state and borrows the runtime's cache. |
| `dohFetch(name, type, opts)` | async | Returns `{ answers, ad, status, kind }` — **never throws for a resolver failure**. Throws only `DnsTypeError`, for an unsupported record type. |
| `responseKind(status, answerCount)` | pure | Six of the ten kinds. Status 0 → `success`/`nodata` by answer count, 3 → `nxdomain`, 2 → `servfail`, 5 → `refused`, else `dns-error`. |
| `TRANSPORT_KINDS` | frozen array | The closed set of ten. Spec §3 forbids renaming, merging or adding a member. |
| `RETRY_TERMINAL_KINDS` | frozen array | `success`, `nodata`, `nxdomain`, `cancelled`. |
| `CACHEABLE_KINDS` | frozen array | `success`, `nodata`, `nxdomain`. A strict subset of the above. |
| `DOH_ENDPOINT` | string | `https://cloudflare-dns.com/dns-query`. The only third-party host this application contacts. |
| `DOH_TIMEOUT_MS`, `DOH_RETRIES`, `MAX_DOH_CONCURRENCY` | numbers | 8000, 1, 16. |

### `optional.js` — layer 4, error and cancellation policy (Task 3.5)

| Export | Kind | Contract |
| --- | --- | --- |
| `optionalCheck(run, fallback)` | async | Returns `run()`'s value, or the caller's declared unknown if it throws. `fallback` may be a value or a function of the error. |
| `RETHROWN_ERROR_NAMES` | frozen array | `AbortError`, `DnsTypeError`. |

**A resolver hiccup must degrade one check, never delete the result.** Before
this existed, a transient SERVFAIL on one enrichment lookup discarded the whole
audit for a domain whose real records had resolved perfectly.

**It re-throws by NAME, not by kind.** That is why `dnsError()` names a
`cancelled` query `AbortError` while leaving its kind `cancelled`. An aborted
audit is not an unknown result, and an unsupported record type is a defect in
this repository rather than a resolver hiccup.

### `existence.js` — name existence, a named exception edge (Task 3.5)

| Export | Kind | Contract |
| --- | --- | --- |
| `existenceFromResponse(response)` | pure | `no` for `nxdomain`, `yes` for `success`/`nodata`, `unknown` for the other seven and for a missing response. |
| `createExistence({ dohFetch })` | factory | Returns `domainExists(name, opts)`. Re-throws a cancelled probe rather than reporting `unknown`. |
| `EXISTENCE_STATES` | frozen array | `yes`, `no`, `unknown`. |

**This module bypasses layer 3 deliberately**, and has to: after normalization
`nodata` and `nxdomain` are both an empty array, and which of the two it was is
the entire question. Spec §3 names it an exception edge for that reason.

**The third value is load-bearing.** An audit that collapsed `unknown` into `no`
would tell someone their domain is unregistered because a query timed out.
`unknown` claims the resolver was asked and would not say — which is why a
cancelled probe throws instead: it never got that far.

### `resolver.js` — layers 2 and 3 (Task 3.4)

| Export | Kind | Contract |
| --- | --- | --- |
| `createResolver({ dohFetch })` | factory | Returns `{ requireUsable, dohQuery, dohAll, checkConnectivity, cleanAnswerData }`. |
| `requireUsable(result, name, type)` | pure | Returns the raw result for `success`/`nodata`/`nxdomain`; **throws** `dnsError(kind, …)` for the other seven. |
| `dohQuery(name, type, opts)` | async | Cleaned strings for answers **of the requested type**. No kind. |
| `dohAll(name, type, opts)` | async | Cleaned strings for **every** answer, so a CNAME in front of the record survives. No kind. |
| `checkConnectivity()` | async | `true` for `success`/`nodata`. A **named exception edge** — reads `.kind` directly. |
| `cleanAnswerData(data, type)` | pure | One answer's value. TXT chunks are concatenated; a malformed escape keeps its literal source text, a confirmed divergence. |
| `USABLE_KINDS` | frozen array | `success`, `nodata`, `nxdomain`. |

**Layer 3 drops the kind deliberately.** That is what makes a normalized array
safe for a protocol module: it can read records without deciding what a
`servfail` means, because layer 2 refused to hand it one. `nodata` and
`nxdomain` are indistinguishable after normalization — anything that needs to
tell them apart is a named exception edge and reads `dohFetch` directly.

**`nxdomain` is an answer.** It means the name does not exist, which is
information, not a failure to obtain information.

### `errors.js` — the thrown paths (Task 3.3)

| Export | Kind | Contract |
| --- | --- | --- |
| `dnsTypeNum(type)` | pure | The IANA number, or **throws** `DnsTypeError`. Partial on purpose: it used to end in `?? 16`, which answered every unknown type with the TXT number and produced a confident "no records published" about a type never asked for. |
| `dnsError(kind, name, type, detail)` | pure | **Returns** an `Error` carrying `kind`, `queryName`, `queryType`. Returned rather than thrown so the call site reads as `throw dnsError(…)`. |
| `DNS_TYPES` | frozen object | The eleven supported record types. |

**The throw/kind boundary.** `DnsTypeError` is thrown and is not a transport
kind; spec §3 forbids it becoming one. `dnsError` names a `cancelled` query
`AbortError` and everything else `DnsQueryError` — the **name** is what
`optionalCheck()` re-throws on, so it decides whether a failure degrades to a
stated "unknown" or ends the run, while the **kind** still says what happened at
the transport.

### `cache.js` — the DoH response cache (Task 3.2)

| Export | Kind | Contract |
| --- | --- | --- |
| `createDohCache({ maxEntries })` | factory | Returns `{ get, set, size }`. Bounded, least-recently-used. **One per runtime**, never a singleton. |
| `get(key)` | | The stored value, or `undefined` for a miss. Re-inserts, so a read counts as a use. |
| `set(key, value)` | | Stores, then evicts from the least-recently-used end until the ceiling holds. |
| `size` | getter | Observable for tests and for reasoning about the ceiling. Never a gate. |
| `MAX_DOH_CACHE_ENTRIES` | number | 4096 — a full 200-domain run with comprehensive DKIM, as a fixed ceiling rather than a leak. |

**This module decides nothing about what may be cached.** It stores what it is
given. The rule that only `success`, `nodata` and `nxdomain` are admitted lives
in `doh.js`, where the kind is known; holding it in both places is how two
copies of one rule drift apart.

**Least-recently-used, not first-in-first-out**, and the difference is
load-bearing: a DMARC tree walk re-reads one organizational domain across
siblings, so an entry can be old and hot at once. Evicting it would re-issue a
query the published fan-out assumes is cached.

**`opts`**: `signal`, `timeoutMs`, `retries`, `noCache`, `dnssec`,
`checkingDisabled`. `dnssec` sets `do=1`, `checkingDisabled` sets `cd=1`, and
both are part of the **cache key** — `checkDNSSEC()` asks for the same name
with different bits and must not be served the other's answer.

## Result axes

`kind` is the only discriminant this layer produces, and it is closed:

```
success  nodata  nxdomain  servfail  refused
dns-error  http-error  cancelled  timeout  network-error
```

`DnsTypeError` is **thrown** and is not a kind. It must not become one.

### The two rules a coarser model would flatten

- **Cacheable ⊂ retry-terminal.** They differ by exactly `cancelled`: retrying
  an aborted audit is pointless, but a cancellation is a fact about the run and
  not about the name, so it is never cached.
- **A type error is resolved before the request.** `dnsTypeNum()` runs before
  the concurrency slot and before the `try`, because the `catch` turns every
  throw into `network-error` — an unsupported type checked inside it would be
  reported as a resolver failure.

## Lifetime

| Scope | Holds | Constructed |
| --- | --- | --- |
| Runtime / page | the DoH cache; the concurrency limiter's in-flight count and waiter queue | once per `createAuditRuntime()` |
| Call | retry attempt, timeout timer, abort forwarding | per `dohFetch()` |

**One cache per runtime, and it is passed in.** A transport that made its own
would put the cache's lifetime in the wrong place. `tools/scoring.test.mjs:1888-1891`
asserts a first DMARC walk issues three queries and a sibling issues one, and
`PRIVACY.md` publishes the fan-out that reuse produces — so narrowing the scope
is a privacy change, not a detail. Spec correction 3, Risk R10.
