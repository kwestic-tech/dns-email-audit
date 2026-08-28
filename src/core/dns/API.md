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
