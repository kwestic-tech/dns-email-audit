# Capture: 0.9.2 PTR fan-out, executed

| Field | Value |
| --- | --- |
| Settles | `OQ-MXV-03`, the query cost of 0.9.2's divergence procedure |
| Spec | [mx-host-validity](../mx-host-validity.md) §4, §7 |
| Harness | [`ptr-fan-out-spike-0.9.2.mjs`](ptr-fan-out-spike-0.9.2.mjs) beside this file |
| Executes through | `createDohCache()`, `createDohTransport()` and `createResolver()` as production composes them, with a recording `fetch` beneath |
| Captured | 2026-09-05 |
| Resolver | **None.** No network. See "What is real and what is fixture" below. |

## Why this exists rather than a count

The 0.14 draft answered `OQ-MXV-03` by counting addresses already stored in
`baseline-v0.9.1.json` and calling the result measured. Review reproduced the
arithmetic and rejected the label: counting stored addresses says how many `PTR`
calls the algorithm *would request*, which is a projection, and it cannot say
anything at all about the forward-confirm step — `v0.9.1` holds no `PTR`
answers, so no candidate name can be selected from it.

That gap was not academic. The projection put the corpus at **8** additional
queries. Executing the procedure makes **16** calls.

A second version of this capture then made the same mistake one layer down. It
measured the 16 calls, observed that one provider name repeats, and *calculated*
that a real run would send 14 requests. `PRIVACY.md` publishes transport fan-out
— what leaves the browser after cache reuse — so that calculated 14 was another
unexecuted claim about outbound behavior.

It is now executed. The harness runs §4 through the **production cache and
transport**, with a recording `fetch` underneath: `fetch` is the seam `doh.js`
takes from its injected platform precisely so it can be substituted, so the
cache's real key (`name|type|dnssec|cd`) and real admission rules are the ones
under test. Outbound requests are counted at that seam.

## What is real and what is fixture

**Real:** the qualifying hosts and their addresses, read from the committed
`baseline-v0.9.1.json` — seven hosts across seven domains, out of 80 audited.
The gate (`inAudited && resolves === 'yes' && reachability !== 'none'`), the
two-host cap, the four-address cap and the two-candidate cap are §4 executed
literally.

**Fixture:** the `PTR` and forward answers. No such answers exist yet, and the
tool makes no network request here. Each is chosen to exercise one branch:

| Domain | Reverse answer | Branch exercised |
| --- | --- | --- |
| `alpha.test` | provider name, forward-confirms to a superset | `mx.vanity-divergent` |
| `bravo.test` | a name inside the audited domain | self-hosted; no candidate, no forward query |
| `delta.test` | empty answer | `mx.no-reverse-dns` — absence claimed |
| `foxtrot.test` | lookup did not return | no claim either way |
| `golf.test` | provider name that does **not** forward-confirm | step 3 stops |
| `hotel.test` | provider name, forward-confirms to an equal set | confirmed, compared, reports nothing |
| `nowww.host.test` | provider name, forward-confirms to a superset | `mx.vanity-divergent` |

## Observed

```
domains audited                      : 80
qualifying hosts                     : 7
procedure calls ABOVE the cache      : 16  (8 PTR + 8 forward)
requests that LEFT the browser       : 14
saved by page-lifetime cache reuse   : 2
outbound per audited domain          : 0.175
```

**14 is the number `PRIVACY.md` speaks in**, and it is now observed at the
transport seam rather than derived from 16 by subtraction.

### The ordered outbound trace

All fourteen questions that leave the browser, in the order they are asked.
This block is asserted equal to `EXPECTED.outboundTrace` by the harness, so it
cannot drift from the executable without failing it.

```text
20.0.2.100.in-addr.arpa/PTR
0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa/PTR
mailfilter.provider.test/A
mailfilter.provider.test/AAAA
5.100.51.100.in-addr.arpa/PTR
5.113.0.100.in-addr.arpa/PTR
9.113.0.100.in-addr.arpa/PTR
11.113.0.100.in-addr.arpa/PTR
unconfirmed.provider.test/A
unconfirmed.provider.test/AAAA
13.113.0.100.in-addr.arpa/PTR
equal.provider.test/A
equal.provider.test/AAAA
10.100.51.100.in-addr.arpa/PTR
```

Reading it: four of the entries are forward-confirmation pairs and the other
ten are reverse lookups. `mailfilter.provider.test` appears **once**, though two
domains ask for it — that pair is the cache reuse, and control 2 removes it by
renaming the second.

### Controls

```
CONTROL 1 — gate off
  above the cache: 0   outbound: 0   findings: 0

CONTROL 2 — a repeated query renamed
  above the cache: 16   outbound: 16          (rose from 14)

CONTROL 3 — the cache key includes the type
  first A: 1   repeated A: 1   then AAAA: 2
```

Each earns its place. **1** proves the gate: with deep checks off there is no
`mxHealth` to read, so nothing may be issued, and a measurement that counted
queries the gate was supposed to prevent would be measuring the wrong thing.
**2** proves the two saved requests are the *cache's* doing and not an artefact
of the harness — rename the repeated provider on the second domain and outbound
returns to 16. **3** proves the key discriminates on type as well as name: the
same name asked twice under `A` goes out once, and asking it under `AAAA` goes
out again.

## Three things the projection could not have told us

**1. Forward-confirm doubles the cost.** 8 `PTR` and 8 forward, not 8 total. The
forward step is per candidate, and five of the seven domains produced one.

**2. The cache absorbs exactly two of the sixteen, and no more.** `alpha.test`
and `nowww.host.test` both reach `mailfilter.provider.test`; the two-candidate
cap is per domain and does not dedupe across domains, so the procedure asks
twice and the cache answers the second pair from memory. Sixteen calls, fourteen
requests. That is measured at the transport, and control 2 shows the saving
disappears when the repetition does.

It also bounds how much help the cache can be here: the saving is one repeated
provider across 80 domains. A corpus with more distinct providers would save
less, not more.

**3. Two of the seven qualifying hosts cost a `PTR` and nothing else** —
`bravo.test` selects no candidate because its reverse name is inside the audited
domain, and `foxtrot.test`'s lookup does not return. The gate admits more hosts
than the forward step spends on.

## What this capture still does not establish

The `PTR` and forward answers are a fixture, so the **shape** of the fan-out is
executed but its real-world distribution is not. How often a vanity host's
reverse name actually forward-confirms, and how often two audited domains share
a provider, are properties of the internet and not of this corpus. The published
`PRIVACY.md` per-domain figures must therefore be re-measured on the release
that ships 0.9.2, not adjusted by adding 0.175 to them.

## Reproducing

```sh
node docs/specs/fixtures/ptr-fan-out-spike-0.9.2.mjs
```

Deterministic: no network, no clock, no randomness. The harness is not imported
by `src/` and is not part of any suite; it is evidence, kept beside the spec it
settles, per the captured-evidence rule in [the specs README](../README.md).
