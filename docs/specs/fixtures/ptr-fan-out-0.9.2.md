# Capture: 0.9.2 PTR fan-out, executed

| Field | Value |
| --- | --- |
| Settles | `OQ-MXV-03`, the query cost of 0.9.2's divergence procedure |
| Spec | [mx-host-validity](../mx-host-validity.md) §4, §7 |
| Harness | [`ptr-fan-out-spike-0.9.2.mjs`](ptr-fan-out-spike-0.9.2.mjs) beside this file |
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
queries. Executing the procedure issues **16**.

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
domains audited                 : 80
qualifying hosts                : 7
PTR queries ISSUED              : 8
forward-confirm queries ISSUED  : 8
TOTAL additional queries        : 16
per audited domain              : 0.200

NEGATIVE CONTROL, deep checks off
queries issued                  : 0
findings produced               : 0
```

The negative control matters: with the gate off there is no `mxHealth` to read,
so the procedure must issue nothing. A measurement that counted queries the gate
was supposed to prevent would be measuring the wrong thing.

## Three things the projection could not have told us

**1. Forward-confirm doubles the cost.** 8 `PTR` and 8 forward, not 8 total. The
forward step is per candidate, and five of the seven domains produced one.

**2. The same provider name is resolved once per domain.** `alpha.test` and
`nowww.host.test` both reach `mailfilter.provider.test`, and the trace shows
`mailfilter.provider.test/A` and `/AAAA` twice. The two-candidate cap is
per domain, so it does not dedupe across domains.

This spike counts **requests, not cache misses.** The application's DoH cache
lives for the page, so a real run of these 80 domains would collapse those four
requests to two and issue **14**. The published `PRIVACY.md` figures are
measured through that cache, which is why they must be re-measured on the
shipping release rather than adjusted by adding this number.

**3. Two of the seven qualifying hosts cost a `PTR` and nothing else** —
`bravo.test` selects no candidate because its reverse name is inside the audited
domain, and `foxtrot.test`'s lookup does not return. The gate admits more hosts
than the forward step spends on.

## Reproducing

```sh
node docs/specs/fixtures/ptr-fan-out-spike-0.9.2.mjs
```

Deterministic: no network, no clock, no randomness. The harness is not imported
by `src/` and is not part of any suite; it is evidence, kept beside the spec it
settles, per the captured-evidence rule in [the specs README](../README.md).
