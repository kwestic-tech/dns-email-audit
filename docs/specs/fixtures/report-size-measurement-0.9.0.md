# Measured report size, and what actually drives it

Evidence for `OQ-CMP-01` and `OQ-CMP-02`, which the 0.3 draft explicitly
deferred: it "asks for the file size to be measured on a realistic estate
before the decision is locked in." This is that measurement.

Captured 2026-09-03 from `tests/fixtures/equivalence/baseline-v0.8.0.json`,
the deterministic corpus the `v0.8.1` release was verified against: 32 cases,
80 domain results, 79 of them scored. Measuring the corpus rather than a live
estate is deliberate — it is the only domain set whose result objects are
committed, byte-stable and reviewable by anyone re-running this.

## Method

Serialized length of `JSON.stringify()` over three candidate report bodies,
averaged per domain result and projected linearly. The “curated” body below is
the broad 1.0 review candidate, not the normative 1.1 schema: it deliberately
keeps whole `dkimStatus` and `advanced` objects and therefore supplies a
conservative upper bound for 1.1's normalized record projection.

```bash
node -e "
const fs=require('fs');
const j=JSON.parse(fs.readFileSync('tests/fixtures/equivalence/baseline-v0.8.0.json','utf8'));
const curate=r=>({
 domain:r.domain, organizationalDomain:r.organizationalDomain,
 score:r.score?{pts:r.score.pts,max:r.score.max,grade:r.score.grade,parked:r.score.parked,
                unproven:r.score.unproven,pillars:r.score.breakdown&&r.score.breakdown.pillars}:null,
 spfRecord:r.spfRecord, dmarcRecord:r.dmarcRecord, dmarcAtDomain:r.dmarcAtDomain,
 mx:r.mx, ns:r.ns, dkimStatus:r.dkimStatus, advanced:r.advanced,
 findings:(r.findings||[]).map(f=>({id:f.id,protocol:f.protocol,severity:f.severity,
   confidence:f.confidence,category:f.category,effort:f.effort,args:f.args,
   dependsOn:f.dependsOn,evidence:f.evidence})),
 remediationPlan:r.remediationPlan
});
let full=0,cur=0,noEv=0,noRec=0,n=0;
for(const c of j.cases) for(const d of c.result){ if(!d.result) continue; n++;
  const r=d.result; full+=JSON.stringify(r).length;
  const s=curate(r); cur+=JSON.stringify(s).length;
  noEv+=JSON.stringify({...s,findings:s.findings.map(({evidence,...k})=>k)}).length;
  noRec+=JSON.stringify({domain:s.domain,score:s.score,findings:s.findings,
                         remediationPlan:s.remediationPlan}).length;
}
const mb=b=>(b/n*1000/1048576).toFixed(2);
console.log(n, Math.round(full/n), Math.round(cur/n), Math.round(noEv/n), Math.round(noRec/n));
console.log(mb(full), mb(cur), mb(noEv), mb(noRec));
"
```

## Result

| Body | Bytes per domain | 200 domains (`MAX_DOMAINS`) | 1000 domains (draft import cap) |
| --- | --- | --- | --- |
| Whole `result` object, unfiltered | 9,035 | 1.72 MiB | **8.62 MiB** |
| Broad 1.0 candidate, full evidence | 6,103 | 1.16 MiB | 5.82 MiB |
| Broad 1.0 candidate, no evidence | 5,368 | 1.02 MiB | 5.12 MiB |
| Findings and score only, no records | 3,096 | 0.59 MiB | 2.95 MiB |

## What the numbers settle

**The 0.3 draft cannot import its own export.** Exporting the whole result
object at the draft's own 1000-domain array limit produces 8.62 MB, and the
draft's own byte limit before `JSON.parse` is 8 MiB. A tool that emits files it
then rejects is a defect, not a tuning question, and it is only invisible
because nobody has built the exporter yet.

**Evidence is not the size driver.** Dropping every `evidence[]` entry saves
735 bytes per domain — 12% — which is not worth making a report
unverifiable by its recipient. `OQ-CMP-01`'s severity-threshold middle option
optimizes the wrong half of the file.

**Records are the size driver.** Records and their protocol detail are 3,007
bytes per domain, 49% of the curated body. `OQ-CMP-02` — records, findings, or
both — is therefore the only one of the two questions with a real size
consequence, and it is the one the draft answered without measurement.

**The corpus understates real files.** These are synthetic fixtures:
`alpha.test`, four-selector DKIM sets, short SPF records. Real estates carry
longer names, longer `include:` chains, more MX hosts and more CAA issuers, so
every figure above is a floor. Any limit derived from this table needs
headroom, not a rounded-up match.

## The bound the draft missed

`MAX_DOMAINS = 200` in [`src/ui/events.js`](../../../src/ui/events.js), stated
in `index.html`, `locales/en.json` (`errors.tooMany`) and the package
description. **This tool cannot produce a report with more than 200 domains
in it.** The draft's 1000-domain import limit therefore accepts files this
application could not have written, and the limit is a round number rather
than a product bound.
