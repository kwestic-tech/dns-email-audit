/**
 * A programmable `fetch` for the test sandbox, standing in for Cloudflare's
 * DNS-over-HTTPS JSON endpoint.
 *
 * `js/dns.js` gets no test seam. There is no `__setResolver`, no injected
 * transport and no production branch that exists only for tests — this repo
 * has consistently refused those, and a resolver stub that bypasses the real
 * request-building code would stop testing the part most likely to be wrong.
 * Instead the sandbox's own `fetch` is replaced, so a fixture exercises the
 * genuine URL construction, the genuine `application/dns-json` parsing, the
 * cache, the concurrency limiter and the retry loop.
 *
 * Shared rather than inlined because `dns-protocol-depth` (0.4.0) and
 * `dnssec-evidence` (0.5.0) both need it — see `OQ-DMARC-03`.
 *
 * Unmatched queries default to NXDOMAIN, deliberately. A fixture that silently
 * fell through to the network would pass or fail depending on someone else's
 * DNS, and the failure would look like a code defect rather than a missing
 * fixture entry.
 */

const TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  DS: 43, DNSKEY: 48, TLSA: 52, CAA: 257,
};
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));

const STATUS = { noerror: 0, nodata: 0, nxdomain: 3, servfail: 2, refused: 5 };

/** Wrap TXT strings in the quoted presentation form Cloudflare returns. */
export const txt = (...strings) => strings.map(s => ({ type: 16, data: `"${String(s).replace(/"/g, '\\"')}"` }));
export const ns = (...hosts) => hosts.map(h => ({ type: 2, data: h }));
export const mx = (...entries) => entries.map(e => ({ type: 15, data: e }));
export const a = (...addresses) => addresses.map(v => ({ type: 1, data: v }));
export const aaaa = (...addresses) => addresses.map(v => ({ type: 28, data: v }));
export const cname = (...targets) => targets.map(v => ({ type: 5, data: v }));
export const caa = (...records) => records.map(v => ({ type: 257, data: v }));
/**
 * TLSA answers are written in the resolver's own presentation form —
 * parenthesised, uppercase hex — so a fixture exercises the parenthesis strip
 * rather than a tidied-up shape that would let the trap through untested.
 */
export const tlsa = (...records) => records.map(v => ({ type: 52, data: v }));

/**
 * `DS` and `DNSKEY` answers, in the two different shapes the same resolver
 * returns for them — captured in
 * `docs/specs/implemented/fixtures/doh-shapes-0.4.0.md` and extended in
 * `docs/specs/fixtures/dnssec-live-states-0.5.0.md`.
 *
 * Neither builder normalizes its argument, and that is the point. A `DS`
 * digest is lowercase hex; a `DNSKEY` public key is case-sensitive base64
 * containing `+`, `/` and `=`. A fixture that tidied either one would hide the
 * defect most likely to ship here — a parser that lowercases the key field,
 * destroying it, so that every digest fails to match and a healthy zone is
 * reported as a broken chain. Write the record exactly as the resolver sends
 * it.
 */
export const ds = (...records) => records.map(v => ({ type: 43, data: v }));
export const dnskey = (...records) => records.map(v => ({ type: 48, data: v }));

/**
 * The `RRSIG` that rides along with a `do=1` answer.
 *
 * Every DNSSEC-relevant query this project makes sets `do=1`, and the resolver
 * returns the signature beside the record it signs: `Answer: [43, 46]` for a
 * `DS` query, `[48, 48, 46]` for `DNSKEY`. A parser that reads the answer array
 * without filtering on the numeric type treats `DS 8 2 3600 1788794710 …` as a
 * DS record — key tag `NaN`, digest `3600…` — which raises no error and matches
 * no key, and so reports a mismatched chain on every signed domain audited.
 *
 * This builder exists so a fixture can carry that companion record and prove
 * the filter is there. It is the same trap as the `_dane` CNAME beside a TLSA
 * answer, which is why `cname()` is used the same way in section 37.
 *
 * Note the timestamps: Cloudflare's JSON returns RRSIG inception and expiration
 * as Unix seconds, not the `YYYYMMDDHHMMSS` of a zone file.
 */
export const rrsig = (...records) => records.map(v => ({ type: 46, data: v }));

/**
 * Build a `fetch` implementation from a fixture map.
 *
 * The map is keyed `"<name> <TYPE>"` (or just `"<name>"` to answer every type
 * at that name). A value may be:
 *
 *   - an array of answer records → NOERROR with those answers
 *   - `'nxdomain'` / `'servfail'` / `'refused'` / `'nodata'` → that response
 *   - `{ status, answers, ad, ok, httpStatus }` → full control
 *
 * `calls` records every query in order, so a test can assert on the number of
 * queries and on the exact names walked — which is the whole point for a Tree
 * Walk, where the query sequence IS the behaviour under test.
 */
export function dohFixture(map, options = {}) {
  const fallback = options.fallback || 'nxdomain';
  const calls = [];
  const normalize = name => String(name || '').toLowerCase().replace(/\.$/, '');

  const fetchImpl = async url => {
    const params = new URL(url, 'https://cloudflare-dns.com').searchParams;
    const name = normalize(params.get('name'));
    const type = TYPE_NAME[params.get('type')] || 'TXT';
    calls.push(`${name} ${type}`);

    // A `cd=1` re-query can be answered differently from the same name and
    // type without it. That difference IS the bogus signature — a SERVFAIL
    // that succeeds with checking disabled means validation failed rather than
    // the zone being unsigned — so a fixture has to be able to express it.
    // Key a variant as "<name> <TYPE> cd"; without one, cd falls back to the
    // ordinary entry, so every existing fixture behaves exactly as before.
    if (params.get('cd') === '1') {
      const cdEntry = map[`${name} ${type} cd`];
      if (cdEntry !== undefined) return respond(cdEntry, type);
    }

    const entry = resolve(map, name, type, fallback);
    return respond(entry, type);
  };

  fetchImpl.calls = calls;
  fetchImpl.callsFor = type => calls.filter(c => c.endsWith(` ${type}`)).map(c => c.split(' ')[0]);
  fetchImpl.reset = () => { calls.length = 0; };
  return fetchImpl;
}

/**
 * Look up a name the way a resolver would, including wildcard synthesis.
 *
 * RFC 4592 §2.3: "When a wildcard domain name appears in a message's query
 * section, no special processing occurs." So a fixture cannot test wildcard
 * behaviour by querying the asterisk owner directly — that retrieves the
 * literal node. The synthesis has to happen HERE, while answering the real
 * query, or the test proves nothing about what a resolver would return.
 *
 * §4.3.2 step 3c and §2.2.1: synthesis applies only when the queried name does
 * not itself exist. An owner that exists with unrelated data SUPPRESSES the
 * wildcard, which is the case that separates an authorized external reporting
 * arrangement from an unauthorized one.
 */
function resolve(map, name, type, fallback) {
  const exact = map[`${name} ${type}`] !== undefined ? map[`${name} ${type}`]
    : map[name] !== undefined ? map[name] : undefined;
  if (exact !== undefined) return exact;

  // The queried name does not exist. Look for the closest enclosing wildcard.
  const labels = name.split('.');
  for (let i = 1; i < labels.length; i++) {
    const parent = labels.slice(i).join('.');
    // An existing name between the wildcard and the query name also suppresses
    // synthesis, so stop climbing as soon as one is found.
    if (i > 1 && (map[parent] !== undefined || map[`${parent} ${type}`] !== undefined)) break;
    const star = `*.${parent}`;
    const hit = map[`${star} ${type}`] !== undefined ? map[`${star} ${type}`]
      : map[star] !== undefined ? map[star] : undefined;
    if (hit !== undefined) return hit;
  }
  return fallback;
}

function respond(entry, type) {
  if (typeof entry === 'string') {
    if (entry === 'http-error') return { ok: false, status: 500 };
    const status = STATUS[entry];
    if (status === undefined) throw new Error(`doh-fixture: unknown response keyword '${entry}'`);
    return json({ Status: status, Answer: [] });
  }
  if (Array.isArray(entry)) return json({ Status: 0, Answer: entry });
  if (entry && typeof entry === 'object') {
    if (entry.ok === false) return { ok: false, status: entry.httpStatus || 500 };
    return json({
      Status: entry.status === undefined ? 0 : entry.status,
      AD: entry.ad === true,
      Answer: entry.answers || [],
    });
  }
  throw new Error(`doh-fixture: unusable fixture entry for ${type}`);
}

const json = body => ({ ok: true, status: 200, json: async () => body });

export { TYPE_NUM };
