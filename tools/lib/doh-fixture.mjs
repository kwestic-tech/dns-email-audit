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

const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));

const STATUS = { noerror: 0, nodata: 0, nxdomain: 3, servfail: 2, refused: 5 };

/** Wrap TXT strings in the quoted presentation form Cloudflare returns. */
export const txt = (...strings) => strings.map(s => ({ type: 16, data: `"${String(s).replace(/"/g, '\\"')}"` }));
export const ns = (...hosts) => hosts.map(h => ({ type: 2, data: h }));
export const mx = (...entries) => entries.map(e => ({ type: 15, data: e }));
export const a = (...addresses) => addresses.map(v => ({ type: 1, data: v }));

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

    const entry = map[`${name} ${type}`] !== undefined ? map[`${name} ${type}`]
      : map[name] !== undefined ? map[name]
        : fallback;
    return respond(entry, type);
  };

  fetchImpl.calls = calls;
  fetchImpl.callsFor = type => calls.filter(c => c.endsWith(` ${type}`)).map(c => c.split(' ')[0]);
  fetchImpl.reset = () => { calls.length = 0; };
  return fetchImpl;
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
