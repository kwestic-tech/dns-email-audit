/**
 * DNS-over-HTTPS transport. Spec Design §3 layer 1, implementation Task 3.1.
 *
 * The bottom of the DNS stack: build a request, bound its concurrency, time it
 * out, retry it where retrying can help, and return **one of ten kinds**. It
 * decides nothing about whether an answer is usable — that is `requireUsable()`
 * one layer up — and it knows nothing about SPF, DKIM, DMARC or any other
 * protocol. `src/core/dns/` owns obtaining DNS information and nothing else.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * This is `js/dns.js`'s transport closure with its captured values turned into
 * factory arguments. The request URL, the parameter names, the retry rule, the
 * cache rule, the abort forwarding, the slot accounting and every one of the
 * ten kinds are as they were at `v0.5.0`. A query trace is the release's
 * primary gate, and this file exists to move code beneath it, not to improve
 * on it.
 *
 * ── The ten kinds, and the two rules that are easy to flatten ───────────
 *
 * `success`, `nodata`, `nxdomain`, `servfail`, `refused`, `dns-error`,
 * `http-error`, `cancelled`, `timeout`, `network-error`. The set is closed:
 * spec §3 forbids renaming, merging or adding a member.
 *
 * **Cacheable ⊂ retry-terminal.** Retry stops on `success`, `nodata`,
 * `nxdomain` **and `cancelled`**; the cache admits only the first three.
 * `cancelled` is terminal — retrying an aborted audit is pointless — but it is
 * never cached, because a cancellation is a fact about this run and not about
 * the name. The two sets differ by exactly that one member and a model that
 * used one set for both would lose it.
 *
 * **A throw is not a kind.** `DnsTypeError` leaves through `dnsTypeNum()` and
 * never appears as a `kind`. It is resolved BEFORE the slot is acquired and
 * before the try block, deliberately: the catch turns every throw into
 * `network-error`, so an unsupported type checked inside it would be reported
 * as a resolver failure — a wrong answer wearing the costume of a real one.
 */

/** Cloudflare's DoH endpoint. The only third-party host this app contacts. */
export const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
export const DOH_TIMEOUT_MS = 8000;
export const DOH_RETRIES = 1;
export const MAX_DOH_CONCURRENCY = 16;

/**
 * Retry stops here. Note `cancelled`: an aborted audit is terminal.
 * Frozen so the closed set cannot be edited by a consumer at run time.
 */
export const RETRY_TERMINAL_KINDS = Object.freeze(['success', 'nodata', 'nxdomain', 'cancelled']);

/** The cache admits only these — a strict subset of the above. */
export const CACHEABLE_KINDS = Object.freeze(['success', 'nodata', 'nxdomain']);

/** Every kind this layer can return. Closed; spec §3. */
export const TRANSPORT_KINDS = Object.freeze([
  'success', 'nodata', 'nxdomain', 'servfail', 'refused', 'dns-error',
  'http-error', 'cancelled', 'timeout', 'network-error',
]);

/**
 * A DNS response status to its kind. Six of the ten are constructed here; the
 * other four come from the request itself failing.
 */
export function responseKind(status, answerCount) {
  if (status === 0) return answerCount ? 'success' : 'nodata';
  if (status === 3) return 'nxdomain';
  if (status === 2) return 'servfail';
  if (status === 5) return 'refused';
  return 'dns-error';
}

/**
 * Build one transport over one platform and one cache.
 *
 * The cache is PASSED, never created here, and that is spec Design §5: one
 * cache per runtime, and `createAuditRuntime()` makes one runtime per page.
 * A transport that made its own would put the cache's lifetime in the wrong
 * place — narrowing it changes the DNS fan-out, which `PRIVACY.md` publishes,
 * so cache ownership is a privacy decision rather than a detail.
 *
 * The concurrency limiter's state — the in-flight count and the waiter queue —
 * belongs to the transport, so two transports do not share a slot pool. That
 * matches the closure this was lifted from, where both lived beside the cache
 * inside one `createDnsEngine()` call.
 *
 * `dnsError` and `dnsTypeNum` arrive as arguments until Task 3.3 gives them a
 * module of their own; the shape they are called with does not change then.
 */
export function createDohTransport({
  platform,
  cache,
  dnsError,
  dnsTypeNum,
  endpoint = DOH_ENDPOINT,
  timeoutMs = DOH_TIMEOUT_MS,
  retries: defaultRetries = DOH_RETRIES,
  maxConcurrency = MAX_DOH_CONCURRENCY,
}) {
  // Named, not reached for. `fetch` is the load-bearing one: the DoH fixture
  // works by substituting it, and a module that resolved `fetch` from Node's
  // globals would quietly query the real internet from a unit test.
  const { fetch, AbortController, URLSearchParams, setTimeout, clearTimeout } = platform;

  var activeDoh = 0;
  var dohWaiters = [];

  async function acquireDohSlot(signal) {
    if (signal && signal.aborted) throw dnsError('cancelled', '', '');
    if (activeDoh < maxConcurrency) { activeDoh++; return; }
    await new Promise(function (resolve, reject) {
      var waiter = { resolve: resolve, reject: reject, signal: signal, onAbort: null };
      if (signal) {
        waiter.onAbort = function () {
          var idx = dohWaiters.indexOf(waiter);
          if (idx !== -1) dohWaiters.splice(idx, 1);
          reject(dnsError('cancelled', '', ''));
        };
        signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      dohWaiters.push(waiter);
    });
    activeDoh++;
  }

  function releaseDohSlot() {
    activeDoh = Math.max(0, activeDoh - 1);
    var waiter = dohWaiters.shift();
    if (!waiter) return;
    if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
    waiter.resolve();
  }

  async function fetchDohOnce(name, type, opts) {
    // Resolved before the slot and before the try: the catch below turns every
    // throw into 'network-error', so an unsupported type checked inside it
    // would be reported as a resolver failure — the same silent-wrong-answer
    // shape dnsTypeNum() was changed to prevent, one layer up.
    const typeNum = dnsTypeNum(type);
    await acquireDohSlot(opts.signal);
    var controller = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; controller.abort(); }, opts.timeoutMs || timeoutMs);
    var forwardAbort = function () { controller.abort(); };
    if (opts.signal) opts.signal.addEventListener('abort', forwardAbort, { once: true });
    try {
      const params = new URLSearchParams({ name: name, type: String(typeNum) });
      if (opts.dnssec) params.set('do', '1');
      if (opts.checkingDisabled) params.set('cd', '1');
      const r = await fetch(`${endpoint}?${params}`, {
        headers: { Accept: 'application/dns-json' }, signal: controller.signal,
      });
      if (!r.ok) return { answers: [], ad: false, status: -1, kind: 'http-error', httpStatus: r.status };
      const j = await r.json();
      const answers = Array.isArray(j.Answer) ? j.Answer : [];
      const status = Number.isInteger(j.Status) ? j.Status : -1;
      return { answers: answers, ad: j.AD === true, status: status, kind: responseKind(status, answers.length) };
    } catch (e) {
      if (opts.signal && opts.signal.aborted) return { answers: [], ad: false, status: -1, kind: 'cancelled' };
      return { answers: [], ad: false, status: -1, kind: timedOut ? 'timeout' : 'network-error' };
    } finally {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener('abort', forwardAbort);
      releaseDohSlot();
    }
  }

  async function dohFetch(name, type, opts = {}) {
    dnsTypeNum(type);   // throw on an unsupported type before the cache, not only on a miss
    const normalizedName = String(name || '').toLowerCase().replace(/\.$/, '');
    const key = [normalizedName, type, opts.dnssec ? 1 : 0, opts.checkingDisabled ? 1 : 0].join('|');
    if (!opts.noCache) {
      var cached = cache.get(key);
      if (cached !== undefined) return cached;
    }
    var result;
    var retries = opts.retries ?? defaultRetries;
    for (var attempt = 0; attempt <= retries; attempt++) {
      result = await fetchDohOnce(normalizedName, type, opts);
      if (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain' || result.kind === 'cancelled') break;
      if (attempt < retries) await new Promise(function (resolve) { setTimeout(resolve, 150 * (attempt + 1)); });
    }
    if (!opts.noCache && result && (result.kind === 'success' || result.kind === 'nodata' || result.kind === 'nxdomain')) cache.set(key, result);
    return result;
  }

  return { dohFetch };
}
