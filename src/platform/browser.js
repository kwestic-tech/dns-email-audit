/**
 * The browser platform adapter. Spec §11, implementation Task 2.4.
 *
 * The one place in `src/` that touches ambient browser state. Everything else
 * receives what it needs, which is what makes a test able to hand the
 * application a different `fetch`, a different clock or a different Web Crypto
 * without the application having a test-only branch anywhere in it.
 *
 * `src/platform/` imports **nothing** — spec §12's allowed-edge matrix gives it
 * no outgoing edges at all. It is the floor of the graph.
 *
 * ── A factory, not a singleton ───────────────────────────────────────────
 *
 * `createBrowserPlatform(win)` takes its window rather than reading the global
 * one, and returns a fresh object each call. A module-level singleton would
 * make the platform ambient again one layer up, and would stop two runtimes in
 * one process from being genuinely independent — which is the property
 * `createAuditRuntime()` (Task 2.5) exists to provide and that contract tests
 * assert.
 *
 * ── Receivers ────────────────────────────────────────────────────────────
 *
 * Several of these are methods that require their original receiver. A browser
 * throws `TypeError: Illegal invocation` for a bare `fetch` or `setTimeout`
 * pulled off `window`, and `localStorage.getItem` and `crypto.subtle.digest`
 * need their own objects. So:
 *
 *   • methods are BOUND to the object that owns them;
 *   • host objects (`document`, `localStorage`, `crypto`, `console`, `Intl`)
 *     are passed whole, so their own methods keep their receivers;
 *   • constructors are passed as-is, because `new` supplies the receiver.
 *
 * Node is more forgiving than a browser about all of this, so getting it wrong
 * would pass every test here and fail only in production. That is why the
 * binding is deliberate rather than incidental.
 */

/**
 * Language built-ins are NOT platform services.
 *
 * `Promise`, `Map`, `Set`, `BigInt`, `JSON` and `Array` are required APIs, and
 * spec §11 says so explicitly. Injecting them would be ceremony that buys
 * nothing: there is no substitute a test would want to supply, and no runtime
 * that has one and not the others. `Intl` IS here, because a test genuinely may
 * want to pin locale formatting.
 */
export function createBrowserPlatform(win) {
  if (!win) throw new Error('platform: createBrowserPlatform needs a window');

  return {
    // ── Network ──────────────────────────────────────────────────────────
    // Bound. A bare `fetch` lifted off `window` throws Illegal invocation in
    // every browser, and this is the primitive the DoH fixture substitutes —
    // so it is both the most important one to get right and the one a test
    // replaces most often.
    fetch: win.fetch.bind(win),

    /**
     * Open a URL in a new browsing context.
     *
     * Bound, like `fetch`: a bare `open` lifted off `window` throws Illegal
     * invocation. `openLearnMore()` calls it as
     * `open(url, '_blank', 'noopener')` over a `Blob` URL, and `noopener` is
     * load-bearing — without it the opened page gets a reference back to this
     * one through `window.opener`.
     *
     * The first NAVIGATION SIDE EFFECT on this list rather than a data
     * capability, and named as such because the platform is the security
     * boundary between `src/` and the browser. Whether page construction should
     * be split from navigation is a real question and a Phase 5 one — `src/ui/`
     * owns that decomposition. Not redesigned here.
     */
    open: win.open.bind(win),

    // ── Cancellation and timing ──────────────────────────────────────────
    AbortController: win.AbortController,
    setTimeout: win.setTimeout.bind(win),
    clearTimeout: win.clearTimeout.bind(win),

    // ── Parsing and construction ─────────────────────────────────────────
    URL: win.URL,
    URLSearchParams: win.URLSearchParams,
    Blob: win.Blob,
    FileReader: win.FileReader,

    // ── Host objects, passed whole so their methods keep their receivers ──
    document: win.document,
    localStorage: win.localStorage,
    crypto: win.crypto,
    console: win.console,
    Intl: win.Intl,
    navigator: win.navigator,

    /**
     * The current instant, in milliseconds.
     *
     * A method rather than a `Date`, so the clock is a capability the runtime
     * holds rather than a value captured once. Production reads the real one;
     * the equivalence runner supplies a window whose `Date` is pinned, and the
     * same call then returns the fixed instant with no branch in the code that
     * uses it.
     */
    now() { return win.Date.now(); },

    /**
     * Format an instant for display, preserving v0.5.0 behaviour exactly.
     *
     * `js/app.js` rendered the exported report's timestamp with
     * `new Date().toLocaleString(i18n.lang)`. That is what this is — same call,
     * same arguments, same ICU — moved behind the platform so time and locale
     * become controlled INPUTS to an equivalence run rather than fields a
     * canonicalizer has to be told to ignore. Spec Design §8 permits no
     * timestamp wildcard, and this is why it does not need one.
     */
    formatDateTime(date, locale) {
      const value = date instanceof win.Date ? date : new win.Date(date ?? win.Date.now());
      return value.toLocaleString(locale);
    },
  };
}

/**
 * Every name the platform is contracted to provide, from spec §11.
 *
 * Exported so `tests/contract/platform.test.mjs` can assert the set is complete
 * rather than checking whichever names someone remembered. A platform missing
 * one of these fails a module at run time, in a browser, on a path a unit test
 * may never take.
 */
export const PLATFORM_PRIMITIVES = [
  'fetch', 'crypto', 'AbortController', 'URLSearchParams', 'setTimeout',
  'clearTimeout', 'document', 'localStorage', 'navigator', 'open', 'URL', 'Blob',
  'FileReader', 'Intl', 'console', 'now', 'formatDateTime',
];
