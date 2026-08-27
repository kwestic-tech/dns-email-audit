/**
 * Load one equivalence SUBJECT — a complete repository or built-artifact root.
 *
 * Spec Design §8: "Each subject is a complete repository or built-artifact
 * root. The runner must load that subject's own `index.html`, stylesheet,
 * generated English bundle and JavaScript; it may not pair baseline JavaScript
 * with current-branch assets."
 *
 * That is enforced structurally here rather than promised: the script list is
 * read out of the subject's OWN `index.html`, in its own order, and every file
 * read is hashed into the manifest. A subject whose `index.html` lists one
 * bundled artifact loads one file; a subject at v0.5.0 loads seven. Nothing in
 * this module knows which it is dealing with, which is what lets the same
 * runner drive `v0.5.0`, the working tree and `_site/`.
 *
 * The DOM shim, the DoH fixture and the canonicalizer come from the RUNNER's
 * tree, not the subject's. They are the instrument, and one instrument
 * measuring three subjects is the point.
 */

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, posix } from 'node:path';
import vm from 'node:vm';

import { createDocument } from '../../tools/lib/dom-shim.mjs';
import { platformProfile } from './platform.mjs';

/**
 * The time zone every subject formats in.
 *
 * Set before anything reads a date, and it is not decoration. `js/app.js:1651`
 * renders the report's timestamp with `toLocaleString(i18n.lang)`, which uses
 * the HOST time zone — so a baseline captured in Asia/Taipei and a CI run in
 * UTC disagree on a report the code produced identically. Found by running the
 * runner, not by reading it: the first capture rendered a 12:00 UTC instant as
 * "8:00:00 PM".
 *
 * Pinned rather than excluded. Spec Design §8 permits no timestamp wildcard;
 * time, locale and now zone are controlled INPUTS.
 */
export const FIXED_TIMEZONE = 'UTC';
process.env.TZ = FIXED_TIMEZONE;

/** The instant every subject sees. Fixed, and recorded in the manifest. */
export const FIXED_INSTANT = Date.UTC(2026, 0, 15, 12, 0, 0);
/** The locale every subject formats with. */
export const FIXED_LOCALE = 'en';

const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');

/**
 * The `<script src>` list, in document order, and the stylesheet href.
 *
 * Deliberately a scan of the markup rather than a hard-coded list. Task 1.6
 * replaces seven tags with one, and the whole point of the delivery boundary
 * is that this function does not change when it does.
 */
export function readEntryPoints(indexHtml) {
  const scripts = [];
  const tagPattern = /<script\b([^>]*)>/gi;
  let match;
  while ((match = tagPattern.exec(indexHtml))) {
    const attrs = match[1];
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    // An inline <script type="application/ld+json"> has no src and is data.
    if (!src) continue;
    const type = /\btype\s*=\s*["']([^"']+)["']/i.exec(attrs);
    scripts.push({ src: src[1], type: type ? type[1] : null });
  }
  const stylesheets = [];
  const linkPattern = /<link\b([^>]*)>/gi;
  while ((match = linkPattern.exec(indexHtml))) {
    const attrs = match[1];
    if (!/\brel\s*=\s*["']?stylesheet/i.test(attrs)) continue;
    const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (href) stylesheets.push(href[1]);
  }
  return { scripts, stylesheets };
}

/**
 * A `Date` pinned to the fixed instant.
 *
 * `js/app.js:1651` builds the report's timestamp with
 * `new Date().toLocaleString(i18n.lang)`. Time is an INPUT to the comparison,
 * not an excluded output — spec Design §8 permits no timestamp wildcard — so
 * the subject is given a clock rather than the surface being told to ignore
 * one. An explicit argument still constructs a real date, because a fixture
 * that carries one must keep working.
 */
function pinnedDate(instant) {
  return new Proxy(Date, {
    construct(target, args) {
      return args.length === 0 ? new target(instant) : new target(...args);
    },
    get(target, property) {
      if (property === 'now') return () => instant;
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

/**
 * Load a subject root and return its window, plus the manifest of what was
 * read.
 *
 * `options.fetch` is installed as the sandbox's `fetch`. There is no test seam
 * inside the subject: the sandbox's own `fetch` is replaced, exactly as
 * `tools/lib/doh-fixture.mjs` states the project's standing rule, so a run
 * exercises the genuine URL construction, `application/dns-json` parsing,
 * cache, concurrency limiter and retry loop.
 */
export function loadSubject(root, options = {}) {
  const entry = options.entry || 'classic';
  if (entry !== 'classic') {
    // Phase 2 introduces `src/`. Until it exists there is nothing to load, and
    // a silent fallback to the classic path would report the classic result
    // under the ESM subject's name — the substitution hazard again.
    throw new Error(
      `subject: --entry=${entry} is not implemented until Phase 2 creates src/. ` +
      `Refusing to fall back to the classic path, which would report the wrong subject.`);
  }

  const indexPath = join(root, 'index.html');
  if (!existsSync(indexPath)) throw new Error(`subject: no index.html at ${root}`);
  const indexBuffer = readFileSync(indexPath);
  const indexHtml = indexBuffer.toString('utf8');

  const inputs = [{ path: 'index.html', bytes: indexBuffer.length, sha256: sha256(indexBuffer) }];
  const { scripts, stylesheets } = readEntryPoints(indexHtml);

  const document = createDocument();
  const instant = options.instant ?? FIXED_INSTANT;
  // Substituting an ambient primitive is the same move this project makes with
  // `fetch`, and the profile is recorded in the manifest so a baseline captured
  // under one cannot be silently compared against another.
  const platform = platformProfile(options.platform);
  const win = {
    document,
    navigator: { language: FIXED_LOCALE, languages: [FIXED_LOCALE] },
    location: { href: 'https://dnsaudit.kwestic.com/' },
    localStorage: {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    },
    fetch: options.fetch || (async () => ({ ok: false })),
    console: options.console || console,
    setTimeout, clearTimeout, queueMicrotask,
    URL, URLSearchParams, AbortController,
    crypto: platform.crypto(),
    Date: pinnedDate(instant),
    Intl,
  };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  vm.createContext(win);

  for (const { src, type } of scripts) {
    if (type && type !== 'text/javascript' && type !== 'module') {
      throw new Error(`subject: unexpected script type ${type} for ${src}`);
    }
    if (type === 'module') {
      throw new Error(
        `subject: ${src} is a module script. The IIFE bundle decision (OQ-ARCH-06) ` +
        `keeps file:// working and forbids type="module".`);
    }
    const scriptPath = join(root, src);
    if (!existsSync(scriptPath)) throw new Error(`subject: ${src} listed in index.html but missing from ${root}`);
    const buffer = readFileSync(scriptPath);
    inputs.push({ path: posix.normalize(src), bytes: buffer.length, sha256: sha256(buffer) });
    vm.runInContext(buffer.toString('utf8'), win, { filename: src });
  }

  // The stylesheet the exported report inlines. Read from THIS subject, so a
  // baseline run can never pair v0.5.0 JavaScript with current-branch CSS.
  let css = '';
  for (const href of stylesheets) {
    const cssPath = join(root, href);
    if (!existsSync(cssPath)) throw new Error(`subject: ${href} listed in index.html but missing from ${root}`);
    const buffer = readFileSync(cssPath);
    inputs.push({ path: posix.normalize(href), bytes: buffer.length, sha256: sha256(buffer) });
    css += buffer.toString('utf8');
  }

  buildPageSkeleton(document, indexHtml);

  return {
    win,
    document,
    css,
    manifest: {
      root,
      entry,
      scripts: scripts.map(s => s.src),
      stylesheets,
      inputs,
      instant,
      locale: FIXED_LOCALE,
      timezone: FIXED_TIMEZONE,
      resolvedTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      platform: platform.id,
      node: process.version,
      icu: process.versions.icu,
      unicode: process.versions.unicode,
    },
  };
}

/** HTML void elements — they never open a nesting level. */
const VOID_ELEMENTS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img',
  'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);

/**
 * Build the element skeleton the application wires itself to, DERIVED from the
 * subject's own `index.html` rather than hand-listed.
 *
 * `js/app.js` reaches 34 ids, and their tag, `type`, `checked` default and
 * nesting are all facts about the subject's markup. Hand-listing them here
 * would make the runner's page a copy of `index.html` maintained separately
 * from it — and the first divergence would show up as an equivalence diff in
 * the application rather than as a bug in the instrument.
 *
 * The DOM shim parses no HTML, so this is a tag-stack walk that records, for
 * each id, its tag and its nearest ancestor carrying an id. That is exactly
 * the structure `exportHTML()` depends on: it clones `#resultsSection`, and
 * `#tableBody` has to be inside it.
 */
export function buildPageSkeleton(document, indexHtml) {
  const stack = [];
  const created = new Map();
  const pattern = /<(\/?)([a-zA-Z][\w-]*)\b([^>]*?)(\/?)>/g;
  let match;
  while ((match = pattern.exec(indexHtml))) {
    const [, closing, rawTag, attrs, selfClosing] = match;
    const tag = rawTag.toLowerCase();
    if (closing) {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].tag === tag) { stack.length = i; break; }
      }
      continue;
    }
    const idMatch = /\bid\s*=\s*["']([^"']+)["']/.exec(attrs);
    if (idMatch) {
      const id = idMatch[1];
      const element = document.createElement(tag);
      element.id = id;
      const type = /\btype\s*=\s*["']([^"']+)["']/.exec(attrs);
      if (type) element.type = type[1];
      if (/\bchecked\b/.test(attrs)) element.checked = true;
      if (tag === 'input' || tag === 'textarea' || tag === 'select') element.value = element.value || '';
      const parentId = [...stack].reverse().find(entry => entry.id);
      const parent = parentId ? created.get(parentId.id) : null;
      (parent || document.body).appendChild(element);
      created.set(id, element);
      if (!VOID_ELEMENTS.has(tag) && !selfClosing) stack.push({ tag, id });
    } else if (!VOID_ELEMENTS.has(tag) && !selfClosing) {
      stack.push({ tag, id: null });
    }
  }
  return created;
}
