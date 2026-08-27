/* ──────────────────────────────────────────────────────────────────────────
   A dependency-free DOM good enough to test the renderer, and no more.

   What this proves
   ----------------
   That `src/ui/render.js` and `src/main.js` put every DNS-derived value into a text
   node or an allowlisted attribute, and never into a markup sink. That is a
   question about which DOM methods the renderer calls, so a shim answers it
   exactly: after the 0.2.3 rewrite the render path never parses a string into
   markup at all. It calls createElement, sets textContent, and calls
   setAttribute against an allowlist.

   What this does NOT prove
   ------------------------
   That a browser renders the resulting tree safely. It does not need to. A
   text node is not markup by definition of the DOM, not by grace of this file.
   Nor does it model mutation XSS, entity re-parsing, or namespace confusion —
   all three require a parser, and after 0.2.3 there is no parsing path left in
   the render code for them to act on. `tools/export.test.mjs` asserts on the
   real serialized strings rather than on this model, which is where a
   serializer bug would show up.

   Enforcement
   -----------
   `innerHTML` and `outerHTML` are accessor properties whose SETTERS THROW.
   That catches `el.innerHTML = x`, `el['inner' + 'HTML'] = x` and
   `Object.assign(el, { innerHTML: x })` alike — forms a static pattern misses.
   The `outerHTML` getter works normally, because building a tree and reading
   `outerHTML` once is the supported way to serialize a document (spec §1a).
   ────────────────────────────────────────────────────────────────────────── */

/** Thrown by the markup-sink setter trap. Tests assert on the name. */
export class MarkupSinkError extends Error {
  constructor(prop, tagName) {
    super(
      'Refused to assign to ' + prop + ' on <' + String(tagName).toLowerCase() + '>. ' +
      'The markup-sink allowlist is empty: build nodes with R.el/R.text instead.'
    );
    this.name = 'MarkupSinkError';
    this.prop = prop;
  }
}

const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

// Raw-text elements per the HTML spec: their text children serialize verbatim,
// with no entity escaping. This is not a shim convenience — a browser does the
// same, and getting it wrong would corrupt every `>` and `&` in the stylesheet
// the exported report inlines, making the export tests assert on output no
// browser would ever produce. Nothing untrusted is ever placed in one: the
// only raw-text node this codebase creates holds css/style.css.
const RAW_TEXT_ELEMENTS = new Set(['style', 'script']);

// Serializing a text node is where the safety argument is cashed in: `<` and
// `&` become entities, so a text node containing `<script>` round-trips back to
// a text node and never to an element. `>` is escaped too — not strictly
// required in text, but the export tests scan for raw `<script` and a
// consistently escaped output is easier to reason about than a nearly-escaped
// one.
function escapeText(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Attribute values escape ONLY `&`, `"` and U+00A0, per the HTML fragment
// serialization algorithm. A browser leaves `<` and `>` alone inside a quoted
// value, and escaping them here would make the export tests assert on bytes no
// browser produces — which matters, because `data-tip` is a real attribute
// that carries DNS-derived text. A raw `<` inside a quoted value is still just
// data when the document is reparsed.
function escapeAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/\u00A0/g, '&nbsp;')
    .replace(/"/g, '&quot;');
}

let nodeCounter = 0;

class ShimNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.childNodes = [];
    this.parentNode = null;
    this._id = ++nodeCounter;
  }

  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }

  get nextElementSibling() {
    if (!this.parentNode) return null;
    const siblings = this.parentNode.childNodes;
    for (let i = siblings.indexOf(this) + 1; i < siblings.length; i++) {
      if (siblings[i].nodeType === 1) return siblings[i];
    }
    return null;
  }

  appendChild(child) {
    if (child == null) return child;
    // A fragment appends its children and is itself discarded, matching the DOM.
    if (child.nodeType === 11) {
      child.childNodes.slice().forEach((c) => this.appendChild(c));
      child.childNodes.length = 0;
      return child;
    }
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  /** Deep or shallow copy, as `Node.cloneNode`. */
  cloneNode(deep) {
    const copy = this._shallowClone();
    if (deep) this.childNodes.forEach((c) => copy.appendChild(c.cloneNode(true)));
    return copy;
  }

  removeChild(child) {
    const i = this.childNodes.indexOf(child);
    if (i >= 0) {
      this.childNodes.splice(i, 1);
      child.parentNode = null;
    }
    return child;
  }

  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }

  replaceChildren(...nodes) {
    this.childNodes.slice().forEach((c) => { c.parentNode = null; });
    this.childNodes.length = 0;
    nodes.forEach((n) => this.appendChild(n));
  }

  append(...nodes) {
    nodes.forEach((n) => {
      this.appendChild(typeof n === 'string' ? new ShimText(n) : n);
    });
  }

  addEventListener(type, handler) {
    if (typeof handler !== 'function') return;
    const listeners = this._listeners || (this._listeners = {});
    (listeners[type] || (listeners[type] = [])).push(handler);
  }

  removeEventListener(type, handler) {
    const handlers = this._listeners && this._listeners[type];
    if (!handlers) return;
    const at = handlers.indexOf(handler);
    if (at >= 0) handlers.splice(at, 1);
  }

  /**
   * Dispatch to the listeners this tree actually registered, then bubble.
   *
   * A no-op until Task 2.8, and the change is what that task needs. The
   * equivalence runner used to drive the application by calling
   * `win.startAudit()`, `win.exportCSV()` and `win.exportHTML()` — three of the
   * fourteen unsupported globals that task removes. The runner now clicks
   * `#auditBtn`, `#exportCsvBtn` and `#exportHtmlBtn`, which is a MORE FAITHFUL
   * DRIVER rather than a workaround: a user clicks a button, and the path from
   * the click to the audit is now part of what the five surfaces cover.
   *
   * Bubbling is real because the application depends on it: `src/main.js` wires
   * ONE click listener on `#tableBody` and dispatches inside it with
   * `event.target.closest(...)`, so a shim that only ran listeners on the exact
   * target would model the direct handlers and silently skip every delegated
   * one.
   *
   * `stopPropagation()` is honoured for the same reason — it is the only
   * control a delegated handler has — and `preventDefault()` is recorded
   * without acting on it, because nothing in this shim has a default action to
   * prevent and pretending otherwise would be the kind of half-model that
   * misleads.
   */
  dispatchEvent(event) {
    const target = event.target || this;
    let node = this;
    while (node) {
      const handlers = node._listeners && node._listeners[event.type];
      if (handlers) {
        // A copy: a handler that removes another must not shift this iteration.
        for (const handler of handlers.slice()) {
          const returned = handler.call(node, { ...event, target, currentTarget: node });
          // The one extension, and it is on the EVENT rather than on the DOM
          // API. `startAudit` is an async function wired straight to the
          // button, and a real `click()` discards the promise it returns — a
          // browser has nothing to await it with, and neither does a user.
          // The equivalence runner does: it has to know when the audit it
          // started has finished. So a caller that built the event can read
          // what the handlers returned, and a caller that used `click()` sees
          // exactly what a browser would.
          if (event.__results) event.__results.push(returned);
          if (event.__stopped) break;
        }
      }
      if (event.__stopped || !event.bubbles) break;
      node = node.parentNode;
    }
    return !event.__prevented;
  }

  /**
   * A real click, and a detached node still absorbs it.
   *
   * `src/main.js:1600` synthesises a click on a DETACHED anchor to start a
   * download. The download is the browser's, not the document's, and the
   * equivalence runner captures the content at the `Blob` instead — so that
   * anchor has no listeners and no parent, and dispatching to it does exactly
   * what it did when this method was empty. Nothing about the export path
   * changed.
   */
  click() {
    const event = { type: 'click', bubbles: true };
    event.stopPropagation = () => { event.__stopped = true; };
    event.preventDefault = () => { event.__prevented = true; };
    event.target = this;
    return this.dispatchEvent(event);
  }

  /** Depth-first walk over every descendant, this node excluded. */
  * walk() {
    for (const child of this.childNodes) {
      yield child;
      if (child.walk) yield* child.walk();
    }
  }
}

class ShimText extends ShimNode {
  constructor(data) {
    super(3);
    this.data = String(data === undefined || data === null ? '' : data);
  }

  _shallowClone() { return new ShimText(this.data); }

  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v === undefined || v === null ? '' : v); }
  get nodeValue() { return this.data; }

  get outerHTML() { return escapeText(this.data); }
}

class ShimFragment extends ShimNode {
  constructor() { super(11); }

  _shallowClone() { return new ShimFragment(); }

  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }

  get outerHTML() {
    return this.childNodes.map((c) => c.outerHTML).join('');
  }
}

class ShimClassList {
  constructor(el) { this._el = el; }

  _list() {
    const raw = this._el._attrs.get('class') || '';
    return raw.split(/\s+/).filter(Boolean);
  }

  _write(list) {
    if (list.length) this._el._attrs.set('class', list.join(' '));
    else this._el._attrs.delete('class');
  }

  add(...names) {
    const list = this._list();
    names.filter(Boolean).forEach((n) => { if (!list.includes(n)) list.push(n); });
    this._write(list);
  }

  remove(...names) {
    this._write(this._list().filter((n) => !names.includes(n)));
  }

  contains(name) { return this._list().includes(name); }

  toggle(name, force) {
    const has = this.contains(name);
    const want = force === undefined ? !has : !!force;
    if (want) this.add(name); else this.remove(name);
    return want;
  }

  get length() { return this._list().length; }
  toString() { return this._list().join(' '); }
}

class ShimStyle {
  constructor() { this._props = new Map(); }

  setProperty(name, value) {
    this._props.set(String(name), String(value));
  }

  getPropertyValue(name) { return this._props.get(String(name)) || ''; }

  removeProperty(name) { this._props.delete(String(name)); }

  get cssText() {
    return Array.from(this._props, ([k, v]) => k + ':' + v).join(';');
  }
}

// The properties the app assigns as `el.style.foo = x`. Defined as accessors
// so that idiom behaves the way it does in a browser instead of silently
// writing a plain own-property the serializer would never see — which would
// let a test pass while the real page did nothing.
for (const prop of ['display', 'width', 'opacity', 'color', 'background']) {
  Object.defineProperty(ShimStyle.prototype, prop, {
    configurable: true,
    enumerable: true,
    get() { return this.getPropertyValue(prop); },
    set(v) {
      if (v === '' || v === null || v === undefined) this.removeProperty(prop);
      else this.setProperty(prop, v);
    },
  });
}

class ShimElement extends ShimNode {
  constructor(tagName, ownerDocument) {
    super(1);
    this.tagName = String(tagName).toUpperCase();
    this.localName = String(tagName).toLowerCase();
    this.ownerDocument = ownerDocument || null;
    this._attrs = new Map();
    this.dataset = {};
    this.style = new ShimStyle();
    this.classList = new ShimClassList(this);
  }

  _shallowClone() {
    const copy = new ShimElement(this.localName, this.ownerDocument);
    this._attrs.forEach((v, k) => copy._attrs.set(k, v));
    Object.keys(this.dataset).forEach((k) => { copy.dataset[k] = this.dataset[k]; });
    this.style._props.forEach((v, k) => copy.style.setProperty(k, v));
    return copy;
  }

  /**
   * Deliberately minimal: matches `.class` and `tag` only. The renderer needs
   * no selector engine — tests walk the tree — but the disclosure control
   * looks up `.rv-rest` on its own parent, so that one form is supported.
   */
  querySelectorAll(selector) {
    const sel = String(selector).trim();
    const matches = (el) => (sel.charAt(0) === '.'
      ? el.classList.contains(sel.slice(1))
      : el.localName === sel.toLowerCase());
    const out = [];
    for (const node of this.walk()) {
      if (node.nodeType === 1 && matches(node)) out.push(node);
    }
    return out;
  }

  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }

  /* ── Attributes ───────────────────────────────────────────────────── */

  setAttribute(name, value) {
    this._attrs.set(String(name).toLowerCase(), String(value === undefined || value === null ? '' : value));
  }

  getAttribute(name) {
    const key = String(name).toLowerCase();
    return this._attrs.has(key) ? this._attrs.get(key) : null;
  }

  hasAttribute(name) { return this._attrs.has(String(name).toLowerCase()); }

  removeAttribute(name) { this._attrs.delete(String(name).toLowerCase()); }

  /** Live view, matching the shape the sanitizer iterates over. */
  get attributes() {
    return Array.from(this._attrs, ([name, value]) => ({ name, value }));
  }

  get className() { return this._attrs.get('class') || ''; }
  set className(v) { this.setAttribute('class', v); }

  get id() { return this._attrs.get('id') || ''; }
  set id(v) { this.setAttribute('id', v); }

  get title() { return this._attrs.get('title') || ''; }
  set title(v) { this.setAttribute('title', v); }

  /* ── Content ──────────────────────────────────────────────────────── */

  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }

  set textContent(value) {
    this.childNodes.slice().forEach((c) => { c.parentNode = null; });
    this.childNodes.length = 0;
    // Matching the DOM: setting '' clears without leaving an empty text node.
    if (value !== '' && value !== null && value !== undefined) {
      this.appendChild(new ShimText(value));
    }
  }

  /* ── Serialization ────────────────────────────────────────────────── */

  _openTag() {
    // dataset is materialized at serialization time so `el.dataset.foo = x`
    // reaches the output the way it does in a browser.
    const attrs = new Map(this._attrs);
    Object.keys(this.dataset).forEach((k) => {
      const name = 'data-' + k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());
      attrs.set(name, String(this.dataset[k]));
    });
    const css = this.style.cssText;
    if (css) attrs.set('style', attrs.has('style') ? attrs.get('style') + ';' + css : css);

    let out = '<' + this.localName;
    for (const [name, value] of attrs) out += ' ' + name + '="' + escapeAttr(value) + '"';
    return out + '>';
  }

  get innerHTML() {
    if (RAW_TEXT_ELEMENTS.has(this.localName)) {
      return this.childNodes.map((c) => (c.nodeType === 3 ? c.data : c.outerHTML)).join('');
    }
    return this.childNodes.map((c) => c.outerHTML).join('');
  }

  get outerHTML() {
    if (VOID_ELEMENTS.has(this.localName)) return this._openTag();
    return this._openTag() + this.innerHTML + '</' + this.localName + '>';
  }
}

/* ── The markup-sink trap ───────────────────────────────────────────────
   Defined on the prototype as accessor properties so an assignment anywhere
   — direct, computed, or via Object.assign — hits the setter and throws.
   The getters are left working: reading is how §1a serializes a document. */
for (const prop of ['innerHTML', 'outerHTML']) {
  const existing = Object.getOwnPropertyDescriptor(ShimElement.prototype, prop);
  Object.defineProperty(ShimElement.prototype, prop, {
    configurable: true,
    enumerable: false,
    get: existing.get,
    set(value) { throw new MarkupSinkError(prop, this.tagName); },
  });
}

// A fragment has no tag of its own but is just as much a sink if something
// assigns markup to it.
Object.defineProperty(ShimFragment.prototype, 'innerHTML', {
  configurable: true,
  enumerable: false,
  get() { return this.childNodes.map((c) => c.outerHTML).join(''); },
  set() { throw new MarkupSinkError('innerHTML', 'documentfragment'); },
});

class ShimDocument {
  constructor() {
    this._byId = new Map();
    this.documentElement = null;
    this.head = null;
    this.body = null;
    this.title = '';
    this.implementation = {
      createHTMLDocument: (title) => createHTMLDocument(title),
    };
  }

  createElement(tag) {
    const el = new ShimElement(tag, this);
    // getElementById has no live index in the shim; register on creation and
    // let the id setter below keep it current.
    const self = this;
    Object.defineProperty(el, 'id', {
      configurable: true,
      get() { return this._attrs.get('id') || ''; },
      set(v) { this.setAttribute('id', v); self._byId.set(String(v), this); },
    });
    return el;
  }

  createTextNode(data) { return new ShimText(data); }

  createDocumentFragment() { return new ShimFragment(); }

  addEventListener(type, handler) {
    if (typeof handler !== 'function') return;
    const listeners = this._listeners || (this._listeners = {});
    (listeners[type] || (listeners[type] = [])).push(handler);
  }

  removeEventListener(type, handler) {
    const handlers = this._listeners && this._listeners[type];
    if (!handlers) return;
    const at = handlers.indexOf(handler);
    if (at >= 0) handlers.splice(at, 1);
  }

  /**
   * The document has no parent, so nothing bubbles past it.
   *
   * This is how `DOMContentLoaded` reaches the application: `src/main.js` wires
   * every control from inside that listener, so a subject whose document never
   * fires it has an inert page with no handlers on any button. The equivalence
   * runner fires it before it clicks anything.
   */
  dispatchEvent(event) {
    const handlers = this._listeners && this._listeners[event.type];
    if (!handlers) return true;
    for (const handler of handlers.slice()) {
      handler.call(this, { ...event, target: event.target || this, currentTarget: this });
      if (event.__stopped) break;
    }
    return !event.__prevented;
  }

  /** No selector engine: tests walk the tree. Present so load-time calls work. */
  querySelectorAll() { return []; }

  querySelector() { return null; }

  getElementById(id) { return this._byId.get(String(id)) || null; }

  /** Copy a node from another document, as `Document.importNode`. */
  importNode(node, deep) { return node.cloneNode(deep); }

  /** Move a node in from another document, as `Document.adoptNode`. */
  adoptNode(node) {
    if (node.parentNode) node.parentNode.removeChild(node);
    return node;
  }
}

/**
 * A detached document with html/head/body, matching
 * `document.implementation.createHTMLDocument()` closely enough for the two
 * document builders in `src/main.js` (spec §1a).
 */
export function createHTMLDocument(title) {
  const doc = new ShimDocument();
  const html = doc.createElement('html');
  const head = doc.createElement('head');
  const body = doc.createElement('body');
  html.appendChild(head);
  html.appendChild(body);
  doc.documentElement = html;
  doc.head = head;
  doc.body = body;
  if (title !== undefined && title !== null && title !== '') {
    const titleEl = doc.createElement('title');
    titleEl.textContent = title;
    head.appendChild(titleEl);
    doc.title = String(title);
  }
  return doc;
}

/** A fresh top-level document, as `window.document`. */
export function createDocument() {
  const doc = createHTMLDocument('');
  return doc;
}

/**
 * Build a `window`-like global for loading `js/render.js`, `js/i18n.js` and
 * `js/app.js` into a `node:vm` sandbox, the way `tools/backtest.mjs` already
 * loads `js/dns.js`.
 */
export function createWindow(extra = {}) {
  const document = createDocument();
  const win = {
    document,
    navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://dnsaudit.kwestic.com/' },
    console,
    setTimeout,
    clearTimeout,
    Intl,
    URL,
    Set,
    Map,
    Date,
    Math,
    JSON,
    ...extra,
  };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  return win;
}

export {
  ShimNode,
  ShimText,
  ShimElement,
  ShimFragment,
  ShimDocument,
  escapeText,
  escapeAttr,
};
