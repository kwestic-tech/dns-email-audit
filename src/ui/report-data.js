/**
 * The 0.9.0 report schema, its importer and the comparison.
 * Spec: report-comparison 1.9 (Final), sections 1, 4 and 5.
 *
 * -- Pure, and deliberately so ------------------------------------------
 *
 * No DOM, no download, no locale lookup, no `platform`. `src/ui/report.js`
 * wires `projectReport()` to the existing download capability and
 * `src/ui/events.js` wires `parseReport()` and `compareReports()` to controls;
 * everything here is data in, data out, so the round-trip and the hostile-input
 * suite drive it directly.
 *
 * Section 0 forbids a `src/ui/` to `src/audit/` import, so this module reaches
 * for nothing in the engine. The two version values arrive as data through the
 * composition root (`src/runtime.js`), and the DS/DNSKEY/TLSA presentation
 * strings below are composed here rather than imported from
 * `src/audit/findings.js`.
 *
 * -- The schema is a PROJECTION, not a dump -----------------------------
 *
 * Section 1's exclusion table is the specification, and the reason is not size.
 * A dump would carry `score.cls` and `dmarcStatus.cls` (CSS class names), the
 * finding's locale routing (`key`, `keyspace`, `noteKey`, `noteArgs`), `blocks`
 * (derived within one run), the Tree Walk query trace, the provider heuristics
 * -- and `txt`/`verifications`, which hold every apex TXT record including
 * `google-site-verification=` and its siblings. A report is made to be handed
 * to a colleague or an auditor; handing over the domain's third-party SaaS
 * inventory is not what they asked for.
 *
 * `REPORT_PATHS` is that decision in machine-readable form, and the co-located
 * suite proves it in BOTH directions: every path a real projection emits is
 * registered, and every registered path is reached by a fixture. A one-way test
 * would pass on a dump; the other direction catches a registry member that
 * nothing produces any more.
 */

/* -- Identity and closed vocabularies --------------------------------- */

export const SCHEMA_ID = 'dns-email-audit/report';
export const SCHEMA_VERSION = 1;

/**
 * The maximum domains in one run, and therefore in one report.
 *
 * Section 4: the importer's limit is "imported from the same constant the run
 * enforces, not restated, so the two cannot drift." It lives here rather than
 * in `events.js` because this is the module that has to reject a file, and a
 * UI module importing a schema constant is the direction the sibling edge
 * already allows.
 */
export const MAX_DOMAINS = 200;

const RECORD_KINDS = ['ns', 'mx', 'spf', 'dmarc', 'dkim', 'bimi', 'caa',
  'mtaSts', 'tlsRpt', 'tlsa', 'dnskey', 'ds'];

/** The thirteen `PROTOCOLS` tokens `observability` is total over (section 1). */
export const PROTOCOL_TOKENS = ['spf', 'dkim', 'dmarc', 'dnssec', 'caa', 'mta-sts',
  'tls-rpt', 'bimi', 'mx', 'dane', 'dns', 'defensive', 'reporting'];

export const OBSERVABILITY_STATES = ['observed', 'unproven', 'not-run'];
export const DOMAIN_STATES = ['audited', 'unregistered', 'error'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const CONFIDENCES = ['confirmed', 'probable', 'unverified'];
export const CATEGORIES = ['authentication', 'policy', 'reporting', 'transport',
  'issuance', 'resilience', 'hygiene'];
export const EFFORTS = ['trivial', 'moderate', 'involved'];
export const RATIONALES = ['foundation', 'afterPrereq', 'cleanup'];
export const GRADES = ['A++', 'A+', 'A', 'B', 'C', 'D', 'F'];
export const PILLAR_KEYS = ['spf', 'dmarc', 'dkim', 'dnssec', 'caa', 'mtaSts', 'bimi', 'tlsRpt'];
export const TERMINATIONS = ['root', 'error', 'psd-y', 'psd-n'];
export const EVIDENCE_KINDS = ['txt', 'absent', 'selector', 'host', 'mx', 'address',
  'cname', 'caa', 'dnssec', 'tlsa', 'mechanism', 'info'];
const OPTION_KEYS = ['dkim', 'dkimComprehensive', 'www', 'wildcard', 'advanced', 'deepChecks'];

export const DOMAIN_STATUSES = ['added', 'removed', 'improved', 'regressed',
  'changed', 'unchanged', 'incomparable'];

/**
 * Section 5's closed option-to-protocol mapping, including the 1.2 correction.
 *
 * `advanced` reaches `spf`, `dmarc` and `reporting` as well as the five
 * dedicated advanced protocols, because it gates `spfLookups`, `spfSubnets` and
 * `reportAuth` -- the facts nine finding ids depend on, eight of them
 * `protocol: 'spf'`. Without those three entries an `advanced` mismatch would
 * report all eight SPF findings as `resolved`.
 */
export const OPTION_PROTOCOLS = {
  dkim: ['dkim'],
  dkimComprehensive: ['dkim'],
  selectors: ['dkim'],
  deepChecks: ['mx', 'dane'],
  wildcard: ['dns', 'dkim'],
  www: ['dns'],
  advanced: ['dnssec', 'caa', 'mta-sts', 'tls-rpt', 'bimi', 'spf', 'dmarc', 'reporting'],
};

/** Which protocol owns each record kind, for the `recordChanges` filter. */
const RECORD_PROTOCOL = {
  ns: 'dns', mx: 'mx', spf: 'spf', dmarc: 'dmarc', dkim: 'dkim', bimi: 'bimi',
  caa: 'caa', mtaSts: 'mta-sts', tlsRpt: 'tls-rpt', tlsa: 'dane',
  dnskey: 'dnssec', ds: 'dnssec',
};

/**
 * The closed set of rejection codes (report-comparison 1.9 section 4).
 *
 * ONLY the code is localized. `path` is a schema path and `detail` is the
 * clause that failed; both stay literal technical data, for the same reason a
 * schema field name is never translated -- they identify a location in a
 * document rather than address a reader.
 *
 * The first implementation returned English prose from eighty call sites, which
 * the interface could not translate at all. Translating each clause instead
 * would have added roughly fifty keys in thirteen languages to describe fields
 * a report written by this tool cannot contain.
 */
export const ERROR_CODES = ['invalid-json', 'not-report', 'newer-version',
  'too-large', 'too-many-domains', 'malformed'];

const reject = (code, extra) => [Object.assign({ code }, extra || {})];

/** Section 4's limits, each failing closed and enforced in order. */
export const LIMITS = {
  bytes: 8 * 1024 * 1024,
  domains: MAX_DOMAINS,
  findings: 200,
  evidence: 20,
  depth: 8,
};

/* -- Small helpers ---------------------------------------------------- */

/**
 * Every map built from imported material, per section 4 and 0.8.1's precedent.
 *
 * A finding id, a domain name and a protocol token all reach this module from a
 * stranger's file. Against an object literal, an id of `__proto__` resolves
 * through the prototype chain to something truthy, which is the defect 0.8.1
 * fixed for DNS-derived and locale keys.
 */
const emptyMap = () => Object.create(null);
const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const isPlainObject = v => !!v && typeof v === 'object' && !Array.isArray(v);
const isString = v => typeof v === 'string';
const isBool = v => typeof v === 'boolean';
const isInt = v => typeof v === 'number' && Number.isInteger(v);
const isFiniteNum = v => typeof v === 'number' && Number.isFinite(v);
const oneOf = (v, list) => isString(v) && list.indexOf(v) !== -1;

const str = v => (v === undefined || v === null ? '' : String(v));

/** Sorted, deduplicated, and stable -- used for selectors and id unions. */
function uniqueSorted(values) {
  const seen = emptyMap();
  const out = [];
  values.forEach(function (v) {
    const k = str(v);
    if (has(seen, k)) return;
    seen[k] = true;
    out.push(k);
  });
  return out.sort();
}

/* -- Record normalization --------------------------------------------- */

/**
 * The ordered field tuple for each record kind.
 *
 * Section 1: entries are "deduplicated by their complete value tuple and sorted
 * lexicographically by that tuple before export and comparison, so resolver
 * answer order cannot create a record change." That last clause is the point --
 * a DNS answer set has no guaranteed order, so without this a re-run of an
 * unchanged domain would show a record change.
 */
const RECORD_FIELDS = {
  default: ['queryName', 'value'],
  tlsa: ['queryName', 'value', 'authenticated'],
  dkim: ['queryName', 'value', 'selector', 'keyType', 'keyBits'],
};

const fieldsFor = kind => RECORD_FIELDS[kind] || RECORD_FIELDS.default;

function tupleOf(kind, entry) {
  return fieldsFor(kind).map(function (f) { return JSON.stringify(entry[f]); }).join(' ');
}

export function normalizeRecords(kind, entries) {
  const seen = emptyMap();
  const out = [];
  (entries || []).forEach(function (e) {
    if (!isPlainObject(e)) return;
    const picked = {};
    fieldsFor(kind).forEach(function (f) { picked[f] = e[f]; });
    const key = tupleOf(kind, picked);
    if (has(seen, key)) return;
    seen[key] = true;
    out.push(picked);
  });
  return out.sort(function (a, b) {
    const ka = tupleOf(kind, a);
    const kb = tupleOf(kind, b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

const plain = (queryName, value) => ({ queryName: str(queryName), value: str(value) });

/**
 * The selector predicate, or a loud failure.
 *
 * A missing capability is a WIRING bug, not a bad file, so it throws rather
 * than returning a validation error: a caller that forgot to compose it should
 * see a broken build, not a report that looks merely invalid.
 */
function requireSelectorPredicate(predicate) {
  if (typeof predicate !== 'function') {
    throw new TypeError('report-data: a validSelector capability is required');
  }
  return predicate;
}

/* -- Producer: the projection ----------------------------------------- */

function projectRecords(r) {
  const advanced = r.advanced || {};
  const domain = str(r.domain);
  const dkimSelectors = (r.dkimStatus && r.dkimStatus.selectors) || [];
  const tlsaHosts = (advanced.tlsa && advanced.tlsa.hosts) || [];
  const dnssec = advanced.dnssec || {};

  const single = (queryName, value) => (value ? [plain(queryName, value)] : []);
  const many = (queryName, values) => (values || []).map(v => plain(queryName, v));

  return {
    ns: normalizeRecords('ns', many(domain, r.ns)),
    mx: normalizeRecords('mx', many(domain, r.mx)),
    spf: normalizeRecords('spf', many(domain, r.spfRecords)),
    dmarc: normalizeRecords('dmarc', single(str(r.dmarcAtDomain) || '_dmarc.' + domain, r.dmarcRecord)),
    dkim: normalizeRecords('dkim', dkimSelectors.map(function (s) {
      const key = s.key || {};
      return {
        queryName: str(s.queryName), value: str(s.value), selector: str(s.sel),
        keyType: isString(key.keyType) ? key.keyType : null,
        keyBits: isInt(key.keyBits) ? key.keyBits : null,
      };
    })),
    bimi: normalizeRecords('bimi', single('default._bimi.' + domain, advanced.bimi && advanced.bimi.record)),
    caa: normalizeRecords('caa', many(str((advanced.caa && advanced.caa.atDomain) || domain),
      advanced.caa && advanced.caa.records)),
    mtaSts: normalizeRecords('mtaSts', single('_mta-sts.' + domain, advanced.mtaSts && advanced.mtaSts.record)),
    tlsRpt: normalizeRecords('tlsRpt', single('_smtp._tls.' + domain, advanced.tlsRpt && advanced.tlsRpt.record)),
    tlsa: normalizeRecords('tlsa', tlsaHosts.reduce(function (acc, host) {
      (host.records || []).forEach(function (rec) {
        acc.push({
          queryName: str(host.queryName),
          // Composed here, not imported: section 0 forbids a ui-to-audit edge,
          // and this is the RFC 6698 presentation order.
          value: [rec.usage, rec.selector, rec.matchingType, rec.data].join(' '),
          authenticated: !!host.authenticated,
        });
      });
      return acc;
    }, [])),
    dnskey: normalizeRecords('dnskey', (dnssec.keys || []).map(function (k) {
      return plain(domain, [k.flags, k.protocol, k.algorithm, k.publicKey].join(' '));
    })),
    ds: normalizeRecords('ds', (dnssec.ds || []).map(function (d) {
      return plain(domain, [d.keyTag, d.algorithm, d.digestType, d.digest].join(' '));
    })),
  };
}

function projectFinding(f) {
  return {
    id: str(f.id),
    protocol: str(f.protocol),
    severity: str(f.severity),
    confidence: str(f.confidence),
    category: str(f.category),
    effort: str(f.effort),
    // `args` carries protocol tokens and DNS material, never a translation.
    args: (f.args || []).slice(),
    dependsOn: (f.dependsOn || []).slice(),
    evidence: (f.evidence || []).map(function (e) {
      return { kind: str(e.kind), queryName: str(e.queryName), value: str(e.value) };
    }),
  };
}

function projectDomain(r) {
  const domain = str(r.domain);
  // Section 1: an unregistered or errored domain carries no observability,
  // score, discovery, records, findings or plan -- there is nothing observed.
  if (r.unregistered) return { domain, state: 'unregistered' };
  if (r.error) return { domain, state: 'error' };

  const score = r.score || {};
  const pillars = (score.breakdown && score.breakdown.pillars) || [];
  const discovery = r.dmarcDiscovery || {};
  const applied = discovery.applied || {};

  return {
    domain,
    organizationalDomain: str(r.organizationalDomain),
    state: 'audited',
    observability: PROTOCOL_TOKENS.reduce(function (map, p) {
      const v = r.observability && r.observability[p];
      // Fail closed: a protocol the audit did not report on is not observed.
      map[p] = oneOf(v, OBSERVABILITY_STATES) ? v : 'not-run';
      return map;
    }, {}),
    score: {
      pts: isFiniteNum(score.pts) ? score.pts : 0,
      max: isFiniteNum(score.max) ? score.max : 0,
      grade: oneOf(score.grade, GRADES) ? score.grade : 'F',
      parked: !!score.parked,
      unproven: (score.unproven || []).slice().sort(),
      pillars: pillars.map(function (p) {
        return { key: PILLAR_KEYS.indexOf(p.key) !== -1 ? p.key : 'spf', pts: isFiniteNum(p.pts) ? p.pts : 0, max: isFiniteNum(p.max) ? p.max : 0 };
      }),
    },
    // Only the settled provenance tokens the CSV already publishes; the walk's
    // `queries` and `steps` are one run's trace, not a comparable fact.
    dmarcDiscovery: {
      foundAt: applied.foundAt === undefined ? null : str(applied.foundAt),
      labelsUp: isInt(applied.labelsUp) ? applied.labelsUp : null,
      terminated: oneOf(discovery.terminated, TERMINATIONS) ? discovery.terminated : 'error',
      organizationalDomain: str(discovery.organizationalDomain),
      policyDomain: discovery.policyDomain === undefined || discovery.policyDomain === null
        ? null : str(discovery.policyDomain),
      psdBoundary: discovery.psdBoundary === undefined || discovery.psdBoundary === null
        ? null : str(discovery.psdBoundary),
    },
    records: projectRecords(r),
    findings: (r.findings || []).map(projectFinding),
    remediationPlan: (r.remediationPlan || []).map(function (s) {
      return {
        step: isInt(s.step) ? s.step : 0,
        rationale: oneOf(s.rationale, RATIONALES) ? s.rationale : 'cleanup',
        findings: (s.findings || []).slice(),
        unblocks: (s.unblocks || []).slice(),
      };
    }),
  };
}

/**
 * Build the report body from completed audit results.
 *
 * `generatedAt` is the moment the RUN completed, supplied by the caller and
 * reused by every export of that run -- section 1. As export time, two exports
 * of one audit in two languages would differ and acceptance criterion 4 would
 * be untestable.
 *
 * Artifact findings are absent by construction, not by filter: nothing here
 * reads an artifact session, so there is no path by which a `user-supplied`
 * finding can reach the file (RQ-CMP-07).
 */
export function projectReport(input) {
  const opts = (input && input.options) || {};
  const versions = (input && input.versions) || {};
  // The producer FILTERS with the same predicate the importer validates with,
  // so a selector this build would reject can never reach a file this build
  // wrote. Without the filter, user input like `-bad` was emitted and then
  // refused on import -- the self-rejection defect, one field over.
  const validSelector = requireSelectorPredicate(input && input.validSelector);
  const selectors = (opts.selectors || []).filter(validSelector);
  return {
    schema: SCHEMA_ID,
    schemaVersion: SCHEMA_VERSION,
    generatedAt: str(input && input.generatedAt),
    generator: {
      version: str(versions.app),
      analysisVersion: isInt(versions.analysis) ? versions.analysis : 0,
    },
    resolver: str(input && input.resolver),
    options: OPTION_KEYS.reduce(function (o, k) {
      o[k] = !!opts[k];
      return o;
    }, { selectors: uniqueSorted(selectors) }),
    domains: ((input && input.results) || []).map(projectDomain),
  };
}

/* -- The closed path registry ----------------------------------------- */

function recordPaths() {
  const out = [];
  RECORD_KINDS.forEach(function (kind) {
    fieldsFor(kind).forEach(function (field) {
      out.push('domains[].records.' + kind + '[].' + field);
    });
  });
  return out;
}

/**
 * Every path a conforming report may contain. Section 1's "bidirectional schema
 * test" reads this; adding a field here without producing it, or producing one
 * without adding it here, fails.
 */
export const REPORT_PATHS = [
  'schema', 'schemaVersion', 'generatedAt',
  'generator.version', 'generator.analysisVersion',
  'resolver',
].concat(
  OPTION_KEYS.map(k => 'options.' + k),
  ['options.selectors[]'],
  ['domains[].domain', 'domains[].organizationalDomain', 'domains[].state'],
  PROTOCOL_TOKENS.map(p => 'domains[].observability.' + p),
  ['domains[].score.pts', 'domains[].score.max', 'domains[].score.grade',
    'domains[].score.parked', 'domains[].score.unproven[]',
    'domains[].score.pillars[].key', 'domains[].score.pillars[].pts',
    'domains[].score.pillars[].max'],
  ['domains[].dmarcDiscovery.foundAt', 'domains[].dmarcDiscovery.labelsUp',
    'domains[].dmarcDiscovery.terminated', 'domains[].dmarcDiscovery.organizationalDomain',
    'domains[].dmarcDiscovery.policyDomain', 'domains[].dmarcDiscovery.psdBoundary'],
  recordPaths(),
  ['domains[].findings[].id', 'domains[].findings[].protocol', 'domains[].findings[].severity',
    'domains[].findings[].confidence', 'domains[].findings[].category',
    'domains[].findings[].effort', 'domains[].findings[].args[]',
    'domains[].findings[].dependsOn[]', 'domains[].findings[].evidence[].kind',
    'domains[].findings[].evidence[].queryName', 'domains[].findings[].evidence[].value'],
  ['domains[].remediationPlan[].step', 'domains[].remediationPlan[].rationale',
    'domains[].remediationPlan[].findings[]', 'domains[].remediationPlan[].unblocks[]']
);

/** Every leaf path actually present in a value, with `[]` for array members. */
export function pathsIn(value, prefix) {
  const base = prefix || '';
  if (Array.isArray(value)) {
    const out = [];
    value.forEach(function (v) {
      if (isPlainObject(v) || Array.isArray(v)) out.push.apply(out, pathsIn(v, base + '[]'));
      else out.push(base + '[]');
    });
    return out;
  }
  if (isPlainObject(value)) {
    const out = [];
    Object.keys(value).forEach(function (k) {
      out.push.apply(out, pathsIn(value[k], base ? base + '.' + k : k));
    });
    return out;
  }
  return [base];
}

/* -- Importer --------------------------------------------------------- */

const BANNED_KEYS = ['__proto__', 'constructor', 'prototype'];

/**
 * UTF-8 byte length, counted rather than encoded.
 *
 * `TextEncoder` would be simpler and is wrong here: `platform.test.mjs` holds
 * every `src/` module to reaching for no ambient primitive the platform does
 * not name, and this module is pure data code with no `platform` argument to
 * take one from. Counting code points costs nothing and keeps the boundary.
 */
function byteLength(text) {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff
      && i + 1 < text.length && text.charCodeAt(i + 1) >= 0xdc00 && text.charCodeAt(i + 1) <= 0xdfff) {
      // A COMPLETE pair is one four-byte code point. An earlier version
      // consumed the next unit unconditionally, so a lone high surrogate
      // followed by a three-byte character was counted as four bytes instead
      // of six -- an undercount, which is the wrong direction for a limit.
      bytes += 4;
      i++;
    } else {
      // Any lone surrogate encodes as U+FFFD, which is three bytes, the same
      // as the BMP characters this branch also covers.
      bytes += 3;
    }
  }
  return bytes;
}

function depthOf(value, depth) {
  const d = depth || 1;
  if (d > LIMITS.depth) return d;
  if (Array.isArray(value)) {
    return value.reduce(function (max, v) { return Math.max(max, depthOf(v, d + 1)); }, d);
  }
  if (isPlainObject(value)) {
    return Object.keys(value).reduce(function (max, k) {
      return Math.max(max, depthOf(value[k], d + 1));
    }, d);
  }
  return d;
}

/**
 * -- Strict, not forgiving -------------------------------------------------
 *
 * Section 4: "Every field is checked for type and range", and a valid-JSON
 * wrong shape is "rejected, no partial state". An earlier draft of this
 * importer COERCED instead -- a missing `generator` became `{}`, an unknown
 * severity became `info`, a negative `pts` passed through. That is worse than
 * useless on an attacker-supplied file: it silently repairs a malformed report
 * into a comparable-looking one, and the comparison then reports confident
 * differences derived from values nobody wrote.
 *
 * So every known member is required and range-checked, and the only thing
 * still dropped silently is an UNKNOWN member -- which is the forward
 * compatibility section 4 does ask for.
 */
/**
 * Record one malformed field and stop.
 *
 * `path` is the schema location and `detail` the clause it failed, both kept
 * verbatim: the interface frames them with a localized message rather than
 * translating them.
 */
function fail(errors, path, detail) {
  errors.push({ code: 'malformed', path: path, detail: detail });
  return false;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
// Canonical `major.minor.patch`: no leading zeros, so `00.9.0` is not a release
// string this tool ever wrote.
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
// One LDH label: letters, digits and inner hyphens, 1-63 characters.
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DOMAIN_RE = new RegExp('^' + LABEL + '(?:\\.' + LABEL + ')*$');
// An HTTPS URL with a real host. `URL` would be simpler and is an ambient this
// module may not reach for; a prefix test would accept `https://`. The port is
// checked NUMERICALLY below rather than by digit count, because `:99999` has
// the right shape and is not a port.
const HTTPS_RE = new RegExp('^https://(' + LABEL + '(?:\\.' + LABEL + ')*)(?::(\\d{1,5}))?(?:/[^\\s]*)?$');

const isNonNegative = v => isFiniteNum(v) && v >= 0;
const stringOrNull = v => v === null || isString(v);

/**
 * A normalized ASCII domain string, per section 1's scalar contract.
 *
 * Domain identity is a GRAMMAR-BOUNDED field, unlike a record or evidence
 * value, which carries whatever the resolver returned and is bounded only by
 * the file. A report whose `domain` is `<img src=x onerror=alert(1)>` was not
 * written by this tool, so it is rejected here rather than carried to the
 * renderer -- the rendering-safety guarantee belongs on the unbounded values,
 * where hostile bytes legitimately arrive.
 */
function isDomainName(v) {
  return isString(v) && v.length > 0 && v.length <= 253 && DOMAIN_RE.test(v);
}

/**
 * A real UTC instant, not merely the right shape.
 *
 * `2026-99-99T99:99:99.999Z` matches the pattern and is not a date. An earlier
 * version distinguished them by round-tripping through `Date`, which quietly
 * reintroduced the boundary this module removed `TextEncoder` to keep: `Date`
 * is a browser primitive the platform contract owns, and it escaped the lexical
 * ambient scan only because that catalog does not happen to list the name. The
 * calendar is arithmetic, so it is done arithmetically.
 */
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year) {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function isTimestamp(v) {
  if (!isString(v) || !RFC3339.test(v)) return false;
  const year = +v.slice(0, 4);
  const month = +v.slice(5, 7);
  const day = +v.slice(8, 10);
  const hour = +v.slice(11, 13);
  const minute = +v.slice(14, 16);
  const second = +v.slice(17, 19);
  if (month < 1 || month > 12) return false;
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1];
  if (day < 1 || day > maxDay) return false;
  // No leap second: `toISOString()` never emits :60, so a report carrying one
  // was not written by this tool.
  return hour <= 23 && minute <= 59 && second <= 59;
}

/**
 * An HTTPS URL whose port, if present, is a real one.
 *
 * The port range is the reason this is a function rather than one regex: a
 * five-digit shape check accepts `:99999`, which no host listens on.
 */
function isResolverUrl(v) {
  if (!isString(v)) return false;
  const match = HTTPS_RE.exec(v);
  if (!match) return false;
  if (match[1].length > 253) return false;
  if (match[2] === undefined) return true;
  const port = +match[2];
  // 0 is inside the URL port range -- `new URL('https://h:0/').port` is "0" --
  // so the bound is an upper one only. An earlier fix rejected it while fixing
  // `:99999`, which traded one wrong answer for another.
  return port >= 0 && port <= 65535;
}

function pickRecords(raw, errors, where) {
  if (!isPlainObject(raw)) { fail(errors, where, 'records is not an object'); return null; }
  const out = {};
  for (let i = 0; i < RECORD_KINDS.length; i++) {
    const kind = RECORD_KINDS[i];
    const list = raw[kind];
    if (!Array.isArray(list)) { fail(errors, where, 'records.' + kind + ' is not an array'); return null; }
    const entries = [];
    for (let j = 0; j < list.length; j++) {
      const e = list[j];
      const at = where + '.records.' + kind + '[' + j + ']';
      if (!isPlainObject(e)) { fail(errors, at, 'not an object'); return null; }
      if (!isString(e.queryName)) { fail(errors, at, 'queryName is not a string'); return null; }
      if (!isString(e.value)) { fail(errors, at, 'value is not a string'); return null; }
      const picked = { queryName: e.queryName, value: e.value };
      if (kind === 'tlsa') {
        if (!isBool(e.authenticated)) { fail(errors, at, 'authenticated is not a boolean'); return null; }
        picked.authenticated = e.authenticated;
      }
      if (kind === 'dkim') {
        if (!isString(e.selector)) { fail(errors, at, 'selector is not a string'); return null; }
        if (!stringOrNull(e.keyType)) { fail(errors, at, 'keyType is not a string or null'); return null; }
        if (!(e.keyBits === null || (isInt(e.keyBits) && e.keyBits > 0))) {
          fail(errors, at, 'keyBits is not a positive integer or null'); return null;
        }
        picked.selector = e.selector;
        picked.keyType = e.keyType;
        picked.keyBits = e.keyBits;
      }
      entries.push(picked);
    }
    out[kind] = normalizeRecords(kind, entries);
  }
  return out;
}

function pickScore(raw, errors, where) {
  if (!isPlainObject(raw)) { fail(errors, where, 'score is not an object'); return null; }
  if (!isNonNegative(raw.pts)) { fail(errors, where, 'score.pts is not a non-negative number'); return null; }
  if (!isNonNegative(raw.max)) { fail(errors, where, 'score.max is not a non-negative number'); return null; }
  if (!oneOf(raw.grade, GRADES)) { fail(errors, where, 'score.grade is not a grade'); return null; }
  if (!isBool(raw.parked)) { fail(errors, where, 'score.parked is not a boolean'); return null; }
  if (!Array.isArray(raw.unproven)) { fail(errors, where, 'score.unproven is not an array'); return null; }
  for (let i = 0; i < raw.unproven.length; i++) {
    if (PILLAR_KEYS.indexOf(raw.unproven[i]) === -1) {
      fail(errors, where, 'score.unproven has an unknown pillar'); return null;
    }
  }
  if (!Array.isArray(raw.pillars)) { fail(errors, where, 'score.pillars is not an array'); return null; }
  const pillars = [];
  for (let i = 0; i < raw.pillars.length; i++) {
    const p = raw.pillars[i];
    const at = where + '.score.pillars[' + i + ']';
    if (!isPlainObject(p)) { fail(errors, at, 'not an object'); return null; }
    if (!oneOf(p.key, PILLAR_KEYS)) { fail(errors, at, 'key is not a pillar'); return null; }
    if (!isNonNegative(p.pts)) { fail(errors, at, 'pts is not a non-negative number'); return null; }
    if (!isNonNegative(p.max)) { fail(errors, at, 'max is not a non-negative number'); return null; }
    pillars.push({ key: p.key, pts: p.pts, max: p.max });
  }
  return {
    pts: raw.pts, max: raw.max, grade: raw.grade, parked: raw.parked,
    unproven: raw.unproven.slice().sort(), pillars,
  };
}

function pickDiscovery(raw, errors, where) {
  if (!isPlainObject(raw)) { fail(errors, where, 'dmarcDiscovery is not an object'); return null; }
  // Section 1: these four are normalized ASCII domain names, the first three
  // nullable. They are identity fields like `domain`, not record values.
  if (!(raw.foundAt === null || isDomainName(raw.foundAt))) {
    fail(errors, where, 'dmarcDiscovery.foundAt is not a domain name or null'); return null;
  }
  if (!(raw.labelsUp === null || (isInt(raw.labelsUp) && raw.labelsUp >= 0))) {
    fail(errors, where, 'dmarcDiscovery.labelsUp is not a non-negative integer or null'); return null;
  }
  if (!oneOf(raw.terminated, TERMINATIONS)) {
    fail(errors, where, 'dmarcDiscovery.terminated is not a termination token'); return null;
  }
  if (!isDomainName(raw.organizationalDomain)) {
    fail(errors, where, 'dmarcDiscovery.organizationalDomain is not a domain name'); return null;
  }
  if (!(raw.policyDomain === null || isDomainName(raw.policyDomain))) {
    fail(errors, where, 'dmarcDiscovery.policyDomain is not a domain name or null'); return null;
  }
  if (!(raw.psdBoundary === null || isDomainName(raw.psdBoundary))) {
    fail(errors, where, 'dmarcDiscovery.psdBoundary is not a domain name or null'); return null;
  }
  return {
    foundAt: raw.foundAt, labelsUp: raw.labelsUp, terminated: raw.terminated,
    organizationalDomain: raw.organizationalDomain,
    policyDomain: raw.policyDomain, psdBoundary: raw.psdBoundary,
  };
}

function pickFindings(raw, errors, where) {
  if (!Array.isArray(raw)) { fail(errors, where, 'findings is not an array'); return null; }
  if (raw.length > LIMITS.findings) {
    fail(errors, where + '.findings', 'has more than ' + LIMITS.findings + ' entries'); return null;
  }
  const seen = emptyMap();
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    const f = raw[i];
    const at = where + '.findings[' + i + ']';
    if (!isPlainObject(f)) { fail(errors, at, 'not an object'); return null; }
    if (!isString(f.id) || !f.id) { fail(errors, at, 'id is missing'); return null; }
    // Duplicate ids would make the comparison's last-write-wins index depend on
    // array order, so a file carrying two of one id is rejected rather than
    // silently resolved one way.
    if (has(seen, f.id)) { fail(errors, at, 'duplicate finding id ' + f.id); return null; }
    seen[f.id] = true;
    if (!oneOf(f.protocol, PROTOCOL_TOKENS)) { fail(errors, at, 'protocol is not a protocol token'); return null; }
    if (!oneOf(f.severity, SEVERITIES)) { fail(errors, at, 'severity is not a severity'); return null; }
    if (!oneOf(f.confidence, CONFIDENCES)) { fail(errors, at, 'confidence is not a confidence'); return null; }
    if (!oneOf(f.category, CATEGORIES)) { fail(errors, at, 'category is not a category'); return null; }
    if (!oneOf(f.effort, EFFORTS)) { fail(errors, at, 'effort is not an effort'); return null; }
    if (!Array.isArray(f.args)) { fail(errors, at, 'args is not an array'); return null; }
    for (let a = 0; a < f.args.length; a++) {
      const v = f.args[a];
      if (!(isString(v) || isFiniteNum(v) || isBool(v))) { fail(errors, at, 'args has a non-scalar'); return null; }
    }
    if (!Array.isArray(f.dependsOn) || !f.dependsOn.every(isString)) {
      fail(errors, at, 'dependsOn is not an array of strings'); return null;
    }
    if (!Array.isArray(f.evidence)) { fail(errors, at, 'evidence is not an array'); return null; }
    if (f.evidence.length > LIMITS.evidence) {
      fail(errors, at + '.evidence', 'has more than ' + LIMITS.evidence + ' entries'); return null;
    }
    const evidence = [];
    for (let e = 0; e < f.evidence.length; e++) {
      const ev = f.evidence[e];
      const evAt = at + '.evidence[' + e + ']';
      if (!isPlainObject(ev)) { fail(errors, evAt, 'not an object'); return null; }
      if (!oneOf(ev.kind, EVIDENCE_KINDS)) { fail(errors, evAt, 'kind is not an evidence kind'); return null; }
      if (!isString(ev.queryName)) { fail(errors, evAt, 'queryName is not a string'); return null; }
      if (!isString(ev.value)) { fail(errors, evAt, 'value is not a string'); return null; }
      evidence.push({ kind: ev.kind, queryName: ev.queryName, value: ev.value });
    }
    out.push({
      id: f.id, protocol: f.protocol, severity: f.severity, confidence: f.confidence,
      category: f.category, effort: f.effort, args: f.args.slice(),
      dependsOn: f.dependsOn.slice(), evidence,
    });
  }
  return out;
}

function pickPlan(raw, errors, where) {
  if (!Array.isArray(raw)) { fail(errors, where, 'remediationPlan is not an array'); return null; }
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    const s = raw[i];
    const at = where + '.remediationPlan[' + i + ']';
    if (!isPlainObject(s)) { fail(errors, at, 'not an object'); return null; }
    // Section 1: "positive integer, unique and contiguous from 1".
    if (!isInt(s.step) || s.step !== i + 1) { fail(errors, at, 'step is not contiguous from 1'); return null; }
    if (!oneOf(s.rationale, RATIONALES)) { fail(errors, at, 'rationale is not a rationale'); return null; }
    if (!Array.isArray(s.findings) || !s.findings.every(isString)) {
      fail(errors, at, 'findings is not an array of strings'); return null;
    }
    if (!Array.isArray(s.unblocks) || !s.unblocks.every(isString)) {
      fail(errors, at, 'unblocks is not an array of strings'); return null;
    }
    out.push({ step: s.step, rationale: s.rationale, findings: s.findings.slice(), unblocks: s.unblocks.slice() });
  }
  return out;
}

function pickDomain(raw, errors, index) {
  const where = 'domains[' + index + ']';
  if (!isPlainObject(raw)) { fail(errors, where, 'not an object'); return null; }
  if (!isDomainName(raw.domain)) { fail(errors, where, 'domain is not a normalized ASCII domain name'); return null; }
  if (!oneOf(raw.state, DOMAIN_STATES)) { fail(errors, where, 'state is not a domain state'); return null; }
  if (raw.state !== 'audited') return { domain: raw.domain, state: raw.state };

  if (!isDomainName(raw.organizationalDomain)) {
    fail(errors, where, 'organizationalDomain is not a normalized ASCII domain name'); return null;
  }
  if (!isPlainObject(raw.observability)) { fail(errors, where, 'observability is not an object'); return null; }
  const observability = {};
  for (let i = 0; i < PROTOCOL_TOKENS.length; i++) {
    const p = PROTOCOL_TOKENS[i];
    if (!oneOf(raw.observability[p], OBSERVABILITY_STATES)) {
      fail(errors, where, 'observability.' + p + ' is missing or not a state'); return null;
    }
    observability[p] = raw.observability[p];
  }

  const score = pickScore(raw.score, errors, where);
  if (!score) return null;
  const dmarcDiscovery = pickDiscovery(raw.dmarcDiscovery, errors, where);
  if (!dmarcDiscovery) return null;
  const records = pickRecords(raw.records, errors, where);
  if (!records) return null;
  const findings = pickFindings(raw.findings, errors, where);
  if (!findings) return null;
  const remediationPlan = pickPlan(raw.remediationPlan, errors, where);
  if (!remediationPlan) return null;

  return {
    domain: raw.domain,
    organizationalDomain: raw.organizationalDomain,
    state: 'audited',
    observability, score, dmarcDiscovery, records, findings, remediationPlan,
  };
}

/**
 * Parse and validate an imported report. `{ ok: true, report }` or
 * `{ ok: false, errors }` -- never a partial result, so a rejected file leaves
 * no half-built state for a caller to render.
 */
export function parseReport(text, capabilities) {
  const errors = [];
  // The DKIM selector grammar belongs to `src/core/dkim/`, which `src/ui/` may
  // not import, so it arrives as a capability through the composition root.
  // It is REQUIRED, not optional: treating an absent predicate as permission
  // would make a forgotten wiring call silently skip the check, which is
  // exactly how the composition defect in `create-audit.js` stayed invisible
  // while a suite that imported the predicate directly stayed green.
  const validSelector = requireSelectorPredicate(capabilities && capabilities.validSelector);
  if (!isString(text)) return { ok: false, errors: reject('invalid-json', { detail: 'not text' }) };
  if (byteLength(text) > LIMITS.bytes) {
    return { ok: false, errors: reject('too-large') };
  }

  let raw;
  try {
    // Section 4: the reviver rejects the three keys rather than sanitizing
    // them. A report containing them was not written by this tool, and there
    // is no benign reading of one that was.
    raw = JSON.parse(text, function (key, value) {
      if (BANNED_KEYS.indexOf(key) !== -1) throw new SyntaxError('unsafe key: ' + key);
      return value;
    });
  } catch (e) {
    // The engine's own parse text is a DIAGNOSTIC, never the message shown:
    // it varies by JavaScript runtime and is not text this project controls.
    return { ok: false, errors: reject('invalid-json', { detail: e && e.message ? e.message : '' }) };
  }

  if (!isPlainObject(raw)) return { ok: false, errors: reject('not-report') };
  if (raw.schema !== SCHEMA_ID) return { ok: false, errors: reject('not-report') };
  if (!isInt(raw.schemaVersion) || raw.schemaVersion < 1) {
    return { ok: false, errors: reject('malformed', { path: 'schemaVersion', detail: 'is not a positive integer' }) };
  }
  if (raw.schemaVersion > SCHEMA_VERSION) {
    return { ok: false, errors: reject('newer-version') };
  }
  if (depthOf(raw) > LIMITS.depth) return { ok: false, errors: reject('malformed', { path: '', detail: 'is nested more than ' + LIMITS.depth + ' deep' }) };

  if (!isTimestamp(raw.generatedAt)) {
    return { ok: false, errors: reject('malformed', { path: 'generatedAt', detail: 'is not a UTC RFC 3339 timestamp' }) };
  }
  if (!isPlainObject(raw.generator)) return { ok: false, errors: reject('malformed', { path: 'generator', detail: 'is not an object' }) };
  if (!isString(raw.generator.version) || !SEMVER.test(raw.generator.version)) {
    return { ok: false, errors: reject('malformed', { path: 'generator.version', detail: 'is not a release string' }) };
  }
  if (!isInt(raw.generator.analysisVersion) || raw.generator.analysisVersion < 1) {
    return { ok: false, errors: reject('malformed', { path: 'generator.analysisVersion', detail: 'is not a positive integer' }) };
  }
  if (!isResolverUrl(raw.resolver)) {
    return { ok: false, errors: reject('malformed', { path: 'resolver', detail: 'is not an HTTPS URL' }) };
  }
  if (!isPlainObject(raw.options)) return { ok: false, errors: reject('malformed', { path: 'options', detail: 'is not an object' }) };
  for (let i = 0; i < OPTION_KEYS.length; i++) {
    if (!isBool(raw.options[OPTION_KEYS[i]])) {
      return { ok: false, errors: reject('malformed', { path: 'options.' + OPTION_KEYS[i], detail: 'is missing or not a boolean' }) };
    }
  }
  if (!Array.isArray(raw.options.selectors) || !raw.options.selectors.every(isString)) {
    return { ok: false, errors: reject('malformed', { path: 'options.selectors', detail: 'is not an array of strings' }) };
  }
  if (!raw.options.selectors.every(validSelector)) {
    return { ok: false, errors: reject('malformed', { path: 'options.selectors', detail: 'has a selector this build would not query' }) };
  }
  if (!Array.isArray(raw.domains)) return { ok: false, errors: reject('malformed', { path: 'domains', detail: 'is not an array' }) };
  if (raw.domains.length > LIMITS.domains) {
    return { ok: false, errors: reject('too-many-domains') };
  }

  const domains = [];
  const seenDomains = emptyMap();
  for (let i = 0; i < raw.domains.length; i++) {
    const d = pickDomain(raw.domains[i], errors, i);
    if (!d) return { ok: false, errors };
    // Domain identity is the domain name (section 5). Two entries for one name
    // would make the comparison depend on which one the index kept.
    if (has(seenDomains, d.domain)) {
      return { ok: false, errors: reject('malformed', { path: 'domains[' + i + ']', detail: 'is a duplicate domain' }) };
    }
    seenDomains[d.domain] = true;
    domains.push(d);
  }

  return {
    ok: true,
    report: {
      schema: SCHEMA_ID,
      schemaVersion: raw.schemaVersion,
      generatedAt: raw.generatedAt,
      generator: {
        version: raw.generator.version,
        analysisVersion: raw.generator.analysisVersion,
      },
      resolver: raw.resolver,
      options: OPTION_KEYS.reduce(function (o, k) {
        o[k] = raw.options[k];
        return o;
      }, { selectors: uniqueSorted(raw.options.selectors) }),
      domains,
    },
  };
}

/* -- Comparison ------------------------------------------------------- */

function optionDifferences(a, b) {
  const diffs = [];
  OPTION_KEYS.forEach(function (k) { if (a[k] !== b[k]) diffs.push(k); });
  if (a.selectors.join(',') !== b.selectors.join(',')) diffs.push('selectors');
  return diffs;
}

function indexBy(list, key) {
  const map = emptyMap();
  list.forEach(function (item) { map[item[key]] = item; });
  return map;
}

/**
 * Which protocols cannot be compared for this domain, and why.
 *
 * Two independent sources, both per section 5: a protocol not `observed` on
 * either side, and a mismatched option mapped through `OPTION_PROTOCOLS`.
 */
function incomparableProtocolsFor(baseDomain, currDomain, optionDiffs) {
  const reasons = emptyMap();
  const order = [];
  const add = (protocol, reason, side) => {
    const key = protocol + '|' + reason + '|' + side;
    if (has(reasons, key)) return;
    reasons[key] = true;
    order.push({ protocol, reason, side });
  };

  PROTOCOL_TOKENS.forEach(function (p) {
    const b = baseDomain.observability[p];
    const c = currDomain.observability[p];
    if (b !== 'observed') add(p, b, 'baseline');
    if (c !== 'observed') add(p, c, 'current');
  });
  optionDiffs.forEach(function (opt) {
    (OPTION_PROTOCOLS[opt] || []).forEach(function (p) { add(p, 'options', 'both'); });
  });

  return order;
}

/**
 * Section 5 step 4: compare the highest-severity changed finding, descending.
 *
 * A severity increase counts as new at the higher severity AND resolved at the
 * lower; a decrease is the reverse. That is what lets "resolved a critical,
 * gained a low" read as `improved` however the counts fall.
 */
function severityVerdict(movement) {
  for (let i = 0; i < SEVERITIES.length; i++) {
    const sev = SEVERITIES[i];
    const resolved = has(movement.resolvedBySeverity, sev) ? movement.resolvedBySeverity[sev] : 0;
    const added = has(movement.newBySeverity, sev) ? movement.newBySeverity[sev] : 0;
    if (resolved > added) return 'improved';
    if (added > resolved) return 'regressed';
  }
  return null;
}

function compareDomain(baseDomain, currDomain, context) {
  const optionDiffs = context.optionDifferences;
  const incomparableProtocols = incomparableProtocolsFor(baseDomain, currDomain, optionDiffs);
  const blocked = emptyMap();
  incomparableProtocols.forEach(function (e) { blocked[e.protocol] = true; });

  const comparableProtocols = PROTOCOL_TOKENS.filter(function (p) { return !has(blocked, p); });

  const baseFindings = indexBy(baseDomain.findings, 'id');
  const currFindings = indexBy(currDomain.findings, 'id');
  const ids = uniqueSorted(baseDomain.findings.map(f => f.id).concat(currDomain.findings.map(f => f.id)));

  const findings = { new: [], resolved: [], unchanged: [], unknown: [], severityChanged: [] };
  let blockedFindingMovement = false;
  const movement = { newBySeverity: emptyMap(), resolvedBySeverity: emptyMap() };
  const bump = (bucket, sev) => { bucket[sev] = (has(bucket, sev) ? bucket[sev] : 0) + 1; };

  ids.forEach(function (id) {
    const b = has(baseFindings, id) ? baseFindings[id] : null;
    const c = has(currFindings, id) ? currFindings[id] : null;
    const protocol = (c || b).protocol;
    // Section 5: a finding whose protocol is incomparable is `unknown`, never
    // `new` or `resolved`. Saying "resolved" would tell someone a problem is
    // fixed when the tool did not look.
    if (has(blocked, protocol)) {
      findings.unknown.push(id);
      // Movement INSIDE a blocked protocol still counts for the domain's
      // status: section 5 makes a domain incomparable when "every observed
      // change belongs to an incomparable protocol". A finding that is simply
      // present and unchanged on both sides is not movement.
      if (!b || !c || b.severity !== c.severity) blockedFindingMovement = true;
      return;
    }
    if (b && !c) { findings.resolved.push(id); bump(movement.resolvedBySeverity, b.severity); return; }
    if (!b && c) { findings.new.push(id); bump(movement.newBySeverity, c.severity); return; }
    if (b.severity !== c.severity) {
      findings.severityChanged.push({ id, from: b.severity, to: c.severity });
      // The finding now exists at the current severity and no longer exists at
      // the baseline's, which is section 5's rule for BOTH directions without a
      // branch: an increase is new at the higher and resolved at the lower, and
      // a decrease is exactly that read the other way round. An earlier version
      // branched on which was higher and had the decrease backwards, reporting
      // a critical dropping to low as a regression.
      bump(movement.newBySeverity, c.severity);
      bump(movement.resolvedBySeverity, b.severity);
      return;
    }
    findings.unchanged.push(id);
  });

  const recordChanges = [];
  let blockedRecordMovement = false;
  RECORD_KINDS.forEach(function (kind) {
    const from = JSON.stringify(baseDomain.records[kind]);
    const to = JSON.stringify(currDomain.records[kind]);
    if (from === to) return;
    // Section 5: a record path belonging to an incomparable protocol is OMITTED
    // from the reported changes -- but it is still observed movement, and
    // dropping it entirely would leave a domain whose only change is a blocked
    // one looking `unchanged`. It is reported as incomparable instead.
    if (has(blocked, RECORD_PROTOCOL[kind])) { blockedRecordMovement = true; return; }
    recordChanges.push({ path: 'records.' + kind, from, to });
  });

  const incomparableReasons = [];
  if (!comparableProtocols.length) incomparableReasons.push('no-comparable-protocol');
  if (optionDiffs.length) incomparableReasons.push('options');
  if (!context.analysisVersionsMatch) incomparableReasons.push('analysis-version');

  const scoreUnproven = baseDomain.score.unproven.length > 0 || currDomain.score.unproven.length > 0;
  const scoreComparable = context.analysisVersionsMatch && !scoreUnproven;
  const scoreDelta = scoreComparable ? currDomain.score.pts - baseDomain.score.pts : null;
  // Section 2 gates score AND grade on the analysis version: a grade is a
  // threshold applied to a score, so a grade move across rubric versions says
  // no more than the score move it came from.
  const gradeChange = scoreComparable && baseDomain.score.grade !== currDomain.score.grade
    ? { from: baseDomain.score.grade, to: currDomain.score.grade } : null;

  const moved = findings.new.length || findings.resolved.length
    || findings.severityChanged.length || recordChanges.length;
  const blockedMovement = blockedRecordMovement || blockedFindingMovement;
  const scoreMoved = !!scoreDelta || !!gradeChange;

  let status;
  if (!comparableProtocols.length) {
    status = 'incomparable';
  } else if (!moved && !scoreMoved && blockedMovement) {
    // EVERYTHING that moved on this domain moved inside a protocol nobody could
    // compare. `scoreMoved` belongs in this condition: a blocked TLSA change
    // alongside a real, comparable score delta is not a wholly incomparable
    // domain, and calling it one would discard a verdict the reports support.
    incomparableReasons.push('only-incomparable-movement');
    status = 'incomparable';
  } else if (!context.findingSemanticsMatch) {
    // A different generator version cannot support a causal claim, and that
    // includes one made from the score: two releases can move a score without
    // either configuration changing.
    status = moved || scoreMoved ? 'changed' : 'unchanged';
  } else {
    const verdict = moved ? severityVerdict(movement) : null;
    if (verdict) status = verdict;
    else if (scoreComparable && scoreDelta > 0) status = 'improved';
    else if (scoreComparable && scoreDelta < 0) status = 'regressed';
    else status = moved || scoreMoved ? 'changed' : 'unchanged';
  }

  return {
    domain: currDomain.domain,
    status,
    scoreDelta,
    scoreComparable,
    gradeChange,
    incomparableReasons,
    incomparableProtocols,
    findings,
    recordChanges,
  };
}

function blankDomain(domain, status) {
  return {
    domain, status, scoreDelta: null, scoreComparable: false, gradeChange: null,
    incomparableReasons: [], incomparableProtocols: [],
    findings: { new: [], resolved: [], unchanged: [], unknown: [], severityChanged: [] },
    recordChanges: [],
  };
}

/**
 * Compare two validated reports. Pure, in memory, and nothing is persisted:
 * the caller holds both inputs and the result, and a reload discards all three.
 */
export function compareReports(baseline, current) {
  const optionDiffs = optionDifferences(baseline.options, current.options);
  const context = {
    schemaVersionsMatch: baseline.schemaVersion === current.schemaVersion,
    analysisVersionsMatch: baseline.generator.analysisVersion === current.generator.analysisVersion,
    // Section 5: only an equal generator version establishes that a detector
    // behaved the same. Stable ids give identity, not equivalence -- 0.4.0
    // added twenty-one advisory findings with zero score movement.
    findingSemanticsMatch: baseline.generator.version === current.generator.version,
    optionsMatch: optionDiffs.length === 0,
    optionDifferences: optionDiffs,
  };

  const baseByDomain = indexBy(baseline.domains, 'domain');
  const currByDomain = indexBy(current.domains, 'domain');
  const domainNames = uniqueSorted(
    baseline.domains.map(d => d.domain).concat(current.domains.map(d => d.domain))
  );

  const domains = domainNames.map(function (name) {
    const b = has(baseByDomain, name) ? baseByDomain[name] : null;
    const c = has(currByDomain, name) ? currByDomain[name] : null;
    if (!b) return blankDomain(name, 'added');
    if (!c) return blankDomain(name, 'removed');
    if (b.state !== 'audited' || c.state !== 'audited') {
      const d = blankDomain(name, b.state === c.state ? 'unchanged' : 'incomparable');
      if (b.state !== c.state) d.incomparableReasons = ['state'];
      return d;
    }
    return compareDomain(b, c, context);
  });

  const summary = DOMAIN_STATUSES.reduce(function (acc, s) { acc[s] = 0; return acc; }, {});
  domains.forEach(function (d) { summary[d.status] += 1; });

  return {
    meta: {
      schemaVersionsMatch: context.schemaVersionsMatch,
      analysisVersionsMatch: context.analysisVersionsMatch,
      findingSemanticsMatch: context.findingSemanticsMatch,
      optionsMatch: context.optionsMatch,
      optionDifferences: optionDiffs,
      baselineGeneratedAt: baseline.generatedAt,
      currentGeneratedAt: current.generatedAt,
      baselineAppVersion: baseline.generator.version,
      currentAppVersion: current.generator.version,
    },
    domains,
    summary,
  };
}
