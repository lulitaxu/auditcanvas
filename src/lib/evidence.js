// Evidence schema, redaction, and check-result types for AuditCanvas.
//
// Spec anchors (SPEC.md v2.2):
//  - "The scanner decides what exists; the model decides what it means."
//    Findings are created only by deterministic checks, each with a stable
//    finding ID and evidence IDs.
//  - Four outcomes, never two: Pass / Finding / Inconclusive / Not assessed.
//  - Evidence is minimal and redacted by construction: snippets, not
//    bodies; redaction before storage AND before any model call;
//    Set-Cookie is stored as attribute flags, never values.

export const SCANNER_VERSION = '0.1.0';
export const RULES_VERSION = '1.1.0';
export const EVIDENCE_SCHEMA_VERSION = 1;

export const OUTCOMES = Object.freeze(['pass', 'finding', 'inconclusive', 'not-assessed']);
export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high']);

// ---------------------------------------------------------------------------
// Redaction (by construction: anything stored passes through here first)
// ---------------------------------------------------------------------------

const SENSITIVE_PARAM = /^(.*?(token|key|secret|auth|session|passwd|password|sig|signature|api[-_]?key).*)$/i;
const SECRET_PATTERNS = [
  [/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, '[redacted-jwt]'],
  [/((?:api[-_]?key|access[-_]?token|auth[-_]?token|refresh[-_]?token|token|secret|password|passwd)\s*[:=]\s*)[^\s"',;}&]+/gi, '$1[redacted]'],
];

export function redactString(value, maxLen = 512) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const [re, rep] of SECRET_PATTERNS) out = out.replace(re, rep);
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…[truncated]';
  return out;
}

export function redactUrl(raw) {
  if (typeof raw !== 'string') return raw;
  try {
    const u = new URL(raw);
    for (const key of [...u.searchParams.keys()]) {
      if (SENSITIVE_PARAM.test(key)) u.searchParams.set(key, 'redacted');
    }
    u.hash = '';
    return redactString(u.toString(), 1024);
  } catch {
    return redactString(raw, 1024);
  }
}

// Only these response headers ever have their VALUES stored, and even those
// pass through redactString. Every other header is stored by name only.
// Authorization / Cookie / Set-Cookie values are never stored: Set-Cookie
// becomes parsed attribute flags (see parseSetCookieFlags).
const STORABLE_HEADER_VALUES = new Set([
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-frame-options',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'location',
  'content-type',
  'server',
  'x-powered-by',
  'www-authenticate',
]);

export function sanitizeHeaders(headersObj) {
  const stored = {};
  const names = [];
  for (const [rawName, rawValue] of Object.entries(headersObj || {})) {
    const name = rawName.toLowerCase();
    names.push(name);
    if (name === 'set-cookie') continue; // flags only, handled separately
    if (STORABLE_HEADER_VALUES.has(name)) {
      const v = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue);
      stored[name] = redactString(v);
    }
  }
  return { stored, names: [...new Set(names)].sort() };
}

// Parse a raw Set-Cookie header into attribute flags. The cookie VALUE is
// dropped here and never reaches storage.
export function parseSetCookieFlags(raw) {
  if (typeof raw !== 'string' || !raw.includes('=')) return null;
  const parts = raw.split(';').map((s) => s.trim());
  const name = parts[0].slice(0, parts[0].indexOf('=')).trim();
  const flags = {
    name: redactString(name, 128),
    secure: false,
    httpOnly: false,
    sameSite: null,
    path: null,
    domain: null,
    hasExpires: false,
    hasMaxAge: false,
  };
  for (const attr of parts.slice(1)) {
    const eq = attr.indexOf('=');
    const k = (eq === -1 ? attr : attr.slice(0, eq)).trim().toLowerCase();
    const v = eq === -1 ? '' : attr.slice(eq + 1).trim();
    if (k === 'secure') flags.secure = true;
    else if (k === 'httponly') flags.httpOnly = true;
    else if (k === 'samesite') flags.sameSite = v.toLowerCase();
    else if (k === 'path') flags.path = redactString(v, 128);
    else if (k === 'domain') flags.domain = redactString(v, 128);
    else if (k === 'expires') flags.hasExpires = true;
    else if (k === 'max-age') flags.hasMaxAge = true;
  }
  return flags;
}

// ---------------------------------------------------------------------------
// Evidence store: sequential, deterministic IDs per scan (ev-0001, ev-0002…)
// assigned in fixed group/check order, so a scan's IDs are stable and every
// finding ID resolves to evidence IDs inside the same report bundle.
// ---------------------------------------------------------------------------

export function createEvidenceStore() {
  const items = [];
  let counter = 0;
  return {
    items,
    add(kind, target, data) {
      counter += 1;
      const item = {
        id: `ev-${String(counter).padStart(4, '0')}`,
        kind,
        target: redactUrl(String(target)),
        at: new Date().toISOString(),
        data,
      };
      const errs = validateEvidenceItem(item);
      if (errs.length) throw new Error(`Invalid evidence item: ${errs.join('; ')}`);
      items.push(item);
      return item.id;
    },
  };
}

export function validateEvidenceItem(item) {
  const errs = [];
  if (!item || typeof item !== 'object') return ['not an object'];
  if (!/^ev-\d{4,}$/.test(item.id || '')) errs.push('id must look like ev-0001');
  if (typeof item.kind !== 'string' || !item.kind) errs.push('kind is required');
  if (typeof item.target !== 'string' || !item.target) errs.push('target is required');
  if (item.data === undefined) errs.push('data is required');
  const serialized = JSON.stringify(item.data) || '';
  if (/authorization\s*[:=]/i.test(serialized)) errs.push('data appears to contain an Authorization value');
  return errs;
}

// ---------------------------------------------------------------------------
// Check results
// ---------------------------------------------------------------------------

// A check result is the only thing allowed to create a finding.
// outcome: 'pass' | 'finding' | 'inconclusive' | 'not-assessed'
// severity is required iff outcome === 'finding'.
// inference: true when the conclusion rests on inference (e.g. a library
// version guessed from a filename) rather than direct observation; it
// lowers Confidence, never severity.
export function makeCheck({ group, check, outcome, severity = null, title, detail, evidenceIds = [], inference = false }) {
  const result = {
    checkId: `${group}.${check}`,
    findingId: outcome === 'finding' ? `f-${group}-${check}` : null,
    group,
    outcome,
    severity: outcome === 'finding' ? severity : null,
    title,
    detail,
    evidenceIds,
    inference: Boolean(inference),
  };
  const errs = validateCheckResult(result);
  if (errs.length) throw new Error(`Invalid check result (${result.checkId}): ${errs.join('; ')}`);
  return result;
}

// The real per-group check catalog (security fix H1 tightening,
// 2026-10-29): a check result may only name a check the scanner can
// actually emit. Before this, any "<group>.<check>" string passed, so
// a client-carried bundle could invent checks wholesale. The eight
// group IDs are frozen by SPEC.md and mirror scanner/index.js; the
// check names mirror the makeCheck call sites in each scanner module
// (plus 'group-error', the degraded result scanner/index.js emits
// when a group fails). The exposure entry (SPEC addendum 2026-10-29)
// mirrors scanner/exposure.js the same way: its exact list is the
// always/conditionally emitted checks, and its one pattern admits the
// seven per-class js-secret checks. Two groups build names dynamically:
//  - exposed derives names from its fixed path list (/.git/HEAD ->
//    git-head, /.env -> env, /wp-admin/ -> wp-admin, ...);
//  - stack appends the detected library and CVE id
//    (<lib>-current, <lib>-cve-YYYY-NNNN) for the libraries in its
//    detector table.
export const CHECK_CATALOG = Object.freeze({
  headers: Object.freeze({
    exact: Object.freeze([
      'hsts', 'hsts-missing', 'hsts-weak', 'hsts-no-subdomains',
      'csp', 'csp-missing', 'csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard',
      'csp-data-uri', 'csp-no-object-src', 'csp-no-base-uri',
      'xcto', 'xcto-missing', 'referrer-policy', 'referrer-policy-missing',
      'permissions-policy', 'permissions-policy-missing',
      'framing', 'framing-invalid', 'framing-missing', 'group-error',
    ]),
    patterns: Object.freeze([]),
  }),
  tls: Object.freeze({
    exact: Object.freeze([
      'not-applicable', 'protocol', 'hostname', 'hostname-mismatch',
      'chain', 'chain-invalid', 'expiry', 'cert-expired',
      'cert-expiring-14', 'cert-expiring-30', 'group-error',
    ]),
    patterns: Object.freeze([]),
  }),
  cookies: Object.freeze({
    exact: Object.freeze([
      'none-set', 'secure', 'secure-missing', 'httponly', 'httponly-missing',
      'samesite', 'samesite-missing', 'samesite-none-insecure', 'group-error',
    ]),
    patterns: Object.freeze([]),
  }),
  cors: Object.freeze({
    exact: Object.freeze([
      'probe', 'no-cors', 'credentialed-exposure', 'wildcard',
      'reflection-no-creds', 'restricted', 'group-error',
    ]),
    patterns: Object.freeze([]),
  }),
  exposed: Object.freeze({
    exact: Object.freeze(['git-head', 'env', 'wp-admin', 'server-status', 'ds-store', 'phpinfo-php', 'group-error']),
    patterns: Object.freeze([]),
  }),
  exposure: Object.freeze({
    exact: Object.freeze([
      'env-local', 'env-production', 'env-development', 'env-bak', 'env-old',
      'git-config',
      'js-secrets', 'supabase-config', 'client-keys', 'firebase-rtdb',
      'verbose-errors', 'admin-route', 'debug-route', 'group-error',
    ]),
    patterns: Object.freeze([
      /^js-secret-(aws-access-key|aws-secret|stripe-live|github|supabase-service|private-key|slack)$/,
    ]),
  }),
  stack: Object.freeze({
    exact: Object.freeze(['none-detected', 'fetch', 'group-error']),
    patterns: Object.freeze([
      /^(jquery|bootstrap|lodash|angular|moment)-current$/,
      /^(jquery|bootstrap|lodash|angular|moment)-cve-\d{4}-\d{4,}$/,
    ]),
  }),
  email: Object.freeze({
    exact: Object.freeze([
      'spf', 'spf-missing', 'spf-multiple', 'spf-no-all', 'spf-plus-all', 'spf-neutral',
      'dmarc', 'dmarc-missing', 'dmarc-no-policy', 'dmarc-p-none', 'group-error',
    ]),
    patterns: Object.freeze([]),
  }),
  redirects: Object.freeze({
    exact: Object.freeze(['mixed-content', 'https-upgrade', 'https-upgrade-missing', 'open-redirect', 'group-error']),
    patterns: Object.freeze([]),
  }),
});

export function isCatalogCheck(group, check) {
  const entry = CHECK_CATALOG[group];
  if (!entry || typeof check !== 'string') return false;
  if (entry.exact.includes(check)) return true;
  return entry.patterns.some((re) => re.test(check));
}

export function validateCheckResult(r) {
  const errs = [];
  if (!r || typeof r !== 'object') return ['not an object'];
  if (typeof r.checkId !== 'string' || !/^[a-z0-9-]+\.[a-z0-9-]+$/i.test(r.checkId)) {
    errs.push('checkId must be "<group>.<check>"');
  } else {
    const dot = r.checkId.indexOf('.');
    const group = r.checkId.slice(0, dot);
    const check = r.checkId.slice(dot + 1);
    if (!CHECK_CATALOG[group]) {
      errs.push(`checkId names an unknown check group: ${group}`);
    } else if (!isCatalogCheck(group, check)) {
      errs.push(`checkId ${r.checkId} is not a check the ${group} group can emit`);
    }
    if (typeof r.group === 'string' && r.group !== group) errs.push('group does not match the checkId group');
    // findingId is derived, never free-form: makeCheck mints exactly
    // `f-<group>-<check>` for a finding and null for every other
    // outcome. Enforcing the derivation here also keeps findingIds
    // safe to use as fix-pack file names (no path separators can
    // survive the catalog check above plus this equality).
    if (r.outcome === 'finding') {
      if (r.findingId !== `f-${group}-${check}`) errs.push(`findingId must be f-${group}-${check}`);
    } else if (r.findingId !== null && r.findingId !== undefined) {
      errs.push('only a finding may carry a findingId');
    }
  }
  if (!OUTCOMES.includes(r.outcome)) errs.push(`outcome must be one of ${OUTCOMES.join('/')}`);
  if (r.outcome === 'finding') {
    if (!SEVERITIES.includes(r.severity)) errs.push('finding requires a severity');
  } else if (r.severity !== null && r.severity !== undefined) {
    errs.push('only a finding may carry a severity');
  }
  if (typeof r.title !== 'string' || !r.title) errs.push('title is required');
  if (typeof r.detail !== 'string' || !r.detail) errs.push('detail is required');
  if (!Array.isArray(r.evidenceIds)) errs.push('evidenceIds must be an array');
  return errs;
}

// Report validator helper (spec stage 4): every evidence ID a model or a
// check references must resolve inside the same bundle.
export function unresolvedEvidenceIds(results, evidenceItems) {
  const known = new Set(evidenceItems.map((e) => e.id));
  const missing = [];
  for (const r of results) {
    for (const id of r.evidenceIds || []) if (!known.has(id)) missing.push(`${r.checkId} -> ${id}`);
  }
  return missing;
}
