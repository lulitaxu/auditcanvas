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
export const RULES_VERSION = '1.0.0';
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

export function validateCheckResult(r) {
  const errs = [];
  if (!r || typeof r !== 'object') return ['not an object'];
  if (typeof r.checkId !== 'string' || !/^[a-z0-9-]+\.[a-z0-9-]+$/i.test(r.checkId)) errs.push('checkId must be "<group>.<check>"');
  if (!OUTCOMES.includes(r.outcome)) errs.push(`outcome must be one of ${OUTCOMES.join('/')}`);
  if (r.outcome === 'finding') {
    if (!SEVERITIES.includes(r.severity)) errs.push('finding requires a severity');
    if (!r.findingId) errs.push('finding requires a findingId');
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
