// Step-bundle signing (security fix H1, 2026-10-29 sweep).
//
// The stateless scan flow lets the client carry per-group step bundles
// from /api/scan/step to /api/scan/finalize. Before this fix, assembly
// schema-validated the bundles but could not tell a bundle the server
// actually produced from one a client invented — anyone could mint an
// official-looking report (arbitrary findings, or a clean pass)
// without any scan occurring. Now the /step route signs every bundle
// it returns, and assembly verifies the signature BEFORE any of the
// bundle's contents are trusted:
//
//   sig = HMAC-SHA256(secret, canonical({ v, scanId, target, group,
//                                        scanPolicy, results,
//                                        evidence, requests }))
//
// The scanId and the canonical target are supplied by the VERIFIER
// (from the finalize request), never read out of the bundle, so a
// bundle signed for one scan cannot be transplanted into another, and
// any post-signing edit to results/evidence invalidates the signature.
//
// The secret comes from the BUNDLE_SIGNING_SECRET env var. When it is
// unset (local development), an ephemeral per-process secret is
// generated and a warning is logged: bundles then only verify inside
// the same process, so in-flight scans break across serverless
// instances — production must set the env var. Rotating the secret
// invalidates in-flight scans; that is acceptable (a scan is minutes
// long and can simply be restarted).
import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const SIGNATURE_VERSION = 1;

let ephemeralSecret = null;
let warnedEphemeral = false;

export function bundleSigningSecret() {
  const fromEnv = process.env.BUNDLE_SIGNING_SECRET;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv;
  if (!ephemeralSecret) {
    ephemeralSecret = randomBytes(32).toString('hex');
    if (!warnedEphemeral) {
      warnedEphemeral = true;
      console.warn(
        '[auditcanvas] BUNDLE_SIGNING_SECRET is not set; step bundles are signed with an ephemeral ' +
          'per-process secret. Signatures will not survive a process restart — set BUNDLE_SIGNING_SECRET in production.'
      );
    }
  }
  return ephemeralSecret;
}

export function bundleSigningIsEphemeral() {
  return !(typeof process.env.BUNDLE_SIGNING_SECRET === 'string' && process.env.BUNDLE_SIGNING_SECRET.length > 0);
}

// Deterministic JSON: object keys sorted recursively, undefined object
// values dropped (JSON semantics), array order preserved. Signing and
// verification both pass through here, so incidental key order on the
// wire cannot invalidate a genuine bundle.
export function canonicalStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((v) => canonicalStringify(v === undefined ? null : v)).join(',')}]`;
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(value[k])}`).join(',')}}`;
}

// The exact field set a signature covers. Extracted from a bundle the
// same way at signing and at verification time, with the scan identity
// (scanId + canonical target) bound in by the caller — the bundle
// itself does not carry them.
export function bundleSigningPayload({ scanId, target, bundle }) {
  return {
    v: SIGNATURE_VERSION,
    scanId: typeof scanId === 'string' ? scanId : '',
    target: typeof target === 'string' ? target : '',
    group: bundle && typeof bundle.group === 'string' ? bundle.group : '',
    scanPolicy: bundle && typeof bundle.scanPolicy === 'string' ? bundle.scanPolicy : null,
    results: bundle && Array.isArray(bundle.results) ? bundle.results : [],
    evidence: bundle && Array.isArray(bundle.evidence) ? bundle.evidence : [],
    requests: bundle && Array.isArray(bundle.requests) ? bundle.requests : [],
  };
}

export function signStepBundle({ scanId, target, bundle }) {
  const payload = bundleSigningPayload({ scanId, target, bundle });
  return createHmac('sha256', bundleSigningSecret()).update(canonicalStringify(payload)).digest('base64url');
}

// Constant-time verification. Returns false for a missing, malformed,
// tampered, or foreign (other scan / other target) signature.
export function verifyStepBundle(bundle, { scanId, target }) {
  if (!bundle || typeof bundle.sig !== 'string' || !bundle.sig) return false;
  const expected = signStepBundle({ scanId, target, bundle });
  const a = Buffer.from(bundle.sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Digest of a verified bundle SET (scan identity + each group's
// signature), used as the finalized-report cache key (security fix
// H2). The signatures already commit to the full bundle contents, so
// the digest commits to the exact inputs of the report pipeline:
// identical inputs → identical key → the cached report, with zero new
// model calls.
export function bundleSetDigest({ scanId, target, bundles }) {
  const pairs = (Array.isArray(bundles) ? bundles : [])
    .map((b) => [typeof b.group === 'string' ? b.group : '', typeof b.sig === 'string' ? b.sig : ''])
    .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  return createHash('sha256')
    .update(canonicalStringify({ scanId: scanId || '', target: target || '', pairs }))
    .digest('hex');
}
