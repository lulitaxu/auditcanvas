// Scan sessions for the stepwise scan API (SPEC: Architecture).
//
// STATELESS BY DESIGN (production fix, 2026-10-28): on serverless
// (Vercel), consecutive requests of one scan routinely land in
// different function instances, so no in-progress state may live in
// process memory — the original in-memory-only store made every step
// after /start fail with "Unknown scan ID" in production. The flow is
// now: /start issues a scan descriptor (policy decided server-side),
// each /step runs ONE check group in a fresh context and returns that
// group's results + evidence, and /finalize assembles the report
// server-side from the collected bundles. Assembly NEVER trusts the
// bundles blindly (see assembleSession): policy is re-derived from the
// target, every result and evidence item is schema-validated, evidence
// is re-redacted, IDs are renumbered server-side in canonical group
// order, references must resolve, and scores are recomputed by the
// pipeline. The in-memory Map below survives only as a best-effort
// cache of finalized sessions (report downloads/diff within a warm
// process, local development, scripts) — the scan flow never depends
// on it. Abuse controls (per-target cooldown, per-IP daily quota) are
// likewise per-process best-effort on serverless and exact locally.
import { randomBytes } from 'node:crypto';
import { assertUrlAllowed } from './safefetch.js';
import { policyForTarget, createScanContext, isSelfDemoTarget, POLICIES } from './context.js';
import { verificationForHost } from './ownership.js';
import { GROUPS } from './scanner/index.js';
import {
  validateCheckResult,
  validateEvidenceItem,
  unresolvedEvidenceIds,
  redactString,
} from './evidence.js';

const sessions = new Map();
const lastScanAtByTarget = new Map();
const dailyCountByIp = new Map();
const stepCountByIp = new Map();

export const TARGET_COOLDOWN_MS = 30 * 1000;
export const DAILY_QUOTA_PER_IP = 20;
// Step invocations are also metered per IP per day: one scan is eight
// steps, and the cap leaves room for retries without letting the step
// endpoint become an unmetered fetch proxy.
export const DAILY_STEP_CAP_PER_IP = DAILY_QUOTA_PER_IP * GROUPS.length * 4;

function todayKey(ip) {
  return `${new Date().toISOString().slice(0, 10)}:${ip}`;
}

function isDemoExempt(targetUrl, selfOrigin = null) {
  // Our own demo targets are exempt from the cooldown: judge mode must
  // be re-runnable. Server-side config + the self-demo rule only.
  try {
    const u = new URL(targetUrl);
    const host = u.hostname.toLowerCase();
    const listed = (process.env.AUDITCANVAS_DEMO_HOSTS || 'localhost,127.0.0.1')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .includes(host);
    return listed || isSelfDemoTarget(u, selfOrigin);
  } catch {
    return false;
  }
}

export function checkScanAllowed(targetUrl, ip, selfOrigin = null) {
  const key = targetUrl.toLowerCase();
  const last = lastScanAtByTarget.get(key);
  if (last && Date.now() - last < TARGET_COOLDOWN_MS && !isDemoExempt(targetUrl, selfOrigin)) {
    return { ok: false, status: 429, reason: `Target ${targetUrl} was scanned less than ${TARGET_COOLDOWN_MS / 1000}s ago (per-target cooldown).` };
  }
  const count = dailyCountByIp.get(todayKey(ip)) || 0;
  if (count >= DAILY_QUOTA_PER_IP) {
    return { ok: false, status: 429, reason: 'Daily scan quota for this IP is exhausted.' };
  }
  return { ok: true };
}

// Meter one step invocation against the per-IP daily step cap.
export function checkStepAllowed(ip) {
  const count = stepCountByIp.get(todayKey(ip)) || 0;
  if (count >= DAILY_STEP_CAP_PER_IP) {
    return { ok: false, status: 429, reason: 'Daily scan-step quota for this IP is exhausted.' };
  }
  stepCountByIp.set(todayKey(ip), count + 1);
  return { ok: true };
}

// The ONE place a scan's policy is decided: ownership verification
// state for the exact hostname + policyForTarget (demo allowlist,
// self-demo rule, DNS verification). Called identically by session
// creation, the stateless descriptor, every step, and finalization —
// always server-side, never from client-supplied policy fields.
export function deriveScanPolicy(parsedUrl, { attested = false, selfOrigin = null } = {}) {
  const verification = verificationForHost(parsedUrl.hostname);
  const { policy, authorizationState, allowPrivate } = policyForTarget(parsedUrl, {
    attested,
    verified: Boolean(verification),
    selfOrigin,
  });
  return { verification: verification || null, policy, authorizationState, allowPrivate };
}

export function createScan({ url, attested = false, ip = 'unknown', rescanOf = null, selfOrigin = null }) {
  const parsed = assertUrlAllowed(url); // throws SafeFetchError on bad input
  const target = parsed.toString();
  // Ownership verification state is captured WITH the session at
  // creation: a completed DNS TXT verification for this exact hostname
  // unlocks the full policy; anything else stays restricted.
  const { verification, policy, authorizationState, allowPrivate } = deriveScanPolicy(parsed, {
    attested,
    selfOrigin,
  });

  const id = randomBytes(18).toString('base64url');
  const ctx = createScanContext({
    baseUrl: target,
    policy,
    authorizationState,
    allowPrivate,
  });

  const now = new Date().toISOString();
  const session = {
    id,
    target,
    policyName: policy.name,
    authorizationState,
    verification: verification || null,
    attested: Boolean(attested),
    // Rescan lineage (SPEC.md: scan diff + fix verification). A rescan
    // is a fresh session for the same target under the same policy,
    // linked to the completed scan it follows; the diff is computed
    // from the two finalized reports, never stored as its own truth.
    rescanOf: rescanOf || null,
    status: 'running',
    createdAt: now,
    updatedAt: now,
    groupStatus: Object.fromEntries(GROUPS.map((g) => [g.id, 'queued'])),
    results: [],
    ctx,
    auditLog: [
      {
        at: now,
        event: 'scan-created',
        target,
        authorizationState,
        verification: verification
          ? { method: verification.method, hostname: verification.hostname, verifiedAt: verification.verifiedAt }
          : null,
        scanPolicy: policy.name,
        ip,
        ...(rescanOf ? { rescanOf } : {}),
      },
    ],
  };
  sessions.set(id, session);
  lastScanAtByTarget.set(target.toLowerCase(), Date.now());
  dailyCountByIp.set(todayKey(ip), (dailyCountByIp.get(todayKey(ip)) || 0) + 1);
  return session;
}

export function getScan(id) {
  return sessions.get(id) || null;
}

export function recordGroupResults(session, groupId, results) {
  session.results.push(...results);
  session.groupStatus[groupId] = 'done';
  session.updatedAt = new Date().toISOString();
  if (Object.values(session.groupStatus).every((s) => s === 'done')) {
    session.status = 'complete';
    session.auditLog.push({ at: session.updatedAt, event: 'scan-complete', target: session.target });
  }
}

export function scanSummary(session) {
  return {
    scanId: session.id,
    target: session.target,
    status: session.status,
    scanPolicy: session.policyName,
    authorizationState: session.authorizationState,
    verification: session.verification || null,
    rescanOf: session.rescanOf || null,
    groupStatus: session.groupStatus,
    groups: GROUPS.map((g) => ({ id: g.id, name: g.name })),
    policy: POLICIES[session.policyName],
  };
}

// ---------------------------------------------------------------------------
// Stateless scan flow (serverless): descriptor → per-group steps →
// server-side assembly. The descriptor carries only what the client
// may know: an unguessable scan ID, the target, the attestation flag,
// lineage, and display metadata. It carries NO authority: the policy,
// authorization state and SSRF allowances are re-derived server-side
// at every step and again at finalization.
// ---------------------------------------------------------------------------

export function startScanDescriptor({ url, attested = false, ip = 'unknown', rescanOf = null, selfOrigin = null }) {
  const parsed = assertUrlAllowed(url); // throws SafeFetchError on bad input
  const target = parsed.toString();
  const { verification, policy, authorizationState } = deriveScanPolicy(parsed, {
    attested,
    selfOrigin,
  });
  const now = new Date().toISOString();
  lastScanAtByTarget.set(target.toLowerCase(), Date.now());
  dailyCountByIp.set(todayKey(ip), (dailyCountByIp.get(todayKey(ip)) || 0) + 1);
  return {
    scanId: randomBytes(18).toString('base64url'),
    target,
    attested: Boolean(attested),
    rescanOf: rescanOf || null,
    createdAt: now,
    status: 'running',
    scanPolicy: policy.name,
    authorizationState,
    verification,
    groupStatus: Object.fromEntries(GROUPS.map((g) => [g.id, 'queued'])),
    groups: GROUPS.map((g) => ({ id: g.id, name: g.name })),
    policy: POLICIES[policy.name],
  };
}

const MAX_RESULTS_PER_GROUP = 64;
const MAX_EVIDENCE_PER_GROUP = 128;
const MAX_ASSEMBLY_BYTES = 2 * 1024 * 1024;

// Re-apply redaction to every string in an evidence payload at the
// assembly boundary: evidence is redacted before storage AND before
// any model call, and the finalize endpoint is the storage boundary
// for client-carried bundles.
function redactDeep(value) {
  if (typeof value === 'string') return redactString(value, 8192);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v);
    return out;
  }
  return value;
}

export class AssemblyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AssemblyError';
    this.status = 400;
  }
}

// Assemble a completed scan session from client-carried per-group
// bundles ({ group, results, evidence, requests }). Everything the
// report will claim is re-established here, server-side:
//  - the target is re-validated and the policy re-derived (a bundle
//    claiming a stronger policy than the server derives is stamped
//    with the derived one — claims are display-only);
//  - all eight groups must be present exactly once;
//  - every check result passes validateCheckResult and belongs to
//    its bundle's group; check IDs are unique across the scan;
//  - every evidence item passes validateEvidenceItem AFTER a fresh
//    redaction pass; byte-identical items are deduped (spec stage 2);
//  - evidence is renumbered in canonical group order and every
//    result's evidence references are rewritten through the per-group
//    map — a reference to an ID the group never produced is rejected.
export function assembleSession({ scanId, target, attested = false, rescanOf = null, createdAt = null, bundles, ip = 'unknown', selfOrigin = null }) {
  if (typeof scanId !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(scanId)) {
    throw new AssemblyError('A valid scan ID is required to finalize a scan.');
  }
  if (!Array.isArray(bundles)) throw new AssemblyError('Step bundles are required.');
  if (JSON.stringify(bundles).length > MAX_ASSEMBLY_BYTES) {
    throw new AssemblyError('Step bundles exceed the maximum accepted size.');
  }
  const parsed = assertUrlAllowed(target);
  const canonicalTarget = parsed.toString();
  const { verification, policy, authorizationState } = deriveScanPolicy(parsed, {
    attested,
    selfOrigin,
  });

  const bundleByGroup = new Map();
  for (const b of bundles) {
    if (!b || typeof b !== 'object' || !GROUPS.some((g) => g.id === b.group)) {
      throw new AssemblyError(`Unknown check group in step bundles: ${b && b.group}`);
    }
    if (bundleByGroup.has(b.group)) throw new AssemblyError(`Duplicate step bundle for group ${b.group}.`);
    bundleByGroup.set(b.group, b);
  }
  for (const g of GROUPS) {
    if (!bundleByGroup.has(g.id)) throw new AssemblyError(`Missing step bundle for group ${g.id}; the scan is incomplete.`);
  }

  const mergedEvidence = [];
  const evidenceByKey = new Map(); // dedup key -> merged item
  const mergedResults = [];
  const seenCheckIds = new Set();
  const requests = [];

  for (const g of GROUPS) {
    const bundle = bundleByGroup.get(g.id);
    const results = Array.isArray(bundle.results) ? bundle.results : null;
    const evidence = Array.isArray(bundle.evidence) ? bundle.evidence : null;
    if (!results || !evidence) throw new AssemblyError(`Step bundle for ${g.id} must carry results and evidence arrays.`);
    if (results.length > MAX_RESULTS_PER_GROUP) throw new AssemblyError(`Step bundle for ${g.id} carries too many results.`);
    if (evidence.length > MAX_EVIDENCE_PER_GROUP) throw new AssemblyError(`Step bundle for ${g.id} carries too much evidence.`);
    if (Array.isArray(bundle.requests)) requests.push(...bundle.requests.slice(0, POLICIES.full.budget));

    // Evidence: validate, re-redact, dedup, renumber.
    const idMap = new Map(); // bundle-local id -> merged id
    for (const raw of evidence) {
      if (!raw || typeof raw !== 'object') throw new AssemblyError(`Malformed evidence item in group ${g.id}.`);
      const item = {
        id: raw.id,
        kind: raw.kind,
        target: typeof raw.target === 'string' ? redactString(raw.target, 1024) : raw.target,
        at: typeof raw.at === 'string' ? raw.at : new Date().toISOString(),
        data: redactDeep(raw.data),
      };
      const errs = validateEvidenceItem(item);
      if (errs.length) throw new AssemblyError(`Invalid evidence in group ${g.id}: ${errs.join('; ')}`);
      const key = `${item.kind}\n${item.target}\n${JSON.stringify(item.data)}`;
      const existing = evidenceByKey.get(key);
      if (existing) {
        idMap.set(raw.id, existing.id);
        continue;
      }
      item.id = `ev-${String(mergedEvidence.length + 1).padStart(4, '0')}`;
      mergedEvidence.push(item);
      evidenceByKey.set(key, item);
      idMap.set(raw.id, item.id);
    }

    // Results: validate, then rewrite evidence refs through the map.
    for (const r of results) {
      const errs = validateCheckResult(r);
      if (errs.length) throw new AssemblyError(`Invalid check result in group ${g.id}: ${errs.join('; ')}`);
      if (r.group !== g.id) throw new AssemblyError(`Check result ${r.checkId} does not belong to group ${g.id}.`);
      if (seenCheckIds.has(r.checkId)) throw new AssemblyError(`Duplicate check result ${r.checkId}.`);
      seenCheckIds.add(r.checkId);
      const refs = [];
      for (const id of r.evidenceIds || []) {
        const mapped = idMap.get(id);
        if (!mapped) throw new AssemblyError(`Check result ${r.checkId} references evidence ${id} that group ${g.id} never produced.`);
        if (!refs.includes(mapped)) refs.push(mapped);
      }
      mergedResults.push({ ...r, evidenceIds: refs });
    }
  }

  const unresolved = unresolvedEvidenceIds(mergedResults, mergedEvidence);
  if (unresolved.length) {
    throw new AssemblyError(`Evidence references do not resolve: ${unresolved.join(', ')}`);
  }

  const now = new Date().toISOString();
  const created = typeof createdAt === 'string' && !Number.isNaN(Date.parse(createdAt)) ? createdAt : now;
  const session = {
    id: scanId,
    target: canonicalTarget,
    policyName: policy.name,
    authorizationState,
    verification,
    attested: Boolean(attested),
    rescanOf: rescanOf || null,
    status: 'complete',
    createdAt: created,
    updatedAt: now,
    groupStatus: Object.fromEntries(GROUPS.map((g) => [g.id, 'done'])),
    results: mergedResults,
    ctx: { evidence: { items: mergedEvidence } },
    requests,
    auditLog: [
      {
        at: created,
        event: 'scan-created',
        target: canonicalTarget,
        authorizationState,
        verification: verification
          ? { method: verification.method, hostname: verification.hostname, verifiedAt: verification.verifiedAt }
          : null,
        scanPolicy: policy.name,
        ip,
        flow: 'stateless',
        ...(rescanOf ? { rescanOf } : {}),
      },
      { at: now, event: 'scan-complete', target: canonicalTarget, flow: 'stateless' },
    ],
  };
  return session;
}

// Best-effort cache of a finalized session, for the ID-keyed report
// routes (downloads, diff) when they happen to land in a warm process.
// Nothing in the scan flow depends on a cache hit.
export function cacheSession(session) {
  sessions.set(session.id, session);
  return session;
}
