// Admin scan grants and history (admin design §13, §14).
//
// The override is a validated database grant, not a mode flag: the
// admin_scan_runs row created at start, bound to the creating
// session and one canonical target, expiring after 30 minutes. No
// grant, no full policy. No matching target, no full policy. No
// creating-session match, no full policy. No live status, no full
// policy. Step and finalize re-load and re-check the grant on every
// call; the public scan routes never see any of this.
import { createHash, randomBytes } from 'node:crypto';
import { assertUrlAllowed, SafeFetchError } from '../safefetch.js';
import { createScanContext } from '../context.js';
import { redactUrl } from '../evidence.js';
import {
  assembleSession,
  buildScanDescriptor,
  deriveScanPolicy,
  AssemblyError,
} from '../scanstore.js';
import { GROUPS, groupById, runGroup } from '../scanner/index.js';
import { signStepBundle, verifyStepBundle, bundleSetDigest, canonicalStringify } from '../bundlesig.js';
import { finalizeReportForBundleSet } from '../pipeline.js';
import { insertAdminEventStmt } from './events.js';
import { adminSourceHash, clientIp, readJsonBody, BodyError } from './http.js';
import { toIso, toNum, AdminStoreUnavailable, AdminStoreError } from './db.js';

export const GRANT_TTL_MS = 30 * 60 * 1000;
export const MAX_ACTIVE_GRANTS_PER_SESSION = 3;
export const MAX_STARTS_PER_HOUR = 10;
export const MAX_STARTS_PER_DAY = 100;
export const REPORT_MAX_BYTES = 5 * 1024 * 1024;

const SCAN_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;

const RUN_COLUMNS =
  'scan_id, origin, target, target_host, target_display, authorization_state, scan_policy, status, ' +
  'created_by_session_id, rescan_of, completed_groups, step_attempts, bundle_set_digest, risk_score, ' +
  'risk_grade, findings_count, confirmed_findings_count, coverage_ratio, confidence_ratio, report_json, ' +
  'report_sha256, error_code, created_at, updated_at, expires_at, finalized_at';
const RUN_LIST_COLUMNS =
  'scan_id, origin, target, target_host, target_display, authorization_state, scan_policy, status, ' +
  'created_by_session_id, rescan_of, completed_groups, step_attempts, bundle_set_digest, risk_score, ' +
  'risk_grade, findings_count, confirmed_findings_count, coverage_ratio, confidence_ratio, ' +
  "report_sha256, error_code, created_at, updated_at, expires_at, finalized_at, " +
  "report_json->>'authorizationState' as report_authorization_state";

function toReport(value) {
  if (value == null) return null;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  return typeof value === 'object' ? value : null;
}

export function normalizeRunRow(row, { now = Date.now() } = {}) {
  if (!row) return null;
  let status = row.status;
  // Expiry is computed on read for live grants (design §14.1); the
  // Phase 2 prune materializes it for old rows.
  if ((status === 'created' || status === 'running') && !(Date.parse(toIso(row.expires_at)) > now)) {
    status = 'expired';
  }
  return {
    scanId: row.scan_id,
    origin: row.origin,
    target: row.target,
    targetHost: row.target_host,
    targetDisplay: row.target_display,
    authorizationState: row.authorization_state,
    scanPolicy: row.scan_policy,
    status,
    storedStatus: row.status,
    createdBySessionId: row.created_by_session_id,
    rescanOf: row.rescan_of || null,
    completedGroups: Array.isArray(row.completed_groups) ? [...row.completed_groups] : [],
    stepAttempts: toNum(row.step_attempts) ?? 0,
    bundleSetDigest: row.bundle_set_digest || null,
    riskScore: toNum(row.risk_score),
    riskGrade: row.risk_grade || null,
    // The report's own authorization state, when one is stored: it
    // can carry the stronger factual basis (e.g. 'verified') that
    // the run row's 'admin' column cannot express (design §14.3).
    reportAuthorizationState: row.report_authorization_state || null,
    findingsCount: toNum(row.findings_count),
    confirmedFindingsCount: toNum(row.confirmed_findings_count),
    coverageRatio: toNum(row.coverage_ratio),
    confidenceRatio: toNum(row.confidence_ratio),
    report: toReport(row.report_json),
    reportSha256: row.report_sha256 || null,
    errorCode: row.error_code || null,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
    expiresAt: toIso(row.expires_at),
    finalizedAt: toIso(row.finalized_at),
  };
}

export async function loadGrant(db, scanId) {
  if (typeof scanId !== 'string' || !SCAN_ID_RE.test(scanId)) return null;
  const rows = await db.query(
    `/*ac:runs.byId*/ select ${RUN_COLUMNS} from public.admin_scan_runs where scan_id = $1`,
    [scanId]
  );
  return rows.length ? normalizeRunRow(rows[0]) : null;
}

// The trusted grant object scanstore derives policy from. Built ONLY
// here, from a database row — never from request data.
export function grantForDerivation(grant) {
  return {
    origin: 'admin',
    scanId: grant.scanId,
    sessionId: grant.createdBySessionId,
    target: grant.target,
    expiresAt: grant.expiresAt,
  };
}

// Binding checks shared by step and finalize (design §13.5.7,
// §13.6.5). Returns { grant } or { status, json } for the caller to
// return verbatim. Missing/mismatched grants are one generic 404;
// expiry is the only distinguished state (410), per the design.
export async function requireLiveGrant(db, { scanId, session, now }) {
  const grant = await loadGrant(db, scanId);
  if (!grant) return { status: 404, json: { error: 'Admin scan not found.' } };
  if (grant.origin !== 'admin') return { status: 404, json: { error: 'Admin scan not found.' } };
  if (grant.createdBySessionId !== session.id) return { status: 404, json: { error: 'Admin scan not found.' } };
  if (grant.storedStatus === 'finalized') return { grant, finalized: true };
  if (grant.storedStatus !== 'created' && grant.storedStatus !== 'running') {
    return { status: 404, json: { error: 'Admin scan not found.' } };
  }
  if (!(Date.parse(grant.expiresAt) > now)) {
    return { status: 410, json: { error: 'Admin scan grant has expired.' } };
  }
  return { grant };
}

function storeUnavailable() {
  return { status: 503, json: { error: 'Admin storage unavailable.' } };
}

function isStoreError(err) {
  // Both typed store errors fail closed as a generic 503 on admin
  // paths: the operator cannot act on the distinction, and an
  // unhandled throw would surface as a 500 that leaks 'crashed'.
  return (
    err instanceof AdminStoreUnavailable ||
    err instanceof AdminStoreError ||
    (err && (err.code === 'store_unavailable' || err.code === 'store_error'))
  );
}

// ---------------------------------------------------------------------------
// Start (design §13.4)
// ---------------------------------------------------------------------------

export async function startAdminScan(request, { db, cfg, session, now = Date.now() }) {
  let body;
  try {
    body = await readJsonBody(request, 16 * 1024);
  } catch (err) {
    if (err instanceof BodyError) return { status: err.status, json: { error: 'Invalid request.' } };
    throw err;
  }
  // Only url and optional rescanOf are read. Any policy / origin /
  // attestation fields in the body are ignored: they confer nothing.
  const url = typeof body.url === 'string' ? body.url.trim() : '';
  const rescanOf = typeof body.rescanOf === 'string' && SCAN_ID_RE.test(body.rescanOf) ? body.rescanOf : null;

  let parsed;
  try {
    parsed = assertUrlAllowed(url);
  } catch (err) {
    return {
      status: 400,
      json: { error: `Target rejected: ${err && err.message ? err.message : String(err)}` },
    };
  }
  const target = parsed.toString();
  const nowIso = new Date(now).toISOString();

  // Operator safety ceilings (design §13.4.6): anti-abuse limits for
  // a stolen session, not public quotas. Admin scans intentionally
  // bypass the public per-target cooldown and per-IP daily quota.
  try {
    const active = await db.query(
      `/*ac:runs.countActiveForSession*/ select count(*)::int as n from public.admin_scan_runs
       where created_by_session_id = $1 and status in ('created', 'running') and expires_at > $2`,
      [session.id, nowIso]
    );
    if ((active[0]?.n ?? 0) >= MAX_ACTIVE_GRANTS_PER_SESSION) {
      return { status: 429, json: { error: 'Too many admin scans in progress.' } };
    }
    const hour = await db.query(
      `/*ac:runs.countStartsSince*/ select count(*)::int as n from public.admin_scan_runs where created_at > $1`,
      [new Date(now - 60 * 60 * 1000).toISOString()]
    );
    if ((hour[0]?.n ?? 0) >= MAX_STARTS_PER_HOUR) {
      return { status: 429, json: { error: 'Admin scan start limit reached.' } };
    }
    const day = await db.query(
      `/*ac:runs.countStartsSince*/ select count(*)::int as n from public.admin_scan_runs where created_at > $1`,
      [new Date(now - 24 * 60 * 60 * 1000).toISOString()]
    );
    if ((day[0]?.n ?? 0) >= MAX_STARTS_PER_DAY) {
      return { status: 429, json: { error: 'Admin scan start limit reached.' } };
    }
  } catch (err) {
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }

  const scanId = randomBytes(18).toString('base64url');
  const expiresIso = new Date(now + GRANT_TTL_MS).toISOString();
  const ipHash = adminSourceHash(cfg.visitorHashSecret, clientIp(request));
  try {
    await db.tx([
      {
        text: `/*ac:runs.insert*/ insert into public.admin_scan_runs
          (scan_id, origin, target, target_host, target_display, authorization_state, scan_policy,
           status, created_by_session_id, rescan_of, created_at, updated_at, expires_at)
          values ($1, 'admin', $2, $3, $4, 'admin', 'full', 'created', $5, $6, $7, $7, $8)`,
        params: [
          scanId,
          target,
          parsed.hostname.toLowerCase(),
          redactUrl(target),
          session.id,
          rescanOf,
          nowIso,
          expiresIso,
        ],
      },
      insertAdminEventStmt({
        type: 'scan_created',
        occurredAt: nowIso,
        actorSessionId: session.id,
        scanId,
        targetHost: parsed.hostname.toLowerCase(),
        ipHash,
      }),
    ]);
  } catch (err) {
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }

  const grant = {
    scanId,
    origin: 'admin',
    target,
    targetHost: parsed.hostname.toLowerCase(),
    createdBySessionId: session.id,
    expiresAt: expiresIso,
    createdAt: nowIso,
    rescanOf,
  };
  const derived = deriveScanPolicy(parsed, { adminGrant: grantForDerivation(grant) });
  const descriptor = buildScanDescriptor({
    scanId,
    target,
    attested: false,
    rescanOf,
    createdAt: nowIso,
    derived,
  });
  return { status: 200, json: descriptor };
}

// ---------------------------------------------------------------------------
// Step (design §13.5)
// ---------------------------------------------------------------------------

export async function runAdminStep(request, { db, cfg, session, now = Date.now() }) {
  let body;
  try {
    body = await readJsonBody(request, 8 * 1024);
  } catch (err) {
    if (err instanceof BodyError) return { status: err.status, json: { error: 'Invalid request.' } };
    throw err;
  }
  const group = groupById(typeof body.group === 'string' ? body.group : '');
  if (!group) {
    return { status: 400, json: { error: `Unknown check group: ${body.group}` } };
  }

  let checked;
  try {
    checked = await requireLiveGrant(db, { scanId: body.scanId, session, now });
  } catch (err) {
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }
  if (!checked.grant) return { status: checked.status, json: checked.json };
  if (checked.finalized) return { status: 404, json: { error: 'Admin scan not found.' } };
  const grant = checked.grant;

  // The request target must canonicalize to exactly the grant target.
  let parsed;
  try {
    parsed = assertUrlAllowed(typeof body.target === 'string' ? body.target.trim() : '');
  } catch {
    return { status: 400, json: { error: 'Target rejected.' } };
  }
  if (parsed.toString() !== grant.target) {
    return { status: 404, json: { error: 'Admin scan not found.' } };
  }

  const derived = deriveScanPolicy(parsed, { adminGrant: grantForDerivation(grant) });
  const ctx = createScanContext({
    baseUrl: grant.target,
    policy: derived.policy,
    authorizationState: derived.authorizationState,
    allowPrivate: derived.allowPrivate,
  });
  const results = await runGroup(ctx, group.id);
  const bundle = {
    group: group.id,
    scanPolicy: derived.policy.name,
    results,
    evidence: ctx.evidence.items,
    requests: ctx.requests,
  };
  bundle.sig = signStepBundle({ scanId: grant.scanId, target: grant.target, bundle });

  // The step counts only when its completion is durable (design
  // §13.5.13): if Neon fails here, no bundle is returned as progress
  // and finalize (which requires the recorded group set) cannot use
  // it. The target request may already have happened; that is safe —
  // it was a non-destructive scan step under a live grant.
  const nowIso = new Date(now).toISOString();
  try {
    await db.tx([
      {
        text: `/*ac:runs.recordStep*/ update public.admin_scan_runs set
          status = 'running',
          step_attempts = step_attempts + 1,
          completed_groups = case when $2 = any(completed_groups) then completed_groups
                                  else array_append(completed_groups, $2) end,
          updated_at = $3
          where scan_id = $1`,
        params: [grant.scanId, group.id, nowIso],
      },
      insertAdminEventStmt({
        type: 'scan_step_completed',
        occurredAt: nowIso,
        actorSessionId: session.id,
        scanId: grant.scanId,
        targetHost: grant.targetHost,
        metadata: { group: group.id },
      }),
    ]);
  } catch (err) {
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }
  return { status: 200, json: bundle };
}

// ---------------------------------------------------------------------------
// Finalize (design §13.6)
// ---------------------------------------------------------------------------

async function markRunFailed(db, { grant, session, errorCode, now }) {
  const nowIso = new Date(now).toISOString();
  try {
    await db.tx([
      {
        text: `/*ac:runs.fail*/ update public.admin_scan_runs set status = 'failed', error_code = $2, updated_at = $3
          where scan_id = $1 and status <> 'finalized'`,
        params: [grant.scanId, errorCode, nowIso],
      },
      insertAdminEventStmt({
        type: 'scan_failed',
        occurredAt: nowIso,
        actorSessionId: session.id,
        scanId: grant.scanId,
        targetHost: grant.targetHost,
        metadata: { reason: errorCode },
      }),
    ]);
  } catch { /* the failure response stands even if marking fails */ }
}

export async function finalizeAdminScan(request, { db, cfg, session, now = Date.now() }) {
  let body;
  try {
    body = await readJsonBody(request, 3 * 1024 * 1024);
  } catch (err) {
    if (err instanceof BodyError) return { status: err.status, json: { error: 'Invalid request.' } };
    throw err;
  }
  const scan = body && typeof body.scan === 'object' && body.scan !== null ? body.scan : {};
  const bundles = Array.isArray(body.bundles) ? body.bundles : null;

  let checked;
  try {
    checked = await requireLiveGrant(db, { scanId: scan.scanId, session, now });
  } catch (err) {
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }
  if (!checked.grant) return { status: checked.status, json: checked.json };
  const grant = checked.grant;
  const ipHash = adminSourceHash(cfg.visitorHashSecret, clientIp(request));

  // Idempotent repeat finalize (design §13.6.9): the stored digest
  // decides. Identical bundle set -> the stored report, zero new
  // pipeline work. Different set -> 409, never a silent re-run.
  if (checked.finalized) {
    if (!bundles) return { status: 400, json: { error: 'Step bundles are required.' } };
    const digest = bundleSetDigest({ scanId: grant.scanId, target: grant.target, bundles });
    if (grant.bundleSetDigest && digest === grant.bundleSetDigest && grant.report) {
      // The digest covers (group, sig) pairs; a presented bundle
      // whose contents no longer match its signature is not the
      // signed set that was finalized — it is a conflict, not a
      // replay.
      const genuine = bundles.every((b) => verifyStepBundle(b, { scanId: grant.scanId, target: grant.target }));
      if (genuine) return { status: 200, json: grant.report };
    }
    return { status: 409, json: { error: 'Admin scan was finalized from a different bundle set.' } };
  }

  // The recorded group set must be the full registry before assembly
  // (design §13.6.6): bundles minted elsewhere cannot skip steps.
  const completed = new Set(grant.completedGroups);
  if (!GROUPS.every((g) => completed.has(g.id))) {
    return { status: 400, json: { error: 'Admin scan is incomplete: not every check group has a recorded step.' } };
  }
  if (!bundles) return { status: 400, json: { error: 'Step bundles are required.' } };

  let session2;
  try {
    session2 = assembleSession({
      scanId: grant.scanId,
      target: grant.target,
      attested: false,
      rescanOf: grant.rescanOf,
      createdAt: grant.createdAt,
      bundles,
      adminGrant: grantForDerivation(grant),
      requesterIpHash: ipHash,
      selfOrigin: new URL(request.url).origin,
    });
  } catch (err) {
    if (err instanceof AssemblyError) {
      await markRunFailed(db, { grant, session, errorCode: 'assembly_rejected', now });
      return { status: err.status, json: { error: `Finalize rejected: ${err.message}` } };
    }
    if (err instanceof SafeFetchError) {
      return { status: 400, json: { error: 'Target rejected.' } };
    }
    throw err;
  }

  const digest = bundleSetDigest({ scanId: grant.scanId, target: grant.target, bundles });
  let report;
  try {
    ({ report } = await finalizeReportForBundleSet(session2, `admin:${digest}`));
  } catch {
    await markRunFailed(db, { grant, session, errorCode: 'pipeline_failed', now });
    return { status: 500, json: { error: 'Admin scan failed.' } };
  }

  // Report-size rule (design §12.2): never truncate, never store a
  // partial report presented as complete.
  const reportJsonText = JSON.stringify(report);
  if (Buffer.byteLength(reportJsonText, 'utf8') > REPORT_MAX_BYTES) {
    await markRunFailed(db, { grant, session, errorCode: 'report_too_large', now });
    return { status: 500, json: { error: 'Admin scan failed.' } };
  }

  const summary = {
    riskScore: report.scores?.risk?.score ?? null,
    riskGrade: report.scores?.risk?.grade ?? null,
    findingsCount: report.scores?.counts?.findings ?? null,
    confirmedFindingsCount: report.scores?.counts?.confirmedFindings ?? null,
    coverageRatio: report.scores?.coverage?.ratio ?? null,
    confidenceRatio: report.scores?.confidence?.ratio ?? null,
  };
  const reportSha256 = createHash('sha256').update(canonicalStringify(report)).digest('hex');
  const nowIso = new Date(now).toISOString();
  try {
    await db.tx([
      {
        text: `/*ac:runs.finalize*/ update public.admin_scan_runs set
          status = 'finalized', bundle_set_digest = $2, risk_score = $3, risk_grade = $4,
          findings_count = $5, confirmed_findings_count = $6, coverage_ratio = $7,
          confidence_ratio = $8, report_json = $9::jsonb, report_sha256 = $10,
          finalized_at = $11, updated_at = $11
          where scan_id = $1`,
        params: [
          grant.scanId,
          digest,
          summary.riskScore,
          summary.riskGrade,
          summary.findingsCount,
          summary.confirmedFindingsCount,
          summary.coverageRatio,
          summary.confidenceRatio,
          reportJsonText,
          reportSha256,
          nowIso,
        ],
      },
      insertAdminEventStmt({
        type: 'scan_finalized',
        occurredAt: nowIso,
        actorSessionId: session.id,
        scanId: grant.scanId,
        targetHost: grant.targetHost,
        metadata: {
          riskGrade: summary.riskGrade,
          riskScore: summary.riskScore,
          findings: summary.findingsCount,
        },
      }),
    ]);
  } catch (err) {
    // Persistence is part of the deliverable (design §11.3): if the
    // report cannot be stored, no authoritative admin report is
    // returned. The client keeps its signed bundles and may retry
    // while the grant remains live.
    if (isStoreError(err)) return storeUnavailable();
    throw err;
  }
  return { status: 200, json: report };
}

// ---------------------------------------------------------------------------
// History + stored reports (design §14)
// ---------------------------------------------------------------------------

export function encodeHistoryCursor(row) {
  return Buffer.from(JSON.stringify({ createdAt: row.createdAt, scanId: row.scanId }), 'utf8').toString('base64url');
}

export function decodeHistoryCursor(text) {
  if (typeof text !== 'string' || !text) return null;
  try {
    const value = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
    if (!value || typeof value.createdAt !== 'string' || typeof value.scanId !== 'string') return null;
    return value;
  } catch {
    return null;
  }
}

export async function listAdminHistory(db, { status = null, host = null, cursor = null, limit = 25, now = Date.now() } = {}) {
  // The 'expired' filter is special: expiry is computed on read for
  // live grants (the stored status stays created/running until the
  // Phase 2 prune materializes it), so the filter matches live rows
  // whose deadline has passed instead of a stored 'expired' value.
  const rows = await db.query(
    `/*ac:runs.history*/ select ${RUN_LIST_COLUMNS} from public.admin_scan_runs
     where ($1::text is null or status = $1
            or ($1 = 'expired' and status in ('created', 'running') and expires_at <= $6::timestamptz))
       and ($2::text is null or target_host = $2)
       and ($3::timestamptz is null or (created_at, scan_id) < ($3::timestamptz, $4::text))
     order by created_at desc, scan_id desc
     limit $5`,
    [status, host, cursor ? cursor.createdAt : null, cursor ? cursor.scanId : null, limit + 1, new Date(now).toISOString()]
  );
  // RUN_LIST_COLUMNS omits report_json, so normalized rows carry
  // report: null — the list never ships report bodies.
  const normalized = rows.map((r) => normalizeRunRow(r, { now }));
  const hasMore = normalized.length > limit;
  const page = hasMore ? normalized.slice(0, limit) : normalized;
  return {
    rows: page,
    nextCursor: hasMore && page.length ? encodeHistoryCursor(page[page.length - 1]) : null,
  };
}

export async function recentAdminScans(db, limit = 10) {
  const { rows } = await listAdminHistory(db, { limit });
  return rows;
}

export async function getAdminRun(db, scanId, { now = Date.now() } = {}) {
  const run = await loadGrant(db, scanId);
  if (!run) return null;
  void now;
  return run;
}

// Storage liveness for the console readout: a real (cheap) read of
// the schema marker the migration seeds. Throws typed store errors.
export async function adminStorageStatus(db) {
  const rows = await db.query(
    `/*ac:meta.schemaVersion*/ select value from public.admin_meta where key = 'schema_version'`,
    []
  );
  return { connected: true, schemaVersion: rows.length ? rows[0].value : null };
}
