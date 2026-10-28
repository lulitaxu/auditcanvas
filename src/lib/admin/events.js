// Admin audit events (admin design §8.4, §12): allowlisted event
// types and metadata, durable in Neon. Events are the durable basis
// for login backoff, so they are written by the same transactions
// that perform the actions they describe.
//
// An event may contain: timestamp, type, actor session id, scan id,
// target host, admin source hash (HMAC of the IP — never the raw
// address), coarse UA families, and allowlisted scalar metadata.
// It may NEVER contain: a password or password prefix/length, the
// configured hash, a raw IP, a raw user-agent string, a session
// token, or a CSRF token. The sanitizer below is the enforcement
// point: unknown metadata keys are dropped, values are scalars only.
import { toIso } from './db.js';

export const ADMIN_EVENT_TYPES = new Set([
  'login_success',
  'login_failure',
  'login_rate_limited',
  'login_config_error',
  'logout',
  'session_revoked',
  'csrf_rejected',
  'scan_created',
  'scan_step_completed',
  'scan_finalized',
  'scan_failed',
  'report_viewed',
  'report_downloaded',
  'self_exclusion_changed',
  'prune_completed',
  'prune_failed',
  'storage_error',
]);

const METADATA_KEYS = new Set([
  'scope', 'failures', 'group', 'kind', 'route', 'reason',
  'riskGrade', 'riskScore', 'findings', 'deleted', 'status',
]);

export function sanitizeEventMetadata(metadata) {
  const out = {};
  if (!metadata || typeof metadata !== 'object') return out;
  for (const [key, value] of Object.entries(metadata)) {
    if (!METADATA_KEYS.has(key)) continue;
    if (typeof value === 'string') out[key] = value.slice(0, 64);
    else if (typeof value === 'number' && Number.isFinite(value)) out[key] = value;
    else if (typeof value === 'boolean') out[key] = value;
  }
  return out;
}

const INSERT_EVENT_SQL = `/*ac:events.insert*/ insert into public.admin_events
  (occurred_at, event_type, actor_session_id, scan_id, target_host, ip_hash, browser_family, os_family, metadata)
  values ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`;

export function insertAdminEventStmt({
  type,
  occurredAt,
  actorSessionId = null,
  scanId = null,
  targetHost = null,
  ipHash = null,
  browserFamily = null,
  osFamily = null,
  metadata = {},
}) {
  if (!ADMIN_EVENT_TYPES.has(type)) {
    throw new TypeError(`Unknown admin event type: ${type}`);
  }
  return {
    text: INSERT_EVENT_SQL,
    params: [
      occurredAt,
      type,
      actorSessionId,
      scanId,
      targetHost,
      ipHash,
      browserFamily,
      osFamily,
      JSON.stringify(sanitizeEventMetadata(metadata)),
    ],
  };
}

export async function insertAdminEvent(db, fields) {
  const stmt = insertAdminEventStmt(fields);
  await db.query(stmt.text, stmt.params);
}

function normalizeEventRow(row) {
  return {
    id: row.id != null ? Number(row.id) : null,
    occurredAt: toIso(row.occurred_at),
    eventType: row.event_type,
    actorSessionId: row.actor_session_id || null,
    scanId: row.scan_id || null,
    targetHost: row.target_host || null,
    ipHash: row.ip_hash || null,
    browserFamily: row.browser_family || null,
    osFamily: row.os_family || null,
    metadata: row.metadata && typeof row.metadata === 'object' ? row.metadata : {},
  };
}

export async function recentAdminEvents(db, limit = 20) {
  const rows = await db.query(
    `/*ac:events.recent*/ select id, occurred_at, event_type, actor_session_id, scan_id, target_host,
       ip_hash, browser_family, os_family, metadata
     from public.admin_events order by occurred_at desc, id desc limit $1`,
    [limit]
  );
  return rows.map(normalizeEventRow);
}

// Most recent successful login time for one source hash (ISO) or null.
export async function lastLoginSuccessAt(db, ipHash) {
  const rows = await db.query(
    `/*ac:events.lastSuccessBySource*/ select occurred_at from public.admin_events
     where event_type = 'login_success' and ip_hash = $1
     order by occurred_at desc, id desc limit 1`,
    [ipHash]
  );
  return rows.length ? toIso(rows[0].occurred_at) : null;
}

// Failed-login timestamps (newest first) after `sinceIso`. With
// ipHash null, across all sources (the global circuit breaker).
export async function loginFailureTimes(db, { ipHash = null, sinceIso }) {
  const rows = ipHash
    ? await db.query(
        `/*ac:events.failuresBySource*/ select occurred_at from public.admin_events
         where event_type = 'login_failure' and ip_hash = $1 and occurred_at > $2
         order by occurred_at desc, id desc`,
        [ipHash, sinceIso]
      )
    : await db.query(
        `/*ac:events.failuresGlobal*/ select occurred_at from public.admin_events
         where event_type = 'login_failure' and occurred_at > $1
         order by occurred_at desc, id desc limit 200`,
        [sinceIso]
      );
  return rows.map((r) => toIso(r.occurred_at)).filter(Boolean);
}
