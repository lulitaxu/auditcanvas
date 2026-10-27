// In-memory scan sessions for the stepwise scan API (SPEC: Architecture).
// The client drives the scan as short per-check-group steps; in-progress
// state lives server-side keyed by an unguessable scan ID. Abuse controls
// from the spec: one scan per target at a time, per-target cooldown,
// per-IP daily quota. Persistence beyond process memory (and the 7-day
// report expiry) is a later-day concern; the shapes here are the contract.
import { randomBytes } from 'node:crypto';
import { assertUrlAllowed } from './safefetch.js';
import { policyForTarget, createScanContext, POLICIES } from './context.js';
import { GROUPS } from './scanner/index.js';

const sessions = new Map();
const lastScanAtByTarget = new Map();
const dailyCountByIp = new Map();

export const TARGET_COOLDOWN_MS = 30 * 1000;
export const DAILY_QUOTA_PER_IP = 20;

function todayKey(ip) {
  return `${new Date().toISOString().slice(0, 10)}:${ip}`;
}

export function checkScanAllowed(targetUrl, ip) {
  const key = targetUrl.toLowerCase();
  const last = lastScanAtByTarget.get(key);
  if (last && Date.now() - last < TARGET_COOLDOWN_MS) {
    // Our own demo targets are exempt: judge mode must be re-runnable.
    const host = new URL(targetUrl).hostname.toLowerCase();
    const isDemo = (process.env.AUDITCANVAS_DEMO_HOSTS || 'localhost,127.0.0.1')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .includes(host);
    if (!isDemo) {
      return { ok: false, status: 429, reason: `Target ${targetUrl} was scanned less than ${TARGET_COOLDOWN_MS / 1000}s ago (per-target cooldown).` };
    }
  }
  const count = dailyCountByIp.get(todayKey(ip)) || 0;
  if (count >= DAILY_QUOTA_PER_IP) {
    return { ok: false, status: 429, reason: 'Daily scan quota for this IP is exhausted.' };
  }
  return { ok: true };
}

export function createScan({ url, attested = false, ip = 'unknown' }) {
  const parsed = assertUrlAllowed(url); // throws SafeFetchError on bad input
  const target = parsed.toString();
  const { policy, authorizationState, allowPrivate } = policyForTarget(parsed, { attested });

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
    attested: Boolean(attested),
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
        scanPolicy: policy.name,
        ip,
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
    groupStatus: session.groupStatus,
    groups: GROUPS.map((g) => ({ id: g.id, name: g.name })),
    policy: POLICIES[session.policyName],
  };
}
