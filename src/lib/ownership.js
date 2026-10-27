// Ownership verification (SPEC.md: ONE method, done properly) — a DNS
// TXT challenge whose token is bound to the EXACT hostname and is
// short-lived. Verifying a parent domain never authorizes subdomains
// or other ports: the challenge record lives at
// _auditcanvas.<hostname> and the verified state is keyed by that exact
// hostname.
//
// Verified hostnames unlock the full check set (context.js policies);
// unverified targets always run the restricted passive policy,
// attestation checkbox or not. Verification state is stored on the
// scan session at creation time (scanstore.js) and travels into the
// report and the evidence bundle.
import { randomBytes } from 'node:crypto';
import { resolveTxt } from './dnsutil.js';

export const CHALLENGE_TTL_MS = 15 * 60 * 1000; // short-lived, per spec
export const RECORD_PREFIX = '_auditcanvas';
export const TOKEN_PREFIX = 'auditcanvas-verify=';

const challenges = new Map(); // hostname -> { token, createdAt, expiresAt }
const verifiedHosts = new Map(); // hostname -> { method, verifiedAt, recordName }

export function normalizeHostname(input) {
  if (typeof input !== 'string' || !input.trim()) return null;
  let host = input.trim().toLowerCase();
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  host = host.replace(/:\d+$/, '').replace(/\.$/, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host) && host !== 'localhost') {
    return null;
  }
  return host;
}

export function challengeRecordName(hostname) {
  return `${RECORD_PREFIX}.${hostname}`;
}

export function challengeRecordValue(token) {
  return `${TOKEN_PREFIX}${token}`;
}

// Issue a fresh challenge for the exact hostname. Issuing a new one
// invalidates the previous token for that host.
export function createChallenge(rawHostname) {
  const hostname = normalizeHostname(rawHostname);
  if (!hostname) return null;
  const token = randomBytes(24).toString('base64url');
  const now = Date.now();
  const challenge = {
    hostname,
    token,
    recordName: challengeRecordName(hostname),
    recordValue: challengeRecordValue(token),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString(),
  };
  challenges.set(hostname, { token, expiresAtMs: now + CHALLENGE_TTL_MS });
  return challenge;
}

// Look the challenge up in DNS. Outcomes are explicit and follow the
// DNS error taxonomy: resolver errors are reported as dns-error with
// the taxonomy status, never as "record missing".
export async function checkChallenge(rawHostname, { dnsTxtFn = resolveTxt } = {}) {
  const hostname = normalizeHostname(rawHostname);
  if (!hostname) return { status: 'bad-hostname' };
  const challenge = challenges.get(hostname);
  if (!challenge) return { status: 'no-challenge', hostname };
  if (Date.now() > challenge.expiresAtMs) {
    challenges.delete(hostname);
    return { status: 'expired', hostname };
  }
  const res = await dnsTxtFn(challengeRecordName(hostname));
  if (res.status !== 'ok') {
    return { status: 'dns-error', hostname, dnsStatus: res.status };
  }
  const expected = challengeRecordValue(challenge.token);
  const found = res.records.some((r) => typeof r === 'string' && r.trim() === expected);
  if (!found) {
    return { status: 'not-found', hostname, recordsSeen: res.records.length };
  }
  const record = {
    method: 'dns-txt',
    hostname,
    recordName: challengeRecordName(hostname),
    verifiedAt: new Date().toISOString(),
  };
  verifiedHosts.set(hostname, record);
  challenges.delete(hostname);
  return { status: 'verified', hostname, verification: record };
}

export function verificationForHost(rawHostname) {
  const hostname = normalizeHostname(rawHostname);
  if (!hostname) return null;
  return verifiedHosts.get(hostname) || null;
}

export function isVerifiedHost(rawHostname) {
  return Boolean(verificationForHost(rawHostname));
}
