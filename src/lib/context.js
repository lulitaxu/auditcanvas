// Scan policies and the per-scan context (budget, deadline, evidence).
//
// SPEC.md: "Restricted by default. Unverified targets get a passive-only
// scan policy with small budgets, whatever the user attests." Verified
// targets (DNS TXT, the ONE method — ownership.js) and our own
// allowlisted demo hosts get the full check set.
import { createEvidenceStore, redactUrl } from './evidence.js';
import { safeFetch, SafeFetchError } from './safefetch.js';
import { resolveTxt } from './dnsutil.js';

export const POLICIES = {
  full: {
    name: 'full',
    budget: 40,
    perRequestTimeoutMs: 6000,
    deadlineMs: 90000,
    sizeCapBytes: 512 * 1024,
    probes: true, // active-but-benign probes: CORS origin probe, open-redirect probe
  },
  restricted: {
    name: 'restricted',
    budget: 12,
    perRequestTimeoutMs: 4000,
    deadlineMs: 30000,
    sizeCapBytes: 256 * 1024,
    probes: false,
  },
};

// Server-side allowlist of our own demo hosts (exact hostnames). Comes
// from env, never from the scan request.
export function demoHosts() {
  return (process.env.AUDITCANVAS_DEMO_HOSTS || 'localhost,127.0.0.1')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// The seeded demo target (SPEC.md: Judge mode) is THIS app's own
// /api/demo-target route. When a scan target is that exact path on the
// app's own origin — the origin the current request was served from,
// passed in by the route, never by the client — it is allowlisted for
// the full check set, for that exact host only. This is what makes the
// deployed Judge-mode demo run the full policy: the production origin
// is not (and must not need to be) in AUDITCANVAS_DEMO_HOSTS.
export const DEMO_TARGET_PATH = '/api/demo-target';

export function isSelfDemoTarget(url, selfOrigin) {
  if (!selfOrigin) return false;
  let origin;
  try {
    origin = new URL(selfOrigin).origin;
  } catch {
    return false;
  }
  if (url.origin !== origin) return false;
  return url.pathname === DEMO_TARGET_PATH || url.pathname.startsWith(`${DEMO_TARGET_PATH}/`);
}

// authorizationState: 'verified' (allowlisted demo host, the app's own
// seeded demo target, or a hostname with a completed DNS TXT
// verification — the token is bound to the exact hostname,
// ownership.js) or 'attested' / 'unattested' for user targets, which
// always run restricted until verified. Note allowPrivate stays false
// for DNS-verified hosts: verification unlocks the check set, never
// the SSRF address rules. allowPrivate for the self-demo follows the
// demo-host config only: the production demo origin is a public host
// whose addresses pass the normal SSRF validation, so it never needs
// the loopback allowance.
//
// Admin authorization (SPEC addendum 2026-10-29, admin design §13.2):
// `adminAuthorized` is a boolean computed by scanstore.js from a
// validated, durable admin scan grant — never from request data. It
// is evaluated AFTER the verified cases so an admin scan of a demo or
// DNS-verified target preserves that stronger factual basis instead
// of relabelling it; for an ordinary unverified target it yields the
// full policy with the distinct authorizationState 'admin'. An admin
// scan is NOT an ownership-verified scan, and allowPrivate stays
// false: the operator override unlocks the check set, never the SSRF
// address rules.
export function policyForTarget(url, { attested = false, verified = false, selfOrigin = null, adminAuthorized = false } = {}) {
  const host = url.hostname.toLowerCase();
  if (demoHosts().includes(host)) {
    return { policy: POLICIES.full, authorizationState: 'verified', allowPrivate: true };
  }
  if (isSelfDemoTarget(url, selfOrigin)) {
    return { policy: POLICIES.full, authorizationState: 'verified', allowPrivate: false };
  }
  if (verified) {
    return { policy: POLICIES.full, authorizationState: 'verified', allowPrivate: false };
  }
  if (adminAuthorized) {
    return { policy: POLICIES.full, authorizationState: 'admin', allowPrivate: false };
  }
  return {
    policy: POLICIES.restricted,
    authorizationState: attested ? 'attested' : 'unattested',
    allowPrivate: false,
  };
}

export function createScanContext({ baseUrl, policy, authorizationState, allowPrivate = false, dnsTxtFn = null }) {
  const base = new URL(baseUrl);
  const evidence = createEvidenceStore();
  const startedAt = Date.now();
  const ctx = {
    base,
    policy,
    authorizationState,
    allowPrivate,
    evidence,
    requests: [], // audit trail of what we actually fetched (redacted)
    budgetLeft: policy.budget,
    deadlineAt: startedAt + policy.deadlineMs,
    // Join a root-relative path onto the base (the base may carry a path
    // prefix for in-app demo targets; for real targets it is the origin).
    url(path) {
      const prefix = base.pathname.replace(/\/$/, '');
      return `${base.origin}${prefix}${path}`;
    },
    host() {
      return base.hostname;
    },
    isHttps() {
      return base.protocol === 'https:';
    },
    checkBudget() {
      if (ctx.budgetLeft <= 0) throw new SafeFetchError('budget', 'Per-scan request budget exhausted');
      if (Date.now() > ctx.deadlineAt) throw new SafeFetchError('deadline', 'Total scan deadline exceeded');
    },
    async fetch(url, opts = {}) {
      ctx.checkBudget();
      ctx.budgetLeft -= 1;
      const res = await safeFetch(url, {
        timeoutMs: policy.perRequestTimeoutMs,
        sizeCapBytes: policy.sizeCapBytes,
        allowPrivate,
        ...opts,
      });
      ctx.requests.push({ url: redactUrl(url), status: res.status, at: new Date().toISOString() });
      return res;
    },
    dnsTxt: dnsTxtFn || resolveTxt,
  };
  return ctx;
}

// A whole group's failure mode: any SafeFetchError becomes Inconclusive
// results, never a Pass and never a crash (spec fixture rule).
export function inconclusiveFromError(group, check, title, err) {
  return {
    checkId: `${group}.${check}`,
    findingId: null,
    group,
    outcome: 'inconclusive',
    severity: null,
    title,
    detail: `Could not verify: ${err && err.message ? err.message : String(err)}`,
    evidenceIds: [],
    inference: false,
  };
}
