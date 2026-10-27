// Scan policies and the per-scan context (budget, deadline, evidence).
//
// SPEC.md: "Restricted by default. Unverified targets get a passive-only
// scan policy with small budgets, whatever the user attests." Verified
// targets (DNS TXT, one method) and our own allowlisted demo hosts get
// the full check set. The DNS TXT flow lands after Night 0; until then
// only server-allowlisted demo hosts resolve to the full policy.
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

// authorizationState: 'verified' (allowlisted demo host for now; DNS TXT
// verified later) or 'attested' / 'unattested' for user targets, which
// always run restricted until verification exists.
export function policyForTarget(url, { attested = false } = {}) {
  const host = url.hostname.toLowerCase();
  if (demoHosts().includes(host)) {
    return { policy: POLICIES.full, authorizationState: 'verified', allowPrivate: true };
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
