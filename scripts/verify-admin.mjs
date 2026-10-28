// Admin panel verification suite (admin design §21).
//
// Runs the REAL admin route handlers and services against a fake
// Neon adapter that dispatches on the /*ac:...*/ statement tags and
// maintains in-memory tables — the design's test plan: no live
// database is required, and none is claimed. The fake returns Date
// objects for timestamptz columns (like the real driver), records
// every statement's text + params (the sentinel scans at the end
// prove no raw password, raw session token, or raw IP is ever a
// stored value), and snapshots state around transactions so a
// failed tx rolls back.
//
// The full-policy positive flow runs against the local vulnerable
// fixture (a demo host). The unverified-target flow runs with the
// demo-host list narrowed so the same fixture is NOT a demo host:
// the grant must then derive authorizationState 'admin' with
// allowPrivate false, and the SSRF layer must make zero requests.
//
// Run: npm run verify:admin

// Environment must be set before the app modules read it (the admin
// config reads env lazily per call, but keep the discipline anyway).
delete process.env.HTTP_PROXY;
delete process.env.HTTPS_PROXY;
delete process.env.http_proxy;
delete process.env.https_proxy;
process.env.NODE_ENV = 'production';
process.env.BUNDLE_SIGNING_SECRET = 'ac-admin-verify-bundle-signing-secret';
process.env.AUDITCANVAS_DATABASE_URL = 'postgres://fake:fake@127.0.0.1:1/auditcanvas_fake';
process.env.ADMIN_CSRF_SECRET = 'ac-admin-verify-csrf-secret-0123456789abcdef';
process.env.VISITOR_HASH_SECRET = 'ac-admin-verify-visitor-secret-0123456789';
delete process.env.META_API_KEY;
delete process.env.GEMINI_API_KEY;
delete process.env.AUDITCANVAS_DEMO_HOSTS;

import { scryptSync, randomBytes } from 'node:crypto';

const TEST_PASSWORD = 'verify-only admin password 42';
{
  const salt = randomBytes(16);
  const key = scryptSync(TEST_PASSWORD, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  process.env.ADMIN_PASSWORD_HASH = `scrypt$v=1$N=16384$r=8$p=1$${salt.toString('base64url')}$${key.toString('base64url')}`;
}
const GOOD_HASH = process.env.ADMIN_PASSWORD_HASH;

const { startVulnerableHttp } = await import('../fixtures/server.mjs');
const { adminConfig } = await import('../src/lib/admin/config.js');
const { AdminStoreError, AdminStoreUnavailable, setAdminDbForTests } = await import('../src/lib/admin/db.js');
const { verifyAdminPassword, passwordInternals } = await import('../src/lib/admin/password.js');
const {
  hashSessionToken,
  validateSessionToken,
  deriveCsrfToken,
} = await import('../src/lib/admin/session.js');
const { adminSourceHash } = await import('../src/lib/admin/http.js');
const { loginWithPassword } = await import('../src/lib/admin/auth.js');
const { requireAdminApi } = await import('../src/lib/admin/guard.js');
const { startAdminScan, runAdminStep, finalizeAdminScan, listAdminHistory, getAdminRun } = await import(
  '../src/lib/admin/scans.js'
);
const { deriveScanPolicy } = await import('../src/lib/scanstore.js');
const { verifyStepBundle } = await import('../src/lib/bundlesig.js');
const { POST: loginPOST } = await import('../app/api/admin/login/route.js');
const { POST: logoutPOST } = await import('../app/api/admin/logout/route.js');
const { POST: startPOST } = await import('../app/api/admin/scans/start/route.js');
const { POST: stepPOST } = await import('../app/api/admin/scans/step/route.js');
const { POST: finalizePOST } = await import('../app/api/admin/scans/finalize/route.js');
const { GET: evidenceGET } = await import('../app/api/admin/scans/[scanId]/evidence/route.js');
const { GET: fixPackGET } = await import('../app/api/admin/scans/[scanId]/fix-pack/route.js');
const { POST: publicStartPOST } = await import('../app/api/scan/start/route.js');
const { POST: publicEvidencePOST } = await import('../app/api/scan/evidence/route.js');
const nextConfig = (await import('../next.config.mjs')).default;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
function check(name, cond, detail = '') {
  if (cond) {
    passed += 1;
    console.log(`PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// ---------------------------------------------------------------------------
// Fake Neon adapter (dispatches on the /*ac:...*/ statement tags)
// ---------------------------------------------------------------------------

function newFakeState() {
  return { sessions: new Map(), events: [], runs: new Map(), calls: [], eventSeq: 0 };
}

function tagOf(text) {
  const m = /\/\*ac:([a-z0-9.:-]+)\*\//i.exec(text);
  return m ? m[1] : null;
}

const clone = (v) => structuredClone(v);

class FakeDb {
  constructor(state = newFakeState()) {
    this.state = state;
    this.failAll = false;
    this.failNextTx = false;
    this.txSeq = 0;
  }

  async query(text, params = []) {
    if (this.failAll) throw new AdminStoreUnavailable('fake storage outage');
    return this.exec(text, params, null);
  }

  async tx(stmts) {
    if (this.failAll) throw new AdminStoreUnavailable('fake storage outage');
    if (this.failNextTx) {
      this.failNextTx = false;
      throw new AdminStoreError('fake storage failure');
    }
    const snapshot = {
      sessions: clone([...this.state.sessions]),
      events: clone(this.state.events),
      runs: clone([...this.state.runs]),
      eventSeq: this.state.eventSeq,
    };
    const txId = ++this.txSeq;
    try {
      const out = [];
      for (const s of stmts) out.push(await this.exec(s.text, s.params || [], txId));
      return out;
    } catch (err) {
      this.state.sessions = new Map(snapshot.sessions);
      this.state.events = snapshot.events;
      this.state.runs = new Map(snapshot.runs);
      this.state.eventSeq = snapshot.eventSeq;
      throw err;
    }
  }

  exec(text, params, txId) {
    const tag = tagOf(text);
    this.state.calls.push({ tag, text, params: clone(params), tx: txId });
    const st = this.state;
    switch (tag) {
      case 'meta.schemaVersion':
        return [{ value: '1' }];

      case 'sessions.insert': {
        const [id, tokenHash, nowIso, expiresIso, ipHash, browserFamily, osFamily] = params;
        st.sessions.set(id, {
          id,
          token_hash: tokenHash,
          created_at: new Date(nowIso),
          last_seen_at: new Date(nowIso),
          expires_at: new Date(expiresIso),
          revoked_at: null,
          created_ip_hash: ipHash,
          browser_family: browserFamily,
          os_family: osFamily,
        });
        return [];
      }
      case 'sessions.revokeAll': {
        const at = new Date(params[0]);
        for (const s of st.sessions.values()) if (!s.revoked_at) s.revoked_at = at;
        return [];
      }
      case 'sessions.revokeOne': {
        const s = st.sessions.get(params[0]);
        if (s && !s.revoked_at) s.revoked_at = new Date(params[1]);
        return [];
      }
      case 'sessions.byToken':
        return [...st.sessions.values()].filter((s) => s.token_hash === params[0]).map((s) => ({ ...s }));
      case 'sessions.touch': {
        const s = st.sessions.get(params[0]);
        if (s) s.last_seen_at = new Date(params[1]);
        return [];
      }

      case 'events.insert': {
        const [occurredAt, type, actorSessionId, scanId, targetHost, ipHash, browserFamily, osFamily, metadata] = params;
        st.events.push({
          id: ++st.eventSeq,
          occurred_at: new Date(occurredAt),
          event_type: type,
          actor_session_id: actorSessionId,
          scan_id: scanId,
          target_host: targetHost,
          ip_hash: ipHash,
          browser_family: browserFamily,
          os_family: osFamily,
          metadata: JSON.parse(metadata),
        });
        return [];
      }
      case 'events.lastSuccessBySource': {
        const rows = st.events
          .filter((e) => e.event_type === 'login_success' && e.ip_hash === params[0])
          .sort((a, b) => b.occurred_at - a.occurred_at || b.id - a.id);
        return rows.length ? [{ occurred_at: rows[0].occurred_at }] : [];
      }
      case 'events.failuresBySource': {
        const since = new Date(params[1]).getTime();
        return st.events
          .filter((e) => e.event_type === 'login_failure' && e.ip_hash === params[0] && e.occurred_at.getTime() > since)
          .sort((a, b) => b.occurred_at - a.occurred_at || b.id - a.id)
          .map((e) => ({ occurred_at: e.occurred_at }));
      }
      case 'events.failuresGlobal': {
        const since = new Date(params[0]).getTime();
        return st.events
          .filter((e) => e.event_type === 'login_failure' && e.occurred_at.getTime() > since)
          .sort((a, b) => b.occurred_at - a.occurred_at || b.id - a.id)
          .slice(0, 200)
          .map((e) => ({ occurred_at: e.occurred_at }));
      }
      case 'events.recent':
        return [...st.events]
          .sort((a, b) => b.occurred_at - a.occurred_at || b.id - a.id)
          .slice(0, params[0])
          .map((e) => ({ ...e, metadata: { ...e.metadata } }));

      case 'runs.insert': {
        const [scanId, target, host, display, sessionId, rescanOf, nowIso, expiresIso] = params;
        st.runs.set(scanId, {
          scan_id: scanId,
          origin: 'admin',
          target,
          target_host: host,
          target_display: display,
          authorization_state: 'admin',
          scan_policy: 'full',
          status: 'created',
          created_by_session_id: sessionId,
          rescan_of: rescanOf,
          completed_groups: [],
          step_attempts: 0,
          bundle_set_digest: null,
          risk_score: null,
          risk_grade: null,
          findings_count: null,
          confirmed_findings_count: null,
          coverage_ratio: null,
          confidence_ratio: null,
          report_json: null,
          report_sha256: null,
          error_code: null,
          created_at: new Date(nowIso),
          updated_at: new Date(nowIso),
          expires_at: new Date(expiresIso),
          finalized_at: null,
        });
        return [];
      }
      case 'runs.countActiveForSession': {
        const now = new Date(params[1]).getTime();
        const n = [...st.runs.values()].filter(
          (r) => r.created_by_session_id === params[0] && (r.status === 'created' || r.status === 'running') && r.expires_at.getTime() > now
        ).length;
        return [{ n }];
      }
      case 'runs.countStartsSince': {
        const since = new Date(params[0]).getTime();
        return [{ n: [...st.runs.values()].filter((r) => r.created_at.getTime() > since).length }];
      }
      case 'runs.byId': {
        const r = st.runs.get(params[0]);
        return r ? [{ ...r, completed_groups: [...r.completed_groups], report_json: clone(r.report_json) }] : [];
      }
      case 'runs.recordStep': {
        const r = st.runs.get(params[0]);
        if (r) {
          r.status = 'running';
          r.step_attempts += 1;
          if (!r.completed_groups.includes(params[1])) r.completed_groups.push(params[1]);
          r.updated_at = new Date(params[2]);
        }
        return [];
      }
      case 'runs.fail': {
        const r = st.runs.get(params[0]);
        if (r && r.status !== 'finalized') {
          r.status = 'failed';
          r.error_code = params[1];
          r.updated_at = new Date(params[2]);
        }
        return [];
      }
      case 'runs.finalize': {
        const r = st.runs.get(params[0]);
        if (r) {
          r.status = 'finalized';
          r.bundle_set_digest = params[1];
          r.risk_score = params[2];
          r.risk_grade = params[3];
          r.findings_count = params[4];
          r.confirmed_findings_count = params[5];
          r.coverage_ratio = params[6];
          r.confidence_ratio = params[7];
          r.report_json = JSON.parse(params[8]);
          r.report_sha256 = params[9];
          r.finalized_at = new Date(params[10]);
          r.updated_at = new Date(params[10]);
        }
        return [];
      }
      case 'runs.history': {
        const [status, host, cAt, cId, limitPlus, nowIso] = params;
        const now = new Date(nowIso).getTime();
        let rows = [...st.runs.values()].sort(
          (a, b) => b.created_at - a.created_at || (a.scan_id < b.scan_id ? 1 : -1)
        );
        rows = rows.filter((r) => {
          if (status != null) {
            if (status === 'expired') {
              if (!((r.status === 'created' || r.status === 'running') && r.expires_at.getTime() <= now)) return false;
            } else if (r.status !== status) return false;
          }
          if (host != null && r.target_host !== host) return false;
          if (cAt != null) {
            const c = new Date(cAt).getTime();
            const t = r.created_at.getTime();
            if (!(t < c || (t === c && r.scan_id < cId))) return false;
          }
          return true;
        });
        return rows.slice(0, limitPlus).map((r) => ({
          scan_id: r.scan_id,
          origin: r.origin,
          target: r.target,
          target_host: r.target_host,
          target_display: r.target_display,
          authorization_state: r.authorization_state,
          scan_policy: r.scan_policy,
          status: r.status,
          created_by_session_id: r.created_by_session_id,
          rescan_of: r.rescan_of,
          completed_groups: [...r.completed_groups],
          step_attempts: r.step_attempts,
          bundle_set_digest: r.bundle_set_digest,
          risk_score: r.risk_score,
          risk_grade: r.risk_grade,
          findings_count: r.findings_count,
          confirmed_findings_count: r.confirmed_findings_count,
          coverage_ratio: r.coverage_ratio,
          confidence_ratio: r.confidence_ratio,
          report_sha256: r.report_sha256,
          error_code: r.error_code,
          created_at: r.created_at,
          updated_at: r.updated_at,
          expires_at: r.expires_at,
          finalized_at: r.finalized_at,
          report_authorization_state: r.report_json ? r.report_json.authorizationState ?? null : null,
        }));
      }

      default:
        throw new Error(`FakeDb: unhandled statement tag ${tag}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

const ORIGIN = 'https://auditcanvas.test';
const TEST_IP = '203.0.113.77';
const RAW_TOKENS = [];

function makeReq(path, { method = 'POST', body, cookie, csrf, origin = ORIGIN, ip = TEST_IP } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  if (csrf) headers['x-ac-csrf'] = csrf;
  if (origin) headers.origin = origin;
  if (ip) headers['x-forwarded-for'] = ip;
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

const cookieFor = (token) => `__Host-ac_admin_session=${token}`;

async function loginViaRoute(password, opts = {}) {
  const res = await loginPOST(makeReq('/api/admin/login', { body: { password }, ...opts }));
  const setCookie = res.headers.get('set-cookie') || '';
  const m = /__Host-ac_admin_session=([A-Za-z0-9_-]{43})/.exec(setCookie);
  const token = m ? m[1] : null;
  if (token) RAW_TOKENS.push(token);
  const body = await res.json().catch(() => null);
  return { res, setCookie, token, body };
}

// Boot the vulnerable fixture (a demo host at its default address).
const fixture = await startVulnerableHttp(80);

// ===========================================================================
// §21.1 Password verification
// ===========================================================================
{
  check('password: the correct password verifies', verifyAdminPassword(TEST_PASSWORD, GOOD_HASH) === true);
  check('password: a wrong password does not verify', verifyAdminPassword('not the password', GOOD_HASH) === false);

  const parts = GOOD_HASH.split('$');
  const keyPart = parts[6];
  const tamperedKey = (keyPart[0] === 'A' ? 'B' : 'A') + keyPart.slice(1);
  const tampered = [...parts.slice(0, 6), tamperedKey].join('$');
  check('password: one altered key character fails', verifyAdminPassword(TEST_PASSWORD, tampered) === false);

  const wrongN = GOOD_HASH.replace('N=16384', 'N=32768');
  check('password: a changed cost parameter is rejected as unsupported', verifyAdminPassword(TEST_PASSWORD, wrongN) === false);

  const shortSalt = [...parts.slice(0, 5), parts[5].slice(0, 8), parts[6]].join('$');
  check('password: a truncated salt is rejected', verifyAdminPassword(TEST_PASSWORD, shortSalt) === false);
  check('password: a malformed hash never verifies', verifyAdminPassword(TEST_PASSWORD, 'scrypt$v=1') === false);
  check('password: an empty stored hash never verifies', verifyAdminPassword(TEST_PASSWORD, '') === false);

  const before = passwordInternals.deriveCount;
  const longResult = verifyAdminPassword('x'.repeat(129), GOOD_HASH);
  check(
    'password: >128 chars rejected BEFORE scrypt runs',
    longResult === false && passwordInternals.deriveCount === before,
    `deriveCount ${before} -> ${passwordInternals.deriveCount}`
  );
}

// ===========================================================================
// Config gate (§6): missing env -> inert admin, generic 503s
// ===========================================================================
const state = newFakeState();
const db = new FakeDb(state);
setAdminDbForTests(db);
{
  delete process.env.ADMIN_PASSWORD_HASH;
  const cfg = adminConfig();
  check('config: missing ADMIN_PASSWORD_HASH leaves admin unconfigured', cfg.configured === false && cfg.missing.includes('ADMIN_PASSWORD_HASH'));
  const loginRes = await loginViaRoute(TEST_PASSWORD);
  check('config: login is 503 with the generic error while unconfigured',
    loginRes.res.status === 503 && loginRes.body && loginRes.body.error === 'Admin is not configured.');
  const startRes = await startPOST(makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' } }));
  check('config: admin scan start is 503 while unconfigured', startRes.status === 503);
  process.env.ADMIN_PASSWORD_HASH = GOOD_HASH;
  check('config: admin is configured once every variable is set', adminConfig().configured === true);
}

// ===========================================================================
// §21.6 Unauthenticated negatives: flat 401, no policy, no state
// ===========================================================================
{
  const runsBefore = state.runs.size;
  const attempts = [
    ['start', await startPOST(makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' } }))],
    ['step', await stepPOST(makeReq('/api/admin/scans/step', { body: { scanId: 'A'.repeat(24), target: 'http://127.0.0.1/', group: 'headers' } }))],
    ['finalize', await finalizePOST(makeReq('/api/admin/scans/finalize', { body: { scan: { scanId: 'A'.repeat(24) }, bundles: [] } }))],
    ['logout', await logoutPOST(makeReq('/api/admin/logout', { body: {} }))],
    ['evidence', await evidenceGET(makeReq('/api/admin/scans/x/evidence', { method: 'GET', body: undefined }), { params: { scanId: 'A'.repeat(24) } })],
    ['fix-pack', await fixPackGET(makeReq('/api/admin/scans/x/fix-pack', { method: 'GET', body: undefined }), { params: { scanId: 'A'.repeat(24) } })],
  ];
  for (const [name, res] of attempts) {
    const body = await res.json().catch(() => null);
    check(
      `unauthenticated: ${name} is a flat generic 401 with no policy payload`,
      res.status === 401 &&
        body && body.error === 'Admin authentication required.' &&
        !('scanPolicy' in body) && !('groups' in body) && !('policy' in body),
      `status ${res.status}`
    );
  }
  check('unauthenticated: no scan grants were created', state.runs.size === runsBefore);
}

// ===========================================================================
// §21.2 / §8 Login, session rotation, fixation, logout
// ===========================================================================
let session1;
let csrf1;
{
  const wrong = await loginViaRoute('definitely wrong');
  check('login: wrong password is 401 with exactly the generic error',
    wrong.res.status === 401 && wrong.body && wrong.body.error === 'Invalid password.' && Object.keys(wrong.body).length === 1);
  check('login: the failure is audit-logged', state.events.some((e) => e.event_type === 'login_failure'));

  const noOriginDerives = passwordInternals.deriveCount;
  const noOrigin = await loginViaRoute(TEST_PASSWORD, { origin: null });
  check('login: missing Origin in production is rejected BEFORE scrypt',
    noOrigin.res.status === 403 && passwordInternals.deriveCount === noOriginDerives);

  const good = await loginViaRoute(TEST_PASSWORD);
  check('login: correct password succeeds', good.res.status === 200 && good.body && good.body.ok === true);
  check('cookie: __Host- name, HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age=43200, no Domain',
    good.setCookie.includes('__Host-ac_admin_session=') &&
      good.setCookie.includes('HttpOnly') &&
      good.setCookie.includes('Secure') &&
      good.setCookie.includes('SameSite=Lax') &&
      good.setCookie.includes('Path=/') &&
      good.setCookie.includes('Max-Age=43200') &&
      !good.setCookie.includes('Domain='));
  const token1 = good.token;
  check('session: the stored row holds the token HASH, never the raw token',
    state.sessions.size === 1 &&
      [...state.sessions.values()][0].token_hash === hashSessionToken(token1) &&
      ![...state.sessions.values()].some((s) => JSON.stringify(s).includes(token1)));

  session1 = await validateSessionToken(db, token1);
  check('session: the issued token validates against the store', !!session1);
  csrf1 = deriveCsrfToken(adminConfig().csrfSecret, session1);

  // Fixation: a planted cookie value must never become the session.
  const attackerToken = 'F'.repeat(43);
  const planted = await loginViaRoute(TEST_PASSWORD, { cookie: cookieFor(attackerToken) });
  check('fixation: login mints a fresh token, never the planted one',
    planted.res.status === 200 && planted.token && planted.token !== attackerToken);
  check('fixation: the planted token does not validate', (await validateSessionToken(db, attackerToken)) === null);
  check('rotation: the second login revoked the first session',
    (await validateSessionToken(db, token1)) === null && (await validateSessionToken(db, planted.token)) !== null);

  // Expiry: absolute 12h, and last_seen touch never extends it.
  const live = await validateSessionToken(db, planted.token);
  const expired = await validateSessionToken(db, planted.token, { now: Date.now() + 13 * 60 * 60 * 1000 });
  check('session: an expired session is rejected like an unknown one', live !== null && expired === null);
  const guardExpired = await requireAdminApi(
    makeReq('/api/admin/scans/start', { body: {}, cookie: cookieFor(planted.token), csrf: 'x'.repeat(43) }),
    { now: Date.now() + 13 * 60 * 60 * 1000 }
  );
  check('session: the API guard returns the same generic 401 for an expired session',
    guardExpired.ok === false && guardExpired.response.status === 401);

  // Logout: revoke + event + cleared cookie; replay is unknown.
  const logoutRes = await logoutPOST(
    makeReq('/api/admin/logout', { body: {}, cookie: cookieFor(planted.token), csrf: deriveCsrfToken(adminConfig().csrfSecret, live) })
  );
  const logoutBody = await logoutRes.json().catch(() => null);
  check('logout: succeeds and clears the cookie',
    logoutRes.status === 200 && logoutBody && logoutBody.ok === true &&
      (logoutRes.headers.get('set-cookie') || '').includes('Max-Age=0'));
  check('logout: the event is recorded', state.events.some((e) => e.event_type === 'logout'));
  const replay = await startPOST(
    makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' }, cookie: cookieFor(planted.token), csrf: 'x'.repeat(43) })
  );
  check('logout: replaying the revoked cookie is a generic 401', replay.status === 401);

  // Storage failure fails closed.
  db.failAll = true;
  const downLogin = await loginViaRoute(TEST_PASSWORD);
  check('storage: login during a storage outage is a generic 503, never a session',
    downLogin.res.status === 503 && downLogin.body && downLogin.body.error === 'Admin storage unavailable.');
  db.failAll = false;

  // Re-login for the CSRF + flow sections.
  const again = await loginViaRoute(TEST_PASSWORD);
  session1 = await validateSessionToken(db, again.token);
  csrf1 = deriveCsrfToken(adminConfig().csrfSecret, session1);
  var adminCookie = cookieFor(again.token); // eslint-disable-line no-var
}

// ===========================================================================
// §21.3 Durable exponential backoff (service level, explicit clock)
// ===========================================================================
{
  const cfg = adminConfig();
  const bState = newFakeState();
  const bDb = new FakeDb(bState);
  const ip = '192.0.2.55';
  const t0 = Date.now();
  const attempt = (pw, now, dbInst = bDb) =>
    loginWithPassword(makeReq('/api/admin/login', { body: { password: pw }, ip }), { db: dbInst, cfg, now });

  for (let i = 0; i < 4; i += 1) {
    const r = await attempt('wrong', t0 + i * 1000);
    check(`backoff: failure ${i + 1} of 4 is a plain 401`, r.status === 401);
  }
  const derivesBefore5 = passwordInternals.deriveCount;
  const fifth = await attempt('wrong', t0 + 4000);
  check('backoff: the 5th failure still runs the password check', fifth.status === 401 && passwordInternals.deriveCount === derivesBefore5 + 1);

  const derivesBeforeLimited = passwordInternals.deriveCount;
  const limited = await attempt(TEST_PASSWORD, t0 + 5000);
  check('backoff: during the delay even the CORRECT password is 429 with Retry-After',
    limited.status === 429 && typeof limited.retryAfterSec === 'number' && limited.retryAfterSec >= 1,
    `status ${limited.status}`);
  check('backoff: a rate-limited attempt never runs scrypt', passwordInternals.deriveCount === derivesBeforeLimited);

  // Durability: a fresh service-side instance over the SAME tables
  // still sees the backoff (no in-memory counters involved).
  const otherInstance = new FakeDb(bState);
  const stillLimited = await attempt(TEST_PASSWORD, t0 + 6000, otherInstance);
  check('backoff: the delay survives a fresh instance over the same store', stillLimited.status === 429);

  const after = await attempt(TEST_PASSWORD, t0 + 10000);
  check('backoff: login succeeds once the delay has passed', after.status === 200);
  const reset = await attempt('wrong', t0 + 11000);
  check('backoff: a success resets the consecutive-failure count', reset.status === 401);

  // Global circuit breaker: 50 failures from 50 distinct sources.
  const gState = newFakeState();
  const gDb = new FakeDb(gState);
  for (let i = 0; i < 50; i += 1) {
    await loginWithPassword(
      makeReq('/api/admin/login', { body: { password: 'wrong' }, ip: `198.51.100.${i + 1}` }),
      { db: gDb, cfg, now: t0 }
    );
  }
  const derivesBeforeBreaker = passwordInternals.deriveCount;
  const breaker = await loginWithPassword(
    makeReq('/api/admin/login', { body: { password: TEST_PASSWORD }, ip: '203.0.113.200' }),
    { db: gDb, cfg, now: t0 }
  );
  check('backoff: the global breaker (50 failures / 15 min) rejects a fresh source',
    breaker.status === 429 && passwordInternals.deriveCount === derivesBeforeBreaker);
  check('backoff: the breaker rejection is logged with global scope',
    gState.events.some((e) => e.event_type === 'login_rate_limited' && e.metadata && e.metadata.scope === 'global'));
}

// ===========================================================================
// §21.4 CSRF + origin battery on the admin scan start route
// ===========================================================================
{
  const runsBefore = state.runs.size;
  const startAttempt = (over) =>
    startPOST(makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' }, cookie: adminCookie, csrf: csrf1, ...over }));

  const noCsrf = await startAttempt({ csrf: undefined });
  check('csrf: a missing token is 403', noCsrf.status === 403, `status ${noCsrf.status}`);
  const wrongCsrf = await startAttempt({ csrf: 'A'.repeat(43) });
  check('csrf: a wrong token is 403', wrongCsrf.status === 403);
  const foreignCsrf = await startAttempt({ csrf: deriveCsrfToken(adminConfig().csrfSecret, { id: 'other-session', tokenHash: 'f'.repeat(64) }) });
  check('csrf: a token derived for another session is 403', foreignCsrf.status === 403);
  const altered = csrf1.slice(0, -1) + (csrf1.endsWith('A') ? 'B' : 'A');
  const alteredCsrf = await startAttempt({ csrf: altered });
  check('csrf: a one-character-altered token is 403', alteredCsrf.status === 403);
  const crossOrigin = await startAttempt({ origin: 'https://evil.example' });
  check('csrf: a cross-origin POST is 403 even with a valid token', crossOrigin.status === 403);
  const noOriginReq = await startAttempt({ origin: null });
  check('csrf: a missing Origin in production is 403', noOriginReq.status === 403);

  check('csrf: rejected attempts created zero grants', state.runs.size === runsBefore);
  check('csrf: rejections are audit-logged with the route class',
    state.events.some((e) => e.event_type === 'csrf_rejected' && e.metadata && e.metadata.route === 'scan-start'));
}

// ===========================================================================
// Full admin flow on the demo target (verified basis preserved)
// ===========================================================================
let demoReport;
let demoScanId;
{
  const startRes = await startPOST(
    makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' }, cookie: adminCookie, csrf: csrf1 })
  );
  const start = await startRes.json();
  check('flow: admin start returns a full-policy descriptor with admin origin',
    startRes.status === 200 && start.origin === 'admin' && start.scanPolicy === 'full' && start.policy && start.policy.name === 'full');
  check('flow: a demo-host target keeps its VERIFIED basis under an admin grant',
    start.authorizationState === 'verified' && start.verification === null);
  demoScanId = start.scanId;

  const bundles = new Map();
  let stepError = '';
  for (const g of start.groups) {
    // 'headers' is deliberately stepped twice: completion is a set.
    const reps = g.id === 'headers' ? 2 : 1;
    for (let i = 0; i < reps; i += 1) {
      const res = await stepPOST(
        makeReq('/api/admin/scans/step', { body: { scanId: demoScanId, target: start.target, group: g.id }, cookie: adminCookie, csrf: csrf1 })
      );
      const bundle = await res.json().catch(() => null);
      if (res.status !== 200 || !bundle || !bundle.sig) { stepError = `${g.id}: status ${res.status}`; break; }
      if (!verifyStepBundle(bundle, { scanId: demoScanId, target: start.target })) { stepError = `${g.id}: bad sig`; break; }
      bundles.set(g.id, bundle);
    }
    if (stepError) break;
  }
  check('flow: every group step returns a verifiable signed bundle', !stepError, stepError);
  const runAfterSteps = await getAdminRun(db, demoScanId);
  check('flow: completed_groups is a set (9 unique) while step_attempts counts retries (10)',
    runAfterSteps.completedGroups.length === 9 && runAfterSteps.stepAttempts === 10,
    `groups ${runAfterSteps.completedGroups.length}, attempts ${runAfterSteps.stepAttempts}`);

  const finRes = await finalizePOST(
    makeReq('/api/admin/scans/finalize', { body: { scan: { scanId: demoScanId }, bundles: [...bundles.values()] }, cookie: adminCookie, csrf: csrf1 })
  );
  demoReport = await finRes.json().catch(() => null);
  check('flow: finalize returns the report', finRes.status === 200 && !!demoReport, `status ${finRes.status}`);
  check('provenance: report origin/provenance are admin/server-admin',
    demoReport.origin === 'admin' && demoReport.provenance === 'server-admin');
  check('provenance: stamp carries origin + authorizationState',
    demoReport.stamp.origin === 'admin' && demoReport.stamp.authorizationState === 'verified');
  check('provenance: the report keeps the verified basis (never relabelled)',
    demoReport.authorizationState === 'verified');
  const auditEntry = (demoReport.auditLog || []).find((e) => e.event === 'scan-created');
  check('provenance: the admin audit entry records basis + source hash, never a raw IP',
    !!auditEntry && auditEntry.origin === 'admin' && auditEntry.policyBasis === 'admin-session-grant' &&
      auditEntry.requesterIpHash === adminSourceHash(adminConfig().visitorHashSecret, TEST_IP) &&
      !JSON.stringify(demoReport).includes(TEST_IP));

  const stored = await getAdminRun(db, demoScanId);
  check('persistence: the finalized run stores the report + matching summary',
    stored.storedStatus === 'finalized' && !!stored.report &&
      stored.riskScore === demoReport.scores.risk.score &&
      stored.riskGrade === demoReport.scores.risk.grade &&
      stored.findingsCount === demoReport.scores.counts.findings &&
      typeof stored.reportSha256 === 'string' && stored.reportSha256.length === 64);

  // Idempotent repeat finalize: same bundles -> the stored report.
  const againRes = await finalizePOST(
    makeReq('/api/admin/scans/finalize', { body: { scan: { scanId: demoScanId }, bundles: [...bundles.values()] }, cookie: adminCookie, csrf: csrf1 })
  );
  const againReport = await againRes.json().catch(() => null);
  check('finalize: a repeat finalize returns the identical stored report',
    againRes.status === 200 && JSON.stringify(againReport) === JSON.stringify(demoReport));

  // A different bundle set for a finalized run is a 409.
  const tampered = [...bundles.values()].map((b) => ({ ...b }));
  tampered[0] = { ...tampered[0], results: tampered[0].results.map((r, i) => (i === 0 ? { ...r, title: 'tampered' } : r)) };
  const conflictRes = await finalizePOST(
    makeReq('/api/admin/scans/finalize', { body: { scan: { scanId: demoScanId }, bundles: tampered }, cookie: adminCookie, csrf: csrf1 })
  );
  check('finalize: a different bundle set for a finalized run is 409', conflictRes.status === 409);

  // Downloads come from the stored report only.
  const evRes = await evidenceGET(
    makeReq('/api/admin/scans/x/evidence', { method: 'GET', body: undefined, cookie: adminCookie }),
    { params: { scanId: demoScanId } }
  );
  const evBundle = await evRes.json().catch(() => null);
  check('downloads: the evidence bundle is built from the stored admin report',
    evRes.status === 200 && evBundle && evBundle.origin === 'admin' && evBundle.provenance === 'server-admin');
  const evidenceIds = new Set((evBundle.evidence || []).map((e) => e.id));
  const unresolved = (evBundle.results || []).flatMap((r) => r.evidenceIds || []).filter((id) => !evidenceIds.has(id));
  check('downloads: every result evidence id resolves in the bundle', unresolved.length === 0, unresolved.join(','));
  const zipRes = await fixPackGET(
    makeReq('/api/admin/scans/x/fix-pack', { method: 'GET', body: undefined, cookie: adminCookie }),
    { params: { scanId: demoScanId } }
  );
  const zipBytes = new Uint8Array(await zipRes.arrayBuffer());
  check('downloads: the fix pack is a ZIP built from the stored report',
    zipRes.status === 200 && (zipRes.headers.get('content-type') || '').includes('application/zip') &&
      zipBytes[0] === 0x50 && zipBytes[1] === 0x4b);
  check('downloads: report_downloaded events are recorded without report bodies',
    state.events.some((e) => e.event_type === 'report_downloaded' && e.metadata && e.metadata.kind === 'evidence'));

  // History + persistence across a fresh adapter over the same tables.
  const history = await listAdminHistory(db, {});
  check('history: the finalized scan is listed with its report authorization state',
    history.rows.some((r) => r.scanId === demoScanId && r.reportAuthorizationState === 'verified'));
  const freshAdapter = new FakeDb(state);
  const reopened = await getAdminRun(freshAdapter, demoScanId);
  check('persistence: the report survives a fresh adapter instance (no in-memory state)',
    !!reopened && !!reopened.report && reopened.report.scanId === demoScanId);
}

// ===========================================================================
// Unverified target under admin: authorizationState 'admin', SSRF intact.
// (Demo-host list narrowed so the fixture is NOT a demo host here.)
// ===========================================================================
process.env.AUDITCANVAS_DEMO_HOSTS = 'localhost';
{
  const cfg = adminConfig();
  const startRes = await startPOST(
    makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' }, cookie: adminCookie, csrf: csrf1 })
  );
  const start = await startRes.json();
  check('unverified: admin start derives full policy with authorizationState admin',
    startRes.status === 200 && start.scanPolicy === 'full' && start.authorizationState === 'admin' && start.verification === null);

  const stepRes = await stepPOST(
    makeReq('/api/admin/scans/step', { body: { scanId: start.scanId, target: start.target, group: 'headers' }, cookie: adminCookie, csrf: csrf1 })
  );
  const bundle = await stepRes.json().catch(() => null);
  check('ssrf: an admin step toward a private target makes ZERO requests (allowPrivate stays false)',
    stepRes.status === 200 && bundle && Array.isArray(bundle.requests) && bundle.requests.length === 0 && bundle.results.every((r) => r.outcome === 'inconclusive'),
    bundle ? `requests ${JSON.stringify(bundle.requests)} status ${stepRes.status} body ${JSON.stringify(bundle).slice(0, 160)}` : 'no bundle');

  const bundles = new Map([['headers', bundle]]);
  for (const g of start.groups) {
    if (g.id === 'headers') continue;
    const res = await stepPOST(
      makeReq('/api/admin/scans/step', { body: { scanId: start.scanId, target: start.target, group: g.id }, cookie: adminCookie, csrf: csrf1 })
    );
    bundles.set(g.id, await res.json());
  }
  const finRes = await finalizePOST(
    makeReq('/api/admin/scans/finalize', { body: { scan: { scanId: start.scanId }, bundles: [...bundles.values()] }, cookie: adminCookie, csrf: csrf1 })
  );
  const report = await finRes.json().catch(() => null);
  check("unverified: the finalized report states authorizationState 'admin' (never 'verified')",
    finRes.status === 200 && report && report.authorizationState === 'admin' && report.verification === null &&
      report.origin === 'admin' && report.scanPolicy === 'full',
    `status ${finRes.status} body ${JSON.stringify(report).slice(0, 200)}`);

  // Cloud metadata address under admin derivation: full policy on
  // paper, but the fetch layer still refuses the address class.
  const metaGrant = {
    origin: 'admin',
    scanId: 'A'.repeat(24),
    sessionId: session1.id,
    target: 'http://169.254.169.254/',
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  };
  const derived = deriveScanPolicy(new URL('http://169.254.169.254/'), { adminGrant: metaGrant });
  check('ssrf: derivation for a link-local target keeps allowPrivate false',
    derived.authorizationState === 'admin' && derived.allowPrivate === false && derived.policy.name === 'full');
  const metaStart = await startAdminScan(makeReq('/api/admin/scans/start', { body: { url: 'http://169.254.169.254/' } }), { db, cfg, session: session1 });
  const metaStep = await runAdminStep(
    makeReq('/api/admin/scans/step', { body: { scanId: metaStart.json.scanId, target: 'http://169.254.169.254/', group: 'headers' } }),
    { db, cfg, session: session1 }
  );
  check('ssrf: a step toward 169.254.169.254 makes zero requests',
    metaStep.status === 200 && Array.isArray(metaStep.json.requests) && metaStep.json.requests.length === 0);

  // Public routes ignore admin authority completely (§21.6).
  const pubRes = await publicStartPOST(
    makeReq('/api/scan/start', {
      body: { url: 'http://127.0.0.1/', admin: true, origin: 'admin', scanPolicy: 'full', authorizationState: 'admin', allowPrivate: true },
      cookie: adminCookie,
    })
  );
  const pubBody = await pubRes.json().catch(() => null);
  check('public: admin-looking fields + the admin cookie change NOTHING on the public path',
    pubRes.status === 200 && pubBody && pubBody.scanPolicy === 'restricted' && !('origin' in pubBody),
    pubBody ? `policy ${pubBody.scanPolicy}` : 'no body');

  // A client-supplied report claiming admin provenance is stripped
  // by the public bare-download path.
  const forged = { ...demoReport, origin: 'admin', provenance: 'server-admin' };
  const bareRes = await publicEvidencePOST(makeReq('/api/scan/evidence', { body: { report: forged } }));
  const bareBundle = await bareRes.json().catch(() => null);
  check('public: a bare report claiming admin origin is downgraded to client-supplied-unverified',
    bareRes.status === 200 && bareBundle && bareBundle.provenance === 'client-supplied-unverified' && bareBundle.origin === 'public',
    bareBundle ? `provenance ${bareBundle.provenance}` : 'no bundle');
}
delete process.env.AUDITCANVAS_DEMO_HOSTS;

// ===========================================================================
// §21.5 Grant binding battery (service level)
// ===========================================================================
{
  const cfg = adminConfig();
  const start = await startAdminScan(makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' } }), { db, cfg, session: session1 });
  const scanId = start.json.scanId;
  const stepBody = { scanId, target: 'http://127.0.0.1/', group: 'headers' };

  const wrongSession = await runAdminStep(makeReq('/api/admin/scans/step', { body: stepBody }), {
    db, cfg, session: { id: '00000000-0000-4000-8000-000000000000' },
  });
  check('grant: a step from a different session is a generic 404', wrongSession.status === 404);

  const wrongTarget = await runAdminStep(
    makeReq('/api/admin/scans/step', { body: { ...stepBody, target: 'http://127.0.0.1/other' } }),
    { db, cfg, session: session1 }
  );
  check('grant: a step against a different target is a generic 404', wrongTarget.status === 404);

  const unknownGroup = await runAdminStep(
    makeReq('/api/admin/scans/step', { body: { ...stepBody, group: 'nope' } }),
    { db, cfg, session: session1 }
  );
  check('grant: an unknown group is 400', unknownGroup.status === 400);

  const unknownScan = await runAdminStep(
    makeReq('/api/admin/scans/step', { body: { ...stepBody, scanId: 'Z'.repeat(24) } }),
    { db, cfg, session: session1 }
  );
  check('grant: an unknown scan id is the same generic 404', unknownScan.status === 404);

  const t0 = Date.now();
  const expStart = await startAdminScan(makeReq('/api/admin/scans/start', { body: { url: 'http://127.0.0.1/' } }), { db, cfg, session: session1, now: t0 });
  const expired = await runAdminStep(
    makeReq('/api/admin/scans/step', { body: { scanId: expStart.json.scanId, target: 'http://127.0.0.1/', group: 'headers' } }),
    { db, cfg, session: session1, now: t0 + 31 * 60 * 1000 }
  );
  check('grant: a step after the 30-minute grant expiry is 410', expired.status === 410, `status ${expired.status}`);

  const incomplete = await finalizeAdminScan(
    makeReq('/api/admin/scans/finalize', { body: { scan: { scanId }, bundles: [] } }),
    { db, cfg, session: session1 }
  );
  check('grant: finalize before every group is recorded is rejected', incomplete.status === 400, `status ${incomplete.status}`);
  const stillOpen = await getAdminRun(db, scanId);
  check('grant: the rejected finalize neither finalizes nor fails the run',
    stillOpen.storedStatus === 'created' && !stillOpen.report);

  db.failNextTx = true;
  const failedStep = await runAdminStep(makeReq('/api/admin/scans/step', { body: stepBody }), { db, cfg, session: session1 });
  check('grant: a storage failure during step recording is 503 and returns no bundle as progress',
    failedStep.status === 503 && !('sig' in failedStep.json));
  const afterFailure = await getAdminRun(db, scanId);
  check('grant: the failed step recorded nothing', afterFailure.completedGroups.length === 0 && afterFailure.stepAttempts === 0);
}

// ===========================================================================
// §21.11 Headers: config rules + live admin responses
// ===========================================================================
{
  const rules = await nextConfig.headers();
  const adminApi = rules.find((r) => r.source === '/api/admin/:path*');
  const adminPages = rules.find((r) => r.source === '/admin/:path*');
  const asMap = (rule) => Object.fromEntries((rule ? rule.headers : []).map((h) => [h.key, h.value]));
  const apiH = asMap(adminApi);
  check('headers: /admin and /api/admin rules exist in next.config', !!adminApi && !!adminPages);
  check('headers: admin CSP forbids framing and the cache is no-store',
    (apiH['Content-Security-Policy'] || '').includes("frame-ancestors 'none'") &&
      apiH['Cache-Control'] === 'no-store, max-age=0' &&
      apiH['X-Frame-Options'] === 'DENY');
  check('headers: admin X-Robots-Tag is noindex, nofollow, noarchive',
    apiH['X-Robots-Tag'] === 'noindex, nofollow, noarchive');

  const probe = await loginViaRoute('wrong again');
  check('headers: live admin API responses carry no-store + noarchive',
    (probe.res.headers.get('cache-control') || '').includes('no-store') &&
      (probe.res.headers.get('x-robots-tag') || '').includes('noarchive'));
}

// ===========================================================================
// Sentinel sweep: no raw secret is ever a stored value (§21.1/§21.2)
// ===========================================================================
{
  const haystack =
    JSON.stringify(state.calls) +
    JSON.stringify([...state.sessions.values()]) +
    JSON.stringify(state.events) +
    JSON.stringify([...state.runs.values()]);
  check('sentinel: the test password appears in NO recorded statement, param, or row', !haystack.includes(TEST_PASSWORD));
  check('sentinel: no raw session token appears in any stored value',
    RAW_TOKENS.length >= 3 && RAW_TOKENS.every((t) => !haystack.includes(t)));
  check('sentinel: the raw client IP appears in NO recorded statement, param, or row', !haystack.includes(TEST_IP));
  check('sentinel: stored session rows contain only 64-hex token hashes',
    [...state.sessions.values()].every((s) => /^[0-9a-f]{64}$/.test(s.token_hash)));
}

// ---------------------------------------------------------------------------

fixture.close();
console.log(`\n[verify-admin] ${passed}/${passed + failed} assertions passed`);
process.exit(failed ? 1 : 0);
