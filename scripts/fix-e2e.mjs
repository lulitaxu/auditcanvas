// HTTP end-to-end proof for the 2026-10-29 sweep fixes (H1/H2/M4).
//
// Boots the production build (`npm run build` first) on a scratch
// port and drives the REAL signed scan flow against the built-in
// demo target: /start -> /step x8 (bundles come back HMAC-signed) ->
// /finalize. Then attacks it the way the sweep did:
//
//   (a) finalize with the signatures stripped        -> 400, no report
//   (b) finalize with a finding deleted post-signing -> 400
//   (c) finalize with the bundles under another scan -> 400
//   (d) finalize the identical payload again         -> 200, cache
//       header "hit", body byte-identical to the first finalize
//   (e) downloads: a bare forged report (inflated scores, fake
//       stamp, dangling evidence ref) comes back recomputed,
//       re-stamped, integrity unverified; the same download WITH
//       the signed chain returns the server's own integrity ok:true
//
// Usage: node scripts/fix-e2e.mjs   (requires a prior `npm run build`)
import { spawn } from 'node:child_process';
import fs from 'node:fs';

// The scanner only speaks ports 80/443 (SPEC.md), so the scratch
// server binds port 80 on loopback.
const PORT = 80;
const ORIGIN = 'http://127.0.0.1';
const TARGET = `${ORIGIN}/api/demo-target`;

if (!fs.existsSync(new URL('../.next/BUILD_ID', import.meta.url))) {
  console.error('[fix-e2e] no production build found — run `npm run build` first.');
  process.exit(2);
}

const results = [];
function check(name, cond, detail = '') {
  results.push({ name, pass: Boolean(cond) });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : ` — ${detail}`}`);
}

const server = spawn('npx', ['next', 'start', '-p', String(PORT)], {
  cwd: new URL('..', import.meta.url).pathname,
  env: { ...process.env, BUNDLE_SIGNING_SECRET: 'fix-e2e-throwaway-secret' },
  stdio: 'pipe',
  detached: true, // kill the whole process group in the finally block
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });

async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${ORIGIN}/api/samples`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function post(path, body) {
  const res = await fetch(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, headers: res.headers, text, json };
}

const clone = (v) => JSON.parse(JSON.stringify(v));

try {
  check('server boots (production build)', await waitReady(), serverLog.slice(-400));

  // --- the real signed flow -------------------------------------------
  const start = await post('/api/scan/start', { url: TARGET, attested: true });
  check('start issues a descriptor', start.status === 200 && typeof start.json.scanId === 'string', JSON.stringify(start.json).slice(0, 200));
  const descriptor = start.json;

  const bundles = [];
  let allSigned = true;
  for (const g of descriptor.groups) {
    const step = await post('/api/scan/step', { scanId: descriptor.scanId, target: descriptor.target, attested: true, group: g.id });
    if (step.status !== 200) throw new Error(`step ${g.id} failed: ${step.text.slice(0, 200)}`);
    if (typeof step.json.sig !== 'string' || !step.json.sig) allSigned = false;
    bundles.push({ group: g.id, scanPolicy: step.json.scanPolicy, results: step.json.results, evidence: step.json.evidence, requests: step.json.requests, sig: step.json.sig });
  }
  check('every step bundle comes back HMAC-signed', allSigned);

  const scan = {
    scanId: descriptor.scanId,
    target: descriptor.target,
    attested: descriptor.attested,
    rescanOf: descriptor.rescanOf,
    createdAt: descriptor.createdAt,
  };
  const fin1 = await post('/api/scan/finalize', { scan, bundles });
  check('signed finalize returns a report', fin1.status === 200 && fin1.json && typeof fin1.json.scores === 'object', fin1.text.slice(0, 200));
  check('finalize is engine-only locally (no META_API_KEY)', fin1.json?.stamp?.modelConfigured === false && fin1.json?.stamp?.modelId === 'none (engine-only)', JSON.stringify(fin1.json?.stamp));
  check('first finalize is a cache miss', fin1.headers.get('x-auditcanvas-finalize-cache') === 'miss', fin1.headers.get('x-auditcanvas-finalize-cache'));

  // (a) unsigned
  const unsigned = clone(bundles).map(({ sig, ...rest }) => rest);
  const fa = await post('/api/scan/finalize', { scan, bundles: unsigned });
  check('(a) finalize with unsigned bundles is rejected, no report', fa.status === 400 && !fa.json?.scores, `${fa.status} ${fa.text.slice(0, 160)}`);

  // (b) tampered after signing: delete a finding from one bundle
  const tampered = clone(bundles);
  let removed = false;
  for (const b of tampered) {
    const idx = b.results.findIndex((r) => r.outcome === 'finding');
    if (idx >= 0) { b.results.splice(idx, 1); removed = true; break; }
  }
  const fb = await post('/api/scan/finalize', { scan, bundles: tampered });
  check('(b) finalize with a post-signing tampered bundle is rejected', removed && fb.status === 400 && !fb.json?.scores, `${fb.status} ${fb.text.slice(0, 160)}`);

  // (c) transplant into another scan identity
  const fc = await post('/api/scan/finalize', { scan: { ...scan, scanId: 'transplanted-scan-0001' }, bundles: clone(bundles) });
  check('(c) finalize with bundles transplanted into another scan is rejected', fc.status === 400 && !fc.json?.scores, `${fc.status} ${fc.text.slice(0, 160)}`);

  // (d) identical repeat finalize -> cache hit, byte-identical body
  const fin2 = await post('/api/scan/finalize', { scan, bundles: clone(bundles) });
  check('(d) repeat finalize is a cache hit', fin2.status === 200 && fin2.headers.get('x-auditcanvas-finalize-cache') === 'hit', `${fin2.status} ${fin2.headers.get('x-auditcanvas-finalize-cache')}`);
  check('(d) cached finalize body is byte-identical (zero new model calls)', fin2.text === fin1.text);

  // (e) downloads: bare forged report vs the signed chain
  const forged = clone(fin1.json);
  forged.scores = { ...forged.scores, risk: { ...forged.scores.risk, score: 0, grade: 'A' } };
  forged.stamp = { ...forged.stamp, modelId: 'forged-model', modelConfigured: true };
  forged.integrity = { unresolvedEvidenceIds: [], ok: true };
  forged.results = [...forged.results, {
    checkId: 'headers.csp', findingId: null, group: 'headers', outcome: 'pass', severity: null,
    title: 'Forged pass with dangling evidence', detail: 'forged', evidenceIds: ['ev-9999'], inference: false,
  }];
  const dlBare = await post('/api/scan/evidence', { report: forged });
  check('(e) bare download is built (200) but recomputed + re-stamped + unverified',
    dlBare.status === 200
    && dlBare.json?.integrity?.ok === false
    && dlBare.json?.integrity?.provenance === 'client-supplied-unverified'
    && dlBare.json?.scores?.risk?.score === fin1.json.scores.risk.score
    && dlBare.json?.scores?.risk?.score > 0
    && dlBare.json?.stamp?.modelId === 'none (engine-only)'
    && dlBare.json?.integrity?.unresolvedEvidenceIds?.some((x) => x.includes('ev-9999')),
    dlBare.text.slice(0, 300));
  const dlChain = await post('/api/scan/evidence', { report: fin1.json, scan, bundles: clone(bundles) });
  check('(e) download WITH the signed chain returns the server integrity (ok:true)',
    dlChain.status === 200 && dlChain.json?.integrity?.ok === true && dlChain.json?.provenance === 'server',
    dlChain.text.slice(0, 300));
} catch (err) {
  check(`e2e completed without harness errors (${err.message})`, false);
} finally {
  try { process.kill(-server.pid, 'SIGTERM'); } catch { server.kill('SIGTERM'); }
}

const failed = results.filter((r) => !r.pass);
console.log(`\n[fix-e2e] ${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
