// AuditCanvas scanner verification (SPEC.md: fixture suite).
//
// Runs the deterministic scanner against the fixture servers and asserts
// the spec's verdicts: expected findings on the vulnerable target, ZERO
// findings on the hardened target, and Inconclusive (never Pass) on the
// malformed/timeout targets. Also unit-checks the SSRF address rules,
// redaction-by-construction and the scoring cap rule.
//
// Usage: npm run verify
// The script generates a throwaway local CA (openssl) so the HTTPS
// fixture validates like a real site, then re-runs itself once with
// NODE_EXTRA_CA_CERTS set.
import { spawnSync, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(import.meta.url);
const CERT_DIR = path.join(os.tmpdir(), 'auditcanvas-fixture-certs');

function genCerts() {
  fs.mkdirSync(CERT_DIR, { recursive: true });
  if (fs.existsSync(path.join(CERT_DIR, 'cert.pem'))) return true;
  const run = (args) => execFileSync('openssl', args, { stdio: 'pipe' });
  run(['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(CERT_DIR, 'ca-key.pem'), '-out', path.join(CERT_DIR, 'ca.pem'), '-days', '30', '-nodes', '-subj', '/CN=AuditCanvas Fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE']);
  run(['req', '-newkey', 'rsa:2048', '-keyout', path.join(CERT_DIR, 'key.pem'), '-out', path.join(CERT_DIR, 'csr.pem'), '-nodes', '-subj', '/CN=localhost']);
  // This openssl build's `x509` command has no -addext; SAN goes via -extfile.
  fs.writeFileSync(path.join(CERT_DIR, 'server-ext.cnf'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  run(['x509', '-req', '-in', path.join(CERT_DIR, 'csr.pem'), '-CA', path.join(CERT_DIR, 'ca.pem'), '-CAkey', path.join(CERT_DIR, 'ca-key.pem'), '-CAcreateserial', '-out', path.join(CERT_DIR, 'cert.pem'), '-days', '2', '-extfile', path.join(CERT_DIR, 'server-ext.cnf')]);
  return true;
}

if (!process.env.AC_VERIFY_CHILD) {
  let httpsOk = false;
  try {
    httpsOk = genCerts();
  } catch (err) {
    console.log(`[verify] openssl CA generation failed (${err.message}); HTTPS fixture assertions will be skipped.`);
  }
  const env = { ...process.env, AC_VERIFY_CHILD: '1', AC_CERT_DIR: CERT_DIR };
  if (httpsOk) env.NODE_EXTRA_CA_CERTS = path.join(CERT_DIR, 'ca.pem');
  else env.AC_NO_HTTPS = '1';
  const r = spawnSync(process.execPath, [SCRIPT], { stdio: 'inherit', env });
  process.exit(r.status == null ? 1 : r.status);
}

// ---------------------------------------------------------------- child
const { validateAddressSet } = await import('../src/lib/iputil.js');
const { parseSetCookieFlags, redactString, unresolvedEvidenceIds, EVIDENCE_SCHEMA_VERSION } = await import('../src/lib/evidence.js');
const { computeScores } = await import('../src/lib/scoring.js');
const { createScanContext, POLICIES, policyForTarget } = await import('../src/lib/context.js');
const { runAllGroups, runGroup } = await import('../src/lib/scanner/index.js');
const { buildChains, deriveChains } = await import('../src/lib/chains.js');
const { applyRefutation, refutationScope } = await import('../src/lib/refutation.js');
const { buildEvidenceBundle, buildFixPack, EVIDENCE_FILENAME, FIX_PACK_FILENAME } = await import('../src/lib/downloads.js');
const { listZipEntries, readZipEntry } = await import('../src/lib/zip.js');
const ownership = await import('../src/lib/ownership.js');
const { createScan, startScanDescriptor, assembleSession, AssemblyError } = await import('../src/lib/scanstore.js');
const { finalizeReport } = await import('../src/lib/pipeline.js');
const { diffReports } = await import('../src/lib/diff.js');
const fixtures = await import('../fixtures/server.mjs');

const results = [];
function check(name, cond, detail = '') {
  results.push({ name, pass: Boolean(cond), detail });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : ` — ${detail}`}`);
}

// --- unit: SSRF address rules ---
check('iputil rejects RFC1918 10.0.0.1', !validateAddressSet(['10.0.0.1']).ok);
check('iputil rejects loopback 127.0.0.1', !validateAddressSet(['127.0.0.1']).ok);
check('iputil rejects link-local 169.254.169.254', !validateAddressSet(['169.254.169.254']).ok);
check('iputil rejects IPv4-mapped IPv6 ::ffff:10.0.0.1', !validateAddressSet(['::ffff:10.0.0.1']).ok);
check('iputil rejects IPv6 link-local fe80::1', !validateAddressSet(['fe80::1']).ok);
check('iputil rejects IPv6 loopback ::1', !validateAddressSet(['::1']).ok);
check('iputil rejects one bad address in a set', !validateAddressSet(['8.8.8.8', '192.168.1.1']).ok);
check('iputil accepts public 8.8.8.8', validateAddressSet(['8.8.8.8']).ok);
check('iputil accepts public IPv6 2606:4700:4700::1111', validateAddressSet(['2606:4700:4700::1111']).ok);

// --- unit: redaction by construction ---
const flags = parseSetCookieFlags('sessionid=supersecretvalue; Path=/; HttpOnly');
check('cookie value is never stored', !JSON.stringify(flags).includes('supersecretvalue') && flags.httpOnly === true);
check('redactString strips labelled secrets', !redactString('token=abc123secret').includes('abc123secret'));

// --- unit: scoring ---
const mk = (outcome, severity, extra = {}) => ({
  checkId: 'x', findingId: outcome === 'finding' ? 'f-x' : null, group: 'headers',
  outcome, severity, title: 't', detail: 'd', evidenceIds: [], inference: false, ...extra,
});
const diluted = computeScores([mk('finding', 'high'), ...Array.from({ length: 20 }, () => mk('pass', null))]);
check('a single high is not diluted by passes (grade D, score 40)', diluted.risk.grade === 'D' && diluted.risk.score === 40, JSON.stringify(diluted.risk));
const clean = computeScores([mk('pass', null), mk('pass', null)]);
check('all-pass scores grade A / risk 0', clean.risk.grade === 'A' && clean.risk.score === 0);
const partial = computeScores([mk('pass', null), mk('inconclusive', null)]);
check('inconclusive reduces coverage (0.5)', partial.coverage.ratio === 0.5, JSON.stringify(partial.coverage));

// --- fixture scans ---
// The scanner only speaks ports 80/443 (SPEC.md), so the fixtures bind
// those ports on distinct loopback addresses. The vulnerable HTTP fixture
// is bound on both 127.0.0.1 and ::1 so "localhost" resolves to a live
// socket in either family (the HTTPS-upgrade check fetches it by name).
const servers = [];
async function boot(fn, ...args) {
  const s = await fn(...args);
  servers.push(s);
  return s;
}
await boot(fixtures.startVulnerableHttp, 80, '127.0.0.1');
await boot(fixtures.startVulnerableHttp, 80, '::1');
await boot(fixtures.startHardenedHttp, 80, '127.0.0.2');
await boot(fixtures.startSlowHttp, 80, '127.0.0.3');
await boot(fixtures.startGarbageTcp, 80, '127.0.0.4');

const dnsMissing = async () => ({ status: 'empty' });
const dnsValid = async (host) =>
  host.startsWith('_dmarc')
    ? { status: 'ok', records: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.org'] }
    : { status: 'ok', records: ['v=spf1 -all'] };
const dnsTimeout = async () => ({ status: 'timeout' });

async function scan(baseUrl, { dnsTxt = dnsMissing, timeout = 4000 } = {}) {
  const ctx = createScanContext({
    baseUrl,
    policy: { ...POLICIES.full, perRequestTimeoutMs: timeout },
    authorizationState: 'verified',
    allowPrivate: true,
    dnsTxtFn: dnsTxt,
  });
  const scanResults = await runAllGroups(ctx);
  return { results: scanResults, evidence: ctx.evidence.items };
}
const byId = (rs, id) => rs.find((r) => r.checkId === id);
const findingsOf = (rs) => rs.filter((r) => r.outcome === 'finding');

// POSITIVE — vulnerable HTTP target
{
  const { results: rs, evidence } = await scan(`http://127.0.0.1/`);
  check('vuln: CSP unsafe-inline is a finding', byId(rs, 'headers.csp-unsafe-inline')?.outcome === 'finding');
  check('vuln: X-Content-Type-Options missing is a finding', byId(rs, 'headers.xcto-missing')?.outcome === 'finding');
  check('vuln: framing unprotected is a finding', byId(rs, 'headers.framing-missing')?.outcome === 'finding');
  check('vuln: HSTS is Not assessed on HTTP', byId(rs, 'headers.hsts')?.outcome === 'not-assessed');
  check('vuln: cookie without HttpOnly is a finding', byId(rs, 'cookies.httponly-missing')?.outcome === 'finding');
  check('vuln: SameSite=None without Secure is a finding', byId(rs, 'cookies.samesite-none-insecure')?.outcome === 'finding');
  check('vuln: CORS reflected origin + credentials is HIGH', byId(rs, 'cors.credentialed-exposure')?.severity === 'high');
  check('vuln: /.env exposure is a finding', byId(rs, 'exposed.env')?.outcome === 'finding');
  check('vuln: /.git/HEAD exposure is a finding', byId(rs, 'exposed.git-head')?.outcome === 'finding');
  check('vuln: soft-404 twin (/server-status) is Inconclusive, not a finding', byId(rs, 'exposed.server-status')?.outcome === 'inconclusive', JSON.stringify(byId(rs, 'exposed.server-status')));
  check('vuln: jQuery CVE-2020-11022 matched by version range', rs.some((r) => r.findingId === 'f-stack-jquery-cve-2020-11022'));
  check('vuln: lodash CVE-2020-8203 matched by version range', rs.some((r) => r.findingId === 'f-stack-lodash-cve-2020-8203'));
  check('vuln: filename-based CVE detection is flagged as inference', rs.filter((r) => r.group === 'stack' && r.outcome === 'finding').every((r) => r.inference === true));
  check('vuln: SPF missing (confirmed empty DNS) is a finding', byId(rs, 'email.spf-missing')?.outcome === 'finding');
  check('vuln: DMARC missing (confirmed empty DNS) is a finding', byId(rs, 'email.dmarc-missing')?.outcome === 'finding');
  check('vuln: open redirect confirmed via off-origin Location is HIGH', byId(rs, 'redirects.open-redirect')?.severity === 'high');
  check('vuln: every evidence reference resolves', unresolvedEvidenceIds(rs, evidence).length === 0);
  const bundle = JSON.stringify(evidence);
  check('vuln: evidence contains no cookie values', !bundle.includes('fixturevalue'));
  check('vuln: evidence contains no response-body secrets', !bundle.includes('fixture-not-a-real-secret'));
}

// POSITIVE — vulnerable HTTPS target (fixture CA, cert expires in 2 days)
if (!process.env.AC_NO_HTTPS) {
  await boot(fixtures.startVulnerableHttps, 443, process.env.AC_CERT_DIR, '::');
  const { results: rs } = await scan(`https://localhost/`);
  check('https: HSTS missing is a finding', byId(rs, 'headers.hsts-missing')?.outcome === 'finding');
  check('https: cookie without Secure is a finding', byId(rs, 'cookies.secure-missing')?.outcome === 'finding');
  check('https: certificate expiring within 14 days is a finding', rs.some((r) => r.group === 'tls' && r.checkId.startsWith('tls.cert-expiring') && r.outcome === 'finding'), JSON.stringify(rs.filter((r) => r.group === 'tls')));
  check('https: valid chain under the fixture CA passes', byId(rs, 'tls.chain')?.outcome === 'pass', JSON.stringify(byId(rs, 'tls.chain')));
  check('https: mixed content is a finding', byId(rs, 'redirects.mixed-content')?.outcome === 'finding');
} else {
  console.log('SKIP  https fixture assertions (no local CA available)');
}

// NEGATIVE — hardened target: zero findings across all groups
{
  const { results: rs } = await scan(`http://127.0.0.2/`, { dnsTxt: dnsValid });
  const found = findingsOf(rs);
  check('hardened: ZERO findings across all eight groups', found.length === 0, JSON.stringify(found.map((f) => f.checkId)));
  check('hardened: current jQuery (3.7.1) produces no CVE finding', !rs.some((r) => r.group === 'stack' && r.outcome === 'finding'));
  check('hardened: valid SPF/DMARC pass', byId(rs, 'email.spf')?.outcome === 'pass' && byId(rs, 'email.dmarc')?.outcome === 'pass');
}

// MALFORMED / TIMEOUT — Inconclusive, never Pass
{
  const gtx = createScanContext({
    baseUrl: `http://127.0.0.4/`,
    policy: { ...POLICIES.full, perRequestTimeoutMs: 1500 },
    authorizationState: 'verified', allowPrivate: true, dnsTxtFn: dnsTimeout,
  });
  const gh = await runGroup(gtx, 'headers');
  check('garbage: headers group is Inconclusive (not Pass)', gh.length === 1 && gh[0].outcome === 'inconclusive', JSON.stringify(gh));
  const ge = await runGroup(gtx, 'email');
  check('garbage: DNS timeout makes email checks Inconclusive (not "missing")', ge.every((r) => r.outcome === 'inconclusive'), JSON.stringify(ge));

  const stx = createScanContext({
    baseUrl: `http://127.0.0.3/`,
    policy: { ...POLICIES.full, perRequestTimeoutMs: 800 },
    authorizationState: 'verified', allowPrivate: true, dnsTxtFn: dnsMissing,
  });
  const sh = await runGroup(stx, 'headers');
  check('timeout: slow target makes headers Inconclusive (not Pass)', sh.length === 1 && sh[0].outcome === 'inconclusive', JSON.stringify(sh));
}

// --- Day 4/5: chains, refutation, downloads, ownership ---
// Synthetic reports in the exact shapes the scanner produces.
function httpEv(id, data) {
  return { id, kind: 'http-response', target: 'https://shop.example/', at: '2026-10-28T00:00:00.000Z', data };
}
function corsReport({ withCreds = true, withCookies = true } = {}) {
  const headers = { 'access-control-allow-origin': 'https://ac-probe.invalid', 'content-type': 'text/html; charset=utf-8' };
  if (withCreds) headers['access-control-allow-credentials'] = 'true';
  const ev = httpEv('ev-0001', {
    status: 200, finalUrl: 'https://shop.example/', redirectCount: 0, headers, headerNames: Object.keys(headers),
    setCookies: withCookies ? [{ name: 'sessionid', secure: true, httpOnly: true, sameSite: 'lax', path: '/', domain: null, hasExpires: false, hasMaxAge: false }] : [],
    bodyBytes: 512, truncated: false,
  });
  const finding = {
    checkId: 'cors.credentialed-exposure', findingId: 'f-cors-credentialed-exposure', group: 'cors',
    outcome: 'finding', severity: 'high', title: 'CORS allows credentialed reads from untrusted origins',
    detail: 'Reflected origin with credentials allowed.', evidenceIds: ['ev-0001'], inference: false,
  };
  return { target: 'https://shop.example/', results: [finding], evidence: [ev] };
}
const corsProposal = (extraNodes = []) => ({
  type: 'cors-data-exposure',
  title: 'Credentialed CORS exposes account data to any site',
  claimedClassification: 'supported',
  nodes: [{ findingId: 'f-cors-credentialed-exposure', evidenceIds: ['ev-0001'] }, ...extraNodes],
  edges: [],
});

{
  // CHAINS — the corrected CORS example, all three classifications.
  const supported = buildChains([corsProposal()], corsReport({}));
  check('chains: fully-evidenced CORS chain is Supported and rendered', supported.chains.length === 1 && supported.chains[0].classification === 'supported', JSON.stringify(supported.chains[0]?.preconditions));

  const noCreds = buildChains([corsProposal()], corsReport({ withCreds: false }));
  check('chains: CORS chain without credentials evidence is Unproven and NOT rendered', noCreds.chains.length === 0 && noCreds.unproven.length === 1 && /credentials-allowed/.test(noCreds.unproven[0].reason), JSON.stringify(noCreds.unproven[0]?.reason));

  const conditional = buildChains([corsProposal()], corsReport({ withCookies: false }));
  check('chains: CORS chain with unproven response sensitivity is Conditional (rendered, dashed)', conditional.chains.length === 1 && conditional.chains[0].classification === 'conditional');

  // Cookie flags alone never prove cross-origin exposure (spec correction):
  // a report whose only evidence is insecure cookie flags gives the chain
  // no CORS precondition at all.
  const cookieReport = corsReport({});
  cookieReport.results = [{
    checkId: 'cookies.secure-missing', findingId: 'f-cookies-secure-missing', group: 'cookies',
    outcome: 'finding', severity: 'low', title: 'Cookies without Secure', detail: 'x', evidenceIds: ['ev-0001'], inference: false,
  }];
  cookieReport.evidence = [httpEv('ev-0001', {
    status: 200, finalUrl: 'https://shop.example/', redirectCount: 0, headers: {}, headerNames: [],
    setCookies: [{ name: 'sessionid', secure: false, httpOnly: false, sameSite: null, path: '/', domain: null, hasExpires: false, hasMaxAge: false }],
    bodyBytes: 100, truncated: false,
  })];
  const cookieChain = buildChains(
    [{ type: 'cors-data-exposure', title: 'Session theft via cookie flags', nodes: [{ findingId: 'f-cookies-secure-missing', evidenceIds: ['ev-0001'] }], edges: [] }],
    cookieReport
  );
  check('chains: cookie flags alone can never support a CORS chain (Unproven)', cookieChain.chains.length === 0 && cookieChain.unproven.length === 1);

  const badEv = buildChains([{ ...corsProposal(), nodes: [{ findingId: 'f-cors-credentialed-exposure', evidenceIds: ['ev-9999'] }] }], corsReport({}));
  check('chains: proposal citing an unknown evidence ID is rejected outright', badEv.chains.length === 0 && badEv.invalid.length === 1 && /unknown evidenceId/.test(badEv.invalid[0].problems.join(' ')), JSON.stringify(badEv.invalid));
  const badFinding = buildChains([{ ...corsProposal(), nodes: [{ findingId: 'f-nope', evidenceIds: [] }] }], corsReport({}));
  check('chains: proposal citing an unknown finding ID is rejected outright', badFinding.invalid.length === 1 && /unknown findingId/.test(badFinding.invalid[0].problems.join(' ')));
  const badType = buildChains([{ ...corsProposal(), type: 'session-theft-via-cookie-flags' }], corsReport({}));
  check('chains: unknown chain type is rejected outright', badType.invalid.length === 1 && /unknown chain type/.test(badType.invalid[0].problems.join(' ')));
  const notRun = deriveChains(corsReport({}), null, { configured: false });
  check('chains: without a configured model the state is explicit not-run, zero chains', notRun.status === 'not-run' && notRun.chains.length === 0);

  // REFUTATION — scope, outcomes, and the Risk interaction.
  const lowFinding = {
    checkId: 'cookies.secure-missing', findingId: 'f-cookies-secure-missing', group: 'cookies',
    outcome: 'finding', severity: 'low', title: 'Cookies without Secure', detail: 'x', evidenceIds: ['ev-0001'], inference: false,
  };
  const scopedReport = corsReport({});
  scopedReport.results.push(lowFinding);
  const scopedChains = buildChains([corsProposal([{ findingId: 'f-cookies-secure-missing', evidenceIds: ['ev-0001'] }])], scopedReport);
  check('refutation scope: high findings plus Supported-chain nodes only', refutationScope(scopedReport, scopedChains).map((f) => f.findingId).sort().join(',') === 'f-cookies-secure-missing,f-cors-credentialed-exposure', JSON.stringify(refutationScope(scopedReport, scopedChains).map((f) => f.findingId)));
  check('refutation scope: a low finding outside any chain is out of scope', refutationScope(scopedReport, buildChains([], scopedReport)).map((f) => f.findingId).join(',') === 'f-cors-credentialed-exposure');

  const survived = applyRefutation(corsReport({}), { chains: [] }, { 'f-cors-credentialed-exposure': 'The strongest counterargument imaginable: the probe origin is contrived and no real session was read.' });
  check('refutation: complete evidence survives even a strong counterargument', survived.length === 1 && survived[0].outcome === 'survived-refutation' && survived[0].outcomeLabel === 'Survived refutation', JSON.stringify(survived[0]?.outcome));

  const weakReport = corsReport({ withCreds: false });
  const notSub = applyRefutation(weakReport, { chains: [] }, { 'f-cors-credentialed-exposure': 'Credentials are not actually allowed.' });
  check('refutation: absent required precondition is Not substantiated (deterministic, not the model)', notSub.length === 1 && notSub[0].outcome === 'not-substantiated');
  const rescored = structuredClone(weakReport.results);
  rescored[0].refutation = { outcome: notSub[0].outcome };
  const subScores = computeScores(rescored);
  check('refutation: not-substantiated finding stops driving Risk but stays in the report', subScores.risk.score === 0 && subScores.counts.findings === 1 && subScores.counts.confirmedFindings === 0, JSON.stringify(subScores.risk));

  const truncReport = corsReport({});
  truncReport.evidence[0].data.truncated = true;
  const reduced = applyRefutation(truncReport, { chains: [] }, { 'f-cors-credentialed-exposure': 'The evidence was cut off mid-response.' });
  check('refutation: a confirmed limitation reduces confidence, never severity', reduced.length === 1 && reduced[0].outcome === 'confidence-reduced');
  const redScored = structuredClone(truncReport.results);
  redScored[0].refutation = { outcome: reduced[0].outcome };
  check('refutation: confidence-reduced lowers the Confidence score', computeScores(redScored).confidence.ratio === 0 && computeScores(truncReport.results).confidence.ratio === 1);

  // DOWNLOADS — versioned evidence bundle + fix pack contents.
  const dlReport = corsReport({});
  dlReport.scanId = 'scan-test';
  dlReport.authorizationState = 'verified';
  dlReport.scanPolicy = 'full';
  dlReport.status = 'complete';
  dlReport.startedAt = '2026-10-28T00:00:00.000Z';
  dlReport.findings = dlReport.results;
  dlReport.scores = computeScores(dlReport.results);
  dlReport.stamp = { scannerVersion: '0.1.0' };
  dlReport.integrity = { unresolvedEvidenceIds: [], ok: true };
  dlReport.auditLog = [];
  const bundle = buildEvidenceBundle(dlReport);
  const roundTripped = JSON.parse(JSON.stringify(bundle));
  check('downloads: evidence bundle parses and carries the schema version', roundTripped.schemaVersion === EVIDENCE_SCHEMA_VERSION && EVIDENCE_FILENAME === 'auditcanvas-evidence.json' && unresolvedEvidenceIds(roundTripped.results, roundTripped.evidence).length === 0);
  const zip = buildFixPack(dlReport);
  const names = listZipEntries(zip);
  const fixText = readZipEntry(zip, 'fixes/f-cors-credentialed-exposure.txt') || '';
  check('downloads: fix pack zip holds a per-finding file with finding ID, evidence IDs and the suggested-patch label',
    FIX_PACK_FILENAME === 'auditcanvas-fix-pack.zip' && names.includes('fixes/f-cors-credentialed-exposure.txt')
    && fixText.includes('# Finding: f-cors-credentialed-exposure') && fixText.includes('ev-0001') && fixText.includes('SUGGESTED PATCH'),
    JSON.stringify(names));

  // OWNERSHIP — DNS TXT challenge lifecycle + policy unlock.
  const ch = ownership.createChallenge('verify-fixture.test');
  const goodDns = async (name) => ({ status: 'ok', records: name === ch.recordName ? [ch.recordValue] : [] });
  const verifiedRes = await ownership.checkChallenge('verify-fixture.test', { dnsTxtFn: goodDns });
  check('ownership: matching TXT record verifies the exact hostname', verifiedRes.status === 'verified' && ownership.isVerifiedHost('verify-fixture.test'), JSON.stringify(verifiedRes));
  const verifiedSession = createScan({ url: 'https://verify-fixture.test/', ip: 'verify-test' });
  check('ownership: verified host scans get the full policy with state on the session',
    verifiedSession.policyName === 'full' && verifiedSession.authorizationState === 'verified' && verifiedSession.verification?.hostname === 'verify-fixture.test',
    JSON.stringify({ p: verifiedSession.policyName, a: verifiedSession.authorizationState }));
  const ch2 = ownership.createChallenge('verify-miss.test');
  const missRes = await ownership.checkChallenge('verify-miss.test', { dnsTxtFn: async () => ({ status: 'ok', records: ['auditcanvas-verify=wrong-token'] }) });
  check('ownership: a non-matching TXT record does not verify', missRes.status === 'not-found' && !ownership.isVerifiedHost('verify-miss.test'));
  const restrictedSession = createScan({ url: 'https://unverified-fixture.test/', ip: 'verify-test' });
  check('ownership: unverified targets keep the restricted passive policy', restrictedSession.policyName === 'restricted' && restrictedSession.authorizationState === 'unattested' && policyForTarget(new URL('https://unverified-fixture.test/'), {}).policy.name === 'restricted');
}

// --- Day 6-7: rescan / diff (fix verification) ---
// Same target identity (http://127.0.0.1/) scanned vulnerable, then the
// fixture origin is flipped to its hardened behavior and the SAME
// target is rescanned — the diff must show the fixes as resolved,
// driven purely by the fresh evidence.
{
  const mkReport = (scanId, rs) => ({
    scanId, target: 'http://127.0.0.1/', startedAt: '2026-10-28T00:00:00.000Z',
    scanPolicy: 'full', results: rs, scores: computeScores(rs),
  });

  const beforeScan = await scan('http://127.0.0.1/');
  const before = mkReport('scan-before', beforeScan.results);
  fixtures.setVulnerableOriginHardened(true);
  let after;
  try {
    const afterScan = await scan('http://127.0.0.1/', { dnsTxt: dnsValid });
    after = mkReport('scan-after', afterScan.results);
  } finally {
    fixtures.setVulnerableOriginHardened(false);
  }

  const d = diffReports(before, after);
  const resolvedIds = d.resolved.map((e) => e.checkId);
  check('diff: fixed findings are resolved (CSP, CORS, /.env, cookie flags, jQuery CVE, SPF)',
    ['headers.csp-unsafe-inline', 'cors.credentialed-exposure', 'exposed.env', 'cookies.httponly-missing', 'stack.jquery-cve-2020-11022', 'email.spf-missing']
      .every((id) => resolvedIds.includes(id)), JSON.stringify(resolvedIds));
  check('diff: hardening introduces no new findings and leaves none persistent',
    d.counts.new === 0 && d.counts.persistent === 0 && d.counts.severityChanged === 0,
    JSON.stringify(d.counts));
  check('diff: every before-finding is accounted for as resolved',
    d.counts.resolved === findingsOf(beforeScan.results).length && d.counts.couldNotRepeat === 0,
    JSON.stringify({ counts: d.counts, beforeFindings: findingsOf(beforeScan.results).length }));
  check('diff: risk movement is real (findings -> grade A / risk 0)',
    d.scores.before.riskScore > 0 && d.scores.after.riskScore === 0 && d.scores.after.riskGrade === 'A'
      && d.scores.delta.riskScore === -d.scores.before.riskScore,
    JSON.stringify(d.scores));

  const reverse = diffReports(after, before);
  check('diff: the reverse comparison reports the same flaws as new findings',
    reverse.counts.new === d.counts.resolved && reverse.counts.resolved === 0,
    JSON.stringify(reverse.counts));

  const identity = diffReports(before, before);
  check('diff: a scan diffed against itself is all persistent, zero movement',
    identity.counts.persistent === findingsOf(beforeScan.results).length
      && identity.counts.resolved === 0 && identity.counts.new === 0 && identity.scores.delta.riskScore === 0,
    JSON.stringify(identity.counts));

  // Honesty rule: a finding the rescan could not re-verify (check came
  // back Inconclusive) is could-not-repeat, NEVER resolved.
  const synResult = (outcome, severity) => ({
    checkId: 'headers.hsts-missing', findingId: outcome === 'finding' ? 'f-headers-hsts-missing' : null,
    group: 'headers', outcome, severity, title: 'HSTS missing', detail: 'd', evidenceIds: [], inference: false,
  });
  const synBefore = { scanId: 'syn-b', target: 'https://x.example/', startedAt: '2026-10-28T00:00:00.000Z', scanPolicy: 'full', results: [synResult('finding', 'medium')], scores: computeScores([synResult('finding', 'medium')]) };
  const synAfter = { scanId: 'syn-a', target: 'https://x.example/', startedAt: '2026-10-28T01:00:00.000Z', scanPolicy: 'full', results: [synResult('inconclusive', null)], scores: computeScores([synResult('inconclusive', null)]) };
  const synDiff = diffReports(synBefore, synAfter);
  check('diff: an un-re-verifiable finding is could-not-repeat, never resolved',
    synDiff.counts.couldNotRepeat === 1 && synDiff.counts.resolved === 0, JSON.stringify(synDiff.counts));

  const synAfterHigh = { ...synAfter, results: [synResult('finding', 'high')], scores: computeScores([synResult('finding', 'high')]) };
  const sevDiff = diffReports(synBefore, synAfterHigh);
  check('diff: same check at a different severity is severity-changed, not persistent',
    sevDiff.counts.severityChanged === 1 && sevDiff.counts.persistent === 0
      && sevDiff.severityChanged[0].severityBefore === 'medium' && sevDiff.severityChanged[0].severityAfter === 'high',
    JSON.stringify(sevDiff.counts));
}

// --- Production fix: stateless scan flow + self-demo policy ---
// Regression coverage for the 2026-10-28 serverless failure: scan
// sessions lived only in one process's memory, so every /step after
// /start failed on Vercel; and the deployed demo target got the
// restricted policy because its origin is not a configured demo host.
{
  const { GROUPS: ALL_GROUPS } = await import('../src/lib/scanner/index.js');

  // SELF-DEMO POLICY — full only for the exact demo path on our own origin.
  const demoUrl = new URL('https://auditcanvas.vercel.app/api/demo-target');
  check('policy: seeded demo on the app origin runs the FULL policy',
    policyForTarget(demoUrl, { selfOrigin: 'https://auditcanvas.vercel.app' }).policy.name === 'full'
    && policyForTarget(demoUrl, { selfOrigin: 'https://auditcanvas.vercel.app' }).authorizationState === 'verified');
  check('policy: self-demo never grants the loopback allowance',
    policyForTarget(demoUrl, { selfOrigin: 'https://auditcanvas.vercel.app' }).allowPrivate === false);
  check('policy: the demo path on a FOREIGN origin stays restricted',
    policyForTarget(new URL('https://evil.example/api/demo-target'), { selfOrigin: 'https://auditcanvas.vercel.app' }).policy.name === 'restricted');
  check('policy: a non-demo path on the app origin stays restricted',
    policyForTarget(new URL('https://auditcanvas.vercel.app/account'), { selfOrigin: 'https://auditcanvas.vercel.app' }).policy.name === 'restricted');
  check('policy: without a self origin the demo URL stays restricted',
    policyForTarget(demoUrl, {}).policy.name === 'restricted');
  const demoDescriptor = startScanDescriptor({ url: demoUrl.toString(), attested: true, ip: 'verify-stateless', selfOrigin: 'https://auditcanvas.vercel.app' });
  check('descriptor: start issues the full-policy descriptor for the seeded demo',
    demoDescriptor.scanPolicy === 'full' && demoDescriptor.groups.length === 8 && typeof demoDescriptor.scanId === 'string');

  // STATELESS ASSEMBLY — per-group steps in fresh contexts, assembled
  // server-side, must reproduce the monolithic scan's findings.
  async function stepBundles(baseUrl, dnsTxt = dnsMissing) {
    const bundles = [];
    for (const g of ALL_GROUPS) {
      const ctx = createScanContext({
        baseUrl,
        policy: { ...POLICIES.full },
        authorizationState: 'verified',
        allowPrivate: true,
        dnsTxtFn: dnsTxt,
      });
      const rs = await runGroup(ctx, g.id);
      bundles.push({ group: g.id, results: rs, evidence: ctx.evidence.items, requests: ctx.requests });
    }
    return bundles;
  }

  const bundles = await stepBundles('http://127.0.0.1/');
  const rawEvidenceCount = bundles.reduce((n, b) => n + b.evidence.length, 0);
  const session = assembleSession({
    scanId: 'stateless-verify-0001', target: 'http://127.0.0.1/', attested: true,
    bundles, ip: 'verify-stateless',
  });
  check('stateless: assembly derives the policy server-side (demo host -> full)',
    session.policyName === 'full' && session.status === 'complete');
  check('stateless: identical evidence across groups is deduped at assembly',
    session.ctx.evidence.items.length < rawEvidenceCount,
    `${session.ctx.evidence.items.length} merged vs ${rawEvidenceCount} raw`);
  check('stateless: every assembled evidence reference resolves',
    unresolvedEvidenceIds(session.results, session.ctx.evidence.items).length === 0);
  const statelessReport = await finalizeReport(session);
  const mono = await scan('http://127.0.0.1/');
  const statelessFindings = findingsOf(statelessReport.results).map((f) => f.checkId).sort();
  const monoFindings = findingsOf(mono.results).map((f) => f.checkId).sort();
  check('stateless: assembled findings match the monolithic scan',
    JSON.stringify(statelessFindings) === JSON.stringify(monoFindings),
    JSON.stringify({ statelessFindings, monoFindings }));
  check('stateless: finalized report has real risk and ok integrity',
    statelessReport.scores.risk.score > 0 && statelessReport.integrity.ok === true,
    JSON.stringify(statelessReport.scores.risk));

  // ASSEMBLY REFUSES TAMPERED BUNDLES.
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const expectReject = (name, mutate) => {
    const bad = clone(bundles);
    mutate(bad);
    let rejected = false;
    try {
      assembleSession({ scanId: 'stateless-verify-0002', target: 'http://127.0.0.1/', bundles: bad, ip: 'verify-stateless' });
    } catch (err) {
      rejected = err instanceof AssemblyError;
    }
    check(name, rejected);
  };
  expectReject('stateless: a result citing unknown evidence is rejected', (bad) => {
    bad[0].results[0].evidenceIds = ['ev-9999'];
  });
  expectReject('stateless: a malformed result (finding without severity) is rejected', (bad) => {
    const f = bad.flatMap((b) => b.results).find((r) => r.outcome === 'finding');
    f.severity = null;
  });
  expectReject('stateless: a missing group bundle is rejected', (bad) => {
    bad.splice(0, 1);
  });
  expectReject('stateless: a duplicated group bundle is rejected', (bad) => {
    bad.push(clone(bad[0]));
  });
  const foreign = assembleSession({
    scanId: 'stateless-verify-0003', target: 'https://unverified-fixture.test/', attested: true,
    bundles: clone(bundles).map((b) => ({ ...b, requests: [] })), ip: 'verify-stateless',
  });
  check('stateless: assembly stamps the DERIVED policy, never a claimed one (unverified -> restricted)',
    foreign.policyName === 'restricted' && foreign.authorizationState === 'attested');
}

for (const s of servers) {
  try { s.close(); } catch { /* already closed */ }
}
const failed = results.filter((r) => !r.pass);
console.log(`\n[verify] ${results.length - failed.length}/${results.length} assertions passed`);
process.exit(failed.length ? 1 : 0);
