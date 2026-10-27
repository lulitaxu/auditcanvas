// Group 5 — Exposed paths. Presence checks with soft-404 baselining:
// first fetch a random nonexistent path; a "200" that matches the
// baseline signature is Inconclusive, never a finding. Content is never
// exploited — only a small signature excerpt proves exposure.
import { createHash } from 'node:crypto';
import { makeCheck, redactString } from '../evidence.js';
import { httpEvidence } from './common.js';

const GROUP = 'exposed';

const ALL_PATHS = [
  { path: '/.git/HEAD', label: 'Git repository metadata', signature: (body) => body.startsWith('ref:') },
  { path: '/.env', label: 'Environment file', signature: (body) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(body) || /^(DB_|APP_|SECRET|API_)/m.test(body) },
  { path: '/wp-admin/', label: 'WordPress admin', signature: (body) => /wp-login|user_login|wordpress/i.test(body) },
  { path: '/server-status', label: 'Apache server-status', signature: (body) => /Apache Server Status|Server uptime/i.test(body) },
  { path: '/.DS_Store', label: 'macOS .DS_Store', signature: (body) => body.includes('Bud1') },
  { path: '/phpinfo.php', label: 'phpinfo page', signature: (body) => /phpinfo\(\)|PHP Version/i.test(body) },
];
const RESTRICTED_COUNT = 3;

function signatureOf(res) {
  const head = (res.bodyText || '').slice(0, 2048);
  const body = res.bodyText || '';
  return {
    status: res.status,
    bytes: res.bodyBytes,
    hash: createHash('sha256').update(head).digest('hex').slice(0, 16),
    headHash: createHash('sha256').update(body.slice(0, 256)).digest('hex').slice(0, 16),
    tailHash: createHash('sha256').update(body.slice(-256)).digest('hex').slice(0, 16),
  };
}

// A probe response "matches" the soft-404 baseline when it is the same
// page: byte-identical head, or the same template head and tail with a
// near-identical size (a soft-404 page that echoes the requested path in
// the middle). Size alone is NEVER a match — two unrelated short bodies
// (an exposed /.env, a login form) sit within any size tolerance of a
// short not-found page, and calling them soft-404s would bury real hits.
function matchesBaseline(sig, base) {
  if (sig.status !== base.status) return false;
  if (sig.hash === base.hash) return true;
  const sizeClose = Math.abs(sig.bytes - base.bytes) <= Math.max(8, Math.floor(base.bytes * 0.02));
  return sizeClose && sig.headHash === base.headHash && sig.tailHash === base.tailHash;
}

export async function runExposed(ctx) {
  const out = [];
  const paths = ctx.policy.probes ? ALL_PATHS : ALL_PATHS.slice(0, RESTRICTED_COUNT);
  const nonce = Math.random().toString(36).slice(2, 12);
  const baselineUrl = ctx.url(`/ac-nonexistent-${nonce}`);

  let baseline = null;
  let baselineEvidence = null;
  try {
    const bres = await ctx.fetch(baselineUrl);
    baseline = signatureOf(bres);
    baselineEvidence = httpEvidence(ctx, bres, baselineUrl);
  } catch (err) {
    // Without a baseline we can still judge hard 404s, but every 200
    // becomes inconclusive rather than guessed at.
    baseline = null;
  }

  for (const entry of paths) {
    const url = ctx.url(entry.path);
    const checkName = entry.path.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase() || 'root';
    let res;
    try {
      res = await ctx.fetch(url);
    } catch (err) {
      out.push({
        checkId: `${GROUP}.${checkName}`,
        findingId: null, group: GROUP, outcome: 'inconclusive', severity: null,
        title: `${entry.label} (${entry.path}) could not be checked`,
        detail: `Could not verify: ${err.message}`,
        evidenceIds: baselineEvidence ? [baselineEvidence] : [], inference: false,
      });
      continue;
    }
    const sig = signatureOf(res);
    const ev = httpEvidence(ctx, res, url);
    const evIds = baselineEvidence ? [ev, baselineEvidence] : [ev];

    if (res.status === 404 || res.status === 410) {
      out.push(
        makeCheck({
          group: GROUP, check: checkName, outcome: 'pass',
          title: `${entry.label} not exposed (${entry.path} -> ${res.status})`,
          detail: 'The path returns a not-found status.',
          evidenceIds: evIds,
        })
      );
      continue;
    }
    if (res.status === 401 || res.status === 403) {
      out.push(
        makeCheck({
          group: GROUP, check: checkName, outcome: 'pass',
          title: `${entry.label} is access-controlled (${entry.path} -> ${res.status})`,
          detail: 'The path exists (the status reveals that much) but refuses unauthenticated access.',
          evidenceIds: evIds,
        })
      );
      continue;
    }
    if (res.status !== 200) {
      out.push(
        makeCheck({
          group: GROUP, check: checkName, outcome: 'inconclusive',
          title: `${entry.label} returned HTTP ${res.status}`,
          detail: 'A status other than 200/401/403/404 proves neither exposure nor absence.',
          evidenceIds: evIds,
        })
      );
      continue;
    }
    // HTTP 200: the soft-404 trap. Only content that differs from the
    // baseline AND matches the exposure signature becomes a finding.
    if (baseline && baseline.status === 200 && matchesBaseline(sig, baseline)) {
      out.push(
        makeCheck({
          group: GROUP, check: checkName, outcome: 'inconclusive',
          title: `${entry.label} "200" matches the soft-404 baseline`,
          detail: 'The server answers every path, real or invented, with the same 200 page. This path cannot be distinguished from a nonexistent one, so it is reported as inconclusive, never as a finding.',
          evidenceIds: evIds,
        })
      );
      continue;
    }
    if (entry.signature((res.bodyText || '').slice(0, 4096))) {
      out.push(
        makeCheck({
          group: GROUP, check: checkName, outcome: 'finding',
          severity: entry.path === '/.git/HEAD' || entry.path === '/.env' ? 'high' : 'medium',
          title: `${entry.label} is publicly exposed (${entry.path})`,
          detail: `The path returns real content whose signature differs from the soft-404 baseline. Signature excerpt: "${redactString((res.bodyText || '').slice(0, 48).replace(/\s+/g, ' '))}". Content was not exploited further.`,
          evidenceIds: evIds,
        })
      );
      continue;
    }
    out.push(
      makeCheck({
        group: GROUP, check: checkName, outcome: 'inconclusive',
        title: `${entry.label} returns 200 with unrecognized content`,
        detail: 'The content differs from the soft-404 baseline but matches no known exposure signature, so no verdict is claimed.',
        evidenceIds: evIds,
      })
    );
  }
  return out;
}
