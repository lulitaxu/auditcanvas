// Group 9 — Exposure & secrets (SPEC.md addendum 2026-10-29, founder-
// approved scope addition). Non-destructive, unauthenticated GETs only,
// under both scan policies (restricted scales counts, exactly as
// Exposed paths already does).
//
// The group's honesty rules are the product's rules, sharpened:
//  - Presence is never a finding. Client configuration that is public
//    by design (Supabase anon keys, Stripe publishable keys, Google
//    browser keys) and sign-in surfaces are Inconclusive with the
//    reason stated, because their safety depends on server-side
//    controls an anonymous scan cannot evaluate.
//  - Secrets are evidenced redacted BY CONSTRUCTION: pattern class,
//    a bounded prefix (never more than 8 characters), and a sha256
//    fingerprint so the owner can identify which key was found. The
//    secret value itself is never interpolated into any result,
//    detail, or evidence item — not merely redacted afterwards.
//  - No entropy heuristics: only the anchored patterns below run. A
//    string that merely looks random is not evidence of a secret.
//  - Exhaustion (budget/deadline) degrades to Inconclusive with the
//    reason named, never to a silent skip and never to a Pass.
import { createHash } from 'node:crypto';
import { makeCheck, redactString, redactUrl } from '../evidence.js';
import { httpEvidence, getRoot } from './common.js';

const GROUP = 'exposure';

// ---------------------------------------------------------------------------
// Soft-404 baselining. COPIED from exposed.js (not imported) so this
// group is revert-isolated: removing the group touches no other module.
// A probe response "matches" the baseline when it is the same page:
// byte-identical head, or the same template head and tail with a
// near-identical size. Size alone is NEVER a match.
// ---------------------------------------------------------------------------

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

function matchesBaseline(sig, base) {
  if (sig.status !== base.status) return false;
  if (sig.hash === base.hash) return true;
  const sizeClose = Math.abs(sig.bytes - base.bytes) <= Math.max(8, Math.floor(base.bytes * 0.02));
  return sizeClose && sig.headHash === base.headHash && sig.tailHash === base.tailHash;
}

// ---------------------------------------------------------------------------
// Frozen tables (design §1.1 / §3.3 — adding an entry is a spec change)
// ---------------------------------------------------------------------------

const ENV_CHECKS = [
  { check: 'env-local', path: '/.env.local' },
  { check: 'env-production', path: '/.env.production' },
  { check: 'env-development', path: '/.env.development' },
  { check: 'env-bak', path: '/.env.bak' },
  { check: 'env-old', path: '/.env.old' },
];
// Restricted policy probes the first three env variants only (mirrors
// exposed.js's RESTRICTED_COUNT slicing): the unprobed two are silently
// absent from the result list, not not-assessed placeholders.
const ENV_CHECKS_RESTRICTED = ['env-local', 'env-production', 'env-bak'];

const GIT_CHECK = { check: 'git-config', path: '/.git/config' };

const SURFACE_CHECKS = [
  { check: 'admin-route', path: '/admin', noun: 'administration', surface: 'admin' },
  { check: 'debug-route', path: '/debug', noun: 'debug', surface: 'debug' },
];

const MAX_BUNDLES_FULL = 6;
const MAX_BUNDLES_RESTRICTED = 3;
const BUNDLE_SIZE_CAP = 256 * 1024;

// Anchored secret patterns. `cls` is the evidence class name; capture
// means the regex's group 1 (not the whole match) is the secret value.
const PATTERNS = [
  {
    cls: 'aws-access-key', check: 'js-secret-aws-access-key', severity: 'medium',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    title: 'AWS access key ID in client JavaScript',
    detail: (c) => `A string matching the AWS access key ID format appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}, match prefix "${c.prefix}", sha256 fingerprint ${c.fingerprint}). An access key ID is a credential identifier — it names the account key and enables targeted abuse — so it must be treated as exposed and rotated. The paired secret access key itself was NOT observed in the scanned assets.`,
  },
  {
    cls: 'aws-secret', check: 'js-secret-aws-secret', severity: 'high', capture: true,
    re: /(?:aws_secret_access_key|awsSecretAccessKey|AWS_SECRET_ACCESS_KEY)["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/g,
    title: 'AWS secret access key in client JavaScript',
    detail: (c) => `A value explicitly labelled as an AWS secret access key appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}, match prefix "${c.prefix}", sha256 fingerprint ${c.fingerprint}). Anyone can download this file and use the key with its access key ID. Rotate the key pair immediately and move it server-side.`,
  },
  {
    cls: 'stripe-live', check: 'js-secret-stripe-live', severity: 'high',
    re: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/g,
    title: 'Live Stripe secret key in client JavaScript',
    detail: (c) => `A live Stripe secret key (sk_live_ or rk_live_) appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}, match prefix "${c.prefix}", sha256 fingerprint ${c.fingerprint}). A secret key can move money and read customer data. Roll the key in the Stripe dashboard now and keep secret keys server-side only; the publishable key (pk_live_) is the only Stripe key a browser may hold.`,
  },
  {
    cls: 'github', check: 'js-secret-github', severity: 'high',
    re: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    title: 'GitHub token in client JavaScript',
    detail: (c) => `A GitHub access token appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}, match prefix "${c.prefix}", sha256 fingerprint ${c.fingerprint}). Revoke the token immediately; anything it could reach must be treated as reachable by anyone who downloaded this file.`,
  },
  {
    // Handled specially (JWT decode); see scanCorpus.
    cls: 'supabase-service', check: 'js-secret-supabase-service', severity: 'high',
    title: 'Supabase service-role key in client JavaScript',
    detail: (c) => `A Supabase service-role JWT is embedded in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}; decoded claims: role "service_role"${c.ref ? `, project ref "${c.ref}"` : ''}; sha256 fingerprint ${c.fingerprint}). The service role bypasses Row Level Security entirely, so this key is full database access in public. Rotate it in the Supabase dashboard and treat the database as exposed until you do.`,
  },
  {
    cls: 'private-key', check: 'js-secret-private-key', severity: 'high', headerPrefix: true,
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    title: 'Private key material in client JavaScript',
    detail: (c) => `A private-key block header ("${c.prefix}") appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}). Only the header marker is recorded here, never key material — but a served private key must be considered public: revoke and replace the key pair wherever it is trusted.`,
  },
  {
    cls: 'slack', check: 'js-secret-slack', severity: 'high',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    title: 'Slack token in client JavaScript',
    detail: (c) => `A Slack token (xox…) appears in this site's first-party JavaScript (found in ${c.assetCount} asset(s); e.g. ${c.assetPath}, match prefix "${c.prefix}", sha256 fingerprint ${c.fingerprint}). Revoke the token in Slack's app settings and reissue it server-side only.`,
  },
];

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g;
const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co/;
const STRIPE_PUBLISHABLE_RE = /\bpk_live_[0-9A-Za-z]{16,}\b/g;
const GOOGLE_KEY_RE = /\bAIza[0-9A-Za-z_-]{35}\b/g;
// Discovery accepts http as well as https: the design's §8.1 fixture
// mechanics point databaseURL at loopback http origins, and the host
// gate below (not the scheme) is the SSRF control on where the probe
// may go. Real Firebase URLs are https.
const FIREBASE_DBURL_RE = /["']?databaseURL["']?\s*:\s*["'](https?:\/\/[^"']+)["']/;
const FIREBASE_PROJECT_RE = /["']?projectId["']?\s*:\s*["']([a-z][a-z0-9-]{4,28}[a-z0-9])["']/;
const FIREBASE_HINT_RE = /firebaseio\.com|firebasedatabase\.app|firebase/i;
const FIREBASE_APPID_RE = /["']?appId["']?\s*:\s*["']1:\d+:web:[0-9a-fA-F]+["']/;

// Admin/debug presence signatures (design §2.3). They choose the
// detail wording only — the outcome is Inconclusive either way.
const ADMIN_SIGNATURES = [/type\s*=\s*["']password["']/i, /<form[^>]+(login|signin|auth)/i];
const DEBUG_SIGNATURES = [
  ['Werkzeug debugger', /werkzeug debugger/i],
  ['Laravel Ignition', /ignition/i],
  ['Whoops', /whoops/i],
  ['Django debug page', /django[\s\S]{0,40}debug/i],
  ['Symfony Profiler', /symfony profiler/i],
  ['Debugbar', /debugbar/i],
  ['Laravel Telescope', /\btelescope\b/i],
  ['Spring Boot Actuator', /spring boot actuator/i],
];
const DEBUG_SIGNATURE_ANY = /(werkzeug debugger|ignition|whoops|django[\s\S]{0,40}debug|symfony profiler|debugbar|telescope|spring boot actuator)/i;

// Verbose-error signatures (design §3.5) over the soft-404 baseline
// body. Strong = frames, traces, or internal paths in an error
// context; weak = a bare framework error page with nothing behind it.
const STRONG_ERROR_SIGNATURES = [
  ['node-stack', /\n\s+at\s+[^\n]+\([^)\n]+:\d+:\d+\)/],
  ['node-stack', /(?:TypeError|ReferenceError|SyntaxError):[^\n]*\n\s+at\s/],
  ['python-traceback', /Traceback \(most recent call last\)/],
  ['php-fatal', /(?:Fatal error|Parse error|Uncaught [A-Za-z\\]+):[^\n]*\bin\s+\/\S+\s+on line\s+\d+/],
  ['java-stack', /[\w.]+Exception:[^\n]*\n\s+at\s+[\w.]+\([\w.]+:\d+\)/],
  ['java-stack', /\bjava\.[\w.]+Exception\b/],
];
const WEAK_ERROR_SIGNATURES = [
  ['whitelabel-error-page', /Whitelabel Error Page/],
  ['generic-error-title', /<title>[^<]*Internal Server Error[^<]*<\/title>/i],
  ['whoops-error-page', /Whoops, looks like something went wrong/],
];
const INTERNAL_PATH_RE = /(?:\/home\/[\w.-]+\/|\/var\/www\/|\/srv\/|\/usr\/src\/app\/)[\w./-]*/;

// Two-level public suffixes for the registrable-domain heuristic
// (design §3.1): last three labels when the last two are in this list.
const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'com.au', 'net.au', 'co.jp', 'ne.jp', 'com.br',
  'com.bd', 'co.in', 'com.cn', 'com.tw', 'co.kr', 'com.mx', 'com.sg', 'com.hk',
]);

const FIREBASE_HOSTS = ['.firebaseio.com', '.firebasedatabase.app'];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function fingerprint(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

// Details pass through redaction for secret-shaped substrings, but
// with a cap that never truncates a legitimate detail: the §4.1/§4.2
// contract wordings run past redactString's 512-char default by
// design, and a truncated reason is a broken contract.
function redactDetail(s) {
  return redactString(s, 4096);
}

function registrableDomain(host) {
  const labels = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return TWO_LEVEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function isFirstParty(assetUrl, targetHost) {
  let host;
  try {
    host = new URL(assetUrl).hostname;
  } catch {
    return false;
  }
  if (host === targetHost) return true;
  return registrableDomain(host) === registrableDomain(targetHost);
}

function scriptUrls(html, baseUrl) {
  const urls = [];
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.protocol === 'http:' || u.protocol === 'https:') urls.push(u.toString());
    } catch {
      /* ignore unparseable src */
    }
  }
  return [...new Set(urls)];
}

function decodeJwtPayload(jwt) {
  try {
    const part = jwt.split('.')[1];
    if (!part) return null;
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? obj : null;
  } catch {
    return null;
  }
}

function exhaustionOf(err) {
  if (err && err.code === 'budget') return 'budget';
  if (err && err.code === 'deadline') return 'deadline';
  return null;
}
const EXHAUST_TOKEN = { budget: 'budget-exhausted', deadline: 'deadline-exceeded' };
const EXHAUST_TEXT = {
  budget: "the scan step's request budget was exhausted",
  deadline: "the scan step's deadline was exceeded",
};

// Env-file content proof (design §2.1): not an HTML page, and either
// >= 3 distinct assignment lines or >= 1 assignment whose key is in
// the sensitive set. Values are never read into any output — only key
// NAMES and the line count leave this function.
const ENV_ASSIGN_RE = /^([A-Z][A-Z0-9_]{1,})\s*=\s*\S+/;
const ENV_SENSITIVE_KEY_RE = /^(DB_|DATABASE_|APP_KEY|APP_SECRET|SECRET|API_KEY|API_SECRET|AUTH_|SMTP_|MAIL_|AWS_|STRIPE_|PRIVATE_KEY|JWT_)/;

function envContentProof(body) {
  const text = (body || '').slice(0, 4096);
  const trimmed = text.replace(/^\s+/, '');
  if (/^<!doctype/i.test(trimmed) || /^<html/i.test(trimmed)) return null;
  const lines = new Set();
  const keyNames = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(ENV_ASSIGN_RE);
    if (m) {
      lines.add(line);
      if (!keyNames.includes(m[1])) keyNames.push(m[1]);
    }
  }
  const hasSensitive = keyNames.some((k) => ENV_SENSITIVE_KEY_RE.test(k));
  if (lines.size >= 3 || (lines.size >= 1 && hasSensitive)) {
    return { assignmentLines: lines.size, keyNames: keyNames.slice(0, 10) };
  }
  return null;
}

// Git-config content proof (design §2.2). The remote URL value is used
// ONLY to compute the embedded-credentials boolean; it is never stored
// or printed (git remotes routinely embed credentials).
function gitConfigProof(body) {
  const text = (body || '').slice(0, 4096);
  if (!/\[core\]/.test(text)) return null;
  const hasFormatVersion = /repositoryformatversion\s*=/.test(text);
  const remoteMatch = text.match(/\[remote\s+"[^"]+"\]/);
  const urlLine = text.match(/^\s*url\s*=\s*(\S+)\s*$/m);
  if (!hasFormatVersion && !(remoteMatch && urlLine)) return null;
  const sections = [];
  for (const m of text.matchAll(/\[([^\]]+)\]/g)) {
    if (!sections.includes(m[1])) sections.push(m[1]);
  }
  return {
    sections,
    hasRemote: Boolean(remoteMatch),
    remoteHasEmbeddedCredentials: Boolean(urlLine && /:\/\/[^/@\s]+:[^/@\s]+@/.test(urlLine[1])),
  };
}

// ---------------------------------------------------------------------------
// The group
// ---------------------------------------------------------------------------

export async function runExposure(ctx) {
  const restricted = !ctx.policy.probes;
  const out = [];
  const state = {
    exhaust: null, // 'budget' | 'deadline' once a phase hits the wall
    root: null, // { res, evidenceId }
    rootErr: null, // non-exhaustion error from getRoot
    baseline: null, // signatureOf(baselineRes)
    baselineRes: null,
    baselineEvidence: null,
  };

  // -- Fetch order is frozen (design §5.2): root, baseline, paths,
  // bundles, firebase probe. Evidence IDs follow fetch order.

  // (1) Root document.
  try {
    state.root = await getRoot(ctx);
  } catch (err) {
    const ex = exhaustionOf(err);
    if (ex) state.exhaust = ex;
    else state.rootErr = err;
  }

  // (2) Soft-404 baseline (also the verbose-errors corpus).
  if (!state.exhaust) {
    const nonce = Math.random().toString(36).slice(2, 12);
    const baselineUrl = ctx.url(`/ac-nonexistent-${nonce}`);
    try {
      state.baselineRes = await ctx.fetch(baselineUrl);
      state.baseline = signatureOf(state.baselineRes);
      state.baselineEvidence = httpEvidence(ctx, state.baselineRes, baselineUrl);
      state.baselineUrl = baselineUrl;
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) state.exhaust = ex;
      // Otherwise baseline stays null: 200s are judged on content
      // proof alone and fetch-failed details carry no baseline
      // evidence (mirrors exposed.js).
    }
  }

  const baselineEvIds = () => (state.baselineEvidence ? [state.baselineEvidence] : []);
  const exhaustResult = (check, title) =>
    makeCheck({
      group: GROUP, check, outcome: 'inconclusive',
      title,
      detail: `[reason:${EXHAUST_TOKEN[state.exhaust]}] This check could not be completed because ${EXHAUST_TEXT[state.exhaust]} before it ran. It is reported as inconclusive, never skipped and never passed.`,
      evidenceIds: baselineEvIds(),
    });

  // Shared per-status judgement for the file checks (env variants,
  // git config). proofFn(body) -> proof object | null; onProof builds
  // the finding's detail + extra evidence.
  async function probeFile({ check, path, label, proofFn, buildFinding }) {
    const url = ctx.url(path);
    let res;
    try {
      res = await ctx.fetch(url);
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) {
        state.exhaust = ex;
        return { exhausted: true };
      }
      return makeCheck({
        group: GROUP, check, outcome: 'inconclusive',
        title: `${label} (${path}) could not be checked`,
        detail: `[reason:fetch-failed] The request failed before a response could be judged (${err.message}).`,
        evidenceIds: baselineEvIds(),
      });
    }
    const ev = httpEvidence(ctx, res, url);
    const evIds = state.baselineEvidence ? [ev, state.baselineEvidence] : [ev];
    if (res.status === 404 || res.status === 410) {
      return makeCheck({
        group: GROUP, check, outcome: 'pass',
        title: `${label} not exposed (${path} -> ${res.status})`,
        detail: 'The path returns a not-found status.',
        evidenceIds: evIds,
      });
    }
    if (res.status === 401 || res.status === 403) {
      return makeCheck({
        group: GROUP, check, outcome: 'pass',
        title: `${label} is access-controlled (${path} -> ${res.status})`,
        detail: 'The path exists (the status reveals that much) but refuses unauthenticated access.',
        evidenceIds: evIds,
      });
    }
    if (res.status !== 200) {
      return makeCheck({
        group: GROUP, check, outcome: 'inconclusive',
        title: `${label} returned HTTP ${res.status} (${path})`,
        detail: 'A status other than 200/401/403/404 proves neither exposure nor absence.',
        evidenceIds: evIds,
      });
    }
    const sig = signatureOf(res);
    if (state.baseline && state.baseline.status === 200 && matchesBaseline(sig, state.baseline)) {
      return makeCheck({
        group: GROUP, check, outcome: 'inconclusive',
        title: `${label} "200" matches the soft-404 baseline (${path})`,
        detail: '[reason:soft-404-ambiguous] The server answers every path, real or invented, with the same 200 page. This path cannot be distinguished from a nonexistent one, so it is reported as inconclusive, never as a finding.',
        evidenceIds: evIds,
      });
    }
    const proof = proofFn(res.bodyText || '');
    if (proof) return buildFinding({ proof, res, url, evIds });
    return makeCheck({
      group: GROUP, check, outcome: 'inconclusive',
      title: `${label} returns 200 with unrecognized content (${path})`,
      detail: 'The content differs from the soft-404 baseline but matches no known exposure signature, so no verdict is claimed.',
      evidenceIds: evIds,
    });
  }

  // (3)+(4)+(5) Path phase: env variants, git config, admin/debug.
  const envSet = restricted ? ENV_CHECKS.filter((e) => ENV_CHECKS_RESTRICTED.includes(e.check)) : ENV_CHECKS;
  const pathPlan = [
    ...envSet.map((e) => ({ kind: 'env', ...e })),
    { kind: 'git', ...GIT_CHECK },
    ...SURFACE_CHECKS.map((s) => ({ kind: 'surface', ...s })),
  ];
  const surfaceResults = [];

  for (const step of pathPlan) {
    if (step.kind === 'surface' && restricted) {
      // Restricted: never requested — the cors.js not-assessed
      // precedent, because these verdicts concern surfaces whose
      // assessment implies interaction.
      surfaceResults.push(
        makeCheck({
          group: GROUP, check: step.check, outcome: 'not-assessed',
          title: `${step.surface === 'admin' ? 'Admin' : 'Debug'} surface not assessed under the restricted scan policy (${step.path})`,
          detail: '[reason:policy-restricted] Judging this surface requires interaction the restricted (unverified-target) policy does not perform; the conventional path was not requested.',
          evidenceIds: [],
        })
      );
      continue;
    }
    if (state.exhaust) {
      const r =
        step.kind === 'surface'
          ? exhaustResult(step.check, `${step.path} surface could not be checked`)
          : exhaustResult(step.check, `${step.kind === 'git' ? 'Git configuration' : 'Environment file'} (${step.path}) could not be checked`);
      if (step.kind === 'surface') surfaceResults.push(r);
      else out.push(r);
      continue;
    }

    if (step.kind === 'env' || step.kind === 'git') {
      const isEnv = step.kind === 'env';
      const r = await probeFile({
        check: step.check,
        path: step.path,
        label: isEnv ? 'Environment file' : 'Git configuration',
        proofFn: isEnv ? envContentProof : gitConfigProof,
        buildFinding: ({ proof, url, evIds }) => {
          if (isEnv) {
            const scanEv = ctx.evidence.add('content-scan', url, {
              asset: step.path,
              kind: 'env-file',
              assignmentLines: proof.assignmentLines,
              keyNames: proof.keyNames.map((n) => redactString(n, 64)),
            });
            const firstKeys = proof.keyNames.slice(0, 3).map((n) => redactString(n, 64)).join(', ');
            return makeCheck({
              group: GROUP, check: step.check, outcome: 'finding', severity: 'high',
              title: `Environment file is publicly readable (${step.path})`,
              detail: redactDetail(
                `The file at ${step.path} returns content that parses as an environment file (${proof.assignmentLines} assignment lines, keys include ${firstKeys}) and differs from the site's soft-404 baseline. Environment files routinely contain database credentials and API secrets. The file's values were not recorded; only key names are shown.`
              ),
              evidenceIds: [scanEv, ...evIds],
            });
          }
          const scanEv = ctx.evidence.add('content-scan', url, {
            asset: step.path,
            kind: 'git-config',
            sections: proof.sections.map((s) => redactString(s, 64)),
            hasRemote: proof.hasRemote,
            remoteHasEmbeddedCredentials: proof.remoteHasEmbeddedCredentials,
          });
          let detail = `The file at /.git/config parses as a real git configuration (sections: ${proof.sections.map((s) => redactString(s, 64)).join(', ')}) and differs from the site's soft-404 baseline. It exposes the repository's structure, branch names, and remote topology, and corroborates any exposed Git metadata. The remote URL value was not recorded.`;
          if (proof.remoteHasEmbeddedCredentials) {
            detail += ' The configured remote URL embeds credentials; the credential value was not recorded.';
          }
          return makeCheck({
            group: GROUP, check: step.check, outcome: 'finding', severity: 'medium',
            title: 'Git configuration is publicly readable (/.git/config)',
            detail: redactDetail(detail),
            evidenceIds: [scanEv, ...evIds],
          });
        },
      });
      if (r.exhausted) {
        const rr = exhaustResult(step.check, `${isEnv ? 'Environment file' : 'Git configuration'} (${step.path}) could not be checked`);
        out.push(rr);
      } else {
        out.push(r);
      }
      continue;
    }

    // Surface presence (admin/debug), full policy. NEVER a finding.
    const url = ctx.url(step.path);
    let res;
    try {
      res = await ctx.fetch(url);
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) {
        state.exhaust = ex;
        surfaceResults.push(exhaustResult(step.check, `${step.path} surface could not be checked`));
      } else {
        surfaceResults.push(
          makeCheck({
            group: GROUP, check: step.check, outcome: 'inconclusive',
            title: `${step.path} surface could not be checked`,
            detail: `[reason:fetch-failed] The request failed before a response could be judged (${err.message}).`,
            evidenceIds: baselineEvIds(),
          })
        );
      }
      continue;
    }
    const ev = httpEvidence(ctx, res, url);
    const evIds = state.baselineEvidence ? [ev, state.baselineEvidence] : [ev];
    const body = (res.bodyText || '').slice(0, 4096);
    if (res.status === 404 || res.status === 410) {
      surfaceResults.push(
        makeCheck({
          group: GROUP, check: step.check, outcome: 'pass',
          title: `No ${step.noun} surface at the conventional path (${step.path} -> ${res.status})`,
          detail: 'The conventional path returns a not-found status.',
          evidenceIds: evIds,
        })
      );
    } else if (res.status === 401 || res.status === 403) {
      surfaceResults.push(
        makeCheck({
          group: GROUP, check: step.check, outcome: 'pass',
          title: `${step.noun[0].toUpperCase() + step.noun.slice(1)} surface exists and refuses unauthenticated access (${step.path} -> ${res.status})`,
          detail: 'The surface exists (the status reveals that much) and refuses unauthenticated access.',
          evidenceIds: evIds,
        })
      );
    } else if (res.status === 200) {
      const sig = signatureOf(res);
      if (state.baseline && state.baseline.status === 200 && matchesBaseline(sig, state.baseline)) {
        surfaceResults.push(
          makeCheck({
            group: GROUP, check: step.check, outcome: 'inconclusive',
            title: `${step.path} "200" matches the soft-404 baseline`,
            detail: '[reason:soft-404-ambiguous] The server answers every path, real or invented, with the same 200 page. This path cannot be distinguished from a nonexistent one, so it is reported as inconclusive, never as a finding.',
            evidenceIds: evIds,
          })
        );
      } else if (step.surface === 'admin') {
        const signed = ADMIN_SIGNATURES.some((re) => re.test(body));
        surfaceResults.push(
          makeCheck({
            group: GROUP, check: step.check, outcome: 'inconclusive',
            title: 'Administration sign-in surface is served at /admin',
            detail: redactDetail(
              signed
                ? '[reason:presence-only] An administration sign-in page is served at /admin. Its presence is not itself a vulnerability, and this scan does not attempt sign-in, credential guessing, or authorization bypass, so whether the surface is properly protected is not assessed by this check. Confirm it requires strong authentication and is not reachable from networks that do not need it.'
                : '[reason:presence-only] A page is served at /admin with HTTP 200. Its presence is not itself a vulnerability, and this scan does not attempt sign-in, credential guessing, or authorization bypass, so whether the surface is properly protected is not assessed by this check. Confirm it requires strong authentication and is not reachable from networks that do not need it.'
            ),
            evidenceIds: evIds,
          })
        );
      } else {
        const dbg = DEBUG_SIGNATURES.find(([, re]) => re.test(body));
        surfaceResults.push(
          makeCheck({
            group: GROUP, check: step.check, outcome: 'inconclusive',
            title: 'Debug surface is served at /debug',
            detail: redactDetail(
              dbg
                ? `[reason:presence-only] An interactive framework debug page (${dbg[0]}) is served at /debug. Its presence is not itself a vulnerability, and this scan does not interact with it, so whether it is inert in production is not assessed by this check. Confirm debug tooling is disabled in production builds.`
                : '[reason:presence-only] A page is served at /debug with HTTP 200. Its presence is not itself a vulnerability, and this scan does not interact with it, so whether it is inert in production is not assessed by this check. Confirm debug tooling is disabled in production builds.'
            ),
            evidenceIds: evIds,
          })
        );
      }
    } else {
      surfaceResults.push(
        makeCheck({
          group: GROUP, check: step.check, outcome: 'inconclusive',
          title: `${step.path} returned HTTP ${res.status}`,
          detail: `[reason:fetch-failed] The conventional path returned HTTP ${res.status}, which establishes neither a protected surface nor an unprotected one.`,
          evidenceIds: evIds,
        })
      );
    }
  }

  // (6) JS corpus phase — unless the root never arrived or the step
  // already hit the budget/deadline wall.
  const corpusOutcome = await buildCorpusAndScan(ctx, state, restricted);
  for (const r of corpusOutcome.results) out.push(r);

  // (7) Verbose errors over the already-fetched baseline body.
  out.push(verboseErrorsResult(ctx, state));

  for (const r of surfaceResults) out.push(r);
  return out;
}

// ---------------------------------------------------------------------------
// JS corpus phase (checks 7-17)
// ---------------------------------------------------------------------------

function assetPathOf(item) {
  if (item.inline) return 'the root document';
  try {
    return new URL(item.assetUrl).pathname;
  } catch {
    return item.assetUrl;
  }
}

async function buildCorpusAndScan(ctx, state, restricted) {
  const results = [];
  const rootEvIds = state.root ? [state.root.evidenceId] : [];

  if (state.exhaust) {
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'inconclusive',
        title: 'JavaScript secret scan could not be completed',
        detail: `[reason:${EXHAUST_TOKEN[state.exhaust]}] The JavaScript corpus could not be scanned because ${EXHAUST_TEXT[state.exhaust]}. It is reported as inconclusive, never skipped and never passed.`,
        evidenceIds: rootEvIds,
      })
    );
    return { results };
  }
  if (state.rootErr || !state.root) {
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'inconclusive',
        title: 'JavaScript secret scan could not be completed',
        detail: `[reason:fetch-failed] The root document could not be fetched (${state.rootErr ? state.rootErr.message : 'no response'}), so no JavaScript corpus could be built and no secret patterns were evaluated.`,
        evidenceIds: [],
      })
    );
    return { results };
  }

  // --- Corpus construction (design §3.1) ---
  const rootUrl = state.root.res.finalUrl || ctx.url('/');
  const html = state.root.res.bodyText || '';
  const corpus = [
    { asset: '(inline root document)', assetUrl: ctx.url('/'), inline: true, body: html, res: state.root.res, error: false },
  ];
  const bundleCap = restricted ? MAX_BUNDLES_RESTRICTED : MAX_BUNDLES_FULL;
  const bundleUrls = scriptUrls(html, rootUrl).filter((u) => isFirstParty(u, ctx.host()));
  let bundleExhausted = false;
  for (const url of bundleUrls.slice(0, bundleCap)) {
    if (state.exhaust) {
      bundleExhausted = true;
      break;
    }
    try {
      const res = await ctx.fetch(url, { sizeCapBytes: Math.min(ctx.policy.sizeCapBytes, BUNDLE_SIZE_CAP) });
      corpus.push({ asset: redactUrl(url), assetUrl: url, inline: false, body: res.bodyText || '', res, error: false });
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) {
        state.exhaust = ex;
        bundleExhausted = true;
        break;
      }
      corpus.push({ asset: redactUrl(url), assetUrl: url, inline: false, body: null, res: null, error: true });
    }
  }

  // One manifest evidence item per corpus item (design §3.2). Raw
  // bodies are never stored — only sizes and flags.
  for (const item of corpus) {
    item.manifestEv = ctx.evidence.add('content-scan', item.assetUrl, {
      asset: item.asset,
      inline: item.inline,
      bytesFetched: item.body ? item.body.length : 0,
      bytesTotal: item.res ? item.res.bodyBytes : 0,
      truncated: item.res ? Boolean(item.res.truncated) : false,
      ...(item.error ? { error: true } : {}),
    });
  }
  const manifestEvIds = corpus.map((i) => i.manifestEv);
  const scannedItems = corpus.filter((i) => i.body != null);
  const hasInlineScript = [...html.matchAll(/<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)].some(
    (m) => m[1].trim().length > 0
  );

  // --- Pattern scanning (design §3.3) ---
  const hits = new Map(); // cls -> Map(item -> { count, value })
  const serviceJwts = new Map(); // item -> { count, jwt, claims }
  const anonJwts = [];
  let supaRef = null;
  let supaRefItem = null;
  let supaLabelledItem = null;
  let stripePub = null;
  let googleKey = null;

  for (const item of scannedItems) {
    const text = item.body;
    for (const def of PATTERNS) {
      if (def.cls === 'supabase-service') continue; // JWT pass below
      const matches = [...text.matchAll(def.re)];
      if (!matches.length) continue;
      const value = def.capture ? matches[0][1] : matches[0][0];
      if (!hits.has(def.cls)) hits.set(def.cls, new Map());
      hits.get(def.cls).set(item, { count: matches.length, value });
    }
    for (const m of text.matchAll(JWT_RE)) {
      const claims = decodeJwtPayload(m[0]);
      if (!claims) continue;
      if (claims.role === 'service_role') {
        const prev = serviceJwts.get(item);
        if (prev) prev.count += 1;
        else serviceJwts.set(item, { count: 1, jwt: m[0], claims });
      } else if (claims.role === 'anon') {
        anonJwts.push({ item, jwt: m[0], claims });
      }
    }
    if (!supaRef) {
      const m = text.match(SUPABASE_URL_RE);
      if (m) {
        supaRef = m[1];
        supaRefItem = item;
      }
    }
    if (!supaLabelledItem && /supabase/i.test(text) && /["']?anon["']?\s*[:=]/.test(text)) {
      supaLabelledItem = item;
    }
    if (!stripePub) {
      const m = text.match(STRIPE_PUBLISHABLE_RE);
      if (m) stripePub = { item, value: m[0] };
    }
    if (!googleKey) {
      const m = text.match(GOOGLE_KEY_RE);
      if (m) googleKey = { item, value: m[0] };
    }
  }

  // --- Per-class findings (pattern-table order) ---
  let anyMatch = false;
  for (const def of PATTERNS) {
    if (def.cls === 'supabase-service') {
      if (!serviceJwts.size) continue;
      anyMatch = true;
      const items = [...serviceJwts.entries()].slice(0, 3);
      const evIds = items.map(([item, hit]) =>
        ctx.evidence.add('content-scan', item.assetUrl, {
          asset: item.asset,
          pattern: 'supabase-service',
          matchCount: hit.count,
          prefix: 'eyJ',
          fingerprint: fingerprint(hit.jwt),
          matchLength: hit.jwt.length,
          claims: { role: 'service_role', ref: typeof hit.claims.ref === 'string' ? hit.claims.ref : null },
        })
      );
      const [firstItem, firstHit] = [...serviceJwts.entries()][0];
      results.push(
        makeCheck({
          group: GROUP, check: def.check, outcome: 'finding', severity: def.severity,
          title: def.title,
          detail: redactDetail(
            def.detail({
              assetCount: serviceJwts.size,
              assetPath: assetPathOf(firstItem),
              fingerprint: fingerprint(firstHit.jwt),
              ref: typeof firstHit.claims.ref === 'string' ? redactString(firstHit.claims.ref, 64) : null,
            })
          ),
          evidenceIds: evIds,
        })
      );
      continue;
    }
    const perItem = hits.get(def.cls);
    if (!perItem || !perItem.size) continue;
    anyMatch = true;
    const items = [...perItem.entries()].slice(0, 3);
    const evIds = items.map(([item, hit]) =>
      ctx.evidence.add('content-scan', item.assetUrl, {
        asset: item.asset,
        pattern: def.cls,
        matchCount: hit.count,
        prefix: def.headerPrefix ? hit.value : hit.value.slice(0, 8),
        fingerprint: fingerprint(hit.value),
        matchLength: hit.value.length,
      })
    );
    const [firstItem, firstHit] = [...perItem.entries()][0];
    results.push(
      makeCheck({
        group: GROUP, check: def.check, outcome: 'finding', severity: def.severity,
        title: def.title,
        detail: redactDetail(
          def.detail({
            assetCount: perItem.size,
            assetPath: assetPathOf(firstItem),
            prefix: def.headerPrefix ? firstHit.value : firstHit.value.slice(0, 8),
            fingerprint: fingerprint(firstHit.value),
          })
        ),
        evidenceIds: evIds,
      })
    );
  }

  // --- js-secrets aggregate (design §4.4) ---
  const truncatedOrErrored = corpus.filter((i) => i.error || (i.res && i.res.truncated));
  if (anyMatch) {
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'pass',
        title: 'Secret-pattern scanning completed',
        detail: 'Secret-pattern scanning completed; matches are reported as their own findings.',
        evidenceIds: manifestEvIds,
      })
    );
  } else if (bundleExhausted || state.exhaust) {
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'inconclusive',
        title: 'JavaScript secret scan stopped early',
        detail: `[reason:${EXHAUST_TOKEN[state.exhaust]}] Bundle fetching stopped because ${EXHAUST_TEXT[state.exhaust]}, so the unscanned remainder of the corpus cannot support a clean verdict. No secret patterns were observed in the portion that was scanned.`,
        evidenceIds: manifestEvIds,
      })
    );
  } else if (truncatedOrErrored.length) {
    const parts = truncatedOrErrored.map((i) =>
      i.error ? `${assetPathOf(i)} could not be fetched` : `${assetPathOf(i)} exceeded the fetch size cap and was scanned only in part`
    );
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'inconclusive',
        title: 'JavaScript secret scan was partial',
        detail: redactDetail(
          `[reason:bundle-truncated] Part of the first-party JavaScript corpus could not be scanned completely (${parts.join('; ')}), so a clean verdict is not claimed for the unscanned remainder. No secret patterns were observed in the portion that was scanned.`
        ),
        evidenceIds: manifestEvIds,
      })
    );
  } else if (bundleUrls.length === 0 && !hasInlineScript) {
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'inconclusive',
        title: 'No first-party JavaScript to scan',
        detail: '[reason:no-first-party-js] The root document references no first-party JavaScript bundles and contains no inline script content, so there was no client code to scan for secret patterns.',
        evidenceIds: manifestEvIds,
      })
    );
  } else {
    const totalBytes = scannedItems.reduce((n, i) => n + (i.body ? i.body.length : 0), 0);
    results.push(
      makeCheck({
        group: GROUP, check: 'js-secrets', outcome: 'pass',
        title: 'No known secret patterns in first-party JavaScript',
        detail: `No known secret patterns in ${scannedItems.length} scanned first-party assets (${totalBytes} bytes). Patterns are anchored formats (AWS, Stripe, GitHub, Supabase service-role, Slack, private-key blocks); this does not prove the absence of every possible credential.`,
        evidenceIds: manifestEvIds,
      })
    );
  }

  // --- supabase-config (design §4.1): presence only, never a finding ---
  const anonFirst = anonJwts[0] || null;
  const supaTriggerItem = supaRefItem || (anonFirst ? anonFirst.item : null) || supaLabelledItem;
  if (!serviceJwts.size && (supaRef || anonFirst || supaLabelledItem)) {
    const ev = ctx.evidence.add('content-scan', supaTriggerItem.assetUrl, {
      asset: supaTriggerItem.asset,
      pattern: 'supabase-config',
      projectRef: supaRef,
      anonKeyFingerprint: anonFirst ? fingerprint(anonFirst.jwt) : null,
    });
    const refText = supaRef ? redactString(supaRef, 64) : 'not captured';
    let detail;
    if (supaRef && anonFirst) {
      detail = `[reason:config-presence] This site's JavaScript contains a Supabase project reference (project ref: ${refText}) and an anonymous (anon) API key. Both are designed to be public in browser clients; their presence is not a vulnerability. What this scan cannot determine anonymously is whether Row Level Security policies actually restrict the anon role, which is the control that decides whether this configuration is safe. Verify in the Supabase dashboard that RLS is enabled on every table and that policies grant the anon role only the rows it needs. If the service-role key were exposed instead, that WOULD be a finding; it was not observed.`;
    } else if (supaRef) {
      detail = `[reason:config-presence] This site's JavaScript contains a Supabase project reference (project ref: ${refText}); no anonymous (anon) API key was captured in the scanned assets. A project reference is designed to be public in browser clients; its presence is not a vulnerability. What this scan cannot determine anonymously is whether Row Level Security policies actually restrict the anon role, which is the control that decides whether this configuration is safe. Verify in the Supabase dashboard that RLS is enabled on every table and that policies grant the anon role only the rows it needs. If the service-role key were exposed instead, that WOULD be a finding; it was not observed.`;
    } else {
      detail = `[reason:config-presence] This site's JavaScript contains an anonymous (anon) API key for a Supabase project (project ref: not captured). Anon keys are designed to be public in browser clients; their presence is not a vulnerability. What this scan cannot determine anonymously is whether Row Level Security policies actually restrict the anon role, which is the control that decides whether this configuration is safe. Verify in the Supabase dashboard that RLS is enabled on every table and that policies grant the anon role only the rows it needs. If the service-role key were exposed instead, that WOULD be a finding; it was not observed.`;
    }
    results.push(
      makeCheck({
        group: GROUP, check: 'supabase-config', outcome: 'inconclusive',
        title: anonFirst
          ? 'Supabase project reference and anonymous key are embedded in client code'
          : 'Supabase project reference is embedded in client code',
        detail: redactDetail(detail),
        evidenceIds: [ev],
      })
    );
  }

  // --- client-keys (design §4.2): browser-intended keys, never a finding ---
  if (stripePub || googleKey) {
    const evIds = [];
    if (stripePub) {
      evIds.push(
        ctx.evidence.add('content-scan', stripePub.item.assetUrl, {
          asset: stripePub.item.asset,
          pattern: 'stripe-publishable',
          prefix: stripePub.value.slice(0, 8),
          fingerprint: fingerprint(stripePub.value),
          matchLength: stripePub.value.length,
        })
      );
    }
    if (googleKey) {
      evIds.push(
        ctx.evidence.add('content-scan', googleKey.item.assetUrl, {
          asset: googleKey.item.asset,
          pattern: 'google-api-key',
          prefix: googleKey.value.slice(0, 8),
          fingerprint: fingerprint(googleKey.value),
          matchLength: googleKey.value.length,
        })
      );
    }
    const seen = stripePub && googleKey ? 'a Stripe publishable key and a Google API key' : stripePub ? 'a Stripe publishable key' : 'a Google API key';
    results.push(
      makeCheck({
        group: GROUP, check: 'client-keys', outcome: 'inconclusive',
        title: 'Browser-intended API keys are present in client code',
        detail: redactDetail(
          `[reason:publishable-key] The site's JavaScript contains ${seen}. These key types are designed to be embedded in browsers — a publishable key can only initiate client-side payment flows, and a browser Google key is identified by it in every request. Their presence is not a finding. What this scan cannot verify is the server-side restriction posture: the Google key should carry HTTP referrer restrictions limited to this site's origins, and no SECRET key of either provider should ever appear in client code (none was observed; secret keys are checked separately and WOULD be a finding).`
        ),
        evidenceIds: evIds,
      })
    );
  }

  // --- firebase-rtdb (design §3.4) ---
  const fb = await firebaseProbe(ctx, state, scannedItems);
  if (fb) results.push(fb);

  return { results };
}

// Firebase discovery + the single shallow probe. The database URL is
// target-supplied data, so the probe is gated to real Firebase hosts
// (design §3.4 / §10.4) unless the scan context itself is our own
// allowPrivate demo/fixture context. Without the gate this check
// would be an SSRF oracle; with it, the check is one anonymous GET
// whose shallow response contains key NAMES only, by construction.
async function firebaseProbe(ctx, state, scannedItems) {
  let dbUrl = null;
  let dbItem = null;
  let urlSource = null;
  let projectId = null;
  let projectItem = null;
  let materialItem = null;

  for (const item of scannedItems) {
    const m = item.body.match(FIREBASE_DBURL_RE);
    if (m) {
      dbUrl = m[1];
      dbItem = item;
      urlSource = 'config';
      break;
    }
  }
  if (!dbUrl) {
    for (const item of scannedItems) {
      const m = item.body.match(FIREBASE_PROJECT_RE);
      if (m) {
        projectId = m[1];
        projectItem = item;
        break;
      }
    }
    if (projectId) {
      dbUrl = `https://${projectId}-default-rtdb.firebaseio.com`;
      dbItem = projectItem;
      urlSource = 'project-id';
    }
  }
  if (!dbUrl) {
    for (const item of scannedItems) {
      if (FIREBASE_HINT_RE.test(item.body) || FIREBASE_APPID_RE.test(item.body)) {
        materialItem = item;
        break;
      }
    }
    if (!materialItem) return null; // no Firebase material at all
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
      title: 'Firebase configuration present; Realtime Database not identifiable',
      detail: '[reason:config-incomplete] Firebase configuration material is present in this site\'s client code, but no databaseURL or projectId could be identified, so the Realtime Database could not be located to judge its rules. Presence of Firebase configuration is not itself a vulnerability.',
      evidenceIds: [materialItem.manifestEv],
    });
  }

  let dbHost = '';
  try {
    dbHost = new URL(dbUrl).hostname;
  } catch {
    dbHost = '';
  }
  const hostTrusted =
    FIREBASE_HOSTS.some((suffix) => dbHost === suffix.slice(1) || dbHost.endsWith(suffix)) || ctx.allowPrivate;
  if (!hostTrusted) {
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
      title: 'Firebase database URL points at a non-Firebase host; not probed',
      detail: redactDetail(
        `[reason:db-host-untrusted] The Firebase configuration in this site's client code names a database URL on a non-Firebase host (${dbHost || 'unparseable'}). A URL supplied by the scanned page is never followed to a host that is not a known Firebase domain, so the database was not probed.`
      ),
      evidenceIds: [dbItem.manifestEv],
    });
  }

  const probeUrl = `${dbUrl.replace(/\/+$/, '')}/.json?shallow=true`;
  let res;
  try {
    res = await ctx.fetch(probeUrl);
  } catch (err) {
    const ex = exhaustionOf(err);
    if (ex) {
      state.exhaust = ex;
      return makeCheck({
        group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
        title: 'Firebase Realtime Database could not be probed',
        detail: `[reason:${EXHAUST_TOKEN[ex]}] The Firebase database probe could not run because ${EXHAUST_TEXT[ex]}.`,
        evidenceIds: [dbItem.manifestEv],
      });
    }
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
      title: 'Firebase Realtime Database could not be probed',
      detail: redactDetail(
        `[reason:fetch-failed] The database probe failed before a response could be judged (${err.message}).${res_status_404_hint(urlSource)}`
      ),
      evidenceIds: [dbItem.manifestEv],
    });
  }
  const probeEv = httpEvidence(ctx, res, probeUrl);
  const evIds = [probeEv, dbItem.manifestEv];
  const constructedNote =
    urlSource === 'project-id'
      ? ' The database URL was constructed from the projectId in the client configuration (no databaseURL was stated directly).'
      : '';

  if (res.status === 401 || res.status === 403) {
    return firebaseDenied(evIds, `HTTP ${res.status}`, constructedNote);
  }
  if (res.status === 404) {
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
      title: 'Firebase Realtime Database probe returned 404',
      detail: redactDetail(
        `[reason:fetch-failed] The configured database endpoint returned 404.${urlSource === 'project-id' ? ' The project may not have a Realtime Database, or it may live in a region the constructed URL does not reach.' : ''}${constructedNote}`
      ),
      evidenceIds: evIds,
    });
  }
  if (res.status !== 200) {
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
      title: `Firebase Realtime Database probe returned HTTP ${res.status}`,
      detail: `[reason:fetch-failed] A status other than 200/401/403 proves neither open rules nor closed ones.${constructedNote}`,
      evidenceIds: evIds,
    });
  }
  const text = (res.bodyText || '').trim();
  if (text === 'null' || text === '{}') {
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'pass',
      title: 'Firebase Realtime Database root is empty',
      detail: `An unauthenticated shallow read of the configured database root returned no data, so nothing is readable at the root.${constructedNote}`,
      evidenceIds: evIds,
    });
  }
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && typeof parsed.error === 'string' && /permission denied/i.test(parsed.error)) {
    return firebaseDenied(evIds, 'a permission-denied response', constructedNote);
  }
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length >= 1) {
    const keyNames = Object.keys(parsed).sort();
    const scanEv = ctx.evidence.add('content-scan', dbUrl, {
      asset: redactUrl(dbUrl),
      kind: 'firebase-rtdb-root',
      keyCount: keyNames.length,
      keyNames: keyNames.slice(0, 20).map((n) => redactString(n, 64)),
    });
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'finding', severity: 'high',
      title: 'Firebase Realtime Database is readable without authentication',
      detail: redactDetail(
        `The Firebase Realtime Database configured in this site's own client code answers an unauthenticated read of its root, exposing ${keyNames.length} top-level collections (names only recorded: ${keyNames.slice(0, 5).map((n) => redactString(n, 64)).join(', ')}). Anyone on the internet can read — and, if the rules are as permissive for writes, modify — this data. Restrict the database rules to authenticated, per-user access.${constructedNote}`
      ),
      evidenceIds: [scanEv, ...evIds],
    });
  }
  return makeCheck({
    group: GROUP, check: 'firebase-rtdb', outcome: 'inconclusive',
    title: 'Firebase Realtime Database probe was not parseable',
    detail: `[reason:fetch-failed] The database probe returned HTTP 200 but the response could not be parsed as a complete JSON document${res.truncated ? ' (the response exceeded the fetch size cap and arrived truncated)' : ''}, so no verdict is claimed.${constructedNote}`,
    evidenceIds: evIds,
  });

  function firebaseDenied(ids, how, note) {
    return makeCheck({
      group: GROUP, check: 'firebase-rtdb', outcome: 'pass',
      title: 'Firebase Realtime Database denies unauthenticated reads',
      detail: `The database configured in this site's client code refuses an unauthenticated read of its root (${how}), so its rules are doing their job at the root. Rules for paths below the root were not evaluated.${note}`,
      evidenceIds: ids,
    });
  }
  function res_status_404_hint(source) {
    return source === 'project-id' ? ' The project may not have a Realtime Database, or it may live in a region the constructed URL does not reach.' : '';
  }
}

// ---------------------------------------------------------------------------
// Verbose errors (check 18) — zero added requests: the corpus is the
// soft-404 baseline body already fetched for the path phase.
// ---------------------------------------------------------------------------

function verboseErrorsResult(ctx, state) {
  const check = 'verbose-errors';
  if (state.exhaust === 'deadline') {
    return makeCheck({
      group: GROUP, check, outcome: 'inconclusive',
      title: 'Error responses could not be judged',
      detail: `[reason:deadline-exceeded] The error-surface check did not run because ${EXHAUST_TEXT.deadline}.`,
      evidenceIds: [],
    });
  }
  if (!state.baselineRes) {
    const token = state.exhaust === 'budget' ? 'budget-exhausted' : 'fetch-failed';
    const why =
      state.exhaust === 'budget'
        ? `the baseline request could not be made because ${EXHAUST_TEXT.budget}`
        : 'the soft-404 baseline request failed';
    return makeCheck({
      group: GROUP, check, outcome: 'inconclusive',
      title: 'Error responses could not be judged',
      detail: `[reason:${token}] No error response was available to judge for stack traces or internal paths: ${why}.`,
      evidenceIds: [],
    });
  }
  const evIds = state.baselineEvidence ? [state.baselineEvidence] : [];
  const body = (state.baselineRes.bodyText || '').slice(0, 8192);

  const strong = [];
  for (const [name, re] of STRONG_ERROR_SIGNATURES) {
    const m = body.match(re);
    if (m) strong.push({ name, index: m.index });
  }
  const aspnet = body.match(/Server Error in '[^']+' Application/);
  if (aspnet && /<customErrors|stack trace/i.test(body)) strong.push({ name: 'aspnet-error', index: aspnet.index });
  const dbg = body.match(DEBUG_SIGNATURE_ANY);
  if (dbg) strong.push({ name: 'framework-debug', index: dbg.index });
  const pathRe = new RegExp(INTERNAL_PATH_RE.source, 'g');
  let pm;
  while ((pm = pathRe.exec(body)) !== null) {
    const before = body.slice(Math.max(0, pm.index - 200), pm.index);
    if (/error|exception|failed/i.test(before)) {
      strong.push({ name: 'internal-path', index: pm.index });
      break;
    }
  }

  if (strong.length) {
    strong.sort((a, b) => a.index - b.index);
    const names = [...new Set(strong.map((s) => s.name))];
    const first = strong[0];
    const excerpt = redactString(body.slice(Math.max(0, first.index - 30), first.index + 50).replace(/\s+/g, ' '), 96);
    const scanEv = ctx.evidence.add('content-scan', state.baselineUrl, {
      asset: redactUrl(state.baselineUrl),
      kind: 'error-surface',
      signatures: names,
      excerpt,
    });
    return makeCheck({
      group: GROUP, check, outcome: 'finding', severity: 'medium',
      title: 'Error responses disclose stack traces or internal paths',
      detail: redactDetail(
        `The response served for a nonexistent path discloses internal implementation details (signatures: ${names.join(', ')}). Stack frames and internal file paths hand an attacker the exact code layout to aim at. Serve a generic error page in production and keep stack traces in server logs only.`
      ),
      evidenceIds: [scanEv, ...evIds],
    });
  }

  const weak = WEAK_ERROR_SIGNATURES.filter(([, re]) => re.test(body)).map(([name]) => name);
  if (weak.length) {
    const scanEv = ctx.evidence.add('content-scan', state.baselineUrl, {
      asset: redactUrl(state.baselineUrl),
      kind: 'error-surface',
      signatures: weak,
      excerpt: null,
    });
    return makeCheck({
      group: GROUP, check, outcome: 'inconclusive',
      title: 'Error page resembles a framework default',
      detail: `[reason:weak-signature] The response to a nonexistent path is a bare framework error page (${weak.join(', ')}), with no stack frames, internal paths, or debug-tooling signatures, so information disclosure is not proven. Confirm the production error handler never renders the framework's debug variant.`,
      evidenceIds: [scanEv, ...evIds],
    });
  }

  return makeCheck({
    group: GROUP, check, outcome: 'pass',
    title: 'Error responses do not disclose internals',
    detail: 'Error responses do not disclose stack traces or internal paths (judged on the response to a nonexistent path).',
    evidenceIds: evIds,
  });
}
