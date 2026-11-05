// Group 10 — Authentication & injection (admin-only).
//
// Added 2026-11-05 at the founder's direction, AFTER the hackathon
// submission. This group exists only under a validated admin scan
// grant (ctx.adminAuthorized, set solely by src/lib/admin/scans.js
// from a durable grant row). Every other scan — public, restricted,
// verified, demo — receives two Not assessed results and this module
// makes ZERO requests. The scanner/index.js registry includes the
// group for every scan so assembly stays uniform; the gate is here.
//
// Scope is detection, never exploitation, and it is bounded by
// construction:
//  - SQL injection: error-based detection only. For each discovered
//    GET form parameter (max 3 injection points), ONE baseline
//    request with a benign value and ONE probe request with a single
//    quote appended. A finding requires a database error signature
//    in the probe response that is absent from the baseline. No
//    UNION, no stacked queries, no data extraction, ever.
//  - Default credentials: only for products fingerprinted on the
//    target that have a documented factory default (Grafana,
//    Apache Tomcat Manager). One single attempt per product with
//    that one documented default, then stop either way. No
//    wordlists, no user enumeration, no guessing at generic login
//    forms (a login form whose product is unknown is never tried).
import { makeCheck, redactString } from '../evidence.js';
import { httpEvidence, getRoot } from './common.js';

const GROUP = 'auth';

const MAX_INJECTION_POINTS = 3;
const PROBE_VALUE = 'acprobe123';

// Database error signatures (error-based detection). Anchored to
// vendor error phrasing, not to generic words like "error".
const SQL_ERROR_SIGNATURES = [
  ['mysql', /you have an error in your sql syntax|mysql_fetch|mysqli_sql_exception|mysqlexception/i],
  ['postgres', /pg_query\(\)|npgsql\.|postgres(?:ql)? error|PSQLException/i],
  ['sqlite', /sqlite3\.operationalerror|sqlite_exception|SQLITE_ERROR/i],
  ['mssql', /unclosed quotation mark|microsoft ole db provider for sql server|system\.data\.sqlclient\.sqlexception/i],
  ['oracle', /\bORA-\d{5}\b/],
  ['generic-sql', /(?:syntax error|unterminated quoted string)[\s\S]{0,80}\bsql\b|\bsql\b[\s\S]{0,80}(?:syntax error|unterminated quoted string)/i],
];

function sqlErrorIn(body) {
  const text = (body || '').slice(0, 8192);
  for (const [name, re] of SQL_ERROR_SIGNATURES) {
    if (re.test(text)) return name;
  }
  return null;
}

function exhaustionOf(err) {
  if (err && err.code === 'budget') return 'budget';
  if (err && err.code === 'deadline') return 'deadline';
  return null;
}

// ---------------------------------------------------------------------------
// Form discovery (root document only)
// ---------------------------------------------------------------------------

function attr(tag, name) {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(tag);
  return m ? m[1] : null;
}

function discoverForms(html, rootUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html || '')) !== null && forms.length < 4) {
    const attrs = fm[1];
    const inner = fm[2];
    const method = (attr(attrs, 'method') || 'get').toLowerCase();
    if (method !== 'get') continue; // GET forms only: the probe is a URL parameter.
    let actionUrl;
    try {
      actionUrl = new URL(attr(attrs, 'action') || rootUrl, rootUrl);
    } catch {
      continue;
    }
    const inputs = [];
    const inputRe = /<input\b[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(inner)) !== null) {
      const tag = im[0];
      const name = attr(tag, 'name');
      if (!name) continue;
      const type = (attr(tag, 'type') || 'text').toLowerCase();
      inputs.push({ name, type, value: attr(tag, 'value') || '' });
    }
    if (inputs.length) forms.push({ actionUrl, inputs });
  }
  return forms;
}

function buildProbeUrl(form, targetParam, value, baseOrigin) {
  const u = new URL(form.actionUrl.toString());
  if (u.origin !== baseOrigin) return null; // never probe off-origin
  for (const input of form.inputs) {
    if (input.type === 'submit' || input.type === 'button' || input.type === 'image' || input.type === 'checkbox' || input.type === 'radio' || input.type === 'file') continue;
    if (input.name === targetParam) u.searchParams.set(input.name, value);
    else if (input.value) u.searchParams.set(input.name, input.value);
    else if (input.type === 'text' || input.type === 'search' || input.type === 'hidden') u.searchParams.set(input.name, PROBE_VALUE);
  }
  return u.toString();
}

// ---------------------------------------------------------------------------
// Check 1 — error-based SQL injection detection
// ---------------------------------------------------------------------------

async function checkSqli(ctx, root) {
  if (!root) {
    return makeCheck({
      group: GROUP, check: 'sqli-error', outcome: 'inconclusive',
      title: 'SQL injection detection could not run',
      detail: '[reason:fetch-failed] The root document could not be fetched, so no form parameters could be discovered to probe.',
      evidenceIds: [],
    });
  }
  const rootUrl = root.res.finalUrl || ctx.url('/');
  let baseOrigin;
  try {
    baseOrigin = new URL(rootUrl).origin;
  } catch {
    baseOrigin = ctx.base.origin;
  }
  const forms = discoverForms(root.res.bodyText || '', rootUrl);
  const points = [];
  for (const form of forms) {
    for (const input of form.inputs) {
      if (points.length >= MAX_INJECTION_POINTS) break;
      if (input.type !== 'text' && input.type !== 'search') continue;
      points.push({ form, param: input.name });
    }
  }
  if (!points.length) {
    return makeCheck({
      group: GROUP, check: 'sqli-error', outcome: 'not-assessed',
      title: 'No injectable parameters discovered',
      detail: '[reason:no-injection-points] The root document exposes no GET form with a text parameter to probe, and this check probes only parameters it can discover on the landing page. Injection points behind navigation, POST forms, and APIs are not assessed by this check.',
      evidenceIds: [root.evidenceId],
    });
  }

  const evIds = [root.evidenceId];
  let exhausted = null;
  let completed = 0;
  for (const point of points) {
    const baselineUrl = buildProbeUrl(point.form, point.param, PROBE_VALUE, baseOrigin);
    const probeUrl = buildProbeUrl(point.form, point.param, `${PROBE_VALUE}'`, baseOrigin);
    if (!baselineUrl || !probeUrl) continue;
    let baseline;
    let probe;
    try {
      baseline = await ctx.fetch(baselineUrl);
      evIds.push(httpEvidence(ctx, baseline, baselineUrl));
      probe = await ctx.fetch(probeUrl);
      evIds.push(httpEvidence(ctx, probe, probeUrl));
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) { exhausted = ex; break; }
      continue;
    }
    completed += 1;
    const probeError = sqlErrorIn(probe.bodyText);
    const baselineError = sqlErrorIn(baseline.bodyText);
    if (probeError && !baselineError) {
      const actionPath = (() => { try { return new URL(probeUrl).pathname; } catch { return '/'; } })();
      return makeCheck({
        group: GROUP, check: 'sqli-error', outcome: 'finding', severity: 'high',
        title: `Error-based SQL injection signal on parameter "${redactString(point.param, 64)}" (${actionPath})`,
        detail: `A single quote appended to the "${redactString(point.param, 64)}" parameter produced a ${probeError} database error signature that the benign baseline value did not, which indicates the parameter reaches a SQL query without adequate parameterization. Detection used one malformed-input probe only; no data was extracted and no further payloads were sent.`,
        evidenceIds: evIds,
      });
    }
  }
  if (exhausted) {
    return makeCheck({
      group: GROUP, check: 'sqli-error', outcome: 'inconclusive',
      title: 'SQL injection detection stopped early',
      detail: `[reason:${exhausted === 'budget' ? 'budget-exhausted' : 'deadline-exceeded'}] Probing stopped before every discovered parameter could be tested, so a clean verdict is not claimed.`,
      evidenceIds: evIds,
    });
  }
  if (!completed) {
    return makeCheck({
      group: GROUP, check: 'sqli-error', outcome: 'inconclusive',
      title: 'SQL injection detection could not complete a probe',
      detail: '[reason:fetch-failed] Every probe request failed before a response could be judged.',
      evidenceIds: evIds,
    });
  }
  return makeCheck({
    group: GROUP, check: 'sqli-error', outcome: 'pass',
    title: 'No error-based SQL injection signal on discovered parameters',
    detail: `Each discovered GET form parameter (${completed} probed) was tested with a benign baseline and a single-quote probe; no database error signature appeared. This covers error-based detection on landing-page forms only and does not prove the absence of blind or second-order injection elsewhere.`,
    evidenceIds: evIds,
  });
}

// ---------------------------------------------------------------------------
// Check 2 — bounded default-credential verification (fingerprinted only)
// ---------------------------------------------------------------------------

const DEFAULT_CRED_PRODUCTS = [
  {
    product: 'Grafana',
    defaultLabel: 'admin/admin',
    fingerprintPath: '/login',
    fingerprint: (res) => res.status === 200 && /grafana/i.test(res.bodyText || ''),
    attempt: async (ctx, url) => {
      const res = await ctx.fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ user: 'admin', password: 'admin' }),
        follow: false,
      });
      const ok = res.status === 200 && (/"message"\s*:\s*"logged in"/i.test(res.bodyText || '') || (res.setCookies || []).length > 0);
      return { res, ok };
    },
  },
  {
    product: 'Apache Tomcat Manager',
    defaultLabel: 'tomcat/tomcat',
    fingerprintPath: '/manager/html',
    fingerprint: (res) =>
      res.status === 401 &&
      (/tomcat/i.test(res.headers['www-authenticate'] || '') || /tomcat/i.test(res.bodyText || '')),
    attempt: async (ctx, url) => {
      const basic = Buffer.from('tomcat:tomcat', 'utf8').toString('base64');
      const res = await ctx.fetch(url, { headers: { authorization: `Basic ${basic}` }, follow: false });
      return { res, ok: res.status === 200 };
    },
  },
];

async function checkDefaultCreds(ctx) {
  const evIds = [];
  const tested = [];
  const accepted = [];
  let exhausted = null;

  for (const def of DEFAULT_CRED_PRODUCTS) {
    const url = ctx.url(def.fingerprintPath);
    let fp;
    try {
      fp = await ctx.fetch(url, { follow: false });
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) { exhausted = ex; break; }
      continue;
    }
    evIds.push(httpEvidence(ctx, fp, url));
    if (!def.fingerprint(fp)) continue;
    tested.push(def.product);
    let outcome;
    try {
      outcome = await def.attempt(ctx, url);
    } catch (err) {
      const ex = exhaustionOf(err);
      if (ex) { exhausted = ex; break; }
      continue;
    }
    evIds.push(httpEvidence(ctx, outcome.res, url));
    if (outcome.ok) accepted.push(def);
  }

  if (accepted.length) {
    const names = accepted.map((d) => `${d.product} (${d.defaultLabel})`).join('; ');
    return makeCheck({
      group: GROUP, check: 'default-creds', outcome: 'finding', severity: 'high',
      title: `Factory default credentials accepted: ${accepted.map((d) => d.product).join(', ')}`,
      detail: `The fingerprinted product(s) accepted their documented factory default credentials in a single verification attempt: ${names}. Anyone who knows the product's public defaults can sign in. Change the default password immediately and, where the product supports it, disable or rename the default account. Exactly one attempt per product was made; no other credentials were tried.`,
      evidenceIds: evIds,
    });
  }
  if (exhausted && !tested.length) {
    return makeCheck({
      group: GROUP, check: 'default-creds', outcome: 'inconclusive',
      title: 'Default-credential verification stopped early',
      detail: `[reason:${exhausted === 'budget' ? 'budget-exhausted' : 'deadline-exceeded'}] Fingerprinting stopped before any product could be verified, so no verdict is claimed.`,
      evidenceIds: evIds,
    });
  }
  if (tested.length) {
    return makeCheck({
      group: GROUP, check: 'default-creds', outcome: 'pass',
      title: `Factory default credentials rejected (${tested.join(', ')})`,
      detail: `The fingerprinted product(s) — ${tested.join(', ')} — were each given exactly one attempt with their documented factory default credentials and refused them. No other credentials were tried.`,
      evidenceIds: evIds,
    });
  }
  return makeCheck({
    group: GROUP, check: 'default-creds', outcome: 'not-assessed',
    title: 'No fingerprinted product with factory defaults found',
    detail: '[reason:no-fingerprinted-product] Default-credential verification only runs against products this scan can fingerprint that ship with a documented factory default (Grafana, Apache Tomcat Manager). Neither was identified on this target, and generic login forms are never guessed at, so no credential attempt was made.',
    evidenceIds: evIds,
  });
}

// ---------------------------------------------------------------------------
// The group
// ---------------------------------------------------------------------------

export async function runAuth(ctx) {
  if (!ctx.adminAuthorized) {
    const detail =
      '[reason:admin-only] This group performs bounded active probes (a single-quote injection probe and single-attempt factory-default verification on fingerprinted products). It runs only under a validated admin scan grant; this scan has none, so no probe was sent.';
    return [
      makeCheck({
        group: GROUP, check: 'sqli-error', outcome: 'not-assessed',
        title: 'SQL injection detection not assessed (admin-only check)',
        detail, evidenceIds: [],
      }),
      makeCheck({
        group: GROUP, check: 'default-creds', outcome: 'not-assessed',
        title: 'Default-credential verification not assessed (admin-only check)',
        detail, evidenceIds: [],
      }),
    ];
  }

  let root = null;
  try {
    root = await getRoot(ctx);
  } catch {
    root = null; // each check degrades on its own terms below
  }
  const sqli = await checkSqli(ctx, root);
  const creds = await checkDefaultCreds(ctx);
  return [sqli, creds];
}
