// Downloads (SPEC.md v2.2, P1 locked): the two report artifacts.
//
//  - auditcanvas-evidence.json — the redacted evidence bundle, exactly
//    as stored, with a VERSIONED schema (schemaVersion in every
//    bundle). Every finding ID resolves to its evidence IDs inside the
//    bundle, so the artifact is independently inspectable without
//    trusting the UI.
//
//  - auditcanvas-fix-pack.zip — one fix file per finding. Each file's
//    header carries its finding ID and evidence IDs, states which
//    stack and conditions it applies to and exactly where it belongs,
//    and is labelled a SUGGESTED PATCH — untested until a rescan
//    verifies the fix. Only files applicable to the detected stack are
//    generated: an nginx config is never produced for a deployment
//    whose stack gives no sign of nginx.
import { EVIDENCE_SCHEMA_VERSION, SCANNER_VERSION } from './evidence.js';
import { createZip } from './zip.js';

export const EVIDENCE_FILENAME = 'auditcanvas-evidence.json';
export const FIX_PACK_FILENAME = 'auditcanvas-fix-pack.zip';

// ---------------------------------------------------------------------------
// Evidence bundle
// ---------------------------------------------------------------------------

export function buildEvidenceBundle(report) {
  return {
    bundle: 'auditcanvas-evidence',
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    scanId: report.scanId,
    target: report.target,
    authorizationState: report.authorizationState,
    verification: report.verification || null,
    scanPolicy: report.scanPolicy,
    status: report.status,
    startedAt: report.startedAt,
    stamp: report.stamp,
    scores: report.scores,
    results: report.results,
    evidence: report.evidence,
    chains: report.chains || { status: 'not-run', chains: [], unproven: [], invalid: [] },
    refutation: report.refutation || { status: 'not-run', entries: [] },
    auditLog: report.auditLog,
    integrity: report.integrity,
    howToValidate:
      'Every finding in results[] carries evidenceIds; each must resolve to an item in evidence[] with the same id. Check outcomes are one of pass / finding / inconclusive / not-assessed. Scores are deterministic: recompute them from results[] using the formulas in scores (risk.formula, coverage.formula, confidence.formula).',
  };
}

// ---------------------------------------------------------------------------
// Stack detection (from the stored evidence itself: Server /
// X-Powered-By header values, which the evidence layer keeps).
// ---------------------------------------------------------------------------

export function detectStack(report) {
  for (const e of report.evidence || []) {
    if (e.kind !== 'http-response') continue;
    const h = e.data.headers || {};
    const server = h['server'] || '';
    const powered = h['x-powered-by'] || '';
    if (/nginx/i.test(server)) return { id: 'nginx', label: 'nginx', basis: `Server header "${server}" in ${e.id}` };
    if (/apache/i.test(server)) return { id: 'apache', label: 'Apache', basis: `Server header "${server}" in ${e.id}` };
    if (/next\.js/i.test(powered)) return { id: 'nextjs', label: 'Next.js', basis: `X-Powered-By header "${powered}" in ${e.id}` };
    if (/express/i.test(powered)) return { id: 'express', label: 'Express (Node.js)', basis: `X-Powered-By header "${powered}" in ${e.id}` };
    if (/php/i.test(powered)) return { id: 'php', label: 'PHP', basis: `X-Powered-By header "${powered}" in ${e.id}` };
  }
  return { id: 'generic', label: 'generic (no stack signature in the evidence)', basis: 'no Server / X-Powered-By stack signature in the stored evidence' };
}

// ---------------------------------------------------------------------------
// Fix templates. Deterministic, per check, with stack variants where
// the stack changes WHERE the fix belongs. The model never writes
// these; the summary pass may annotate them later, not replace them.
// ---------------------------------------------------------------------------

function headersFix(f) {
  if (f.checkId.startsWith('headers.hsts')) {
    return {
      conditions: 'The site is served over HTTPS and all subdomains are HTTPS-ready before includeSubDomains is added.',
      placement: {
        nginx: 'Inside the server {} block for this site, then reload nginx.',
        apache: 'In the VirtualHost for this site (or .htaccess with mod_headers loaded).',
        nextjs: 'In the headers() config of next.config, applied to all routes.',
        generic: 'At the TLS-terminating server or framework level, on every HTTPS response.',
      },
      body: {
        nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        nextjs: `// next.config headers()
// { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }`,
        generic: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
      },
      verify: 'Reload, then request the HTTPS root and confirm the header is present with a max-age of at least 31536000. Rescan with AuditCanvas to mark this verified.',
    };
  }
  if (f.checkId.startsWith('headers.csp')) {
    return {
      conditions: 'Start from the directives the scanner flagged; a full CSP must be tested in report-only mode first so legitimate inline code is not broken.',
      placement: {
        nginx: 'Inside the server {} block for this site, then reload nginx.',
        apache: 'In the VirtualHost for this site (or .htaccess with mod_headers loaded).',
        nextjs: 'In the headers() config of next.config, applied to all routes.',
        generic: 'At the server or framework level, on every HTML response.',
      },
      body: {
        nginx: `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'" always;`,
        apache: `Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'"`,
        nextjs: `// next.config headers()
// { key: 'Content-Security-Policy', value: "default-src 'self'; object-src 'none'; base-uri 'self'" }`,
        generic: `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'`,
      },
      verify: 'Serve the policy as Content-Security-Policy-Report-Only for a day, watch for violations, then enforce. Rescan to verify.',
    };
  }
  return {
    conditions: 'Applies to every response from this origin.',
    placement: {
      nginx: 'Inside the server {} block for this site, then reload nginx.',
      apache: 'In the VirtualHost for this site (or .htaccess with mod_headers loaded).',
      nextjs: 'In the headers() config of next.config, applied to all routes.',
      generic: 'At the server or framework level, on every response.',
    },
    body: {
      nginx: `# Add the missing header(s) named in the finding, e.g.:
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "SAMEORIGIN" always;`,
      apache: `# Add the missing header(s) named in the finding, e.g.:
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set X-Frame-Options "SAMEORIGIN"`,
      nextjs: `// next.config headers(): add the header named in the finding, e.g.
// { key: 'X-Content-Type-Options', value: 'nosniff' }`,
      generic: 'Add the header named in the finding to every response from this origin, with the value the finding text recommends.',
    },
    verify: 'Request the root document and confirm the header is present with the intended value. Rescan to verify.',
  };
}

function cookiesFix() {
  return {
    conditions: 'Applies to the cookie(s) named by the evidence flags. Raising SameSite or adding Secure can change login flows on older clients; test sign-in after the change.',
    placement: {
      generic: 'Where the session cookie is set (framework session config or the Set-Cookie call named by the evidence).',
      nextjs: 'In the session/cookie configuration of the auth layer that sets this cookie.',
    },
    body: {
      generic: `Set the cookie with all three attributes:
Set-Cookie: <name>=<value>; Path=/; Secure; HttpOnly; SameSite=Lax
- Secure: the cookie only travels over HTTPS (transport).
- HttpOnly: scripts cannot read it (script access).
- SameSite=Lax: it is withheld from cross-site POSTs.
Never use SameSite=None without Secure.`,
    },
    verify: 'Sign in again, inspect the fresh Set-Cookie header, and confirm Secure, HttpOnly, and SameSite are present. Rescan to verify.',
  };
}

function corsFix() {
  return {
    conditions: 'Only origins the product genuinely trusts may be listed. Never reflect an arbitrary request Origin together with credentials.',
    placement: {
      nginx: 'In the location/server block that adds CORS headers for this API.',
      apache: 'In the VirtualHost or .htaccess rules that add CORS headers.',
      generic: 'In the CORS middleware/configuration that produced the headers in the evidence.',
    },
    body: {
      nginx: `# Replace reflection with a fixed allowlist, e.g.:
map $http_origin $cors_origin {
    "https://app.example.com" $http_origin;
    default "";
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Vary "Origin" always;`,
      apache: `# Replace reflection with a fixed allowlist, e.g.:
SetEnvIf Origin "^https://app\\.example\\.com$" CORS_OK=$0
Header always set Access-Control-Allow-Origin "%{CORS_OK}e" env=CORS_OK
Header always set Access-Control-Allow-Credentials "true"
Header always set Vary "Origin"`,
      generic: `Replace "reflect any Origin" with a fixed allowlist of trusted origins.
- Access-Control-Allow-Origin: echo back the request Origin ONLY if it is on the allowlist.
- Access-Control-Allow-Credentials: true only together with an allowlisted origin.
- Add "Vary: Origin" so caches do not mix responses across origins.`,
    },
    verify: 'Send a request with a foreign Origin header and confirm the response no longer reflects it. Rescan to verify (the scanner probes with a foreign origin).',
  };
}

function exposedFix(f) {
  const path = f.title.match(/\((\/[^)]+)\)/)?.[1] || 'the exposed path';
  return {
    conditions: `Applies while ${path} exists under the web root. The durable fix is removing the file from the deployed tree; the server rule is defence in depth.`,
    placement: {
      nginx: 'In the server {} block for this site, then reload nginx.',
      apache: 'In the VirtualHost for this site.',
      generic: 'In the web server configuration for this site; AND remove the file from the deployment.',
    },
    body: {
      nginx: `location = ${path} { deny all; return 404; }`,
      apache: `RedirectMatch 404 ${path.replace(/\./g, '\\.').replace(/\//g, '\\/')}`,
      generic: `1. Remove ${path} from the web root / deployment artifact.
2. Block the path at the server so a redeploy cannot silently re-expose it.
3. If the file held credentials (for example a .env), ROTATE those credentials: the file must be assumed public since exposure.`,
    },
    verify: `Request ${path} again and confirm a 404 (or 403). Rescan to verify.`,
  };
}

function stackFix(f) {
  return {
    conditions: 'Applies to the library version named in the finding. Upgrade to a version outside the affected range stated in the finding; do not just rename the file.',
    placement: { generic: 'In the front-end dependency manifest (package.json / lockfile), then rebuild and redeploy the assets.' },
    body: {
      generic: `Upgrade the library named in the finding to a patched release outside the CVE-affected range, rebuild, and redeploy.
If the version was detected from a filename, confirm the real version in the deployed bundle first — the detection is flagged as inference.`,
    },
    verify: 'Reload the page, confirm the served asset reports the new version, then rescan to verify.',
  };
}

function tlsFix() {
  return {
    conditions: 'Applies to the certificate served for this hostname.',
    placement: { generic: 'At the TLS terminator (load balancer, reverse proxy, or hosting panel) for this hostname.' },
    body: {
      generic: `Renew or replace the certificate for this hostname, and automate renewal (for example an ACME client with a timer) so the expiry window the scanner flagged cannot recur silently.
If the finding is a protocol or chain problem, restrict TLS to 1.2+ and serve the full chain (leaf + intermediates).`,
    },
    verify: 'Reconnect with an external TLS checker or rescan with AuditCanvas; the new expiry and chain are read from the live handshake.',
  };
}

function emailFix(f) {
  const dmarc = f.checkId.startsWith('email.dmarc');
  return {
    conditions: 'DNS change; allow propagation time before judging the result. Publish DMARC at p=none first only if legitimate senders are not yet inventoried — the scanner grades the policy, and p=reject is the goal.',
    placement: { generic: `As a DNS TXT record on ${dmarc ? '_dmarc.<your-domain>' : 'the apex of your domain'}.` },
    body: {
      generic: dmarc
        ? '_dmarc  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@<your-domain>"'
        : 'TXT  "v=spf1 -all"  — then list every legitimate sender with include: mechanisms before keeping -all.',
    },
    verify: 'Query the TXT record from a public resolver after propagation, then rescan to verify.',
  };
}

function redirectsFix(f) {
  if (f.checkId.includes('mixed')) {
    return {
      conditions: 'Applies to the asset URLs named in the evidence on the HTTPS page.',
      placement: { generic: 'In the page template / asset references of the HTTPS page.' },
      body: { generic: 'Change every http:// asset reference on the HTTPS page to https:// (or a protocol-relative URL), including scripts, styles, images, and fonts.' },
      verify: 'Reload the HTTPS page with the browser console open: no mixed-content warnings. Rescan to verify.',
    };
  }
  return {
    conditions: 'Applies to the redirect parameter the probe exercised. An allowlist beats a blocklist: external destinations are rarely needed.',
    placement: { generic: 'In the handler that builds the redirect Location from user input.' },
    body: {
      generic: `Validate the redirect target before using it:
- Parse it as a URL.
- Allow only relative paths, or absolute URLs whose origin is on a fixed allowlist.
- Reject protocol-relative (//host) and backslash tricks.
- Fall back to a safe default (/) for anything else.`,
    },
    verify: 'Replay the probe URL from the evidence and confirm the Location no longer leaves the origin. Rescan to verify.',
  };
}

const FIX_BUILDERS = {
  headers: headersFix,
  cookies: cookiesFix,
  cors: corsFix,
  exposed: exposedFix,
  stack: stackFix,
  tls: tlsFix,
  email: emailFix,
  redirects: redirectsFix,
};

export function fixFileFor(finding, report, stack) {
  const builder = FIX_BUILDERS[finding.group] || (() => ({
    conditions: 'As described in the finding.',
    placement: { generic: 'Where the configuration named in the finding lives.' },
    body: { generic: 'Apply the change described in the finding text, then rescan to verify.' },
    verify: 'Rescan with AuditCanvas to verify.',
  }));
  const fix = builder(finding);
  const placement = fix.placement[stack.id] || fix.placement.generic;
  const body = (fix.body && (fix.body[stack.id] || fix.body.generic)) || '';
  const content = [
    '# SUGGESTED PATCH — untested. This file is a suggestion, not an',
    '# automatically safe production change. Read it, adapt it to your',
    '# deployment, and verify manually. It is marked verified only when',
    '# a rescan shows the finding resolved.',
    '#',
    `# Finding: ${finding.findingId} — ${finding.title}`,
    `# Severity: ${finding.severity}`,
    `# Evidence: ${(finding.evidenceIds || []).join(', ') || '(none cited)'}`,
    `# Stack: ${stack.label} (detected from: ${stack.basis})`,
    `# Applies when: ${fix.conditions}`,
    `# Place at: ${placement}`,
    '#',
    `# What the scanner observed: ${finding.detail}`,
    '',
    body,
    '',
    `# Manual verification: ${fix.verify}`,
    '',
  ].join('\n');
  return { name: `fixes/${finding.findingId}.txt`, content };
}

export function buildFixPack(report) {
  const stack = detectStack(report);
  const findings = report.findings || [];
  const files = findings.map((f) => fixFileFor(f, report, stack));
  const readme = [
    'AuditCanvas fix pack',
    '====================',
    '',
    `Target: ${report.target}`,
    `Scanner: AuditCanvas ${SCANNER_VERSION} · evidence schema v${EVIDENCE_SCHEMA_VERSION}`,
    `Detected stack: ${stack.label} (basis: ${stack.basis})`,
    '',
    'Every file in fixes/ is a SUGGESTED PATCH for one finding. Each',
    'carries a header with its finding ID and evidence IDs, the stack',
    'and conditions it applies to, and exactly where it belongs. Files',
    'are untested until a rescan verifies the fix. Only files for the',
    'detected stack are generated.',
    '',
    findings.length ? `Findings covered: ${findings.map((f) => f.findingId).join(', ')}` : 'No findings: nothing to fix.',
    '',
  ].join('\n');
  return createZip([{ name: 'README.txt', data: readme }, ...files.map((f) => ({ name: f.name, data: f.content }))]);
}
