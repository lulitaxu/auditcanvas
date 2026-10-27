// Group 1 — Security headers (OWASP WSTG). Each header is its own check;
// a present CSP is never auto-called secure, it is parsed per directive.
import { makeCheck } from '../evidence.js';
import { getRoot } from './common.js';
import { inconclusiveFromError } from '../context.js';

const GROUP = 'headers';

function parseCsp(value) {
  const directives = {};
  for (const part of String(value).split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) directives[name.toLowerCase()] = sources;
  }
  return directives;
}

export async function runHeaders(ctx) {
  let root;
  try {
    root = await getRoot(ctx);
  } catch (err) {
    return [inconclusiveFromError(GROUP, 'fetch', 'Landing response could not be fetched', err)];
  }
  const { res, evidenceId } = root;
  const h = res.headers;
  const ev = [evidenceId];
  const out = [];
  const https = ctx.isHttps();

  // --- HSTS: judged on the HTTPS response only. ---
  if (!https) {
    out.push(
      makeCheck({
        group: GROUP, check: 'hsts', outcome: 'not-assessed',
        title: 'HSTS not assessed on an HTTP target',
        detail: 'Strict-Transport-Security is only meaningful on HTTPS responses; this target was scanned over HTTP.',
        evidenceIds: ev,
      })
    );
  } else if (!h['strict-transport-security']) {
    out.push(
      makeCheck({
        group: GROUP, check: 'hsts-missing', outcome: 'finding', severity: 'medium',
        title: 'HSTS header missing on HTTPS response',
        detail: 'The HTTPS response carries no Strict-Transport-Security header, so browsers are never told to refuse plain-HTTP downgrade for this host.',
        evidenceIds: ev,
      })
    );
  } else {
    const value = h['strict-transport-security'];
    const m = value.match(/max-age\s*=\s*(\d+)/i);
    const maxAge = m ? Number(m[1]) : 0;
    if (!m || maxAge < 31536000) {
      out.push(
        makeCheck({
          group: GROUP, check: 'hsts-weak', outcome: 'finding', severity: 'low',
          title: 'HSTS present but max-age is short',
          detail: `Strict-Transport-Security is present but max-age is ${m ? maxAge : 'unparseable'}; under one year (31536000) leaves long downgrade windows.`,
          evidenceIds: ev,
        })
      );
    } else if (!/includesubdomains/i.test(value)) {
      out.push(
        makeCheck({
          group: GROUP, check: 'hsts-no-subdomains', outcome: 'finding', severity: 'info',
          title: 'HSTS does not cover subdomains',
          detail: 'max-age is sufficient but includeSubDomains is absent, so subdomains are not covered by the policy.',
          evidenceIds: ev,
        })
      );
    } else {
      out.push(
        makeCheck({
          group: GROUP, check: 'hsts', outcome: 'pass',
          title: 'HSTS present with a strong policy',
          detail: `Strict-Transport-Security: ${value}`,
          evidenceIds: ev,
        })
      );
    }
  }

  // --- CSP: parsed per directive. ---
  const csp = h['content-security-policy'];
  if (!csp) {
    out.push(
      makeCheck({
        group: GROUP, check: 'csp-missing', outcome: 'finding', severity: 'medium',
        title: 'Content-Security-Policy missing',
        detail: 'No CSP header on the landing response; injected content has no browser-enforced containment.',
        evidenceIds: ev,
      })
    );
  } else {
    const d = parseCsp(csp);
    const scriptSrc = d['script-src'] || d['default-src'] || [];
    const problems = [];
    if (scriptSrc.includes("'unsafe-inline'")) problems.push(['csp-unsafe-inline', 'medium', "script-src allows 'unsafe-inline'"]);
    if (scriptSrc.includes("'unsafe-eval'")) problems.push(['csp-unsafe-eval', 'medium', "script-src allows 'unsafe-eval'"]);
    if (scriptSrc.includes('*')) problems.push(['csp-wildcard', 'medium', 'script sources allow a bare wildcard (*)']);
    if (scriptSrc.includes('data:')) problems.push(['csp-data-uri', 'low', 'script-src allows data: URIs']);
    for (const [check, severity, label] of problems) {
      out.push(
        makeCheck({
          group: GROUP, check, outcome: 'finding', severity,
          title: `CSP weakness: ${label}`,
          detail: `The Content-Security-Policy was parsed per directive: ${label}. Full policy in the linked evidence.`,
          evidenceIds: ev,
        })
      );
    }
    if (!d['object-src']) {
      out.push(
        makeCheck({
          group: GROUP, check: 'csp-no-object-src', outcome: 'finding', severity: 'low',
          title: 'CSP has no object-src directive',
          detail: 'Without object-src, legacy plugin content is not restricted by the policy.',
          evidenceIds: ev,
        })
      );
    }
    if (!d['base-uri']) {
      out.push(
        makeCheck({
          group: GROUP, check: 'csp-no-base-uri', outcome: 'finding', severity: 'low',
          title: 'CSP has no base-uri directive',
          detail: 'Without base-uri, an injected <base> tag can redirect relative URLs (including scripts) to an attacker origin.',
          evidenceIds: ev,
        })
      );
    }
    if (problems.length === 0 && d['object-src'] && d['base-uri']) {
      out.push(
        makeCheck({
          group: GROUP, check: 'csp', outcome: 'pass',
          title: 'CSP present with no flagged directives',
          detail: 'script-src carries no unsafe-inline/unsafe-eval/wildcard, and object-src and base-uri are set.',
          evidenceIds: ev,
        })
      );
    }
  }

  // --- X-Content-Type-Options ---
  const xcto = (h['x-content-type-options'] || '').toLowerCase();
  out.push(
    xcto === 'nosniff'
      ? makeCheck({ group: GROUP, check: 'xcto', outcome: 'pass', title: 'X-Content-Type-Options: nosniff', detail: 'MIME sniffing is disabled.', evidenceIds: ev })
      : makeCheck({
          group: GROUP, check: 'xcto-missing', outcome: 'finding', severity: 'low',
          title: 'X-Content-Type-Options missing or not "nosniff"',
          detail: 'Browsers may MIME-sniff responses into executable types.',
          evidenceIds: ev,
        })
  );

  // --- Referrer-Policy ---
  out.push(
    h['referrer-policy']
      ? makeCheck({ group: GROUP, check: 'referrer-policy', outcome: 'pass', title: 'Referrer-Policy present', detail: `Referrer-Policy: ${h['referrer-policy']}`, evidenceIds: ev })
      : makeCheck({
          group: GROUP, check: 'referrer-policy-missing', outcome: 'finding', severity: 'info',
          title: 'Referrer-Policy missing',
          detail: 'Full URLs (including any sensitive paths) may leak to third parties via the Referer header.',
          evidenceIds: ev,
        })
  );

  // --- Permissions-Policy ---
  out.push(
    h['permissions-policy']
      ? makeCheck({ group: GROUP, check: 'permissions-policy', outcome: 'pass', title: 'Permissions-Policy present', detail: 'Browser features are governed by an explicit policy.', evidenceIds: ev })
      : makeCheck({
          group: GROUP, check: 'permissions-policy-missing', outcome: 'finding', severity: 'info',
          title: 'Permissions-Policy missing',
          detail: 'Powerful browser features (camera, microphone, geolocation) are left to defaults, including for embedded content.',
          evidenceIds: ev,
        })
  );

  // --- Framing: CSP frame-ancestors OR X-Frame-Options ---
  const frameAncestors = csp && parseCsp(csp)['frame-ancestors'];
  const xfo = (h['x-frame-options'] || '').toUpperCase();
  if (frameAncestors || xfo === 'DENY' || xfo === 'SAMEORIGIN') {
    out.push(
      makeCheck({
        group: GROUP, check: 'framing', outcome: 'pass',
        title: 'Framing is restricted',
        detail: frameAncestors ? 'CSP frame-ancestors is set.' : `X-Frame-Options: ${xfo}.`,
        evidenceIds: ev,
      })
    );
  } else if (xfo) {
    out.push(
      makeCheck({
        group: GROUP, check: 'framing-invalid', outcome: 'finding', severity: 'low',
        title: 'X-Frame-Options carries an unrecognized value',
        detail: `X-Frame-Options: ${h['x-frame-options']} is not DENY or SAMEORIGIN and no CSP frame-ancestors backs it up.`,
        evidenceIds: ev,
      })
    );
  } else {
    out.push(
      makeCheck({
        group: GROUP, check: 'framing-missing', outcome: 'finding', severity: 'medium',
        title: 'No clickjacking protection (frame-ancestors / X-Frame-Options)',
        detail: 'Nothing stops a third-party page from framing this site and overlaying deceptive UI.',
        evidenceIds: ev,
      })
    );
  }

  return out;
}
