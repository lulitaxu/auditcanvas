// Group 3 — Cookies. Attributes come from actual Set-Cookie headers on
// the landing response. Cookie VALUES are never stored (flags only, see
// evidence.js). Names are not trusted to identify sessions: anything that
// sounds session-like is labelled an inference.
import { makeCheck } from '../evidence.js';
import { getRoot } from './common.js';
import { parseSetCookieFlags } from '../evidence.js';
import { inconclusiveFromError } from '../context.js';

const GROUP = 'cookies';
const SESSION_LIKE = /sess|sid|auth|token|jwt|login|account|user/i;

export async function runCookies(ctx) {
  let root;
  try {
    root = await getRoot(ctx);
  } catch (err) {
    return [inconclusiveFromError(GROUP, 'fetch', 'Landing response could not be fetched', err)];
  }
  const { res, evidenceId } = root;
  const ev = [evidenceId];
  const cookies = (res.setCookies || []).map(parseSetCookieFlags).filter(Boolean);
  const out = [];

  if (cookies.length === 0) {
    out.push(
      makeCheck({
        group: GROUP, check: 'none-set', outcome: 'pass',
        title: 'No cookies set by the landing response',
        detail: 'The landing response carried no Set-Cookie header, so there are no cookie attributes to fault.',
        evidenceIds: ev,
      })
    );
    return out;
  }

  const names = (list) => list.map((c) => c.name).join(', ');
  const https = ctx.isHttps();
  const anyInference = cookies.some((c) => SESSION_LIKE.test(c.name));

  // Secure
  if (!https) {
    out.push(
      makeCheck({
        group: GROUP, check: 'secure', outcome: 'not-assessed',
        title: 'Secure attribute not assessed on an HTTP target',
        detail: 'The Secure attribute only has meaning when cookies are set over HTTPS.',
        evidenceIds: ev,
      })
    );
  } else {
    const missing = cookies.filter((c) => !c.secure);
    out.push(
      missing.length
        ? makeCheck({
            group: GROUP, check: 'secure-missing', outcome: 'finding', severity: 'low',
            title: `Cookie(s) missing the Secure attribute: ${names(missing)}`,
            detail: 'Without Secure, these cookies can travel over plain HTTP and be captured or injected. Session-likelihood for any individual name is an inference, not a fact.',
            evidenceIds: ev, inference: anyInference,
          })
        : makeCheck({ group: GROUP, check: 'secure', outcome: 'pass', title: 'All cookies carry Secure', detail: `${cookies.length} cookie(s) checked.`, evidenceIds: ev })
    );
  }

  // HttpOnly
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  out.push(
    noHttpOnly.length
      ? makeCheck({
          group: GROUP, check: 'httponly-missing', outcome: 'finding', severity: 'low',
          title: `Cookie(s) missing HttpOnly: ${names(noHttpOnly)}`,
          detail: 'Without HttpOnly, script can read these cookie values, so any XSS can exfiltrate them. HttpOnly governs script access only; it does not by itself prove or disprove session theft. Session-likelihood from a name is an inference.',
          evidenceIds: ev, inference: anyInference,
        })
      : makeCheck({ group: GROUP, check: 'httponly', outcome: 'pass', title: 'All cookies carry HttpOnly', detail: `${cookies.length} cookie(s) checked.`, evidenceIds: ev })
  );

  // SameSite
  const noSameSite = cookies.filter((c) => !c.sameSite);
  out.push(
    noSameSite.length
      ? makeCheck({
          group: GROUP, check: 'samesite-missing', outcome: 'finding', severity: 'low',
          title: `Cookie(s) with no SameSite attribute: ${names(noSameSite)}`,
          detail: 'Browsers fall back to a default (Lax in Chromium) but the site has not stated its intent; explicit SameSite is the durable control.',
          evidenceIds: ev, inference: anyInference,
        })
      : makeCheck({ group: GROUP, check: 'samesite', outcome: 'pass', title: 'All cookies state a SameSite policy', detail: `${cookies.length} cookie(s) checked.`, evidenceIds: ev })
  );

  // SameSite=None without Secure is rejected by browsers and signals a
  // cross-site intent with no transport protection.
  const noneInsecure = cookies.filter((c) => c.sameSite === 'none' && !c.secure);
  if (noneInsecure.length) {
    out.push(
      makeCheck({
        group: GROUP, check: 'samesite-none-insecure', outcome: 'finding', severity: 'medium',
        title: `SameSite=None without Secure: ${names(noneInsecure)}`,
        detail: 'SameSite=None opts into cross-site sending; without Secure the cookie still travels over plain HTTP.',
        evidenceIds: ev, inference: anyInference,
      })
    );
  }

  return out;
}
