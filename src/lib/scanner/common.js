// Shared helpers for scanner groups.
import { sanitizeHeaders, parseSetCookieFlags, redactUrl } from '../evidence.js';

// Record a fetched response as evidence: status line, sanitized headers,
// Set-Cookie attribute flags (never values), size metadata. Bodies are
// never stored (spec: snippets, not bodies).
export function httpEvidence(ctx, res, requestUrl) {
  const { stored, names } = sanitizeHeaders(res.headers);
  return ctx.evidence.add('http-response', requestUrl, {
    status: res.status,
    finalUrl: redactUrl(res.finalUrl || requestUrl),
    redirectCount: res.redirectCount || 0,
    headers: stored,
    headerNames: names,
    setCookies: (res.setCookies || []).map(parseSetCookieFlags).filter(Boolean),
    bodyBytes: res.bodyBytes,
    truncated: Boolean(res.truncated),
  });
}

// Fetch the target's root document once per scan and share it (with its
// evidence ID) across every group that analyzes the landing response.
export async function getRoot(ctx) {
  if (!ctx._rootPromise) {
    ctx._rootPromise = (async () => {
      const url = ctx.url('/');
      const res = await ctx.fetch(url);
      const evidenceId = httpEvidence(ctx, res, url);
      return { res, evidenceId };
    })();
  }
  return ctx._rootPromise;
}
