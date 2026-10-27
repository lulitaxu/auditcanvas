// Group 8 — Redirects and mixed content.
// Open redirect: only on a bounded benign probe whose actual Location
// header is verified to leave the origin; a parameter name proves
// nothing. Mixed content: read from the page's own asset list.
import { makeCheck, redactUrl } from '../evidence.js';
import { getRoot, httpEvidence } from './common.js';
import { inconclusiveFromError } from '../context.js';

const GROUP = 'redirects';
const PROBE_TARGET = 'https://example.org/ac-probe';
const SUBRESOURCE = /<(script|img|link|iframe|source|video|audio|embed|input)\b[^>]*?(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi;

export async function runRedirects(ctx) {
  const out = [];
  const https = ctx.isHttps();

  // --- Mixed content (HTTPS pages only) ---
  if (!https) {
    out.push(
      makeCheck({
        group: GROUP, check: 'mixed-content', outcome: 'not-assessed',
        title: 'Mixed content not assessed on an HTTP target',
        detail: 'Mixed content is a property of HTTPS pages loading HTTP subresources.',
        evidenceIds: [],
      })
    );
  } else {
    try {
      const root = await getRoot(ctx);
      const found = [];
      let m;
      SUBRESOURCE.lastIndex = 0;
      while ((m = SUBRESOURCE.exec(root.res.bodyText || '')) !== null) {
        found.push({ tag: m[1].toLowerCase(), url: redactUrl(m[2]) });
        if (found.length >= 10) break;
      }
      out.push(
        found.length
          ? makeCheck({
              group: GROUP, check: 'mixed-content', outcome: 'finding', severity: 'medium',
              title: `Mixed content: ${found.length} HTTP subresource(s) on an HTTPS page`,
              detail: `The page loads over HTTPS but pulls subresources over plain HTTP: ${found.map((f) => `<${f.tag}> ${f.url}`).join('; ')}. Those requests can be read and rewritten in transit.`,
              evidenceIds: [root.evidenceId],
            })
          : makeCheck({
              group: GROUP, check: 'mixed-content', outcome: 'pass',
              title: 'No mixed content in the landing page asset list',
              detail: 'No script/img/link/iframe subresource is loaded over http://.',
              evidenceIds: [root.evidenceId],
            })
      );
    } catch (err) {
      out.push(inconclusiveFromError(GROUP, 'mixed-content', 'Mixed content could not be assessed', err));
    }
  }

  // --- HTTP -> HTTPS upgrade (HTTPS targets) ---
  if (https) {
    const httpUrl = `http://${ctx.base.host}${ctx.base.pathname.replace(/\/$/, '')}/`;
    try {
      const res = await ctx.fetch(httpUrl, { follow: false });
      const loc = res.headers['location'] || '';
      const ev = httpEvidence(ctx, res, httpUrl);
      if (res.status >= 300 && res.status < 400 && loc.startsWith('https://')) {
        out.push(
          makeCheck({
            group: GROUP, check: 'https-upgrade', outcome: 'pass',
            title: 'HTTP redirects to HTTPS',
            detail: `The plain-HTTP origin answers ${res.status} to ${redactUrl(loc)}.`,
            evidenceIds: [ev],
          })
        );
      } else if (res.status === 200) {
        out.push(
          makeCheck({
            group: GROUP, check: 'https-upgrade-missing', outcome: 'finding', severity: 'low',
            title: 'HTTP origin serves content instead of redirecting to HTTPS',
            detail: 'The same host answers on port 80 with content, so visitors can be kept on the unencrypted origin.',
            evidenceIds: [ev],
          })
        );
      } else {
        out.push(
          makeCheck({
            group: GROUP, check: 'https-upgrade', outcome: 'inconclusive',
            title: `HTTP origin answered ${res.status}`,
            detail: 'Neither a redirect to HTTPS nor served content; no verdict claimed.',
            evidenceIds: [ev],
          })
        );
      }
    } catch (err) {
      out.push(inconclusiveFromError(GROUP, 'https-upgrade', 'HTTP origin could not be probed', err));
    }
  }

  // --- Open redirect: bounded benign probe, Location verified off-origin ---
  if (!ctx.policy.probes) {
    out.push(
      makeCheck({
        group: GROUP, check: 'open-redirect', outcome: 'not-assessed',
        title: 'Open-redirect probe not run under the restricted scan policy',
        detail: 'The probe asks the site to redirect to a benign external URL; the restricted policy for unverified targets does not run it.',
        evidenceIds: [],
      })
    );
    return out;
  }
  const probePaths = [
    `/redirect?url=${encodeURIComponent(PROBE_TARGET)}`,
    `/login?next=${encodeURIComponent(PROBE_TARGET)}`,
  ];
  let probed = 0;
  let hit = null;
  for (const path of probePaths) {
    const url = ctx.url(path);
    try {
      const res = await ctx.fetch(url, { follow: false });
      probed += 1;
      const loc = res.headers['location'];
      if (res.status >= 300 && res.status < 400 && loc) {
        let dest = null;
        try {
          dest = new URL(loc, url);
        } catch {
          dest = null;
        }
        if (dest && dest.hostname === 'example.org') {
          hit = { path, status: res.status, location: loc, evidenceId: httpEvidence(ctx, res, url) };
          break;
        }
      }
    } catch (err) {
      if (err && (err.code === 'budget' || err.code === 'deadline')) break;
      // A refused/unreachable probe path is not evidence either way.
    }
  }
  if (hit) {
    out.push(
      makeCheck({
        group: GROUP, check: 'open-redirect', outcome: 'finding', severity: 'high',
        title: 'Open redirect confirmed by a verified off-origin Location',
        detail: `GET ${hit.path} answered ${hit.status} with Location: ${redactUrl(hit.location)}. The destination was verified to leave the origin; a parameter name alone was not treated as proof.`,
        evidenceIds: [hit.evidenceId],
      })
    );
  } else if (probed > 0) {
    out.push(
      makeCheck({
        group: GROUP, check: 'open-redirect', outcome: 'pass',
        title: 'Bounded probe found no open redirect',
        detail: `Probed ${probed} common redirect parameter(s) with a benign external destination; none produced a verified off-origin Location. This is a bounded probe result, not a proof that no redirect endpoint exists.`,
        evidenceIds: [],
      })
    );
  } else {
    out.push(inconclusiveFromError(GROUP, 'open-redirect', 'Open-redirect probe could not run', new Error('no probe path could be fetched')));
  }

  return out;
}
