// Group 4 — CORS. Corrected logic (spec v2.2): a wildcard alone is NOT
// called exploitable. A finding requires the dangerous combination —
// origin reflection or '*' WITH credentials allowed — observed with a
// benign probe origin. Anything weaker is a low/informational observation
// with the reasoning shown.
import { makeCheck } from '../evidence.js';
import { httpEvidence } from './common.js';
import { inconclusiveFromError } from '../context.js';

const GROUP = 'cors';
const PROBE_ORIGIN = 'https://ac-probe.invalid';

export async function runCors(ctx) {
  if (!ctx.policy.probes) {
    return [
      makeCheck({
        group: GROUP, check: 'probe', outcome: 'not-assessed',
        title: 'CORS not probed under the restricted scan policy',
        detail: 'Judging CORS requires sending a probe Origin header, which the restricted (unverified target) policy does not do.',
        evidenceIds: [],
      }),
    ];
  }
  const url = ctx.url('/');
  let res;
  try {
    res = await ctx.fetch(url, { headers: { origin: PROBE_ORIGIN } });
  } catch (err) {
    return [inconclusiveFromError(GROUP, 'probe', 'CORS probe could not be completed', err)];
  }
  const ev = [httpEvidence(ctx, res, url)];
  const acao = (res.headers['access-control-allow-origin'] || '').trim();
  const acac = (res.headers['access-control-allow-credentials'] || '').trim().toLowerCase() === 'true';

  if (!acao) {
    return [
      makeCheck({
        group: GROUP, check: 'no-cors', outcome: 'pass',
        title: 'No CORS policy advertised to a foreign origin',
        detail: `A request with Origin: ${PROBE_ORIGIN} received no Access-Control-Allow-Origin header, so browsers will not share responses cross-origin.`,
        evidenceIds: ev,
      }),
    ];
  }

  const reflected = acao === PROBE_ORIGIN;
  const wildcard = acao === '*';
  if ((reflected || wildcard) && acac) {
    return [
      makeCheck({
        group: GROUP, check: 'credentialed-exposure', outcome: 'finding', severity: 'high',
        title: 'CORS allows credentialed reads from untrusted origins',
        detail: reflected
          ? `The response reflects an arbitrary request Origin (${PROBE_ORIGIN}) in Access-Control-Allow-Origin AND sends Access-Control-Allow-Credentials: true. Any website can read authenticated responses from a visitor's browser.`
          : 'Access-Control-Allow-Origin is * together with Access-Control-Allow-Credentials: true. Browsers block the wildcard-plus-credentials combination, but the stated policy intent is unsafe and breaks inconsistently across clients.',
        evidenceIds: ev,
      }),
    ];
  }
  if (wildcard) {
    return [
      makeCheck({
        group: GROUP, check: 'wildcard', outcome: 'finding', severity: 'info',
        title: 'Wildcard CORS without credentials (informational)',
        detail: 'Access-Control-Allow-Origin is * but credentials are not allowed, so only public, unauthenticated responses are readable cross-origin. Recorded as an observation, not an exploitable finding.',
        evidenceIds: ev,
      }),
    ];
  }
  if (reflected) {
    return [
      makeCheck({
        group: GROUP, check: 'reflection-no-creds', outcome: 'finding', severity: 'low',
        title: 'CORS reflects arbitrary origins (credentials not allowed)',
        detail: `Access-Control-Allow-Origin reflects the request Origin (${PROBE_ORIGIN}) but Access-Control-Allow-Credentials is not true, so authenticated responses stay unreadable cross-origin. The reflection is still broader than most sites intend.`,
        evidenceIds: ev,
      }),
    ];
  }
  return [
    makeCheck({
      group: GROUP, check: 'restricted', outcome: 'pass',
      title: 'CORS does not expose this origin to the probe origin',
      detail: `Access-Control-Allow-Origin was "${acao}", which is neither the probe origin nor a wildcard.`,
      evidenceIds: ev,
    }),
  ];
}
