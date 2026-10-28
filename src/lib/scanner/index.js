// Scanner registry: the eight frozen check groups (SPEC.md) + exposure
// (SPEC addendum 2026-10-29). No new groups may be added during the
// 9-day build.
import { runHeaders } from './headers.js';
import { runTls } from './tls.js';
import { runCookies } from './cookies.js';
import { runCors } from './cors.js';
import { runExposed } from './exposed.js';
import { runExposure } from './exposure.js';
import { runStack } from './stack.js';
import { runEmail } from './email.js';
import { runRedirects } from './redirects.js';

export const GROUPS = [
  { id: 'headers', name: 'Security headers', run: runHeaders },
  { id: 'tls', name: 'TLS', run: runTls },
  { id: 'cookies', name: 'Cookies', run: runCookies },
  { id: 'cors', name: 'CORS', run: runCors },
  { id: 'exposed', name: 'Exposed paths', run: runExposed },
  { id: 'exposure', name: 'Exposure & secrets', run: runExposure },
  { id: 'stack', name: 'Client stack & CVEs', run: runStack },
  { id: 'email', name: 'Email posture (SPF/DMARC)', run: runEmail },
  { id: 'redirects', name: 'Redirects & mixed content', run: runRedirects },
];

export function groupById(id) {
  return GROUPS.find((g) => g.id === id) || null;
}

// Run one group; any unexpected failure degrades to a single Inconclusive
// for the group rather than crashing the scan (spec fixture rule).
export async function runGroup(ctx, groupId) {
  const group = groupById(groupId);
  if (!group) throw new Error(`Unknown check group: ${groupId}`);
  try {
    return await group.run(ctx);
  } catch (err) {
    return [
      {
        checkId: `${groupId}.group-error`,
        findingId: null,
        group: groupId,
        outcome: 'inconclusive',
        severity: null,
        title: `${group.name} could not be completed`,
        detail: `The check group failed unexpectedly: ${err && err.message ? err.message : String(err)}`,
        evidenceIds: [],
        inference: false,
      },
    ];
  }
}

export async function runAllGroups(ctx) {
  const results = [];
  for (const g of GROUPS) {
    results.push(...(await runGroup(ctx, g.id)));
  }
  return results;
}
