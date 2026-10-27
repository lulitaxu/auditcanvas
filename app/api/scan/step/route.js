import { getScan, recordGroupResults } from '../../../../src/lib/scanstore.js';
import { groupById, runGroup } from '../../../../src/lib/scanner/index.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// POST /api/scan/step { scanId, group }
// Runs exactly ONE check group. The client drives the scan stepwise so
// no request ever has to cover the whole tree (SPEC.md: Architecture —
// stepwise scans survive serverless timeouts).
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  const session = getScan(body.scanId);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });
  const group = groupById(body.group);
  if (!group) return Response.json({ error: `Unknown check group: ${body.group}` }, { status: 400 });

  if (session.groupStatus[group.id] === 'done') {
    return Response.json({
      group: group.id,
      results: session.results.filter((r) => r.group === group.id),
      groupStatus: session.groupStatus,
      status: session.status,
      cached: true,
    });
  }

  session.groupStatus[group.id] = 'running';
  const results = await runGroup(session.ctx, group.id);
  recordGroupResults(session, group.id, results);

  return Response.json({
    group: group.id,
    results,
    groupStatus: session.groupStatus,
    status: session.status,
  });
}
