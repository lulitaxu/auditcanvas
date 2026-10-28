import { assertClientReport } from '../../../../src/lib/downloads.js';
import { diffReports } from '../../../../src/lib/diff.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

// POST /api/scan/diff { before, after }
// Stateless diff of two finalized reports (the rescan flow keeps both
// client-side): resolved / new / persistent / severity-changed /
// could-not-repeat by stable check identity, plus deterministic score
// movement (src/lib/diff.js). Both reports pass the report validator
// (assertClientReport) before any comparison is made.
export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Request body must be JSON.' }, { status: 400 });
  }
  try {
    const before = assertClientReport(body.before);
    const after = assertClientReport(body.after);
    if (before.target !== after.target) {
      return Response.json({ error: 'A diff needs two reports of the same target.' }, { status: 400 });
    }
    return Response.json(diffReports(before, after));
  } catch (err) {
    return Response.json(
      { error: `Diff rejected: ${err && err.message ? err.message : String(err)}` },
      { status: 400 }
    );
  }
}
