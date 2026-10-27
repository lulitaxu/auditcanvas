import { getScan } from '../../../../src/lib/scanstore.js';
import { buildReport } from '../../../../src/lib/report.js';
import { annotateReport, auditorConfig } from '../../../../src/lib/auditor.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/scan/[id] — the assembled report (deterministic bundle +
// scores + reproducibility stamp). When the auditor is not configured,
// the report carries the explicit engine-only status; it never pretends
// the model ran.
export async function GET(request, { params }) {
  const { id } = await params;
  const session = getScan(id);
  if (!session) return Response.json({ error: 'Unknown scan ID.' }, { status: 404 });

  const report = buildReport(session);
  if (session.status === 'complete') {
    report.auditor = auditorConfig().configured
      ? { status: 'configured-not-invoked', reason: 'Auditor passes are invoked from the Day 4 pipeline build; deterministic report below is complete on its own.' }
      : await annotateReport(report);
  }
  return Response.json(report);
}
