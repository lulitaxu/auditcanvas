import { getSample } from '../../../../src/lib/samples.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/samples/[slug] — one preloaded sample report, exactly as the
// scan pipeline finalized it (results, evidence, scores, stamp). These
// are saved results, labelled as such by the UI; they are never
// regenerated or re-stamped on read.
export async function GET(request, { params }) {
  const { slug } = await params;
  const report = await getSample(slug);
  if (!report) return Response.json({ error: 'Unknown sample report.' }, { status: 404 });
  return Response.json(report);
}
