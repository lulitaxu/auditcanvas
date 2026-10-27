import { listSamples, EXPECTED_SAMPLE_TARGETS } from '../../../src/lib/samples.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// GET /api/samples — metadata for the preloaded Judge-mode sample
// reports (full reports via /api/samples/[slug]). An empty list is a
// real state, not an error: the UI renders the explicit
// "generated after deploy" placeholder for the expected targets.
export async function GET() {
  const samples = await listSamples();
  return Response.json({ samples, expectedTargets: EXPECTED_SAMPLE_TARGETS });
}
