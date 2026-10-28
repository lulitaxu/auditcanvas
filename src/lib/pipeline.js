// Report finalization pipeline: deterministic report → auditor pass
// (call 1) → chain validation/classification → refutation pass
// (call 2) → rescoring. The result is cached on the session so the
// per-scan model-call cap (3) holds no matter how often the report is
// fetched, and the downloads serve exactly what the UI shows.
//
// Honesty rules enforced by shape:
//  - Refutation runs BEFORE the final scoring, because a
//    not-substantiated claim must stop driving Risk and a
//    confidence-reduced claim must lower Confidence (scoring.js).
//  - Without a configured model, chains and refutation carry their
//    explicit not-run states and the report is the engine-only report.
//  - Nothing here can create or delete a finding: chains annotate,
//    refutation annotates, scoring recomputes from the same results.
import { buildReport } from './report.js';
import { auditorConfig, auditorPass, MAX_MODEL_CALLS_PER_SCAN } from './auditor.js';
import { deriveChains } from './chains.js';
import { runRefutation } from './refutation.js';
import { computeScores } from './scoring.js';

// ---------------------------------------------------------------------------
// Finalized-report cache, keyed by the verified bundle-set digest
// (security fix H2). The stateless flow builds a fresh session object
// per /finalize request, so the per-session cache inside
// finalizeReport could not stop a repeat finalize from re-running the
// model calls — the 3-call cap held per invocation, not per scan.
// Keyed instead by the digest of the HMAC-signed bundle set (which
// commits to the exact pipeline inputs), a repeat finalize of
// identical bundles returns the cached report and makes ZERO new
// model calls: the cap now holds per bundle-set by construction.
// In-process and bounded (size + TTL), consistent with the codebase's
// documented per-process best-effort limits on serverless.
// ---------------------------------------------------------------------------

const FINALIZE_CACHE_MAX = 50;
const FINALIZE_CACHE_TTL_MS = 60 * 60 * 1000;
const finalizeCache = new Map(); // digest -> { report, at }

export async function finalizeReportForBundleSet(session, bundleSetKey) {
  if (typeof bundleSetKey === 'string' && bundleSetKey) {
    const hit = finalizeCache.get(bundleSetKey);
    if (hit && Date.now() - hit.at < FINALIZE_CACHE_TTL_MS) {
      // Keep the caller's session consistent with the cached report,
      // so a later finalizeReport(session) on it (ID-keyed routes)
      // also short-circuits instead of re-running the pipeline.
      session.finalReport = hit.report;
      return { report: hit.report, cacheHit: true };
    }
    if (hit) finalizeCache.delete(bundleSetKey);
  }
  const report = await finalizeReport(session);
  if (typeof bundleSetKey === 'string' && bundleSetKey) {
    finalizeCache.set(bundleSetKey, { report, at: Date.now() });
    while (finalizeCache.size > FINALIZE_CACHE_MAX) {
      finalizeCache.delete(finalizeCache.keys().next().value);
    }
  }
  return { report, cacheHit: false };
}

export async function finalizeReport(session) {
  if (session.finalReport) return session.finalReport;
  const report = buildReport(session);
  report.verification = session.verification || null;
  if (session.status !== 'complete') return report;

  const config = auditorConfig();
  const calls = [];

  // Call 1: auditor pass (impact/priority + chain proposals).
  let auditorOutput = null;
  let auditorStatus = { status: 'engine-only' };
  if (config.configured) {
    const a = await auditorPass(report, config);
    calls.push({ pass: 'auditor', status: a.status });
    auditorStatus = a;
    if (a.status === 'ok') {
      auditorOutput = a.output;
      if (a.output && Array.isArray(a.output.findingNotes)) {
        report.auditorNotes = a.output.findingNotes;
      }
    }
  }

  // Chains: validated + classified server-side from the proposals.
  const chains = deriveChains(report, auditorOutput, config);
  report.chains = chains;

  // Call 2: refutation (separate adversarial call; claims + evidence
  // only). Runs before rescoring on purpose — see header.
  const refutation = await runRefutation(report, chains, config);
  if (config.configured) calls.push({ pass: 'refutation', status: refutation.status });
  const entryByFinding = new Map((refutation.entries || []).map((e) => [e.findingId, e]));
  for (const r of report.results) {
    const entry = r.findingId ? entryByFinding.get(r.findingId) : null;
    if (entry) {
      r.refutation = {
        claim: entry.claim,
        counterargument: entry.counterargument,
        evidenceAssessment: entry.evidenceAssessment,
        outcome: entry.outcome,
        outcomeLabel: entry.outcomeLabel,
      };
    }
  }
  report.refutation = {
    status: refutation.status,
    reason: refutation.reason || null,
    entries: refutation.entries || [],
  };

  // Rescore with refutation outcomes attached, and rebuild the
  // fix-first list from the rescored drivers.
  report.scores = computeScores(report.results);
  report.fixFirst = report.scores.risk.drivers.slice(0, 5);
  report.findings = report.results.filter((r) => r.outcome === 'finding');

  // If a transport fell back to a different model than configured
  // (the Gemini adapter's capacity fallback), the stamp and the
  // auditor block name the model that actually answered.
  if (config.usedModelId && report.stamp) report.stamp.modelId = config.usedModelId;

  report.auditor = config.configured
    ? {
        status: auditorStatus.status === 'ok' ? 'annotated' : auditorStatus.status,
        provider: config.provider || 'meta',
        modelId: config.usedModelId || config.modelId,
        reason: auditorStatus.reason || null,
        calls,
        callCap: MAX_MODEL_CALLS_PER_SCAN,
      }
    : {
        status: 'engine-only',
        provider: config.provider || 'meta',
        modelId: null,
        reason:
          config.provider === 'gemini'
            ? 'AUDITOR_PROVIDER=gemini but GEMINI_API_KEY is not set; this is the deterministic engine-only report. Auditor reasoning, chains, and refutation are shown as not run, never simulated.'
            : 'META_API_KEY / META_MODEL_ID are not set; this is the deterministic engine-only report. Auditor reasoning, chains, and refutation are shown as not run, never simulated.',
        calls: [],
        callCap: MAX_MODEL_CALLS_PER_SCAN,
      };

  session.finalReport = report;
  session.auditLog.push({
    at: new Date().toISOString(),
    event: 'report-finalized',
    auditorStatus: report.auditor.status,
    chainsRendered: chains.chains ? chains.chains.length : 0,
    chainsUnproven: chains.unproven ? chains.unproven.length : 0,
    refutationStatus: refutation.status,
  });
  return report;
}
