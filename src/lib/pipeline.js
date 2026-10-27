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

  report.auditor = config.configured
    ? {
        status: auditorStatus.status === 'ok' ? 'annotated' : auditorStatus.status,
        modelId: config.modelId,
        reason: auditorStatus.reason || null,
        calls,
        callCap: MAX_MODEL_CALLS_PER_SCAN,
      }
    : {
        status: 'engine-only',
        modelId: null,
        reason:
          'META_API_KEY / META_MODEL_ID are not set; this is the deterministic engine-only report. Auditor reasoning, chains, and refutation are shown as not run, never simulated.',
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
