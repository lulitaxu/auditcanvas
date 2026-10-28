// Report assembly (SPEC stages 2 + 5). The report is the deterministic
// bundle: check results, evidence, scores and a reproducibility stamp.
// The auditor layer may annotate it; it never alters the numbers.
import {
  SCANNER_VERSION,
  RULES_VERSION,
  EVIDENCE_SCHEMA_VERSION,
  unresolvedEvidenceIds,
} from './evidence.js';
import { computeScores } from './scoring.js';
import { snapshotStamp, snapshotStale } from './scanner/stack.js';
import { auditorConfig } from './auditor.js';

export function buildReport(session) {
  const results = session.results;
  const evidence = session.ctx.evidence.items;
  const scores = computeScores(results);
  const snapshot = snapshotStamp();
  const config = auditorConfig();

  const unresolved = unresolvedEvidenceIds(results, evidence);

  // Origin/provenance (SPEC addendum 2026-10-29, admin design §13.7):
  // every report states which execution path produced it. Public
  // reports say so explicitly ('public' / 'server') rather than
  // relying on absence; admin reports are 'admin' / 'server-admin'.
  // An admin origin never upgrades authorizationState — an
  // unverified target scanned by the operator still reports
  // authorizationState 'admin', not 'verified'.
  const origin = session.origin || 'public';

  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    scanId: session.id,
    rescanOf: session.rescanOf || null,
    target: session.target,
    origin,
    provenance: origin === 'admin' ? 'server-admin' : 'server',
    authorizationState: session.authorizationState,
    scanPolicy: session.policyName,
    status: session.status,
    startedAt: session.createdAt,
    updatedAt: session.updatedAt,
    groupStatus: session.groupStatus,
    scores,
    results,
    evidence,
    findings: results.filter((r) => r.outcome === 'finding'),
    // Fix-first list: confirmed findings in deterministic risk order.
    // The auditor may re-annotate this order later; the engine order is
    // severity weight, then group order (stable sort).
    fixFirst: scores.risk.drivers.slice(0, 5),
    integrity: {
      unresolvedEvidenceIds: unresolved,
      ok: unresolved.length === 0,
    },
    stamp: {
      scannerVersion: SCANNER_VERSION,
      rulesVersion: RULES_VERSION,
      provider: config.provider || 'meta',
      modelId: config.modelId || 'none (engine-only)',
      modelConfigured: config.configured,
      timestamp: new Date().toISOString(),
      target: session.target,
      origin,
      authorizationState: session.authorizationState,
      scanPolicy: session.policyName,
      dataSnapshots: {
        cve: { ...snapshot, stale: snapshotStale() },
      },
    },
    auditLog: session.auditLog,
  };
}
