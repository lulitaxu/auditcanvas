// Refutation pass (SPEC.md v2.2) — a SEPARATE adversarial model call
// that argues the strongest plausible false-positive case against a
// finding, followed by a DETERMINISTIC evidence assessment that alone
// decides the outcome.
//
// The honesty boundary, encoded here:
//  - The model sees only the finding CLAIM plus the stored evidence —
//    never the auditor's reasoning, so it cannot anchor on it.
//  - A model argument alone can at most reduce confidence. Only the
//    deterministic evidence assessment (preconditions checked in code
//    against the stored evidence) can mark a claim Not substantiated.
//  - A not-substantiated claim stays in the report; it stops driving
//    the Risk score (see scoring.js isConfirmedFinding) and nothing is
//    ever deleted.
//  - Outcomes are exactly three: Survived refutation / Confidence
//    reduced / Not substantiated.
//  - Scope: high-severity findings, plus any finding used as a node in
//    a Supported chain.
//  - With no model configured, the pass reports its explicit not-run
//    state and no finding carries a refutation record.
import { auditorConfig, callModel } from './auditor.js';

export const REFUTATION_OUTCOMES = Object.freeze([
  'survived-refutation',
  'confidence-reduced',
  'not-substantiated',
]);

export const REFUTATION_OUTCOME_LABELS = Object.freeze({
  'survived-refutation': 'Survived refutation',
  'confidence-reduced': 'Confidence reduced',
  'not-substantiated': 'Not substantiated',
});

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

export function refutationScope(report, chainsResult) {
  const inScope = new Set();
  for (const r of report.results || []) {
    if (r.outcome === 'finding' && r.severity === 'high') inScope.add(r.findingId);
  }
  for (const chain of (chainsResult && chainsResult.chains) || []) {
    if (chain.classification !== 'supported') continue;
    for (const node of chain.nodes || []) inScope.add(node.findingId);
  }
  return (report.results || []).filter((r) => r.findingId && inScope.has(r.findingId));
}

// ---------------------------------------------------------------------------
// Deterministic evidence assessment
//
// Per-check precondition registry: what MUST be present in the finding's
// own cited evidence for the claim to stand. Each checker returns
// { state: 'present' | 'absent', detail } per precondition. Limitations
// are weaknesses the assessment itself confirms from the data (inference,
// truncated evidence) — they are what a counterargument may legitimately
// cash in as "Confidence reduced", never more.
// ---------------------------------------------------------------------------

function citedEvidence(report, finding) {
  const byId = new Map((report.evidence || []).map((e) => [e.id, e]));
  return (finding.evidenceIds || []).map((id) => byId.get(id)).filter(Boolean);
}

function httpItems(items) {
  return items.filter((e) => e.kind === 'http-response');
}

const PRECONDITION_CHECKS = {
  'cors.credentialed-exposure': [
    {
      id: 'origin-allowed-or-reflected',
      description: 'Cited response allows or reflects an untrusted origin',
      check(report, finding, items) {
        let origin = null;
        try {
          origin = new URL(report.target).origin;
        } catch { /* target always parses in practice */ }
        const hit = httpItems(items).find((e) => {
          const acao = (e.data.headers || {})['access-control-allow-origin'];
          if (!acao) return false;
          if (acao === '*') return true;
          try {
            return new URL(acao).origin !== origin;
          } catch {
            return false;
          }
        });
        return { state: hit ? 'present' : 'absent', detail: hit ? `Access-Control-Allow-Origin in ${hit.id}` : 'no permissive Access-Control-Allow-Origin in the cited evidence' };
      },
    },
    {
      id: 'credentials-allowed',
      description: 'Cited response sends Access-Control-Allow-Credentials: true',
      check(report, finding, items) {
        const hit = httpItems(items).find(
          (e) => (e.data.headers || {})['access-control-allow-credentials'] === 'true'
        );
        return { state: hit ? 'present' : 'absent', detail: hit ? `credentials allowed in ${hit.id}` : 'Access-Control-Allow-Credentials: true is not in the cited evidence' };
      },
    },
  ],
  'redirects.open-redirect': [
    {
      id: 'location-leaves-origin',
      description: 'The probe response Location is verified to leave the origin',
      check(report, finding, items) {
        let origin = null;
        try {
          origin = new URL(report.target).origin;
        } catch { /* ignore */ }
        for (const e of httpItems(items)) {
          const loc = (e.data.headers || {}).location;
          if (!loc) continue;
          try {
            const u = new URL(loc, report.target);
            if (u.origin !== origin) return { state: 'present', detail: `Location in ${e.id} leaves the origin (${u.origin})` };
          } catch { /* unparseable Location proves nothing */ }
        }
        return { state: 'absent', detail: 'no off-origin Location header in the cited evidence' };
      },
    },
  ],
};

function defaultPreconditions() {
  return [
    {
      id: 'direct-evidence-cited',
      description: 'The finding cites stored evidence',
      check(report, finding, items) {
        return items.length
          ? { state: 'present', detail: `${items.length} evidence item(s) cited` }
          : { state: 'absent', detail: 'the finding cites no evidence' };
      },
    },
  ];
}

function groupPreconditions(checkId) {
  if (checkId.startsWith('exposed.')) {
    return [
      {
        id: 'exposure-signature-response',
        description: 'A cited response returned HTTP 200 for the exposed path',
        check(report, finding, items) {
          const hit = httpItems(items).find((e) => e.data.status === 200);
          return { state: hit ? 'present' : 'absent', detail: hit ? `HTTP 200 in ${hit.id}` : 'no HTTP 200 response in the cited evidence' };
        },
      },
    ];
  }
  if (checkId.startsWith('cookies.')) {
    return [
      {
        id: 'cookie-flags-observed',
        description: 'Cookie attribute flags were observed in a cited response',
        check(report, finding, items) {
          const hit = httpItems(items).find((e) => (e.data.setCookies || []).length > 0);
          return { state: hit ? 'present' : 'absent', detail: hit ? `Set-Cookie flags in ${hit.id}` : 'no Set-Cookie flags in the cited evidence' };
        },
      },
    ];
  }
  return null;
}

export function assessFinding(report, finding) {
  const items = citedEvidence(report, finding);
  const checks =
    PRECONDITION_CHECKS[finding.checkId] || groupPreconditions(finding.checkId) || defaultPreconditions();
  const preconditions = checks.map((c) => {
    const r = c.check(report, finding, items);
    return { id: c.id, description: c.description, state: r.state, detail: r.detail };
  });
  const limitations = [];
  if (finding.inference) {
    limitations.push('The detection rests on inference rather than direct observation (the scanner flags it as such).');
  }
  if (items.some((e) => e.data && e.data.truncated)) {
    limitations.push('Part of the supporting evidence was truncated at the response-size cap.');
  }
  return { preconditions, limitations };
}

// The outcome decision is a pure function of the deterministic
// assessment. The counterargument text is recorded verbatim; it never
// feeds this function.
export function decideOutcome(assessment) {
  if (assessment.preconditions.some((p) => p.state === 'absent')) return 'not-substantiated';
  if (assessment.limitations.length) return 'confidence-reduced';
  return 'survived-refutation';
}

function assessmentText(finding, assessment, outcome) {
  const parts = assessment.preconditions.map(
    (p) => `${p.id}: ${p.state} (${p.detail})`
  );
  if (assessment.limitations.length) parts.push(`limitations: ${assessment.limitations.join(' ')}`);
  if (outcome === 'not-substantiated') {
    parts.push(
      'A required precondition is absent from the stored evidence, so the interpretive claim is marked not substantiated. The observation itself stays in the report and nothing is deleted.'
    );
  } else if (outcome === 'confidence-reduced') {
    parts.push('All required preconditions are present, but a limitation confirmed above weakens the conclusion; severity and the observation stand.');
  } else {
    parts.push('Every required precondition is present in the stored evidence and no confirmed limitation weakens the claim.');
  }
  return parts.join(' ');
}

// Build the report's refutation entries from counterarguments (from the
// adversarial call in production, or supplied directly in tests). Each
// entry carries exactly the four report fields: original claim,
// counterargument, evidence assessment, outcome.
export function applyRefutation(report, chainsResult, counterarguments = {}) {
  const scope = refutationScope(report, chainsResult);
  return scope.map((finding) => {
    const assessment = assessFinding(report, finding);
    const outcome = decideOutcome(assessment);
    const counter = counterarguments[finding.findingId];
    return {
      findingId: finding.findingId,
      claim: `${finding.title} — ${finding.detail}`,
      counterargument:
        typeof counter === 'string' && counter
          ? counter
          : 'No counterargument was produced for this finding.',
      evidenceAssessment: assessmentText(finding, assessment, outcome),
      outcome,
      outcomeLabel: REFUTATION_OUTCOME_LABELS[outcome],
      assessment,
    };
  });
}

// The live pass: ONE adversarial call for every in-scope finding
// (call 2 of the scan's max 3). Input is claims + stored evidence only.
export async function runRefutation(report, chainsResult, config = auditorConfig(), callFn = callModel) {
  const scope = refutationScope(report, chainsResult);
  if (!scope.length) {
    return {
      status: 'ok',
      pass: 'refutation',
      entries: [],
      reason: 'No findings in refutation scope (high severity, or nodes of a Supported chain).',
    };
  }
  if (!config.configured) {
    return {
      status: 'not-run',
      pass: 'refutation',
      entries: [],
      reason:
        'Refutation is a separate adversarial Muse Spark call and is not configured (META_API_KEY / META_MODEL_ID unset). It is reported as not run, never as passed.',
    };
  }
  const byId = new Map((report.evidence || []).map((e) => [e.id, e]));
  let output;
  try {
    output = await callFn(config, {
      system:
        'You are an adversarial reviewer for a security scanner. For each finding claim you receive, argue the strongest plausible case that it is a false positive or overstated, using ONLY the stored evidence provided. You cannot see any other analysis. Return JSON: {"counterarguments":[{"findingId":"...","counterargument":"..."}]}. Argue honestly: if the evidence plainly supports the claim, say what little can be said.',
      user: JSON.stringify({
        claims: scope.map((f) => ({
          findingId: f.findingId,
          claim: `${f.title} — ${f.detail}`,
          severity: f.severity,
          evidence: (f.evidenceIds || []).map((id) => byId.get(id)).filter(Boolean),
        })),
      }),
    });
  } catch (err) {
    return {
      status: 'failed',
      pass: 'refutation',
      entries: [],
      reason: `Refutation call failed: ${err && err.message ? err.message : String(err)}`,
    };
  }
  const counterarguments = {};
  const scopeIds = new Set(scope.map((f) => f.findingId));
  for (const entry of Array.isArray(output && output.counterarguments) ? output.counterarguments : []) {
    if (entry && scopeIds.has(entry.findingId) && typeof entry.counterargument === 'string') {
      counterarguments[entry.findingId] = entry.counterargument;
    }
  }
  return { status: 'ok', pass: 'refutation', entries: applyRefutation(report, chainsResult, counterarguments) };
}
