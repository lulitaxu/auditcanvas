// Deterministic scoring (SPEC.md). The formula is code; the model never
// touches the numbers, it may only annotate them.
//
//  Risk       severity-weighted sum over CONFIRMED findings only.
//             Cap rule: any confirmed high-severity finding caps the
//             grade band, no matter how many minor passes surround it.
//  Coverage   checks that reached a verdict (Pass or Finding) divided
//             by checks attempted. Inconclusive / Not assessed reduce
//             coverage; they never raise the score.
//  Confidence share of findings backed by direct evidence vs inference.

export const SEVERITY_WEIGHTS = Object.freeze({ high: 40, medium: 15, low: 5, info: 1 });

const BANDS = [
  { max: 0, grade: 'A', label: 'No confirmed risk' },
  { max: 9, grade: 'B', label: 'Low' },
  { max: 24, grade: 'C', label: 'Guarded' },
  { max: 49, grade: 'D', label: 'Elevated' },
  { max: 79, grade: 'E', label: 'High' },
  { max: Infinity, grade: 'F', label: 'Critical' },
];
const GRADE_ORDER = ['A', 'B', 'C', 'D', 'E', 'F'];

// A finding stops driving Risk only when the deterministic evidence
// assessment in the refutation stage marks it "not substantiated"
// (never by a model acting alone — see SPEC.md refutation rules).
export function isConfirmedFinding(r) {
  return r.outcome === 'finding' && !(r.refutation && r.refutation.outcome === 'not-substantiated');
}

export function computeScores(results) {
  const findings = results.filter((r) => r.outcome === 'finding');
  const confirmed = results.filter(isConfirmedFinding);
  const rawRisk = confirmed.reduce((sum, r) => sum + (SEVERITY_WEIGHTS[r.severity] || 0), 0);
  const riskScore = Math.min(100, rawRisk);

  let band = BANDS.find((b) => riskScore <= b.max);
  const hasHigh = confirmed.some((r) => r.severity === 'high');
  let cappedByHigh = false;
  if (hasHigh && GRADE_ORDER.indexOf(band.grade) < GRADE_ORDER.indexOf('D')) {
    band = BANDS.find((b) => b.grade === 'D');
    cappedByHigh = true;
  }

  const attempted = results.filter((r) => r.outcome !== 'not-assessed');
  const verdicts = results.filter((r) => r.outcome === 'pass' || r.outcome === 'finding');
  const coverage = attempted.length ? verdicts.length / attempted.length : 0;

  const direct = findings.filter((r) => !r.inference).length;
  const confidence = findings.length ? direct / findings.length : 1;

  return {
    risk: {
      score: riskScore,
      grade: band.grade,
      label: band.label,
      cappedByHigh,
      drivers: confirmed
        .map((r) => ({ findingId: r.findingId, severity: r.severity, weight: SEVERITY_WEIGHTS[r.severity] || 0, title: r.title }))
        .sort((a, b) => b.weight - a.weight),
      formula:
        'min(100, sum of severity weights over confirmed findings) with weights high=40, medium=15, low=5, info=1; any confirmed high caps the grade band at D or worse.',
    },
    coverage: {
      ratio: Math.round(coverage * 100) / 100,
      verdicts: verdicts.length,
      attempted: attempted.length,
      inconclusive: results.filter((r) => r.outcome === 'inconclusive').length,
      notAssessed: results.filter((r) => r.outcome === 'not-assessed').length,
    },
    confidence: {
      ratio: Math.round(confidence * 100) / 100,
      directFindings: direct,
      inferredFindings: findings.length - direct,
      totalFindings: findings.length,
    },
    counts: {
      pass: results.filter((r) => r.outcome === 'pass').length,
      findings: findings.length,
      confirmedFindings: confirmed.length,
    },
  };
}
