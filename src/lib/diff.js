// Scan diff + fix verification (SPEC.md v2.2: "Scan diff + fix
// verification (P1, demo-critical)"). A rescan stores a NEW scan of the
// same target under the same policy; this module compares the two
// finalized reports and classifies every check that was a finding in
// either scan:
//
//   resolved         the finding's condition is gone, confirmed by the
//                      rescan's fresh evidence (rules below).
//   new              finding now, not a finding before.
//   persistent       finding in both, same severity ("unchanged").
//   severity-changed finding in both, different severity.
//   could-not-repeat the rescan could not reach a verdict on that
//                      check (Inconclusive / Not assessed / the check
//                      group never reached any verdict). Honesty rule:
//                      this is NEVER counted as resolved — "we could
//                      not re-check it" is not "it is fixed".
//
// Finding identity is the stable checkId / findingId pair the scanner
// mints deterministically (evidence.js). One wrinkle: a check's slug
// varies with its outcome (the pass twin of `headers.csp-unsafe-inline`
// is `headers.csp`; of `email.spf-missing` is `email.spf`; a stack CVE
// finding `stack.jquery-cve-2020-11022` passes as
// `stack.jquery-current`). So a before-finding whose exact checkId is
// absent from the rescan is resolved only when the rescan actually
// re-ran that area to a verdict: no inconclusive result in the same
// check family (the slug's first segment, within the group), and at
// least one verdict (Pass or Finding) anywhere in the group. If the
// group itself failed (fetch error, timeout), nothing in it counts as
// resolved. Scores are the deterministic report scores; the diff
// reports their movement and computes nothing of its own.

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function familyOf(r) {
  const slug = r.checkId.slice(r.group.length + 1);
  return slug.split('-')[0];
}

function entry(b, a) {
  const src = a || b;
  return {
    checkId: src.checkId,
    findingId: src.findingId || (b && b.findingId) || null,
    group: src.group,
    title: src.title,
    severityBefore: b ? b.severity : null,
    severityAfter: a ? a.severity : null,
    outcomeBefore: b ? b.outcome : 'not-assessed',
    outcomeAfter: a ? a.outcome : 'not-assessed',
  };
}

function sortEntries(list) {
  return list.sort((x, y) => {
    const sx = SEVERITY_ORDER[x.severityAfter ?? x.severityBefore] ?? 9;
    const sy = SEVERITY_ORDER[y.severityAfter ?? y.severityBefore] ?? 9;
    return sx - sy || x.checkId.localeCompare(y.checkId);
  });
}

function scorePoint(report) {
  const s = report.scores;
  return {
    riskScore: s.risk.score,
    riskGrade: s.risk.grade,
    coverage: s.coverage.ratio,
    confidence: s.confidence.ratio,
    findings: s.counts.findings,
    confirmedFindings: s.counts.confirmedFindings,
  };
}

const round2 = (n) => Math.round(n * 100) / 100;

export function diffReports(before, after) {
  const bMap = new Map((before.results || []).map((r) => [r.checkId, r]));
  const aMap = new Map((after.results || []).map((r) => [r.checkId, r]));
  const aResults = after.results || [];

  // Per-group facts about the rescan: did the group reach any verdict,
  // and which check families came back without one.
  const groupHasVerdict = new Set();
  const unverdictFamilies = new Set();
  for (const r of aResults) {
    if (r.outcome === 'pass' || r.outcome === 'finding') groupHasVerdict.add(r.group);
    if (r.outcome === 'inconclusive' || r.outcome === 'not-assessed') {
      unverdictFamilies.add(`${r.group}.${familyOf(r)}`);
    }
  }

  const resolved = [];
  const newFindings = [];
  const persistent = [];
  const severityChanged = [];
  const couldNotRepeat = [];

  for (const checkId of new Set([...bMap.keys(), ...aMap.keys()])) {
    const b = bMap.get(checkId) || null;
    const a = aMap.get(checkId) || null;
    const bF = Boolean(b && b.outcome === 'finding');
    const aF = Boolean(a && a.outcome === 'finding');
    if (bF && aF) {
      if (b.severity !== a.severity) severityChanged.push(entry(b, a));
      else persistent.push(entry(b, a));
    } else if (bF && !aF) {
      if (a && a.outcome === 'pass') {
        resolved.push(entry(b, a)); // exact pass twin
      } else if (a) {
        couldNotRepeat.push(entry(b, a)); // same check, no verdict
      } else if (unverdictFamilies.has(`${b.group}.${familyOf(b)}`) || !groupHasVerdict.has(b.group)) {
        couldNotRepeat.push(entry(b, a)); // family or whole group unverdicted
      } else {
        resolved.push(entry(b, a)); // check re-ran to verdicts; the condition is gone
      }
    } else if (!bF && aF) {
      newFindings.push(entry(b, a));
    }
  }

  const sb = scorePoint(before);
  const sa = scorePoint(after);

  return {
    target: after.target,
    beforeScanId: before.scanId,
    afterScanId: after.scanId,
    beforeAt: before.startedAt,
    afterAt: after.startedAt,
    scanPolicy: after.scanPolicy,
    resolved: sortEntries(resolved),
    newFindings: sortEntries(newFindings),
    persistent: sortEntries(persistent),
    severityChanged: sortEntries(severityChanged),
    couldNotRepeat: sortEntries(couldNotRepeat),
    counts: {
      resolved: resolved.length,
      new: newFindings.length,
      persistent: persistent.length,
      severityChanged: severityChanged.length,
      couldNotRepeat: couldNotRepeat.length,
    },
    scores: {
      before: sb,
      after: sa,
      delta: {
        riskScore: sa.riskScore - sb.riskScore,
        coverage: round2(sa.coverage - sb.coverage),
        confidence: round2(sa.confidence - sb.confidence),
        findings: sa.findings - sb.findings,
      },
    },
  };
}
