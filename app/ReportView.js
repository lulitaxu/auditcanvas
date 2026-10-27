'use client';

import { useMemo, useState } from 'react';
import { buildGraph } from '../src/lib/graph.js';

const OUTCOME_LABEL = {
  pass: 'Pass',
  finding: 'Finding',
  inconclusive: 'Inconclusive',
  'not-assessed': 'Not assessed',
};

const NODE_W = 196;
const NODE_H = 42;
const GAP_Y = 14;
const COL_X = (layer) => 24 + layer * 248;

function Graph({ report }) {
  const graph = useMemo(() => buildGraph(report), [report]);
  const [selected, setSelected] = useState(null);

  const byLayer = useMemo(() => {
    const map = new Map();
    for (const n of graph.nodes) {
      if (!map.has(n.layer)) map.set(n.layer, []);
      map.get(n.layer).push(n);
    }
    return map;
  }, [graph]);

  const pos = useMemo(() => {
    const p = new Map();
    for (const [layer, list] of byLayer) {
      list.forEach((n, i) => p.set(n.id, { x: COL_X(layer), y: 24 + i * (NODE_H + GAP_Y), node: n }));
    }
    return p;
  }, [byLayer]);

  const maxRows = Math.max(1, ...[...byLayer.values()].map((l) => l.length));
  const height = 24 * 2 + maxRows * NODE_H + (maxRows - 1) * GAP_Y;
  const width = COL_X(3) + NODE_W + 24;

  const chainClassByPair = useMemo(() => {
    const m = new Map();
    for (const cp of graph.chainPaths) {
      for (const pair of cp.pairs) m.set(pair, cp.classification);
    }
    return m;
  }, [graph]);
  const chainClassByNode = useMemo(() => {
    const m = new Map();
    for (const cp of graph.chainPaths) {
      for (const id of cp.nodeIds) m.set(id, cp.classification);
    }
    return m;
  }, [graph]);

  const selectedEvidence = useMemo(() => {
    if (!selected) return new Set();
    const r = (report.results || []).find((x) => `f:${x.findingId}` === selected);
    return new Set(r ? (r.evidenceIds || []).map((id) => `ev:${id}`) : []);
  }, [selected, report]);

  const edgePath = (a, b) => {
    const pa = pos.get(a);
    const pb = pos.get(b);
    if (!pa || !pb) return null;
    const x1 = pa.x + NODE_W;
    const y1 = pa.y + NODE_H / 2;
    const x2 = pb.x;
    const y2 = pb.y + NODE_H / 2;
    const mx = (x1 + x2) / 2;
    return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
  };

  return (
    <div>
      <div className="graph-wrap">
        <svg viewBox={`0 0 ${width} ${height}`} className="graph" role="img" aria-label="Evidence graph">
          {graph.edges.map((e, i) => {
            const d = edgePath(e.from, e.to);
            if (!d) return null;
            const chainCls = chainClassByPair.get(`${e.from}|${e.to}`) || chainClassByPair.get(`${e.to}|${e.from}`);
            const traced = selected && (e.to === selected || selectedEvidence.has(e.from));
            const cls = chainCls
              ? `edge chain-${chainCls}`
              : traced
                ? 'edge traced'
                : 'edge base';
            return <path key={i} d={d} className={cls} fill="none" />;
          })}
          {graph.nodes.map((n) => {
            const p = pos.get(n.id);
            const chainCls = chainClassByNode.get(n.id);
            const isSel = selected === n.id || selectedEvidence.has(n.id);
            return (
              <g
                key={n.id}
                className={`gnode ${n.kind}${chainCls ? ` chain-${chainCls}` : ''}${isSel ? ' selected' : ''}`}
                transform={`translate(${p.x},${p.y})`}
                onClick={() => (n.kind === 'finding' ? setSelected(isSel && selected === n.id ? null : n.id) : null)}
              >
                <rect width={NODE_W} height={NODE_H} rx="2" />
                <text x="10" y="18" className="gtext-1">{n.line1}</text>
                <text x="10" y="33" className="gtext-2">{n.line2}</text>
                {n.title ? <title>{n.title}</title> : null}
              </g>
            );
          })}
        </svg>
      </div>
      <div className="graph-legend">
        <span><span className="swatch solid" /> Supported chain path</span>
        <span><span className="swatch dashed" /> Conditional chain path (dashed, never shown as confirmed)</span>
        <span>Unproven chains are not drawn. Click a finding to trace its evidence.</span>
      </div>
      <div className="graph-layers">
        {['Assets', 'Observations', 'Findings', 'Fixes'].map((l, i) => (
          <span key={l} style={{ left: COL_X(i) }}>{l}</span>
        ))}
      </div>
    </div>
  );
}

function Scores({ report, technical }) {
  const s = report.scores;
  return (
    <>
      <div className="scores">
        <div className="score">
          <div className="k">Risk</div>
          <div className="v">{s.risk.grade} · {s.risk.score}</div>
          <div className="n">{s.risk.label}{s.risk.cappedByHigh ? ' · capped by a confirmed high' : ''}</div>
          {technical ? <div className="formula">{s.risk.formula}</div> : null}
        </div>
        <div className="score">
          <div className="k">Coverage</div>
          <div className="v">{Math.round(s.coverage.ratio * 100)}%</div>
          <div className="n">{s.coverage.verdicts} of {s.coverage.attempted} attempted checks reached a verdict</div>
          {technical && s.coverage.formula ? <div className="formula">{s.coverage.formula}</div> : null}
        </div>
        <div className="score">
          <div className="k">Confidence</div>
          <div className="v">{Math.round(s.confidence.ratio * 100)}%</div>
          <div className="n">{s.confidence.directFindings} findings on direct evidence, {s.confidence.inferredFindings} not direct</div>
          {technical && s.confidence.formula ? <div className="formula">{s.confidence.formula}</div> : null}
        </div>
      </div>
      {!technical ? <p className="policy-line">How these numbers are computed: {s.risk.formula}</p> : null}
    </>
  );
}

function ChainsBlock({ report, technical }) {
  const chains = report.chains || { status: 'not-run', reason: 'Chains have not been computed for this report.', chains: [], unproven: [] };
  return (
    <>
      <h3>Attack paths the auditor derived</h3>
      {chains.status === 'not-run' ? (
        <div className="notice">Chains not run. {chains.reason}</div>
      ) : (
        <>
          {chains.chains.length === 0 ? (
            <p className="policy-line">The auditor proposed no chain that survived server-side validation.</p>
          ) : (
            chains.chains.map((c) => (
              <div key={c.id} className="chain-card">
                <div className="result-head">
                  <span className={`chip chain-${c.classification}`}>{c.classification}</span>
                  <span className="result-title">{c.title}</span>
                  <span className="sev">AI-derived attack path</span>
                </div>
                <div className="result-detail">{c.reason}</div>
                <ul className="preconds">
                  {c.preconditions.map((p) => (
                    <li key={p.id}>
                      <code>{p.id}</code> — {p.state}
                    </li>
                  ))}
                </ul>
                {(c.edges || []).map((e, i) => (
                  <div key={i} className="result-detail">
                    {e.from} → {e.to}: {e.explanation}
                  </div>
                ))}
              </div>
            ))
          )}
          {technical && chains.unproven && chains.unproven.length ? (
            <>
              <h4>Rejected reasoning (Unproven — not rendered as paths)</h4>
              {chains.unproven.map((c) => (
                <div key={c.id} className="chain-card rejected">
                  <div className="result-head">
                    <span className="chip not-assessed">unproven</span>
                    <span className="result-title">{c.title}</span>
                    <span className="sev">AI-derived attack path</span>
                  </div>
                  <div className="result-detail">{c.reason}</div>
                </div>
              ))}
            </>
          ) : null}
          {technical && chains.invalid && chains.invalid.length ? (
            <p className="policy-line">
              {chains.invalid.length} chain proposal(s) were rejected outright for citing unknown findings/evidence or an unknown chain type.
            </p>
          ) : null}
        </>
      )}
    </>
  );
}

function RefutationBlock({ report }) {
  const ref = report.refutation || { status: 'not-run', entries: [] };
  return (
    <>
      <h3>Refutation — the auditor argues against its own findings</h3>
      {ref.status === 'not-run' ? (
        <div className="notice">Refutation not run{ref.reason ? `. ${ref.reason}` : '.'}</div>
      ) : ref.entries.length === 0 ? (
        <p className="policy-line">No findings were in refutation scope (high severity, or nodes of a Supported chain).</p>
      ) : (
        ref.entries.map((e) => (
          <div key={e.findingId} className="refute">
            <div className="result-head">
              <span className={`chip refute-${e.outcome}`}>{e.outcomeLabel}</span>
              <span className="result-title">{e.findingId}</span>
            </div>
            <dl>
              <dt>Original claim</dt>
              <dd>{e.claim}</dd>
              <dt>Counterargument</dt>
              <dd>{e.counterargument}</dd>
              <dt>Evidence assessment</dt>
              <dd>{e.evidenceAssessment}</dd>
              <dt>Outcome</dt>
              <dd>{e.outcomeLabel}</dd>
            </dl>
          </div>
        ))
      )}
    </>
  );
}

function DiffList({ title, items, chipClass, chipLabel, note }) {
  if (!items || items.length === 0) return null;
  return (
    <>
      <h4>{title} ({items.length})</h4>
      <ul className="results">
        {items.map((e) => (
          <li key={e.checkId}>
            <div className="result-head">
              <span className={`chip ${chipClass}`}>{chipLabel}</span>
              {e.severityAfter || e.severityBefore ? (
                <span className="sev">
                  {e.severityBefore && e.severityAfter && e.severityBefore !== e.severityAfter
                    ? `${e.severityBefore} → ${e.severityAfter}`
                    : e.severityAfter || e.severityBefore}
                </span>
              ) : null}
              <span className="result-title">{e.title}</span>
            </div>
            <div className="evids">{e.findingId || e.checkId}</div>
          </li>
        ))}
      </ul>
      {note ? <p className="policy-line">{note}</p> : null}
    </>
  );
}

function DiffBlock({ diff }) {
  if (!diff) return null;
  const { scores, counts } = diff;
  const signed = (n) => (n > 0 ? `+${n}` : `${n}`);
  return (
    <>
      <h3>What changed since the previous scan</h3>
      <p className="policy-line">
        Compared against the scan of {new Date(diff.beforeAt).toLocaleString()} (same target,
        same policy). A finding counts as resolved only when the rescan&apos;s fresh evidence
        passes the check; a check the rescan could not re-verify is listed separately and is
        never counted as fixed.
      </p>
      <div className="scores">
        <div className="score">
          <div className="k">Risk</div>
          <div className="v">{scores.before.riskGrade} · {scores.before.riskScore} → {scores.after.riskGrade} · {scores.after.riskScore}</div>
          <div className="n">{signed(scores.delta.riskScore)} points</div>
        </div>
        <div className="score">
          <div className="k">Coverage</div>
          <div className="v">{Math.round(scores.before.coverage * 100)}% → {Math.round(scores.after.coverage * 100)}%</div>
          <div className="n">{signed(Math.round(scores.delta.coverage * 100))} points</div>
        </div>
        <div className="score">
          <div className="k">Confidence</div>
          <div className="v">{Math.round(scores.before.confidence * 100)}% → {Math.round(scores.after.confidence * 100)}%</div>
          <div className="n">{signed(Math.round(scores.delta.confidence * 100))} points</div>
        </div>
      </div>
      <p className="policy-line">
        {counts.resolved} resolved · {counts.new} new · {counts.persistent} still present
        {counts.severityChanged ? ` · ${counts.severityChanged} severity-changed` : ''}
        {counts.couldNotRepeat ? ` · ${counts.couldNotRepeat} could not be re-checked` : ''}
      </p>
      <DiffList title="Resolved (verified by the rescan)" items={diff.resolved} chipClass="pass" chipLabel="Resolved" />
      <DiffList title="New findings" items={diff.newFindings} chipClass="finding" chipLabel="New" />
      <DiffList title="Still present" items={diff.persistent} chipClass="finding" chipLabel="Unchanged" />
      <DiffList title="Severity changed" items={diff.severityChanged} chipClass="inconclusive" chipLabel="Changed" />
      <DiffList
        title="Could not be re-checked"
        items={diff.couldNotRepeat}
        chipClass="inconclusive"
        chipLabel="Unverified"
        note="These checks did not reach a verdict in the rescan (Inconclusive or not assessed), so the earlier finding is neither confirmed nor cleared."
      />
    </>
  );
}

export default function ReportView({ report, scanId, diff = null, onRescan = null, busy = false }) {
  const [mode, setMode] = useState('owner');
  const technical = mode === 'technical';
  return (
    <div>
      <div className="mode-toggle" role="group" aria-label="Report mode">
        <button aria-pressed={!technical} onClick={() => setMode('owner')}>Owner mode</button>
        <button aria-pressed={technical} onClick={() => setMode('technical')}>Technical mode</button>
        <span className="dl-row">
          {onRescan ? (
            <button className="btn" type="button" onClick={onRescan} disabled={busy}>
              Rescan this target
            </button>
          ) : null}
          {scanId ? (
            <>
              <a className="btn secondary" href={`/api/scan/${scanId}/evidence`} download="auditcanvas-evidence.json">auditcanvas-evidence.json</a>
              <a className="btn secondary" href={`/api/scan/${scanId}/fix-pack`} download="auditcanvas-fix-pack.zip">auditcanvas-fix-pack.zip</a>
            </>
          ) : null}
        </span>
      </div>

      <Scores report={report} technical={technical} />

      {report.auditor ? (
        <p className="policy-line">
          Auditor: <strong>{report.auditor.status}</strong>
          {report.auditor.reason ? ` — ${report.auditor.reason}` : ''}
        </p>
      ) : null}

      {report.verification ? (
        <p className="policy-line">
          Ownership: <strong>verified by DNS TXT</strong> for {report.verification.hostname} at{' '}
          {new Date(report.verification.verifiedAt).toLocaleString()} — full check set ran.
        </p>
      ) : null}

      <DiffBlock diff={diff} />

      <h3>Evidence graph</h3>
      <Graph report={report} />

      <ChainsBlock report={report} technical={technical} />
      <RefutationBlock report={report} />

      {report.fixFirst && report.fixFirst.length ? (
        <>
          <h3>Fix first</h3>
          <ol className="fixfirst">
            {report.fixFirst.map((f) => (
              <li key={f.findingId}>
                <strong>{f.severity}</strong> — {f.title}
              </li>
            ))}
          </ol>
        </>
      ) : null}

      <h3>Checks</h3>
      <ul className="results">
        {(report.results || []).map((r) => (
          <li key={r.checkId}>
            <div className="result-head">
              <span className={`chip ${r.outcome}`}>{OUTCOME_LABEL[r.outcome] || r.outcome}</span>
              {r.severity ? <span className="sev">{r.severity}</span> : null}
              <span className="result-title">{r.title}</span>
              {r.inference ? <span className="sev" style={{ color: 'var(--inconclusive)' }}>inference</span> : null}
              {r.refutation ? <span className="chip refute-chip">{r.refutation.outcomeLabel}</span> : null}
            </div>
            <div className="result-detail">{r.detail}</div>
            {r.evidenceIds && r.evidenceIds.length ? (
              <div className="evids">evidence: {r.evidenceIds.join(', ')}</div>
            ) : null}
          </li>
        ))}
      </ul>

      {technical ? (
        <>
          <h3>Reproducibility</h3>
          <div className="stamp">
            scanner <code>{report.stamp.scannerVersion}</code> · rules <code>{report.stamp.rulesVersion}</code> ·
            model <code>{report.stamp.modelId}</code> · policy <code>{report.stamp.scanPolicy}</code> ·
            CVE snapshot <code>{report.stamp.dataSnapshots.cve.snapshotVersion}</code>
            {report.stamp.dataSnapshots.cve.stale ? ' (stale — treat CVE coverage as dated)' : ''} ·{' '}
            {new Date(report.stamp.timestamp).toLocaleString()}
          </div>
          <h3>Evidence on record</h3>
          <ul className="results">
            {(report.evidence || []).map((e) => (
              <li key={e.id}>
                <div className="result-head">
                  <span className="result-title">{e.id}</span>
                  <span className="sev">{e.kind}</span>
                </div>
                <div className="evids">{e.target}</div>
              </li>
            ))}
          </ul>
          <h3>Audit log</h3>
          <div className="stamp">
            {(report.auditLog || []).map((entry, i) => (
              <div key={i}>
                <code>{entry.at}</code> — {entry.event}
                {entry.authorizationState ? ` · authorization ${entry.authorizationState}` : ''}
                {entry.scanPolicy ? ` · policy ${entry.scanPolicy}` : ''}
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
