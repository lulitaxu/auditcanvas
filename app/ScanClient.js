'use client';

import { useState } from 'react';

const OUTCOME_LABEL = {
  pass: 'Pass',
  finding: 'Finding',
  inconclusive: 'Inconclusive',
  'not-assessed': 'Not assessed',
};

function ResultRow({ r }) {
  return (
    <li>
      <div className="result-head">
        <span className={`chip ${r.outcome}`}>{OUTCOME_LABEL[r.outcome] || r.outcome}</span>
        {r.severity ? <span className="sev">{r.severity}</span> : null}
        <span className="result-title">{r.title}</span>
        {r.inference ? <span className="sev" style={{ color: 'var(--inconclusive)' }}>inference</span> : null}
      </div>
      <div className="result-detail">{r.detail}</div>
      {r.evidenceIds && r.evidenceIds.length ? (
        <div className="evids">evidence: {r.evidenceIds.join(', ')}</div>
      ) : null}
    </li>
  );
}

export default function ScanClient() {
  const [url, setUrl] = useState('');
  const [attested, setAttested] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [scan, setScan] = useState(null);
  const [groupStatus, setGroupStatus] = useState({});
  const [results, setResults] = useState([]);
  const [report, setReport] = useState(null);
  const [showSamples, setShowSamples] = useState(false);

  async function runScan(targetUrl, isAttested) {
    setBusy(true);
    setError(null);
    setReport(null);
    setResults([]);
    setScan(null);
    setGroupStatus({});
    try {
      const startRes = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, attested: isAttested }),
      });
      const start = await startRes.json();
      if (!startRes.ok) throw new Error(start.error || 'Could not start the scan.');
      setScan(start);
      setGroupStatus(start.groupStatus);

      for (const g of start.groups) {
        setGroupStatus((prev) => ({ ...prev, [g.id]: 'running' }));
        const stepRes = await fetch('/api/scan/step', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ scanId: start.scanId, group: g.id }),
        });
        const step = await stepRes.json();
        if (!stepRes.ok) throw new Error(step.error || `The ${g.name} step failed.`);
        setResults((prev) => [...prev, ...step.results]);
        setGroupStatus(step.groupStatus);
      }

      const repRes = await fetch(`/api/scan/${start.scanId}`);
      const rep = await repRes.json();
      if (!repRes.ok) throw new Error(rep.error || 'Could not load the report.');
      setReport(rep);
    } catch (e) {
      setError(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function runDemo() {
    runScan(`${window.location.origin}/api/demo-target`, true);
  }

  function onSubmit(e) {
    e.preventDefault();
    if (url.trim()) runScan(url.trim(), attested);
  }

  return (
    <main>
      <header className="masthead">
        <div className="wordmark">Audit<span>Canvas</span></div>
        <h1>See the auditor reason, not just scan</h1>
        <p>
          Most scanners stop at a list of issues. AuditCanvas scans for real, stores the
          evidence, and then a reasoning auditor reads that evidence back: it explains the
          impact, tries to refute its own findings, and turns what survives into a fix
          order a person can act on. The scanner decides what exists. The model decides
          what it means.
        </p>
        <div className="btn-row">
          <button className="btn" onClick={runDemo} disabled={busy}>
            Run the seeded demo
          </button>
          <button className="btn secondary" onClick={() => setShowSamples((s) => !s)}>
            Explore sample reports
          </button>
        </div>
      </header>

      {showSamples ? (
        <section className="block">
          <h2>Sample reports</h2>
          <p className="lede">
            Saved results appear here, each labelled with its scan timestamp, scanner
            version and model ID. The seeded sample set is produced on Day 7 of the
            build; until then this space is intentionally empty rather than filled with
            invented reports. Run the seeded demo above to see a live one.
          </p>
        </section>
      ) : null}

      <section className="block">
        <h2>Scan a site</h2>
        <p className="lede">
          Unverified targets are scanned with a restricted, passive policy: no CORS
          probes, no redirect probes, a small request budget. The full check set runs
          only on targets verified through DNS or on the seeded demo. Scans are
          non-destructive and read-only.
        </p>
        <form className="scan" onSubmit={onSubmit}>
          <div className="row">
            <input
              type="url"
              required
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={busy}
            />
            <button className="btn" type="submit" disabled={busy}>
              Start scan
            </button>
          </div>
          <label className="attest">
            <input
              type="checkbox"
              checked={attested}
              onChange={(e) => setAttested(e.target.checked)}
              disabled={busy}
            />
            <span>
              I own this site, or I have written authorization to security-test it. (Your
              attestation is logged, but the restricted policy applies either way until
              ownership is verified.)
            </span>
          </label>
        </form>
      </section>

      {error ? (
        <section className="block">
          <div className="error">{error}</div>
        </section>
      ) : null}

      {scan ? (
        <section className="block">
          <h2>
            {report ? 'Report' : 'Scanning'}: {scan.target}
          </h2>
          <p className="policy-line">
            Policy <strong>{scan.scanPolicy}</strong> · authorization{' '}
            <strong>{scan.authorizationState}</strong> · budget{' '}
            <strong>{scan.policy ? scan.policy.budget : '?'} requests</strong> ·{' '}
            {scan.policy && scan.policy.probes ? 'probes on' : 'probes off'}
          </p>
          <ul className="groups">
            {scan.groups.map((g) => (
              <li key={g.id}>
                <span>{g.name}</span>
                <span className={`gstatus ${groupStatus[g.id] || ''}`}>
                  {groupStatus[g.id] || 'queued'}
                </span>
              </li>
            ))}
          </ul>

          {report ? (
            <>
              <div className="scores">
                <div className="score">
                  <div className="k">Risk</div>
                  <div className="v">
                    {report.scores.risk.grade} · {report.scores.risk.score}
                  </div>
                  <div className="n">
                    {report.scores.risk.label}
                    {report.scores.risk.cappedByHigh ? ' · capped by a confirmed high' : ''}
                  </div>
                </div>
                <div className="score">
                  <div className="k">Coverage</div>
                  <div className="v">{Math.round(report.scores.coverage.ratio * 100)}%</div>
                  <div className="n">
                    {report.scores.coverage.verdicts} of {report.scores.coverage.attempted}{' '}
                    attempted checks reached a verdict
                  </div>
                </div>
                <div className="score">
                  <div className="k">Confidence</div>
                  <div className="v">{Math.round(report.scores.confidence.ratio * 100)}%</div>
                  <div className="n">
                    {report.scores.confidence.directFindings} findings on direct evidence,{' '}
                    {report.scores.confidence.inferredFindings} on inference
                  </div>
                </div>
              </div>

              {report.auditor ? (
                <p className="policy-line">
                  Auditor: <strong>{report.auditor.status}</strong>
                  {report.auditor.reason ? ` — ${report.auditor.reason}` : ''}
                </p>
              ) : null}

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

              <h3>Reproducibility</h3>
              <div className="stamp">
                scanner <code>{report.stamp.scannerVersion}</code> · rules{' '}
                <code>{report.stamp.rulesVersion}</code> · model{' '}
                <code>{report.stamp.modelId}</code> · policy{' '}
                <code>{report.stamp.scanPolicy}</code> · CVE snapshot{' '}
                <code>{report.stamp.dataSnapshots.cve.snapshotVersion}</code>
                {report.stamp.dataSnapshots.cve.stale ? ' (stale — treat CVE coverage as dated)' : ''} ·{' '}
                {new Date(report.stamp.timestamp).toLocaleString()}
              </div>
            </>
          ) : null}

          <h3>Checks</h3>
          <ul className="results">
            {results.map((r) => (
              <ResultRow key={r.checkId} r={r} />
            ))}
          </ul>
        </section>
      ) : null}

      <footer className="colophon">
        AuditCanvas runs eight deterministic check groups (headers, TLS, cookies, CORS,
        exposed paths, client stack &amp; CVEs, email posture, redirects &amp; mixed
        content). A result of Inconclusive is never counted as a pass. Reports expire
        after 7 days and carry noindex.
      </footer>
    </main>
  );
}
