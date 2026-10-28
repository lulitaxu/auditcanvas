'use client';

import { useEffect, useRef, useState } from 'react';
import ReportView from './ReportView';

const OUTCOME_LABEL = {
  pass: 'Pass',
  finding: 'Finding',
  inconclusive: 'Inconclusive',
  'not-assessed': 'Not assessed',
};

function LiveRow({ r }) {
  return (
    <li>
      <div className="result-head">
        <span className={`chip ${r.outcome}`}>{OUTCOME_LABEL[r.outcome] || r.outcome}</span>
        {r.severity ? <span className="sev">{r.severity}</span> : null}
        <span className="result-title">{r.title}</span>
      </div>
      <div className="result-detail">{r.detail}</div>
    </li>
  );
}

// Display-only elapsed clock for the scan readout: ticks while the
// scan runs, freezes on the report's own timestamp once it lands.
function Elapsed({ from, to }) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (to) return undefined;
    const id = setInterval(() => setTick((t) => t + 1), 500);
    return () => clearInterval(id);
  }, [to]);
  const end = to ? new Date(to).getTime() : Date.now();
  const secs = Math.max(0, Math.floor((end - new Date(from).getTime()) / 1000));
  const mm = String(Math.floor(secs / 60)).padStart(2, '0');
  const ss = String(secs % 60).padStart(2, '0');
  return <>{`${mm}:${ss}`}</>;
}

function VerifyPanel({ targetUrl }) {
  const [challenge, setChallenge] = useState(null);
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);

  let hostname = '';
  try {
    hostname = targetUrl ? new URL(targetUrl).hostname : '';
  } catch { /* user is still typing */ }

  async function start() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await fetch('/api/verify/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || 'Could not start verification.');
      setChallenge(body);
    } catch (e) {
      setStatus(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function check() {
    setBusy(true);
    try {
      const res = await fetch('/api/verify/check', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ hostname }),
      });
      const body = await res.json();
      if (body.status === 'verified') {
        setStatus(`Verified. Scans of ${hostname} created from now on run the full check set, with the verification stored on the scan session.`);
        setChallenge(null);
      } else if (body.status === 'dns-error') {
        setStatus(`DNS lookup did not complete (${body.dnsStatus}); that is inconclusive, not a missing record. Wait and check again.`);
      } else if (body.status === 'not-found') {
        setStatus('The TXT record was not found yet (or does not match). DNS can take a few minutes to propagate.');
      } else if (body.status === 'expired') {
        setStatus('The challenge token expired (15 minutes). Start again for a fresh token.');
        setChallenge(null);
      } else if (body.status === 'no-challenge') {
        setStatus('No active challenge for this host. Start verification first.');
      } else {
        setStatus(`Status: ${body.status}`);
      }
    } catch (e) {
      setStatus(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="verify">
      <h3>Verify ownership (DNS TXT)</h3>
      <p className="lede">
        One method, done properly: a short-lived token bound to the exact hostname.
        Verified hosts unlock the full check set; unverified targets always run the
        restricted passive policy, attestation or not.
      </p>
      <div className="btn-row">
        <button className="btn secondary" onClick={start} disabled={busy || !hostname} type="button">
          Start verification{hostname ? ` for ${hostname}` : ''}
        </button>
        {challenge ? (
          <button className="btn" onClick={check} disabled={busy} type="button">
            Check the record
          </button>
        ) : null}
      </div>
      {challenge ? (
        <div className="stamp">
          Add a <code>TXT</code> record at <code>{challenge.recordName}</code> with the exact value{' '}
          <code>{challenge.recordValue}</code> — it expires at{' '}
          {new Date(challenge.expiresAt).toLocaleString()}.
        </div>
      ) : null}
      {status ? <p className="policy-line">{status}</p> : null}
    </div>
  );
}

export default function ScanClient() {
  const [mode, setMode] = useState('judge');
  const [url, setUrl] = useState('');
  const [attested, setAttested] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [scan, setScan] = useState(null);
  const [groupStatus, setGroupStatus] = useState({});
  const [results, setResults] = useState([]);
  const [report, setReport] = useState(null);
  const [diff, setDiff] = useState(null);
  const [showSamples, setShowSamples] = useState(false);
  const [samples, setSamples] = useState(null); // null = not loaded yet
  const [expectedTargets, setExpectedTargets] = useState([]);
  const [sampleReport, setSampleReport] = useState(null);
  const [sampleBusy, setSampleBusy] = useState(false);

  // Sample reports are preloaded Saved results (real scans of our own
  // sites, generated by scripts/generate-samples.mjs). The list may be
  // empty: the slot then shows its explicit "generated after deploy"
  // state rather than anything invented.
  async function toggleSamples() {
    const opening = !showSamples;
    setShowSamples(opening);
    if (opening && samples === null) {
      try {
        const res = await fetch('/api/samples');
        const body = await res.json();
        setSamples(body.samples || []);
        setExpectedTargets(body.expectedTargets || []);
      } catch {
        setSamples([]);
      }
    }
  }

  async function openSample(slug) {
    setSampleBusy(true);
    try {
      const res = await fetch(`/api/samples/${slug}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || 'Could not load the sample report.');
      setSampleReport(body);
    } catch (e) {
      setError(e && e.message ? e.message : String(e));
    } finally {
      setSampleBusy(false);
    }
  }

  // The finalized report a rescan follows, held client-side: the
  // stateless flow keeps reports with the client and posts both to
  // /api/scan/diff (serverless instances share no scan state).
  const prevReportRef = useRef(null);

  // The signed step-bundle chain of the last completed scan. Downloads
  // post it alongside the report so the server can rebuild the report
  // from the verified chain instead of trusting the client copy
  // (security fixes H1/M4).
  const bundleChainRef = useRef(null);

  // Drive one scan through its per-group steps and finalize it. The
  // steps are stateless (each runs one group in a fresh server
  // context); the client carries the per-group bundles to
  // /api/scan/finalize, which re-validates everything server-side
  // before a report exists. Shared by fresh scans and rescans.
  async function driveScan(start) {
    setScan(start);
    setGroupStatus(start.groupStatus);
    setResults([]);
    setReport(null);
    setDiff(null);

    const bundles = [];
    for (const g of start.groups) {
      setGroupStatus((prev) => ({ ...prev, [g.id]: 'running' }));
      const stepRes = await fetch('/api/scan/step', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ scanId: start.scanId, target: start.target, attested: start.attested, group: g.id }),
      });
      const step = await stepRes.json();
      if (!stepRes.ok) throw new Error(step.error || `The ${g.name} step failed.`);
      bundles.push({ group: g.id, scanPolicy: step.scanPolicy, results: step.results, evidence: step.evidence, requests: step.requests, sig: step.sig });
      setResults((prev) => [...prev, ...step.results]);
      setGroupStatus((prev) => ({ ...prev, [g.id]: 'done' }));
    }

    const repRes = await fetch('/api/scan/finalize', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        scan: {
          scanId: start.scanId,
          target: start.target,
          attested: start.attested,
          rescanOf: start.rescanOf,
          createdAt: start.createdAt,
        },
        bundles,
      }),
    });
    const rep = await repRes.json();
    if (!repRes.ok) throw new Error(rep.error || 'Could not load the report.');
    bundleChainRef.current = {
      scan: {
        scanId: start.scanId,
        target: start.target,
        attested: start.attested,
        rescanOf: start.rescanOf,
        createdAt: start.createdAt,
      },
      bundles,
    };
    setReport(rep);

    // A rescan carries its lineage: diff the fresh report against the
    // one it followed so the report opens with what changed.
    if (start.rescanOf && prevReportRef.current) {
      const diffRes = await fetch('/api/scan/diff', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ before: prevReportRef.current, after: rep }),
      });
      const d = await diffRes.json();
      if (diffRes.ok) setDiff(d);
    }
  }

  async function runScan(targetUrl, isAttested) {
    setBusy(true);
    setError(null);
    prevReportRef.current = null;
    setReport(null);
    setDiff(null);
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
      await driveScan(start);
    } catch (e) {
      setError(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // Rescan the report's target (same target, same policy) and show the
  // diff: which findings the fresh evidence resolves, which are new,
  // and which are still there.
  async function rescan() {
    if (!scan || !report) return;
    setBusy(true);
    setError(null);
    try {
      prevReportRef.current = report;
      const res = await fetch('/api/scan/rescan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target: report.target, attested: scan.attested, rescanOf: scan.scanId }),
      });
      const start = await res.json();
      if (!res.ok) throw new Error(start.error || 'Could not start the rescan.');
      await driveScan(start);
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

  const progress = scan ? (
    <section className="block">
      <h2>
        {report ? 'Report' : 'Scanning'}: {scan.target}
      </h2>
      <div className="readout" aria-label="Scan readout">
        <div>
          <span className="ro-k">Target</span>
          <span className="ro-v">{scan.target}</span>
        </div>
        <div>
          <span className="ro-k">Scan ID</span>
          <span className="ro-v">{scan.scanId}</span>
        </div>
        <div>
          <span className="ro-k">Groups</span>
          <span className="ro-v">
            {scan.groups.filter((g) => groupStatus[g.id] === 'done').length}/{scan.groups.length} complete
          </span>
        </div>
        <div>
          <span className="ro-k">Elapsed</span>
          <span className="ro-v amber">
            <Elapsed from={scan.createdAt} to={report ? report.stamp.timestamp : null} />
          </span>
        </div>
      </div>
      <p className="policy-line">
        Policy <strong>{scan.scanPolicy}</strong> · authorization{' '}
        <strong>{scan.authorizationState}</strong> · budget{' '}
        <strong>{scan.policy ? scan.policy.budget : '?'} requests</strong> ·{' '}
        {scan.policy && scan.policy.probes ? 'probes on' : 'probes off'}
        {scan.verification ? ' · ownership verified by DNS TXT' : ''}
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
        <ReportView report={report} scanId={scan.scanId} diff={diff} onRescan={rescan} busy={busy} bundleChain={bundleChainRef.current} />
      ) : (
        <>
          <h3>Checks so far</h3>
          <ul className="results">
            {results.map((r) => (
              <LiveRow key={r.checkId} r={r} />
            ))}
          </ul>
        </>
      )}
    </section>
  ) : null;

  return (
    <main>
      <header className="masthead">
        <div className="hero-readout">
          <span>Security audit instrument</span>
          <span className="pipe">Scan → Reason → Refute → Fix order</span>
          <span className="live">Non-destructive</span>
        </div>
        <div className="wordmark">Audit<span>Canvas</span></div>
        <h1>See the auditor reason, not just scan</h1>
        <p>
          Most scanners stop at a list of issues. AuditCanvas scans for real, stores the
          evidence, and then a reasoning auditor reads that evidence back: it explains the
          impact, tries to refute its own findings, and turns what survives into a fix
          order a person can act on. The scanner decides what exists. The model decides
          what it means.
        </p>
        {mode === 'judge' ? (
          <>
            <div className="btn-row">
              <button className="btn" onClick={runDemo} disabled={busy}>
                Run the seeded demo
              </button>
              <button className="btn secondary" onClick={toggleSamples}>
                Explore sample reports
              </button>
            </div>
            <p className="policy-line">
              Judge mode has no URL input: the demo target is fixed and ours.{' '}
              <button className="textbtn" onClick={() => setMode('scan')}>
                Scan a site you own instead
              </button>
            </p>
          </>
        ) : (
          <p className="policy-line">
            <button className="textbtn" onClick={() => setMode('judge')}>
              Back to Judge mode
            </button>
          </p>
        )}
      </header>

      {mode === 'judge' && showSamples ? (
        <section className="block">
          <h2>Sample reports</h2>
          {sampleReport ? (
            <>
              <p className="policy-line">
                <span className="chip inconclusive">Saved result</span> {sampleReport.target} ·
                scanned {new Date(sampleReport.stamp.timestamp).toLocaleString()} · scanner{' '}
                {sampleReport.stamp.scannerVersion} · model {sampleReport.stamp.modelId} ·{' '}
                <button className="textbtn" onClick={() => setSampleReport(null)}>
                  Back to the sample list
                </button>
              </p>
              <ReportView report={sampleReport} scanId={null} />
            </>
          ) : samples === null ? (
            <p className="lede">Loading sample reports…</p>
          ) : samples.length === 0 ? (
            <>
              <p className="lede">
                Sample reports are real scans of our own sites, generated by the scanner
                itself — never hand-assembled — and this slot stays in its placeholder
                state until those scans have actually run. The scanner connects directly
                (pinned IPs, no proxy), so generation happens from the deployed app: one
                run of <code>scripts/generate-samples.mjs</code> after deploy fills this
                space. The build sandbox cannot produce them: its resolver answers these
                hosts with reserved 198.18.0.0/15 addresses, which the scanner correctly
                refuses, and its network intercepts direct TLS.
              </p>
              <ul className="results">
                {expectedTargets.map((t) => (
                  <li key={t}>
                    <div className="result-head">
                      <span className="chip inconclusive">Saved result — pending</span>
                      <span className="result-title">{t}</span>
                    </div>
                    <div className="result-detail">
                      Generated after deploy by a real scan of this site, then labelled
                      with its scan timestamp, scanner version and model ID.
                    </div>
                  </li>
                ))}
              </ul>
              <p className="lede">
                Run the seeded demo above to see a live scan right now.
              </p>
            </>
          ) : (
            <ul className="results">
              {samples.map((s) => (
                <li key={s.slug}>
                  <div className="result-head">
                    <span className="chip inconclusive">{s.label}</span>
                    <span className="result-title">{s.target}</span>
                  </div>
                  <div className="result-detail">
                    Scanned {new Date(s.timestamp).toLocaleString()} · scanner{' '}
                    {s.scannerVersion} · model {s.modelId} · policy {s.scanPolicy} ·{' '}
                    {s.findings} findings
                    {s.risk ? ` · risk ${s.risk.grade} (${s.risk.score})` : ''}
                  </div>
                  <div className="btn-row">
                    <button className="btn secondary" onClick={() => openSample(s.slug)} disabled={sampleBusy}>
                      Open report
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}

      {mode === 'scan' ? (
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
          <VerifyPanel targetUrl={url} />
        </section>
      ) : null}

      {error ? (
        <section className="block">
          <div className="error">{error}</div>
        </section>
      ) : null}

      {progress}

      <footer className="colophon">
        AuditCanvas runs nine deterministic check groups (headers, TLS, cookies, CORS,
        exposed paths, exposure &amp; secrets, client stack &amp; CVEs, email posture,
        redirects &amp; mixed content). A result of Inconclusive is never counted as a pass. Reports expire
        after 7 days and carry noindex.
      </footer>
    </main>
  );
}
