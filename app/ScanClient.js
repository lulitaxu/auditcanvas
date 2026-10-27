'use client';

import { useState } from 'react';
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

  // Drive one scan session through its per-group steps and load the
  // finalized report. Shared by fresh scans and rescans.
  async function driveScan(start) {
    setScan(start);
    setGroupStatus(start.groupStatus);
    setResults([]);
    setReport(null);
    setDiff(null);

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

    // A rescan carries its lineage: fetch the diff against the scan it
    // followed so the report opens with what changed.
    if (start.rescanOf) {
      const diffRes = await fetch(`/api/scan/${start.scanId}/diff`);
      const d = await diffRes.json();
      if (diffRes.ok) setDiff(d);
    }
  }

  async function runScan(targetUrl, isAttested) {
    setBusy(true);
    setError(null);
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
    if (!scan) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/scan/${scan.scanId}/rescan`, { method: 'POST' });
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
        <ReportView report={report} scanId={scan.scanId} diff={diff} onRescan={rescan} busy={busy} />
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
              <button className="btn secondary" onClick={() => setShowSamples((s) => !s)}>
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
          <p className="lede">
            Saved results appear here, each labelled with its scan timestamp, scanner
            version and model ID. The seeded sample set is produced on Day 7 of the
            build; until then this space is intentionally empty rather than filled with
            invented reports. Run the seeded demo above to see a live one.
          </p>
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
        AuditCanvas runs eight deterministic check groups (headers, TLS, cookies, CORS,
        exposed paths, client stack &amp; CVEs, email posture, redirects &amp; mixed
        content). A result of Inconclusive is never counted as a pass. Reports expire
        after 7 days and carry noindex.
      </footer>
    </main>
  );
}
