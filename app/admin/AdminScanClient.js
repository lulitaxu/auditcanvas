'use client';

import { useEffect, useState } from 'react';
import ReportView from '../ReportView';

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

// Display-only elapsed clock, mirroring the public scan readout.
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

// The admin scan driver (admin design §17.3): the same stateless
// start -> per-group steps -> finalize loop as the public client,
// but every call goes to the dedicated /api/admin/* routes with the
// per-session CSRF token, so the durable grant (not anything this
// component claims) authorizes the full policy. If the session dies
// mid-scan the driver STOPS — it never falls back to the public
// routes at restricted policy and pretends the scan continued.
export default function AdminScanClient({ csrfToken }) {
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [scan, setScan] = useState(null);
  const [groupStatus, setGroupStatus] = useState({});
  const [results, setResults] = useState([]);
  const [report, setReport] = useState(null);

  async function adminFetch(path, payload) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ac-csrf': csrfToken },
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401) {
      setSessionExpired(true);
      throw new Error('Admin session expired.');
    }
    if (!res.ok) throw new Error(body.error || 'The admin request failed.');
    return body;
  }

  async function runScan(targetUrl) {
    setBusy(true);
    setError(null);
    setSessionExpired(false);
    setReport(null);
    setResults([]);
    setScan(null);
    setGroupStatus({});
    try {
      const start = await adminFetch('/api/admin/scans/start', { url: targetUrl });
      setScan(start);
      setGroupStatus(start.groupStatus);

      const bundles = [];
      for (const g of start.groups) {
        setGroupStatus((prev) => ({ ...prev, [g.id]: 'running' }));
        const step = await adminFetch('/api/admin/scans/step', {
          scanId: start.scanId,
          target: start.target,
          group: g.id,
        });
        bundles.push({
          group: g.id,
          scanPolicy: step.scanPolicy,
          results: step.results,
          evidence: step.evidence,
          requests: step.requests,
          sig: step.sig,
        });
        setResults((prev) => [...prev, ...step.results]);
        setGroupStatus((prev) => ({ ...prev, [g.id]: 'done' }));
      }

      const rep = await adminFetch('/api/admin/scans/finalize', {
        scan: { scanId: start.scanId },
        bundles,
      });
      setReport(rep);
    } catch (e) {
      if (!sessionExpired) setError(e && e.message ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(e) {
    e.preventDefault();
    if (url.trim()) runScan(url.trim());
  }

  return (
    <div>
      <form className="scan" onSubmit={onSubmit}>
        <div className="row">
          <input
            type="url"
            required
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={busy}
            aria-label="Target URL"
          />
          <button className="btn" type="submit" disabled={busy}>
            Run full scan
          </button>
        </div>
      </form>

      {sessionExpired ? (
        <div className="notice" style={{ marginTop: 14 }}>
          Admin session expired. Sign in again to start a new admin scan.
        </div>
      ) : null}
      {error && !sessionExpired ? (
        <div className="error" style={{ marginTop: 14 }}>{error}</div>
      ) : null}

      {scan ? (
        <div style={{ marginTop: 18 }}>
          <div className="readout" aria-label="Admin scan readout">
            <div>
              <span className="ro-k">Target</span>
              <span className="ro-v">{scan.target}</span>
            </div>
            <div>
              <span className="ro-k">Scan ID</span>
              <span className="ro-v">{scan.scanId}</span>
            </div>
            <div>
              <span className="ro-k">Origin</span>
              <span className="ro-v amber">ADMIN</span>
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
          <p className="policy-line" aria-live="polite">
            Policy <strong>{scan.scanPolicy}</strong> · authorization{' '}
            <strong>{scan.authorizationState}</strong>
            {scan.verification ? ' · ownership verified by DNS TXT' : ' · ownership not verified (operator override)'}
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
            <ReportView report={report} scanId={scan.scanId} downloadMode="admin" />
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
        </div>
      ) : null}
    </div>
  );
}
