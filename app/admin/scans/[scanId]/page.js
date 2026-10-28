import { redirect } from 'next/navigation';
import { resolveAdminPageSession } from '../../../../src/lib/admin/page-session.js';
import { getAdminRun } from '../../../../src/lib/admin/scans.js';
import { insertAdminEvent } from '../../../../src/lib/admin/events.js';
import ReportView from '../../../ReportView';
import AdminLogoutButton from '../../AdminLogoutButton';

export const dynamic = 'force-dynamic';

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

// /admin/scans/[scanId] — one stored admin scan (admin design
// §14.4). A finalized run renders its STORED report (ReportView in
// admin download mode) so refresh, a cold instance, or a later
// session all show the same artifact; viewing records a
// report_viewed event. A non-finalized run shows metadata and
// status only — never a partial or client-held report. An unknown
// or non-admin scan ID is one generic not-found.
export default async function AdminScanDetailPage({ params }) {
  const resolved = await resolveAdminPageSession();
  if (resolved.kind === 'anon') redirect('/admin/login');
  if (resolved.kind === 'down') {
    return (
      <main className="admin-main">
        <div className="stamp">Admin is unavailable.</div>
      </main>
    );
  }
  const { db, session, csrfToken } = resolved;
  const { scanId } = await params;

  let run = null;
  let loadFailed = false;
  try {
    run = await getAdminRun(db, scanId);
  } catch {
    loadFailed = true;
  }

  const shell = (children) => (
    <main className="admin-main">
      <header className="admin-head">
        <div className="wordmark">Audit<span>Canvas</span></div>
        <nav className="admin-nav" aria-label="Admin">
          <a href="/admin">Console</a>
          <a href="/admin/scans">Scan history</a>
          <AdminLogoutButton csrfToken={csrfToken} />
        </nav>
      </header>
      {children}
    </main>
  );

  if (loadFailed) {
    return shell(<div className="stamp">Admin is unavailable.</div>);
  }
  if (!run || run.origin !== 'admin') {
    return shell(<div className="stamp">Admin scan not found.</div>);
  }

  const report = run.storedStatus === 'finalized' ? run.report : null;

  if (report) {
    try {
      await insertAdminEvent(db, {
        type: 'report_viewed',
        occurredAt: new Date().toISOString(),
        actorSessionId: session.id,
        scanId: run.scanId,
        targetHost: run.targetHost,
      });
    } catch { /* viewing the report never fails on telemetry */ }

    const verified = report.authorizationState === 'verified';
    return shell(
      <>
        <p className="policy-line">
          <a className="textbtn" href="/admin/scans">Back to scan history</a>
        </p>
        <div className="readout" aria-label="Admin scan provenance">
          <div>
            <span className="ro-k">Origin</span>
            <span className="ro-v amber">ADMIN</span>
          </div>
          <div>
            <span className="ro-k">Policy</span>
            <span className="ro-v">{String(report.scanPolicy || 'full').toUpperCase()}</span>
          </div>
          <div>
            <span className="ro-k">Authorization</span>
            <span className="ro-v">{String(report.authorizationState || 'admin').toUpperCase()}</span>
          </div>
          <div>
            <span className="ro-k">Ownership verified</span>
            <span className="ro-v">{verified ? 'YES — DNS TXT' : 'NO'}</span>
          </div>
          <div>
            <span className="ro-k">Finalized</span>
            <span className="ro-v">{fmtTime(run.finalizedAt)}</span>
          </div>
          <div>
            <span className="ro-k">Report SHA-256</span>
            <span className="ro-v">{run.reportSha256 ? run.reportSha256.slice(0, 12) : '—'}</span>
          </div>
        </div>
        {report.authorizationState === 'admin' ? (
          <div className="notice">
            Admin operator override: the full non-destructive check set ran. Target ownership was not
            verified by AuditCanvas.
          </div>
        ) : null}
        <ReportView report={report} scanId={run.scanId} downloadMode="admin" />
      </>
    );
  }

  return shell(
    <>
      <p className="policy-line">
        <a className="textbtn" href="/admin/scans">Back to scan history</a>
      </p>
      <div className="notice">
        This admin scan has not finalized. Status: {run.status}. Created {fmtTime(run.createdAt)}.
        {run.status === 'expired' ? ' The 30-minute grant window has closed; start a new admin scan to rescan.' : ''}
        {run.errorCode ? ` Recorded failure: ${run.errorCode}.` : ''}
      </div>
    </>
  );
}
