import { redirect } from 'next/navigation';
import { resolveAdminPageSession } from '../../src/lib/admin/page-session.js';
import { adminStorageStatus, recentAdminScans } from '../../src/lib/admin/scans.js';
import { recentAdminEvents } from '../../src/lib/admin/events.js';
import AdminScanClient from './AdminScanClient';
import AdminLogoutButton from './AdminLogoutButton';

export const dynamic = 'force-dynamic';

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

const EVENT_CLASS = {
  login_success: 'LOGIN',
  login_failure: 'LOGIN',
  login_rate_limited: 'LOGIN',
  login_config_error: 'LOGIN',
  logout: 'LOGOUT',
  session_revoked: 'LOGOUT',
  csrf_rejected: 'CSRF',
  scan_created: 'SCAN',
  scan_step_completed: 'SCAN',
  scan_finalized: 'SCAN',
  scan_failed: 'SCAN',
  report_viewed: 'SCAN',
  report_downloaded: 'SCAN',
  prune_completed: 'PRUNE',
  prune_failed: 'PRUNE',
};

const EVENT_NAME = {
  login_success: 'Signed in',
  login_failure: 'Failed sign-in',
  login_rate_limited: 'Sign-in rate limited',
  login_config_error: 'Sign-in attempted while unconfigured',
  logout: 'Signed out',
  session_revoked: 'Session revoked',
  csrf_rejected: 'CSRF token rejected',
  scan_created: 'Admin scan created',
  scan_step_completed: 'Scan step completed',
  scan_finalized: 'Scan finalized',
  scan_failed: 'Scan failed',
  report_viewed: 'Report viewed',
  report_downloaded: 'Report downloaded',
  prune_completed: 'Prune completed',
  prune_failed: 'Prune failed',
};

function ScanRows({ scans }) {
  if (!scans.length) return <div className="stamp">No admin scans yet.</div>;
  return (
    <>
      <div className="admin-table-wrap admin-wide-only">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Created</th>
              <th>Status</th>
              <th>Policy</th>
              <th>Auth</th>
              <th>Risk</th>
              <th>Findings</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.scanId}>
                <td className="t-target">{s.targetDisplay}</td>
                <td>{fmtTime(s.createdAt)}</td>
                <td>{s.status.toUpperCase()}</td>
                <td>FULL</td>
                <td>{(s.reportAuthorizationState || s.authorizationState).toUpperCase()}</td>
                <td>{s.riskGrade ? `${s.riskGrade} · ${s.riskScore}` : '—'}</td>
                <td>{s.findingsCount == null ? '—' : s.findingsCount}</td>
                <td>{s.status === 'finalized' ? <a href={`/admin/scans/${s.scanId}`}>View report</a> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="results admin-narrow-only">
        {scans.map((s) => (
          <li key={s.scanId}>
            <div className="result-head">
              <span className="chip">ADMIN</span>
              <span className="result-title">{s.targetDisplay}</span>
            </div>
            <div className="result-detail">
              {fmtTime(s.createdAt)} · {s.status.toUpperCase()} · FULL · {(s.reportAuthorizationState || s.authorizationState).toUpperCase()}
              {s.riskGrade ? ` · risk ${s.riskGrade} ${s.riskScore} · ${s.findingsCount} findings` : ''}
              {s.status === 'finalized' ? (
                <>
                  {' · '}
                  <a href={`/admin/scans/${s.scanId}`}>View report</a>
                </>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}

// /admin — the operator console (admin design §17.3). Server-side
// session validation on every render; an anonymous request redirects
// to login, and a storage failure renders the unavailable state
// rather than a partial console.
export default async function AdminConsolePage() {
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
  let storageOk = false;
  let scans = [];
  let events = [];
  try {
    await adminStorageStatus(db);
    storageOk = true;
    scans = await recentAdminScans(db, 10);
    events = await recentAdminEvents(db, 20);
  } catch {
    storageOk = false;
  }

  return (
    <main className="admin-main">
      <header className="admin-head">
        <div className="readout admin-session">
          <div>
            <span className="ro-k">AuditCanvas</span>
            <span className="ro-v amber">ADMIN</span>
          </div>
          <div>
            <span className="ro-k">Session</span>
            <span className="ro-v">ACTIVE</span>
          </div>
          <div>
            <span className="ro-k">Expires</span>
            <span className="ro-v">{fmtTime(session.expiresAt)}</span>
          </div>
          <div>
            <span className="ro-k">Storage</span>
            <span className="ro-v">{storageOk ? 'NEON CONNECTED' : 'STORAGE UNAVAILABLE'}</span>
          </div>
        </div>
        <nav className="admin-nav" aria-label="Admin">
          <a href="/admin" aria-current="page">Console</a>
          <a href="/admin/scans">Scan history</a>
          <AdminLogoutButton csrfToken={csrfToken} />
        </nav>
      </header>

      <section className="block">
        <h2>Admin scan</h2>
        <p className="lede">
          Full non-destructive policy. Ownership is not verified by this mode. SSRF and safety limits
          still apply.
        </p>
        <AdminScanClient csrfToken={csrfToken} />
      </section>

      <section className="block">
        <h2>Recent scans</h2>
        <ScanRows scans={scans} />
      </section>

      <section className="block">
        <h2>Security events</h2>
        {events.length ? (
          <ul className="results">
            {events.map((ev) => (
              <li key={ev.id}>
                <div className="result-head">
                  <span className="chip">{EVENT_CLASS[ev.eventType] || 'EVENT'}</span>
                  <span className="result-title">{EVENT_NAME[ev.eventType] || ev.eventType}</span>
                </div>
                <div className="result-detail">
                  <code>{fmtTime(ev.occurredAt)}</code>
                  {ev.targetHost ? ` · ${ev.targetHost}` : ''}
                  {ev.metadata && ev.metadata.group ? ` · group ${ev.metadata.group}` : ''}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="stamp">No security events recorded yet.</div>
        )}
      </section>

      <footer>
        <div className="stamp">Admin scan reports are retained for 180 days.</div>
      </footer>
    </main>
  );
}
