import { redirect } from 'next/navigation';
import { resolveAdminPageSession } from '../../../src/lib/admin/page-session.js';
import { listAdminHistory, decodeHistoryCursor } from '../../../src/lib/admin/scans.js';
import AdminLogoutButton from '../AdminLogoutButton';

export const dynamic = 'force-dynamic';

const STATUSES = ['created', 'running', 'finalized', 'failed', 'expired'];

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function pageHref({ status, host, stack }) {
  const params = new URLSearchParams();
  if (status) params.set('status', status);
  if (host) params.set('host', host);
  if (stack) params.set('stack', stack);
  const q = params.toString();
  return q ? `/admin/scans?${q}` : '/admin/scans';
}

// /admin/scans — the durable admin scan history (admin design
// §14.3 + §17.4). Data comes from the Neon admin_scan_runs table on
// every render, never from process memory: this page must survive a
// redeploy and agree across instances. Keyset pagination — newest
// first, cursor in the URL; Previous rebuilds the earlier page from
// the cursor stack carried in the URL (stateless back navigation).
export default async function AdminHistoryPage({ searchParams }) {
  const resolved = await resolveAdminPageSession();
  if (resolved.kind === 'anon') redirect('/admin/login');
  if (resolved.kind === 'down') {
    return (
      <main className="admin-main">
        <div className="stamp">Admin is unavailable.</div>
      </main>
    );
  }
  const { db, csrfToken } = resolved;

  const sp = (await searchParams) || {};
  const status = STATUSES.includes(sp.status) ? sp.status : null;
  const host = typeof sp.host === 'string' && sp.host.trim() ? sp.host.trim().toLowerCase().slice(0, 253) : null;
  // Cursor stack: comma-separated encoded cursors; the last one is
  // the cursor for the page being viewed (absent = first page).
  const stackParts = typeof sp.stack === 'string' && sp.stack ? sp.stack.split(',').filter(Boolean) : [];
  const cursor = stackParts.length ? decodeHistoryCursor(stackParts[stackParts.length - 1]) : null;

  let page = null;
  let loadFailed = false;
  try {
    page = await listAdminHistory(db, { status, host, cursor, limit: 25 });
  } catch {
    loadFailed = true;
  }

  const rows = page ? page.rows : [];
  const nextStack = page && page.nextCursor ? [...stackParts, page.nextCursor] : null;
  const prevStack = stackParts.slice(0, -1);

  return (
    <main className="admin-main">
      <header className="admin-head">
        <div className="wordmark">Audit<span>Canvas</span></div>
        <nav className="admin-nav" aria-label="Admin">
          <a href="/admin">Console</a>
          <a href="/admin/scans" aria-current="page">Scan history</a>
          <AdminLogoutButton csrfToken={csrfToken} />
        </nav>
      </header>

      <h1 className="admin-title">Admin scan history</h1>

      <form className="admin-filter-row" method="get" action="/admin/scans">
        <div>
          <label className="admin-label" htmlFor="f-status">Status</label>
          <select id="f-status" name="status" className="admin-input" defaultValue={status || ''}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="admin-label" htmlFor="f-host">Target host</label>
          <input id="f-host" name="host" className="admin-input" type="text" defaultValue={host || ''} placeholder="example.com" />
        </div>
        <div className="admin-actions">
          <button className="btn secondary" type="submit">Filter</button>
          <a className="textbtn" href="/admin/scans">Clear</a>
        </div>
      </form>

      {loadFailed ? (
        <div className="stamp">Admin is unavailable.</div>
      ) : rows.length === 0 ? (
        <div className="stamp">No admin scans match these filters.</div>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Created</th>
                <th>Status</th>
                <th></th>
                <th>Policy</th>
                <th>Auth</th>
                <th>Risk</th>
                <th>Findings</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.scanId}>
                  <td className="t-target">{s.targetDisplay}</td>
                  <td>{fmtTime(s.createdAt)}</td>
                  <td>{s.status.toUpperCase()}</td>
                  <td><span className="chip">ADMIN</span></td>
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
      )}

      <div className="admin-actions">
        {stackParts.length ? (
          <a className="btn secondary" href={pageHref({ status, host, stack: prevStack.join(',') || null })}>Previous 25</a>
        ) : null}
        {nextStack ? (
          <a className="btn secondary" href={pageHref({ status, host, stack: nextStack.join(',') })}>Next 25</a>
        ) : null}
      </div>

      <footer>
        <div className="stamp">Admin scan reports are retained for 180 days.</div>
      </footer>
    </main>
  );
}
