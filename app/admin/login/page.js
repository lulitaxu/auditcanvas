import { redirect } from 'next/navigation';
import { adminConfig } from '../../../src/lib/admin/config.js';
import { resolveAdminPageSession } from '../../../src/lib/admin/page-session.js';
import LoginForm from './LoginForm';

export const dynamic = 'force-dynamic';

// /admin/login — password-only. Already-signed-in operators go
// straight to the console. When admin is not configured the page
// renders the generic configuration state and no form (design §6):
// there is nothing to sign in to, and the page does not say which
// variable is missing.
export default async function AdminLoginPage() {
  const cfg = adminConfig();

  if (cfg.configured) {
    const resolved = await resolveAdminPageSession();
    if (resolved.kind === 'ok') redirect('/admin');
    return (
      <main className="admin-main">
        <div className="admin-login">
          <div className="wordmark">Audit<span>Canvas</span></div>
          <h3>Administrator access</h3>
          <h1 className="admin-title">Admin sign in</h1>
          <p className="policy-line">Operator access only. Sessions expire after 12 hours.</p>
          {resolved.kind === 'down' ? (
            <div className="notice">Admin storage is unavailable. Sign-in will fail until it recovers.</div>
          ) : null}
          <LoginForm />
        </div>
      </main>
    );
  }

  return (
    <main className="admin-main">
      <div className="admin-login">
        <div className="wordmark">Audit<span>Canvas</span></div>
        <h3>Administrator access</h3>
        <h1 className="admin-title">Admin sign in</h1>
        <div className="stamp">Admin is not configured.</div>
      </div>
    </main>
  );
}
