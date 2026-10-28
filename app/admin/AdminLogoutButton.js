'use client';

import { useState } from 'react';

// Logout POSTs with the per-session CSRF token (held in React state
// from the server-rendered page — never localStorage). On success
// the session row is revoked server-side and the browser returns to
// the login page; replaying the old cookie is an unknown token.
export default function AdminLogoutButton({ csrfToken }) {
  const [busy, setBusy] = useState(false);

  async function logout() {
    setBusy(true);
    try {
      await fetch('/api/admin/logout', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ac-csrf': csrfToken },
        body: JSON.stringify({}),
      });
    } catch { /* the redirect below is the outcome either way */ }
    window.location.assign('/admin/login');
  }

  return (
    <button className="btn secondary" type="button" onClick={logout} disabled={busy}>
      Sign out
    </button>
  );
}
