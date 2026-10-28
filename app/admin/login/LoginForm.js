'use client';

import { useState } from 'react';

// Password-only login form (admin design §17.2). One field, no
// username, no remember-me. The browser never sees the configured
// hash and never compares anything: it posts the typed password to
// /api/admin/login and shows the server's generic error verbatim.
export default function LoginForm() {
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || 'Sign in failed.');
      window.location.assign('/admin');
    } catch (err) {
      setError(err && err.message ? err.message : 'Sign in failed.');
      setBusy(false);
    }
  }

  return (
    <form className="admin-form" onSubmit={onSubmit}>
      <div>
        <label className="admin-label" htmlFor="admin-password">Password</label>
        <input
          id="admin-password"
          className="admin-input"
          type="password"
          autoComplete="current-password"
          maxLength={128}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
          required
        />
      </div>
      {error ? <div className="error">{error}</div> : null}
      <div className="admin-actions">
        <button className="btn" type="submit" disabled={busy}>
          Sign in
        </button>
      </div>
    </form>
  );
}
