'use client';

import { useState } from 'react';

// Password-only login form (admin design §17.2). One field, no
// username, no remember-me. The browser never sees the configured
// hash and never compares anything: it posts the typed password to
// /api/admin/login and shows the server's generic error verbatim.
export default function LoginForm() {
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
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
        <div className="password-field">
          <input
            id="admin-password"
            className="admin-input"
            type={visible ? 'text' : 'password'}
            autoComplete="current-password"
            maxLength={128}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
            required
          />
          <button
            type="button"
            className="password-toggle"
            aria-label={visible ? 'Hide password' : 'Show password'}
            aria-pressed={visible}
            title={visible ? 'Hide password' : 'Show password'}
            onClick={() => setVisible((v) => !v)}
          >
            {visible ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M3 3l18 18" />
                <path d="M10.6 5.1A9.8 9.8 0 0 1 12 5c5 0 8.5 4.5 9.7 7-.4 1-1.5 2.6-3.2 4M6.6 6.9C4.4 8.4 3 10.7 2.3 12c1.2 2.5 4.7 7 9.7 7 1.5 0 2.9-.4 4.1-1" />
                <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M2.3 12C3.5 9.5 7 5 12 5s8.5 4.5 9.7 7c-1.2 2.5-4.7 7-9.7 7s-8.5-4.5-9.7-7Z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
        </div>
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
