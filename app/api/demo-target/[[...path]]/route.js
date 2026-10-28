// Seeded demo target (SPEC.md: Judge mode). A deliberately vulnerable
// page OWNED BY THIS APP, so the seeded demo and the scanner can be
// exercised end to end without touching anyone else's site. Everything
// here is intentionally wrong, in the ways the scanner checks for.
const SOFT404 =
  '<!doctype html><html><head><title>Not found</title></head><body><h1>Sorry, that page does not exist.</h1></body></html>';

// Seeded first-party bundle for the Exposure group (SPEC addendum
// 2026-10-29): a format-valid FAKE Stripe live key (a finding) and a
// Supabase anon configuration (presence only — Inconclusive by
// design). The strings are fixture values, shaped to match the
// scanner's anchored patterns; they are not credentials (the JWT is
// an unsigned shaped string for a nonexistent project).
const APP_JS = `/* seeded demo client bundle — format-valid FAKE fixture strings only */
const stripeKey = "sk_live_FIXTURE0000000000abcd";
const supabaseConfig = {
  url: "https://fixtureproject000001.supabase.co",
  anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsInJlZiI6ImZpeHR1cmVwcm9qZWN0IiwiaXNzIjoic3VwYWJhc2UifQ.FIXTURESIG",
};
`;

const PAGE = `<!doctype html><html><head><title>AuditCanvas seeded demo target</title>
<script src="/api/demo-target/vendor/jquery-3.4.1.min.js"></script>
<script src="/api/demo-target/vendor/lodash-4.17.15.min.js"></script>
<script src="/api/demo-target/app.js"></script>
</head><body>
<h1>Seeded demo target</h1>
<p>This page is deliberately misconfigured so a scan produces real findings:
a weak Content-Security-Policy, unflagged cookies, credentialed CORS that
reflects any origin, an exposed /.env and /.git/HEAD, outdated libraries with
known CVEs, a live-format secret key sitting in its own client bundle, and an
open redirect. It belongs to AuditCanvas; scanning it is
the intended use.</p>
</body></html>`;

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request, { params }) {
  const { path: segs } = await params;
  const path = '/' + (segs ? segs.join('/') : '');
  const url = new URL(request.url);

  if (path.startsWith('/vendor/')) {
    return new Response('/* seeded demo library stub (version lives in the filename) */', {
      headers: { 'content-type': 'application/javascript' },
    });
  }
  if (path === '/app.js') {
    return new Response(APP_JS, { headers: { 'content-type': 'application/javascript' } });
  }
  if (path === '/.env') {
    return new Response('DB_HOST=localhost\nDB_PASSWORD=seeded-demo-not-a-real-secret\nAPP_ENV=production\n', {
      headers: { 'content-type': 'text/plain' },
    });
  }
  if (path === '/.git/HEAD') {
    return new Response('ref: refs/heads/main\n', { headers: { 'content-type': 'text/plain' } });
  }
  if (path === '/wp-admin' || path === '/wp-admin/') {
    return new Response(
      '<!doctype html><html><body><form id="loginform" action="wp-login.php"><input name="user_login"></form></body></html>',
      { headers: { 'content-type': 'text/html; charset=utf-8' } }
    );
  }
  if (path === '/redirect') {
    return new Response(null, { status: 302, headers: { location: url.searchParams.get('url') || '/' } });
  }
  if (path === '/' || path === '') {
    const headers = new Headers({
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *",
    });
    headers.append('set-cookie', 'sessionid=seededdemovalue; Path=/');
    headers.append('set-cookie', 'prefs=dark; Path=/; SameSite=None');
    const origin = request.headers.get('origin');
    if (origin) {
      headers.set('access-control-allow-origin', origin);
      headers.set('access-control-allow-credentials', 'true');
    }
    return new Response(PAGE, { headers });
  }
  // Soft-404 trap: unknown paths (and /server-status) all return the
  // same 200 page, exactly the ambiguity the scanner must not call a hit.
  return new Response(SOFT404, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}
