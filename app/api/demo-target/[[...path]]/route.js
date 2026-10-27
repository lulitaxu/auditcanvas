// Seeded demo target (SPEC.md: Judge mode). A deliberately vulnerable
// page OWNED BY THIS APP, so the seeded demo and the scanner can be
// exercised end to end without touching anyone else's site. Everything
// here is intentionally wrong, in the ways the scanner checks for.
const SOFT404 =
  '<!doctype html><html><head><title>Not found</title></head><body><h1>Sorry, that page does not exist.</h1></body></html>';

const PAGE = `<!doctype html><html><head><title>AuditCanvas seeded demo target</title>
<script src="/api/demo-target/vendor/jquery-3.4.1.min.js"></script>
<script src="/api/demo-target/vendor/lodash-4.17.15.min.js"></script>
</head><body>
<h1>Seeded demo target</h1>
<p>This page is deliberately misconfigured so a scan produces real findings:
a weak Content-Security-Policy, unflagged cookies, credentialed CORS that
reflects any origin, an exposed /.env and /.git/HEAD, outdated libraries with
known CVEs, and an open redirect. It belongs to AuditCanvas; scanning it is
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
