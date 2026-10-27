// Fixture servers for AuditCanvas: a deliberately vulnerable target, a
// hardened target, a hanging endpoint and a garbage responder. These are
// OUR OWN test pages (SPEC.md: Demo target and test fixtures); the
// verification script (scripts/verify.mjs) asserts the scanner's verdicts
// against them. Content is synthetic; secrets below are fake fixture
// strings, not credentials.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const SOFT404_BODY =
  '<!doctype html><html><head><title>Not found</title></head><body><h1>Sorry, that page does not exist.</h1></body></html>';

const VULN_HTML = `<!doctype html><html><head><title>Fixture: vulnerable</title>
<script src="/vendor/jquery-3.4.1.min.js"></script>
<script src="/vendor/lodash-4.17.15.min.js"></script>
</head><body><h1>Vulnerable fixture</h1><img src="http://127.0.0.1/pixel.png" alt=""></body></html>`;

const HARDENED_HTML = `<!doctype html><html><head><title>Fixture: hardened</title>
<script src="/vendor/jquery-3.7.1.min.js"></script>
<script src="/vendor/lodash-4.17.21.min.js"></script>
</head><body><h1>Hardened fixture</h1></body></html>`;

function vulnerableHandler(req, res) {
  const u = new URL(req.url, 'http://fixture.local');
  const p = u.pathname;
  const common = { 'content-type': 'text/html; charset=utf-8' };

  if (p === '/vendor/jquery-3.4.1.min.js' || p === '/vendor/lodash-4.17.15.min.js' || p.startsWith('/vendor/')) {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('/* fixture library stub (version is in the filename, deliberately) */');
    return;
  }
  if (p === '/.env') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('DB_HOST=localhost\nDB_PASSWORD=fixture-not-a-real-secret\nAPP_ENV=production\n');
    return;
  }
  if (p === '/.git/HEAD') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ref: refs/heads/main\n');
    return;
  }
  if (p === '/wp-admin/' || p === '/wp-admin') {
    res.writeHead(200, common);
    res.end('<!doctype html><html><body><form id="loginform" action="wp-login.php"><input name="user_login"></form></body></html>');
    return;
  }
  if (p === '/redirect') {
    const dest = u.searchParams.get('url') || '/';
    res.writeHead(302, { location: dest });
    res.end();
    return;
  }
  if (p === '/') {
    const headers = {
      ...common,
      // Deliberately weak CSP: unsafe-inline + unsafe-eval + wildcard,
      // no object-src, no base-uri. No HSTS/XCTO/Referrer/Permissions/XFO.
      'content-security-policy': "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *",
      'set-cookie': ['sessionid=fixturevalue; Path=/', 'prefs=dark; Path=/; SameSite=None'],
    };
    const origin = req.headers.origin;
    if (origin) {
      // The dangerous combination: reflect any origin, allow credentials.
      headers['access-control-allow-origin'] = origin;
      headers['access-control-allow-credentials'] = 'true';
    }
    res.writeHead(200, headers);
    res.end(VULN_HTML);
    return;
  }
  // Everything else (including /server-status and /.DS_Store): the
  // soft-404 trap — the same 200 page for real and invented paths alike.
  res.writeHead(200, common);
  res.end(SOFT404_BODY);
}

function hardenedHandler(req, res) {
  const u = new URL(req.url, 'http://fixture.local');
  const p = u.pathname;
  if (p === '/') {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      'set-cookie': ['sessionid=fixturevalue; Path=/; Secure; HttpOnly; SameSite=Strict'],
    });
    res.end(HARDENED_HTML);
    return;
  }
  if (p.startsWith('/vendor/')) {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end('/* fixture library stub */');
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
}

function slowHandler(req, res) {
  setTimeout(() => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>eventually</body></html>');
  }, 30000);
}

// The fixtures bind the real 80/443 ports on distinct loopback addresses:
// the scanner (per SPEC.md) will only ever speak to ports 80/443, so test
// targets on vanity ports would be unreachable by design. Binding low
// ports needs root or CAP_NET_BIND_SERVICE (see README).
function listen(server, port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server));
  });
}

export function startVulnerableHttp(port = 80, host = '127.0.0.1') {
  return listen(http.createServer(vulnerableHandler), port, host);
}
export function startHardenedHttp(port = 80, host = '127.0.0.2') {
  return listen(http.createServer(hardenedHandler), port, host);
}
export function startSlowHttp(port = 80, host = '127.0.0.3') {
  return listen(http.createServer(slowHandler), port, host);
}
export function startGarbageTcp(port = 80, host = '127.0.0.4') {
  const server = net.createServer((socket) => {
    socket.write(Buffer.from([0x00, 0x01, 0x02]) + 'this is not an HTTP response at all\r\n\r\n');
    setTimeout(() => socket.destroy(), 50);
  });
  return listen(server, port, host);
}
export function startVulnerableHttps(port = 443, certDir, host = '::') {
  const key = fs.readFileSync(path.join(certDir, 'key.pem'));
  const cert = fs.readFileSync(path.join(certDir, 'cert.pem'));
  return listen(https.createServer({ key, cert }, vulnerableHandler), port, host);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const jobs = [startVulnerableHttp(), startHardenedHttp(), startSlowHttp(), startGarbageTcp()];
  if (process.env.AC_CERT_DIR) jobs.push(startVulnerableHttps(443, process.env.AC_CERT_DIR));
  Promise.all(jobs).then(() => {
    console.log('AuditCanvas fixtures listening (on the only ports the scanner speaks):');
    console.log('  vulnerable http   http://127.0.0.1/');
    console.log('  hardened http     http://127.0.0.2/');
    console.log('  slow http         http://127.0.0.3/');
    console.log('  garbage tcp       http://127.0.0.4/');
    if (process.env.AC_CERT_DIR) console.log('  vulnerable https  https://localhost/ (fixture CA from AC_CERT_DIR)');
  });
}
