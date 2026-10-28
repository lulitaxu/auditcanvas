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

// Exposure-group fixture material (design §8.2): format-valid, FAKE
// strings that match the anchored patterns in scanner/exposure.js.
// Defined once here; scripts/verify.mjs imports them for the leak
// assertions. None of these are credentials: the JWTs are unsigned
// shaped strings (dummy third segment, no real project), the keys are
// fixture-shaped, and the git password below exists only so the tests
// can assert it never appears in scanner output.
export const FIXTURE_STRIPE_LIVE = 'sk_live_FIXTURE0000000000abcd';
export const FIXTURE_STRIPE_PUBLISHABLE = 'pk_live_FIXTURE0000000000abcd';
export const FIXTURE_AWS_ACCESS_KEY = 'AKIAFIXTURE123456789';
export const FIXTURE_AWS_SECRET = 'FIXTUREawsSECRETkey/0123456789abcdEF+=GH'; // exactly 40 chars
export const FIXTURE_GITHUB_TOKEN = 'ghp_FIXTUREtoken00000000000000000000abcd';
export const FIXTURE_SLACK_TOKEN = 'xoxb-FIXTURE-0000000000-abcd';
export const FIXTURE_GOOGLE_API_KEY = 'AIzaFIXTURE0000000000000000000000000000'; // AIza + 35 = 39 chars
export const FIXTURE_SUPABASE_URL = 'https://fixtureproject000001.supabase.co'; // 20-char ref
export const FIXTURE_GIT_REMOTE_PASSWORD = 'fixture-git-password';
export function fixtureJwt(role) {
  const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ role, ref: 'fixtureproject', iss: 'supabase' })}.FIXTURESIG`;
}
export const FIXTURE_SERVICE_JWT = fixtureJwt('service_role');
export const FIXTURE_ANON_JWT = fixtureJwt('anon');

const VULN_HTML = `<!doctype html><html><head><title>Fixture: vulnerable</title>
<script src="/vendor/jquery-3.4.1.min.js"></script>
<script src="/vendor/lodash-4.17.15.min.js"></script>
<script src="/app.js"></script>
</head><body><h1>Vulnerable fixture</h1><img src="http://127.0.0.1/pixel.png" alt=""></body></html>`;

const HARDENED_HTML = `<!doctype html><html><head><title>Fixture: hardened</title>
<script src="/vendor/jquery-3.7.1.min.js"></script>
<script src="/vendor/lodash-4.17.23.min.js"></script>
<script src="/app.js"></script>
</head><body><h1>Hardened fixture</h1></body></html>`;

// The vulnerable fixture's own first-party bundle: every anchored
// secret pattern planted exactly once, plus a Firebase config whose
// databaseURL points at the OPEN fixture origin (127.0.0.5) — the
// scanner's host gate passes in fixtures because contexts run with
// allowPrivate: true (design §8.1).
const VULN_APP_JS = `/* fixture client bundle — format-valid FAKE secrets, planted for the exposure group */
const stripeKey = "${FIXTURE_STRIPE_LIVE}";
const awsConfig = { awsAccessKeyId: "${FIXTURE_AWS_ACCESS_KEY}", aws_secret_access_key: "${FIXTURE_AWS_SECRET}" };
const githubToken = "${FIXTURE_GITHUB_TOKEN}";
const slackToken = "${FIXTURE_SLACK_TOKEN}";
const supabaseConfig = { url: "${FIXTURE_SUPABASE_URL}", serviceKey: "${FIXTURE_SERVICE_JWT}" };
const firebaseConfig = { projectId: "fixture-project", databaseURL: "http://127.0.0.5" };
const privateKey = "-----BEGIN RSA PRIVATE KEY-----\\nFIXTURE-NOT-A-REAL-KEY";
`;

// The hardened fixture's bundle: ONLY the negative material — values
// that are public by design (publishable key, browser Google key,
// Supabase anon config) plus a Firebase config whose database DENIES
// unauthenticated reads (127.0.0.6). Zero exposure findings may come
// out of this page.
const HARDENED_APP_JS = `/* fixture client bundle — public-by-design values only */
const stripePublishable = "${FIXTURE_STRIPE_PUBLISHABLE}";
const googleApiKey = "${FIXTURE_GOOGLE_API_KEY}";
const supabaseConfig = { url: "${FIXTURE_SUPABASE_URL}", anonKey: "${FIXTURE_ANON_JWT}" };
const firebaseConfig = { projectId: "fixture-project", databaseURL: "http://127.0.0.6" };
`;

const VULN_ENV_LOCAL = [
  '# fixture environment file (fake values)',
  'APP_ENV=local',
  'DB_HOST=localhost',
  'DB_PASSWORD=fixture-not-a-real-secret',
  'SMTP_HOST=mail.fixture.local',
  '',
].join('\n');

// A real-shaped git config whose remote URL embeds a credential — the
// scanner must record the boolean, never the URL or the password.
const VULN_GIT_CONFIG = [
  '[core]',
  '\trepositoryformatversion = 0',
  '\tfilemode = true',
  '[remote "origin"]',
  `\turl = https://fixture-user:${FIXTURE_GIT_REMOTE_PASSWORD}@127.0.0.1/fixture/repo.git`,
  '\tfetch = +refs/heads/*:refs/remotes/origin/*',
  '',
].join('\n');

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
  if (p === '/app.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(VULN_APP_JS);
    return;
  }
  if (p === '/.env.local') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(VULN_ENV_LOCAL);
    return;
  }
  if (p === '/.git/config') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(VULN_GIT_CONFIG);
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
  if (p === '/app.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(HARDENED_APP_JS);
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

// The vulnerable origin can be flipped to serve the hardened responses
// at the SAME origin, so the rescan/diff flow is exercised the way a
// real fix-and-rescan works: same target identity, changed behavior.
let vulnerableOriginHardened = false;
export function setVulnerableOriginHardened(on) {
  vulnerableOriginHardened = Boolean(on);
}

export function startVulnerableHttp(port = 80, host = '127.0.0.1') {
  return listen(
    http.createServer((req, res) => (vulnerableOriginHardened ? hardenedHandler : vulnerableHandler)(req, res)),
    port,
    host
  );
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
// Exposure-group fixture origins (design §8.1/§8.3). The Firebase
// fixtures stand in for a real firebaseio.com project: the vulnerable
// and hardened pages point their databaseURL at these loopback
// origins, and the scanner's host gate passes because fixture
// contexts run allowPrivate: true.
export function startExposureFirebaseOpenHttp(port = 80, host = '127.0.0.5') {
  return listen(
    http.createServer((req, res) => {
      const u = new URL(req.url, 'http://fixture.local');
      if (u.pathname === '/.json') {
        // Shallow-read shape: top-level key NAMES only, values are
        // the literal `true` the real API returns for shallow=true.
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"users":true,"orders":true,"_meta":true}');
        return;
      }
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
    }),
    port,
    host
  );
}
export function startExposureFirebaseClosedHttp(port = 80, host = '127.0.0.6') {
  return listen(
    http.createServer((req, res) => {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"error":"Permission denied"}');
    }),
    port,
    host
  );
}

// Every path (including the scanner's baseline nonce path) returns a
// Node stack trace: the verbose-errors STRONG case.
const LEAKY_ERROR_BODY = [
  'Internal Server Error',
  'Error: fixture boom',
  '    at handler (/srv/app/index.js:10:15)',
  '    at Server.<anonymous> (/srv/app/index.js:20:3)',
  '',
].join('\n');
export function startLeakyErrorHttp(port = 80, host = '127.0.0.7') {
  return listen(
    http.createServer((req, res) => {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(LEAKY_ERROR_BODY);
    }),
    port,
    host
  );
}

// Every path returns a bare Whitelabel error page: the verbose-errors
// WEAK case (framework default, no frames or paths behind it).
export function startWeakErrorHttp(port = 80, host = '127.0.0.8') {
  return listen(
    http.createServer((req, res) => {
      res.writeHead(500, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><head><title>Error</title></head><body><h1>Whitelabel Error Page</h1></body></html>');
    }),
    port,
    host
  );
}

// Big-bundle fixtures for the truncation contract (design §8.3 items
// 18/19): ~300 KB bundles against the scanner's 256 KB fetch cap. On
// 127.0.0.9 the Stripe fixture key sits beyond the cap (must NOT
// fire; the aggregate goes Inconclusive bundle-truncated); on
// 127.0.0.10 it sits at ~1 KB (must fire despite truncation).
const BIG_BUNDLE_BYTES = 300 * 1024;
function bigBundleBody(keyOffset) {
  const stmt = `const stripeKey = "${FIXTURE_STRIPE_LIVE}";`;
  const before = '/*' + 'a'.repeat(Math.max(0, keyOffset - 2)) + '*/';
  const afterLen = Math.max(0, BIG_BUNDLE_BYTES - before.length - stmt.length - 4);
  return `${before}\n${stmt}\n/*${'a'.repeat(afterLen)}*/`;
}
function bigBundleHandler(keyOffset) {
  return (req, res) => {
    const u = new URL(req.url, 'http://fixture.local');
    if (u.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><html><head><title>Fixture: big bundle</title><script src="/big.js"></script></head><body><h1>Big bundle fixture</h1></body></html>');
      return;
    }
    if (u.pathname === '/big.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end(bigBundleBody(keyOffset));
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  };
}
export function startBigBundleLateKeyHttp(port = 80, host = '127.0.0.9') {
  return listen(http.createServer(bigBundleHandler(280 * 1024)), port, host);
}
export function startBigBundleEarlyKeyHttp(port = 80, host = '127.0.0.10') {
  return listen(http.createServer(bigBundleHandler(1024)), port, host);
}
export function startVulnerableHttps(port = 443, certDir, host = '::') {
  const key = fs.readFileSync(path.join(certDir, 'key.pem'));
  const cert = fs.readFileSync(path.join(certDir, 'cert.pem'));
  return listen(https.createServer({ key, cert }, vulnerableHandler), port, host);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const jobs = [
    startVulnerableHttp(), startHardenedHttp(), startSlowHttp(), startGarbageTcp(),
    startExposureFirebaseOpenHttp(), startExposureFirebaseClosedHttp(),
    startLeakyErrorHttp(), startWeakErrorHttp(),
    startBigBundleLateKeyHttp(), startBigBundleEarlyKeyHttp(),
  ];
  if (process.env.AC_CERT_DIR) jobs.push(startVulnerableHttps(443, process.env.AC_CERT_DIR));
  Promise.all(jobs).then(() => {
    console.log('AuditCanvas fixtures listening (on the only ports the scanner speaks):');
    console.log('  vulnerable http   http://127.0.0.1/');
    console.log('  hardened http     http://127.0.0.2/');
    console.log('  slow http         http://127.0.0.3/');
    console.log('  garbage tcp       http://127.0.0.4/');
    console.log('  firebase open     http://127.0.0.5/');
    console.log('  firebase closed   http://127.0.0.6/');
    console.log('  leaky errors      http://127.0.0.7/');
    console.log('  weak errors       http://127.0.0.8/');
    console.log('  big bundle late   http://127.0.0.9/');
    console.log('  big bundle early  http://127.0.0.10/');
    if (process.env.AC_CERT_DIR) console.log('  vulnerable https  https://localhost/ (fixture CA from AC_CERT_DIR)');
  });

  // Standalone-only control for the demo recording (DEMO-SCRIPT.md):
  // flipping the vulnerable origin to its hardened behavior mid-session
  // is what makes the fix-and-rescan segment recordable — scan the
  // vulnerable fixture in the app, apply the fix pack's changes by
  // flipping, rescan, and the diff verifies from fresh evidence. The
  // verify suite drives the same setter in-process; this HTTP control
  // (on a non-scanner port, loopback only) exists only in main mode.
  const controlPort = Number(process.env.AC_FIXTURE_CONTROL_PORT || 8911);
  http
    .createServer((req, res) => {
      if (req.url === '/flip') {
        setVulnerableOriginHardened(true);
        res.end('vulnerable origin now serves hardened responses\n');
      } else if (req.url === '/reset') {
        setVulnerableOriginHardened(false);
        res.end('vulnerable origin restored\n');
      } else if (req.url === '/state') {
        res.end(`hardened=${vulnerableOriginHardened}\n`);
      } else {
        res.statusCode = 404;
        res.end('control endpoints: /flip /reset /state\n');
      }
    })
    .listen(controlPort, '127.0.0.1', () => {
      console.log(`  fixture control   http://127.0.0.1:${controlPort}/flip (demo recording)`);
    });
}
