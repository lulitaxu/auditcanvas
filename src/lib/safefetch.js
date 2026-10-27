// SSRF-safe fetch layer (SPEC.md: "SSRF and target safety").
//
// Rules implemented here, all non-negotiable:
//  - Only http/https, only ports 80/443.
//  - Resolve the hostname; validate EVERY returned A/AAAA address and
//    reject the whole set if any is non-public (see iputil.js).
//  - Connect to a validated IP (pinning) while preserving TLS SNI and
//    certificate hostname verification against the original hostname.
//    DNS is never re-resolved between validation and connect.
//  - Redirects: max 5; every hop is re-validated end to end before
//    following; scheme or port changes on redirect are refused.
//  - Per-request timeout and a hard response-size cap.
//
// `allowPrivate` exists ONLY so our own seeded demo targets on loopback
// can be scanned in local development. It is set from server-side
// configuration (an exact-host allowlist), never from user input.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import { promises as dns } from 'node:dns';
import { addressBlockReason, validateAddressSet } from './iputil.js';

export class SafeFetchError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SafeFetchError';
    this.code = code;
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS = 5;

function effectivePort(u) {
  if (u.port) return Number(u.port);
  return u.protocol === 'https:' ? 443 : 80;
}

export function assertUrlAllowed(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new SafeFetchError('bad-url', `Unparseable URL: ${rawUrl}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new SafeFetchError('scheme-not-allowed', `Scheme ${u.protocol} is not allowed (http/https only)`);
  }
  const port = effectivePort(u);
  if (port !== 80 && port !== 443) {
    throw new SafeFetchError('port-not-allowed', `Port ${port} is not allowed (80/443 only)`);
  }
  if (u.username || u.password) {
    throw new SafeFetchError('bad-url', 'URLs with embedded credentials are refused');
  }
  return u;
}

// Resolve a hostname (or take an IP literal as-is) and validate the full
// address set. Returns the validated addresses; throws SafeFetchError.
export async function resolveAndValidate(hostname, { allowPrivate = false } = {}) {
  let addresses;
  if (net.isIP(hostname)) {
    const family = net.isIP(hostname);
    addresses = [{ address: hostname, family }];
  } else {
    try {
      addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    } catch (err) {
      throw new SafeFetchError('dns-fail', `DNS resolution failed for ${hostname}: ${err.code || err.message}`);
    }
  }
  if (!allowPrivate) {
    const verdict = validateAddressSet(addresses);
    if (!verdict.ok) {
      throw new SafeFetchError('blocked-ip', `Refusing ${hostname}: ${verdict.reason}`);
    }
  } else {
    for (const { address } of addresses) {
      if (addressBlockReason(address) === 'malformed') {
        throw new SafeFetchError('blocked-ip', `Refusing ${hostname}: malformed address ${address}`);
      }
    }
  }
  return addresses;
}

function requestOnce(u, pinnedAddress, { method = 'GET', headers = {}, timeoutMs = 6000, sizeCapBytes = 512 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = u.protocol === 'https:';
    const port = effectivePort(u);
    const transport = isHttps ? https : http;
    const reqHeaders = {
      'user-agent': 'AuditCanvas/0.1 (+security-audit; non-destructive)',
      accept: '*/*',
      ...headers,
      host: u.host,
    };
    const options = {
      host: pinnedAddress,
      port,
      method,
      path: u.pathname + u.search,
      headers: reqHeaders,
      timeout: timeoutMs,
    };
    if (isHttps) {
      // SNI + certificate hostname verification stay bound to the original
      // hostname even though TCP connects to the pinned IP.
      options.servername = net.isIP(u.hostname) ? undefined : u.hostname;
      options.rejectUnauthorized = true;
    }
    let settled = false;
    const fail = (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };
    const req = transport.request(options, (res) => {
      const chunks = [];
      let total = 0;
      let truncated = false;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total <= sizeCapBytes) {
          chunks.push(chunk);
        } else if (!truncated) {
          truncated = true;
          const room = sizeCapBytes - (total - chunk.length);
          if (room > 0) chunks.push(chunk.subarray(0, room));
          res.destroy();
        }
      });
      res.on('end', () => {
        if (!settled) {
          settled = true;
          resolve(finish(Buffer.concat(chunks)));
        }
      });
      res.on('close', () => {
        if (!settled && truncated) {
          settled = true;
          resolve(finish(Buffer.concat(chunks)));
        }
      });
      res.on('error', (err) => fail(new SafeFetchError('network', `Response error from ${u.hostname}: ${err.message}`)));
      function finish(buf) {
        const rawHeaders = res.headers || {};
        const setCookies = rawHeaders['set-cookie'] ? [...rawHeaders['set-cookie']] : [];
        const flat = {};
        for (const [k, v] of Object.entries(rawHeaders)) {
          if (k === 'set-cookie') continue;
          flat[k] = Array.isArray(v) ? v.join(', ') : String(v);
        }
        return {
          status: res.statusCode,
          headers: flat,
          setCookies,
          bodyText: buf.toString('utf8'),
          bodyBytes: total,
          truncated,
        };
      }
    });
    req.on('timeout', () => {
      req.destroy();
      fail(new SafeFetchError('timeout', `Request to ${u.hostname} exceeded ${timeoutMs}ms`));
    });
    req.on('error', (err) => {
      if (err instanceof SafeFetchError) return fail(err);
      if (err && err.code && String(err.code).startsWith('CERT')) {
        return fail(new SafeFetchError('tls', `TLS verification failed for ${u.hostname}: ${err.message}`));
      }
      fail(new SafeFetchError('network', `Request to ${u.hostname} failed: ${err.message}`));
    });
    req.end();
  });
}

// Full safe fetch with redirect handling. `follow: false` returns the first
// response untouched (used by the bounded open-redirect probe).
export async function safeFetch(rawUrl, opts = {}) {
  const {
    method = 'GET',
    headers = {},
    timeoutMs = 6000,
    sizeCapBytes = 512 * 1024,
    allowPrivate = false,
    follow = true,
  } = opts;
  let current = assertUrlAllowed(rawUrl);
  let redirects = 0;
  for (;;) {
    const addresses = await resolveAndValidate(current.hostname, { allowPrivate });
    const pinned = addresses[0].address;
    const res = await requestOnce(current, pinned, { method, headers, timeoutMs, sizeCapBytes });
    const location = res.headers['location'];
    if (!follow || !REDIRECT_STATUSES.has(res.status) || !location) {
      return { ...res, finalUrl: current.toString(), redirectCount: redirects, remoteAddress: pinned };
    }
    if (redirects >= MAX_REDIRECTS) {
      throw new SafeFetchError('too-many-redirects', `More than ${MAX_REDIRECTS} redirects from ${rawUrl}`);
    }
    let next;
    try {
      next = new URL(location, current);
    } catch {
      throw new SafeFetchError('bad-redirect', `Unparseable redirect Location from ${current.hostname}`);
    }
    assertUrlAllowed(next.toString());
    if (next.protocol !== current.protocol || effectivePort(next) !== effectivePort(current)) {
      throw new SafeFetchError(
        'redirect-scheme-change',
        `Refusing redirect that changes scheme or port (${current.protocol}//${current.host} -> ${next.protocol}//${next.host})`
      );
    }
    current = next;
    redirects += 1;
  }
}

// TLS probe used by the TLS check group: connects to a validated IP with
// SNI bound to the hostname, captures the peer certificate and negotiated
// protocol WITHOUT trusting the chain, then evaluates hostname match
// separately via tls.checkServerIdentity.
export async function probeTls(hostname, { allowPrivate = false, timeoutMs = 6000 } = {}) {
  const addresses = await resolveAndValidate(hostname, { allowPrivate });
  const pinned = addresses[0].address;
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: pinned,
      port: 443,
      servername: net.isIP(hostname) ? undefined : hostname,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    let settled = false;
    const done = (fn, val) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        fn(val);
      }
    };
    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const idError = cert && cert.subject ? tls.checkServerIdentity(hostname, cert) : new Error('no certificate');
      done(resolve, {
        remoteAddress: pinned,
        protocol: socket.getProtocol(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        hostnameMatch: !idError,
        hostnameError: idError ? String(idError.message || idError) : null,
        cert: cert
          ? {
              subject: cert.subject || null,
              issuer: cert.issuer || null,
              validFrom: cert.valid_from || null,
              validTo: cert.valid_to || null,
              fingerprint256: cert.fingerprint256 || null,
              subjectAltName: cert.subjectaltname || null,
              selfSigned:
                JSON.stringify(cert.subject || {}) === JSON.stringify(cert.issuer || {}),
            }
          : null,
      });
    });
    socket.on('timeout', () => done(reject, new SafeFetchError('timeout', `TLS probe to ${hostname} exceeded ${timeoutMs}ms`)));
    socket.on('error', (err) => done(reject, new SafeFetchError('network', `TLS probe to ${hostname} failed: ${err.message}`)));
  });
}
