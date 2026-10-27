// Group 2 — TLS: negotiated protocol, certificate hostname match, chain
// validity, expiry window. A valid cert alone is never the whole verdict.
import tls from 'node:tls';
import { makeCheck } from '../evidence.js';
import { probeTls } from '../safefetch.js';
import { inconclusiveFromError } from '../context.js';

const GROUP = 'tls';

export async function runTls(ctx) {
  if (!ctx.isHttps()) {
    return [
      makeCheck({
        group: GROUP, check: 'not-applicable', outcome: 'not-assessed',
        title: 'TLS not assessed on an HTTP target',
        detail: 'The target was scanned over HTTP, so there is no TLS handshake to evaluate.',
        evidenceIds: [],
      }),
    ];
  }
  let probe;
  try {
    probe = await probeTls(ctx.host(), { allowPrivate: ctx.allowPrivate, timeoutMs: ctx.policy.perRequestTimeoutMs });
  } catch (err) {
    return [inconclusiveFromError(GROUP, 'probe', 'TLS handshake could not be completed', err)];
  }
  const ev = ctx.evidence.add('tls', ctx.base.origin, {
    protocol: probe.protocol,
    authorized: probe.authorized,
    authorizationError: probe.authorizationError,
    hostnameMatch: probe.hostnameMatch,
    remoteAddress: probe.remoteAddress,
    cert: probe.cert
      ? {
          subject: probe.cert.subject,
          issuer: probe.cert.issuer,
          validFrom: probe.cert.validFrom,
          validTo: probe.cert.validTo,
          subjectAltName: probe.cert.subjectAltName,
          selfSigned: probe.cert.selfSigned,
          fingerprint256: probe.cert.fingerprint256,
        }
      : null,
  });
  const out = [];
  const evIds = [ev];

  // Protocol
  const weakProtocol = ['SSLv3', 'TLSv1', 'TLSv1.1'].includes(probe.protocol);
  out.push(
    weakProtocol
      ? makeCheck({
          group: GROUP, check: 'protocol', outcome: 'finding', severity: 'high',
          title: `Weak TLS protocol negotiated: ${probe.protocol}`,
          detail: 'The server negotiated a protocol version with known attacks (POODLE / BEAST class). TLS 1.2 is the floor.',
          evidenceIds: evIds,
        })
      : makeCheck({
          group: GROUP, check: 'protocol', outcome: 'pass',
          title: `TLS protocol ${probe.protocol || 'unknown'}`,
          detail: 'The negotiated protocol is TLS 1.2 or newer.',
          evidenceIds: evIds,
        })
  );

  // Hostname match
  out.push(
    probe.hostnameMatch
      ? makeCheck({ group: GROUP, check: 'hostname', outcome: 'pass', title: 'Certificate matches the hostname', detail: 'tls.checkServerIdentity accepts the certificate for this hostname.', evidenceIds: evIds })
      : makeCheck({
          group: GROUP, check: 'hostname-mismatch', outcome: 'finding', severity: 'high',
          title: 'Certificate does not match the hostname',
          detail: probe.hostnameError || 'The certificate is not valid for this hostname.',
          evidenceIds: evIds,
        })
  );

  // Chain validity (kept separate from hostname: a mismatch already has its
  // own finding, so chain is inconclusive rather than double-counted).
  if (probe.authorized) {
    out.push(
      makeCheck({ group: GROUP, check: 'chain', outcome: 'pass', title: 'Certificate chain validates', detail: 'The chain builds to a trusted root.', evidenceIds: evIds })
    );
  } else if (!probe.hostnameMatch) {
    out.push(
      makeCheck({
        group: GROUP, check: 'chain', outcome: 'inconclusive',
        title: 'Chain validity not independently assessed',
        detail: 'Chain validation failed alongside the hostname mismatch; the mismatch finding carries the verdict.',
        evidenceIds: evIds,
      })
    );
  } else {
    out.push(
      makeCheck({
        group: GROUP, check: 'chain-invalid', outcome: 'finding', severity: 'high',
        title: 'Certificate chain does not validate',
        detail: `Chain validation failed: ${probe.authorizationError || 'unknown error'}${probe.cert && probe.cert.selfSigned ? ' (certificate is self-signed)' : ''}.`,
        evidenceIds: evIds,
      })
    );
  }

  // Expiry window
  if (!probe.cert || !probe.cert.validTo) {
    out.push(
      makeCheck({ group: GROUP, check: 'expiry', outcome: 'inconclusive', title: 'Certificate expiry could not be read', detail: 'The peer certificate carried no readable validity window.', evidenceIds: evIds })
    );
  } else {
    const validTo = new Date(probe.cert.validTo).getTime();
    const days = Math.floor((validTo - Date.now()) / 86400000);
    if (Number.isNaN(validTo)) {
      out.push(makeCheck({ group: GROUP, check: 'expiry', outcome: 'inconclusive', title: 'Certificate expiry unparseable', detail: `valid_to was "${probe.cert.validTo}".`, evidenceIds: evIds }));
    } else if (days < 0) {
      out.push(
        makeCheck({ group: GROUP, check: 'cert-expired', outcome: 'finding', severity: 'high', title: 'Certificate is expired', detail: `The certificate expired ${-days} day(s) ago (${probe.cert.validTo}).`, evidenceIds: evIds })
      );
    } else if (days < 14) {
      out.push(
        makeCheck({ group: GROUP, check: 'cert-expiring-14', outcome: 'finding', severity: 'medium', title: `Certificate expires in ${days} day(s)`, detail: `valid_to is ${probe.cert.validTo}; under 14 days leaves almost no renewal slack.`, evidenceIds: evIds })
      );
    } else if (days < 30) {
      out.push(
        makeCheck({ group: GROUP, check: 'cert-expiring-30', outcome: 'finding', severity: 'low', title: `Certificate expires in ${days} day(s)`, detail: `valid_to is ${probe.cert.validTo}.`, evidenceIds: evIds })
      );
    } else {
      out.push(
        makeCheck({ group: GROUP, check: 'expiry', outcome: 'pass', title: `Certificate valid for ${days} more day(s)`, detail: `valid_to is ${probe.cert.validTo}.`, evidenceIds: evIds })
      );
    }
  }

  return out;
}

// Re-exported for tests: the identity check Node performs for us.
export function checkIdentity(hostname, cert) {
  return tls.checkServerIdentity(hostname, cert);
}
