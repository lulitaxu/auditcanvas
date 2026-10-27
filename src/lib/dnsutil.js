// DNS helpers with the spec's error taxonomy (Scanner group 7, Email
// posture): NXDOMAIN, timeout, and SERVFAIL are Inconclusive; only a
// confirmed empty answer (the name exists, the record type does not) may
// be reported as "missing".
import { promises as dns } from 'node:dns';

export async function resolveTxt(hostname) {
  try {
    const records = await dns.resolveTxt(hostname);
    return { status: 'ok', records: records.map((chunks) => chunks.join('')) };
  } catch (err) {
    switch (err && err.code) {
      case 'ENODATA':
        return { status: 'empty' };
      case 'ENOTFOUND':
        return { status: 'nxdomain' };
      case 'ETIMEOUT':
      case 'ETIMEDOUT':
        return { status: 'timeout' };
      case 'ESERVFAIL':
        return { status: 'servfail' };
      default:
        return { status: 'error', code: (err && err.code) || 'unknown' };
    }
  }
}
