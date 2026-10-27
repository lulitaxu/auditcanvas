// IP address classification for the SSRF-safe fetch layer.
//
// The rule from SPEC.md: resolve the hostname, validate EVERY returned
// A/AAAA address, and reject the whole set if any address is private,
// loopback, link-local, multicast, reserved, or an IPv4-mapped/compatible
// IPv6 form of one of those.
import net from 'node:net';

// Returns null when the IPv4 address is public, otherwise a reason string.
export function ipv4BlockReason(ip) {
  const parts = String(ip).split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return 'malformed';
  const [a, b, c] = parts;
  if (a === 0) return 'reserved (0.0.0.0/8)';
  if (a === 10) return 'private (10.0.0.0/8)';
  if (a === 100 && b >= 64 && b <= 127) return 'private (100.64.0.0/10 shared address space)';
  if (a === 127) return 'loopback (127.0.0.0/8)';
  if (a === 169 && b === 254) return 'link-local (169.254.0.0/16)';
  if (a === 172 && b >= 16 && b <= 31) return 'private (172.16.0.0/12)';
  if (a === 192 && b === 0 && c === 0) return 'reserved (192.0.0.0/24)';
  if (a === 192 && b === 0 && c === 2) return 'reserved (192.0.2.0/24 documentation)';
  if (a === 192 && b === 31 && c === 196) return 'reserved (192.31.196.0/24)';
  if (a === 192 && b === 52 && c === 193) return 'reserved (192.52.193.0/24)';
  if (a === 192 && b === 88 && c === 99) return 'reserved (192.88.99.0/24)';
  if (a === 192 && b === 168) return 'private (192.168.0.0/16)';
  if (a === 198 && (b === 18 || b === 19)) return 'reserved (198.18.0.0/15 benchmarking)';
  if (a === 198 && b === 51 && c === 100) return 'reserved (198.51.100.0/24 documentation)';
  if (a === 203 && b === 0 && c === 113) return 'reserved (203.0.113.0/24 documentation)';
  if (a >= 224 && a <= 239) return 'multicast (224.0.0.0/4)';
  if (a >= 240) return 'reserved (240.0.0.0/4)';
  return null;
}

// Expand an IPv6 address to 8 numeric groups, or null when malformed.
// Handles '::' compression and an embedded trailing IPv4 address (which is
// first rewritten textually into its two hex groups).
export function parseIPv6(ip) {
  let s = String(ip).toLowerCase().trim();
  if (s.includes('.')) {
    const idx = s.lastIndexOf(':');
    if (idx === -1) return null;
    const parts = s.slice(idx + 1).split('.').map((p) => Number(p));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const hi = ((parts[0] << 8) | parts[1]).toString(16);
    const lo = ((parts[2] << 8) | parts[3]).toString(16);
    s = s.slice(0, idx + 1) + hi + ':' + lo;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseSide = (side) =>
    side === '' ? [] : side.split(':').map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  const left = parseSide(halves[0]);
  if (halves.length === 1) {
    if (left.length !== 8 || left.some(Number.isNaN)) return null;
    return left;
  }
  const right = parseSide(halves[1]);
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null; // '::' must compress at least one group
  const groups = [...left, ...Array(missing).fill(0), ...right];
  if (groups.length !== 8 || groups.some(Number.isNaN)) return null;
  return groups;
}

// Returns null when the IPv6 address is public, otherwise a reason string.
export function ipv6BlockReason(ip) {
  const g = parseIPv6(ip);
  if (!g) return 'malformed';
  const isAllZero = g.every((n) => n === 0);
  if (isAllZero) return 'reserved (:: unspecified)';
  const isLoopback = g.slice(0, 7).every((n) => n === 0) && g[7] === 1;
  if (isLoopback) return 'loopback (::1)';
  // IPv4-mapped ::ffff:a.b.c.d — rejected outright (SPEC: reject the set if
  // any address is an IPv4-mapped form; it is never a public target form we
  // are willing to connect to).
  const isMapped = g.slice(0, 5).every((n) => n === 0) && g[5] === 0xffff;
  if (isMapped) return 'ipv4-mapped-ipv6 (::ffff:0:0/96)';
  // IPv4-compatible / NAT64 well-known prefix: validate the embedded IPv4.
  const isCompat = g.slice(0, 6).every((n) => n === 0) && !isAllZero && !isLoopback;
  const isNat64 = g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((n) => n === 0);
  if (isCompat || isNat64) {
    const embedded = `${(g[6] >> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >> 8) & 0xff}.${g[7] & 0xff}`;
    const inner = ipv4BlockReason(embedded);
    if (inner) return `ipv4-embedded-ipv6 (${embedded}: ${inner})`;
    return 'ipv4-embedded-ipv6 (deprecated/translated form)';
  }
  if (g[0] >= 0xfe80 && g[0] <= 0xfebf) return 'link-local (fe80::/10)';
  if ((g[0] & 0xfe00) === 0xfc00) return 'private (fc00::/7 unique local)';
  if ((g[0] & 0xff00) === 0xff00) return 'multicast (ff00::/8)';
  if (g[0] === 0x2001 && g[1] === 0x0db8) return 'reserved (2001:db8::/32 documentation)';
  if (g[0] === 0x2001 && g[1] === 0x0000) return 'reserved (2001::/32 Teredo)';
  if (g[0] === 0x2001 && g[1] === 0x0002) return 'reserved (2001:2::/48 benchmarking)';
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return 'reserved (100::/64 discard)';
  if (g[0] === 0x2001 && g[1] === 0x0010) return 'reserved (2001:10::/28 ORCHID)';
  if (g[0] === 0x2001 && g[1] === 0x0020) return 'reserved (2001:20::/28 ORCHIDv2)';
  return null;
}

export function addressBlockReason(address) {
  if (net.isIPv4(address)) return ipv4BlockReason(address);
  if (net.isIPv6(address)) return ipv6BlockReason(address);
  return 'malformed';
}

// Validate a full resolved address set. One bad address poisons the set:
// that is what kills DNS-rebinding style answers that mix a public address
// with a private one.
export function validateAddressSet(addresses) {
  if (!Array.isArray(addresses) || addresses.length === 0) {
    return { ok: false, reason: 'no addresses resolved' };
  }
  for (const entry of addresses) {
    // Accept both plain address strings and dns.lookup-style {address}
    // records; one bad address poisons the set either way.
    const address = typeof entry === 'string' ? entry : entry && entry.address;
    const reason = addressBlockReason(address);
    if (reason) return { ok: false, reason: `${address} is ${reason}`, address };
  }
  return { ok: true };
}
