// Minimal version + range handling for the Client stack / CVE group.
// Versions are matched against affected RANGES from the snapshot, never
// against "latest": a version is only a finding when it falls inside a
// CVE's affected range.

// '3.4.1' -> [3,4,1]; '1.8.3-rc.1' -> [1,8,3]. Non-numeric suffixes are
// ignored for comparison.
export function parseVersion(v) {
  if (typeof v !== 'string') return null;
  const m = v.trim().match(/^v?(\d+(?:\.\d+){0,3})/);
  if (!m) return null;
  const parts = m[1].split('.').map((n) => Number(n));
  while (parts.length < 3) parts.push(0);
  return parts;
}

export function compareVersions(a, b) {
  const pa = Array.isArray(a) ? a : parseVersion(a);
  const pb = Array.isArray(b) ? b : parseVersion(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

// Range syntax: space-separated comparators are ANDed, '||' separates
// alternatives (OR). Comparators: <, <=, >, >=, = (a bare version means =).
// Examples: '<3.5.0', '>=3.0.0 <3.4.1 || >=4.0.0 <4.3.1'
export function satisfiesRange(version, range) {
  const pv = parseVersion(version);
  if (!pv || typeof range !== 'string') return false;
  return range.split('||').some((alt) =>
    alt
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .every((token) => {
        const m = token.match(/^(<=|>=|<|>|=)?\s*(.+)$/);
        if (!m) return false;
        const op = m[1] || '=';
        const cmp = compareVersions(pv, m[2]);
        if (cmp === null) return false;
        switch (op) {
          case '<': return cmp < 0;
          case '<=': return cmp <= 0;
          case '>': return cmp > 0;
          case '>=': return cmp >= 0;
          case '=': return cmp === 0;
          default: return false;
        }
      })
  );
}
