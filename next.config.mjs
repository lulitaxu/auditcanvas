/** @type {import('next').NextConfig} */

// Admin surface headers (admin design §16.1): no-store, a strict CSP
// with frame-ancestors 'none', DENY framing, nosniff, no-referrer,
// noindex/noarchive, and HSTS. Applied to /admin pages and
// /api/admin/* APIs; route handlers additionally pin Cache-Control
// on their own responses so no-store does not depend solely on this
// config matching.
const ADMIN_HEADERS = [
  { key: 'Cache-Control', value: 'no-store, max-age=0' },
  {
    key: 'Content-Security-Policy',
    value:
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Robots-Tag', value: 'noindex, nofollow, noarchive' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
];

const nextConfig = {
  // Reports and scan pages must never be indexed (spec: Data rules).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow' }],
      },
      { source: '/admin/:path*', headers: ADMIN_HEADERS },
      { source: '/api/admin/:path*', headers: ADMIN_HEADERS },
    ];
  },
};

export default nextConfig;
