/** @type {import('next').NextConfig} */
const nextConfig = {
  // Reports and scan pages must never be indexed (spec: Data rules).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow' }],
      },
    ];
  },
};

export default nextConfig;
