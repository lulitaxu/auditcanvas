// Admin surface metadata (admin design §16): the global layout
// already sets robots noindex/nofollow for the whole app; admin
// pages restate it so the operator surface stays unindexed even if
// the public posture ever changes. This layout is NOT an auth
// boundary — every admin page validates the session server-side
// itself, on every render.
export const metadata = {
  title: 'AuditCanvas Admin',
  robots: { index: false, follow: false, nocache: true },
};

export const dynamic = 'force-dynamic';

export default function AdminLayout({ children }) {
  return children;
}
