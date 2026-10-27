import './globals.css';

export const metadata = {
  title: 'AuditCanvas — See the auditor reason, not just scan',
  description:
    'AuditCanvas scans a website for real, then a reasoning auditor turns the stored evidence into verified, prioritized, understandable remediation. The scanner decides what exists; the model decides what it means.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
