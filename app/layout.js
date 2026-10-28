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
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
