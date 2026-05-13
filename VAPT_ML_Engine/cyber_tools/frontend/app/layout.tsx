import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'VAPT Command Center',
  description: 'Local-first penetration testing intelligence platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
