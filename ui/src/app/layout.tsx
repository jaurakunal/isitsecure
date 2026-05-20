import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "isitsecure",
  description: "AI-powered security scanner for modern web apps",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-bg text-text">
        <nav className="border-b border-border px-6 py-3 flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-text-accent">
            isitsecure
          </a>
          <div className="flex gap-4 text-sm text-text-muted">
            <a href="/" className="hover:text-text-accent transition-colors">
              New Scan
            </a>
            <a
              href="/history/"
              className="hover:text-text-accent transition-colors"
            >
              History
            </a>
          </div>
        </nav>
        <main className="flex-1">{children}</main>
      </body>
    </html>
  );
}
