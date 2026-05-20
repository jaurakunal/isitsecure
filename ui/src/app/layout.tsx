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
      <body className="min-h-full flex flex-col">
        <nav className="sticky top-0 z-50 border-b border-border backdrop-blur-xl bg-bg/80 px-6 py-3 flex items-center justify-between">
          <a href="/" className="text-lg font-semibold text-white tracking-tight">
            isitsecure
          </a>
          <div className="flex gap-5 text-sm">
            <a href="/" className="text-text-muted hover:text-white transition-colors">
              New Scan
            </a>
            <a href="/history/" className="text-text-muted hover:text-white transition-colors">
              History
            </a>
          </div>
        </nav>
        <main className="flex-1">{children}</main>
      </body>
    </html>
  );
}
