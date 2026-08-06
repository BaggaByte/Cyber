import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelAI — Autonomous Cybersecurity Platform",
  description: "AI-powered attack surface mapping, vulnerability scanning, and autonomous threat response.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{
          __html: `
            (function() {
              try {
                const theme = localStorage.getItem('theme') || 'system';
                const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
                if (isDark) {
                  document.documentElement.classList.add('dark');
                  document.documentElement.setAttribute('data-theme', 'dark');
                } else {
                  document.documentElement.classList.remove('dark');
                  document.documentElement.setAttribute('data-theme', 'light');
                }
                document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
              } catch (e) {}
            })();
          `
        }} />
      </head>
      <body className="antialiased min-h-screen relative">{children}</body>
    </html>
  );
}
