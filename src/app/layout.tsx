import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentCanary — AI Agent Supply Chain Security",
  description: "Scan MCP servers and AI skills for security threats before you install them.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-gray-100 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
