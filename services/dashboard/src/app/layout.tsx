import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AegisBastion — Operator Dashboard",
  description:
    "AegisBastion Connector Hub operator surface (doc 10): attack-surface map, findings workflows, gated operations, RoE management.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
