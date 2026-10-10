import type { Metadata, Viewport } from "next";

import Providers from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Madrigal Protocol Lab",
  description:
    "Local protocol reverse-engineering platform: turn raw PCAP recordings into " +
    "checkable binary-protocol specifications.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#0b0d10",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}