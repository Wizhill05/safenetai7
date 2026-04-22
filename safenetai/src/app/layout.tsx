import "~/styles/globals.css";

import { type Metadata } from "next";
import { Orbitron, Space_Grotesk } from "next/font/google";

import { TRPCReactProvider } from "~/trpc/react";

export const metadata: Metadata = {
  title: "SafeNet AI",
  description: "Scam detection platform powered by the T3 Stack",
  icons: [{ rel: "icon", url: "/favicon.ico" }],
};

const bodyFont = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-body",
});

const headingFont = Orbitron({
  subsets: ["latin"],
  variable: "--font-heading",
});

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${bodyFont.variable} ${headingFont.variable} dark`}>
      <body>
        <TRPCReactProvider>{children}</TRPCReactProvider>
      </body>
    </html>
  );
}
