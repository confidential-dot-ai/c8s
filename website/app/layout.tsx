import type { Metadata } from "next";
import Script from "next/script";
import { Source_Serif_4 } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";

// Resolve theme before paint: localStorage wins, else system, else dark.
const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem('theme');if(t!=='light'&&t!=='dark'){t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';}document.documentElement.dataset.theme=t;}catch(e){document.documentElement.dataset.theme='dark';}})();`;

const sourceSerif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "Confidential AI",
    template: "Confidential AI ･ %s",
  },
  description: "The confidential computing stack for AI. Run AI inference, agents, & training in hardware-encrypted Trusted Execution Environments (TEEs).",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <Script
          src="https://plausible.io/js/pa-fe_AMrp4xlNmw8myKYHux.js"
          strategy="afterInteractive"
        />
        <Script id="plausible-init" strategy="afterInteractive">
          {`window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()`}
        </Script>
      </head>
      <body className={`${sourceSerif.variable} ${sourceSerif.className} antialiased`}>
        <Sidebar />
        <div className="md:pl-64 min-h-screen">
          <main className="px-5 md:px-10 py-12">
            <div className="max-w-[680px]">{children}</div>
          </main>
        </div>
      </body>
    </html>
  );
}
