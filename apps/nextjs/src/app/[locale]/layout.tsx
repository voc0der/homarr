import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";

import "@homarr/notifications/styles.css";
import "@homarr/spotlight/styles.css";
import "@homarr/ui/styles.css";

import { Notifications } from "@homarr/notifications";
import {
  ColorSchemeScript,
  MantineProvider,
  uiConfiguration,
} from "@homarr/ui";

import { JotaiProvider } from "./_client-providers/jotai";
import { ModalsProvider } from "./_client-providers/modals";
import { NextInternationalProvider } from "./_client-providers/next-international";
import { TRPCReactProvider } from "./_client-providers/trpc";
import { composeWrappers } from "./compose";

const fontSans = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
});

export const metadata: Metadata = {
  metadataBase: new URL("http://localhost:3000"),
  title: "Create T3 Turbo",
  description: "Simple monorepo with shared backend for web & mobile apps",
  openGraph: {
    title: "Create T3 Turbo",
    description: "Simple monorepo with shared backend for web & mobile apps",
    url: "https://create-t3-turbo.vercel.app",
    siteName: "Create T3 Turbo",
  },
  twitter: {
    card: "summary_large_image",
    site: "@jullerino",
    creator: "@jullerino",
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
};

export default function Layout(props: {
  children: React.ReactNode;
  params: { locale: string };
}) {
  const colorScheme = "dark";

  const StackedProvider = composeWrappers([
    (innerProps) => <JotaiProvider {...innerProps} />,
    (innerProps) => <TRPCReactProvider {...innerProps} />,
    (innerProps) => (
      <NextInternationalProvider {...innerProps} locale={props.params.locale} />
    ),
    (innerProps) => (
      <MantineProvider
        {...innerProps}
        defaultColorScheme={colorScheme}
        {...uiConfiguration}
      />
    ),
    (innerProps) => <ModalsProvider {...innerProps} />,
  ]);

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <ColorSchemeScript defaultColorScheme={colorScheme} />
      </head>
      <body className={["font-sans", fontSans.variable].join(" ")}>
        <StackedProvider>
          <Notifications />
          {props.children}
        </StackedProvider>
      </body>
    </html>
  );
}