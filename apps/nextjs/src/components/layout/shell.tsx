"use client";

import type { PropsWithChildren } from "react";
import { useAtomValue } from "jotai";

import { AppShell } from "@homarr/ui";

import { navigationCollapsedAtom } from "./header/burger";

interface ClientShellProps {
  hasHeader?: boolean;
  hasNavigation?: boolean;
}

export const ClientShell = ({
  hasHeader = true,
  hasNavigation = true,
  children,
}: PropsWithChildren<ClientShellProps>) => {
  const collapsed = useAtomValue(navigationCollapsedAtom);

  return (
    <AppShell
      header={hasHeader ? { height: 60 } : undefined}
      navbar={
        hasNavigation
          ? {
              width: 300,
              breakpoint: "sm",
              collapsed: { mobile: collapsed },
            }
          : undefined
      }
      padding="md"
    >
      {children}
    </AppShell>
  );
};