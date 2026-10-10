"use client";

import { Suspense } from "react";

import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/topbar";
import { WorkspaceProvider } from "@/hooks/use-workspace";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="min-h-0 flex-1 overflow-hidden">{children}</main>
      </div>
    </div>
  );
}

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <WorkspaceProvider>
      <Suspense fallback={<div className="p-4 text-2xs text-text-faint">Loading…</div>}>
        <Shell>{children}</Shell>
      </Suspense>
    </WorkspaceProvider>
  );
}