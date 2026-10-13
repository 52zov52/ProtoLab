"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Boxes,
  FileSearch,
  FileText,
  Fingerprint,
  FlaskConical,
  GitCompare,
  Globe2,
  LayoutDashboard,
  Network,
  ScanLine,
  Search,
  Settings,
  ShieldCheck,
  Sigma,
  Table2,
} from "lucide-react";

import { useWorkspace } from "@/hooks/use-workspace";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/format";

export interface NavEntry {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  description: string;
}

export const NAV: NavEntry[] = [
  { href: "/", label: "Overview", icon: LayoutDashboard, description: "Project metrics and health" },
  { href: "/captures", label: "Captures", icon: FileSearch, description: "Imported packet captures" },
  { href: "/packets", label: "Packets", icon: Table2, description: "Virtualised packet table" },
  { href: "/sessions", label: "TCP Sessions", icon: Network, description: "Conversations and reassembly" },
  { href: "/streams", label: "Stream Explorer", icon: ScanLine, description: "Bytes, hex and provenance" },
  { href: "/tls", label: "TLS Analysis", icon: Fingerprint, description: "JA3/JA3S fingerprints and client families" },
  { href: "/workbench", label: "Protocol Workbench", icon: FlaskConical, description: "Framing, comparison, fields" },
  { href: "/hypotheses", label: "Hypotheses & Rules", icon: Sigma, description: "Specs, validation, counterexamples" },
  { href: "/diff", label: "Capture Diff", icon: GitCompare, description: "Compare two recordings" },
  { href: "/graph", label: "Network Graph", icon: Globe2, description: "Observed interactions" },
  { href: "/anomalies", label: "Anomaly Detection", icon: Activity, description: "Baseline outlier scoring" },
  { href: "/assistant", label: "Investigation Assistant", icon: Search, description: "Typed natural-language search" },
  { href: "/reports", label: "Reports", icon: FileText, description: "Evidence-linked investigation report" },
  { href: "/security", label: "Security Center", icon: ShieldCheck, description: "Real configuration checks" },
  { href: "/settings", label: "Project Settings", icon: Settings, description: "Project options and AI consent" },
];

export function Sidebar() {
  const pathname = usePathname();
  const { projectId, projectName } = useWorkspace();
  const { t } = useI18n();

  return (
    <nav
      aria-label="Primary"
      className="flex h-full w-56 shrink-0 flex-col border-r border-line bg-surface"
    >
      <div className="border-b border-line px-3 py-3">
        <div className="flex items-center gap-2">
          <Boxes className="h-4 w-4 text-accent" aria-hidden />
          <div className="leading-tight">
            <p className="text-xs font-semibold tracking-wide text-text">Madrigal</p>
            <p className="text-2xs uppercase tracking-[0.2em] text-text-faint">
              Protocol Lab
            </p>
          </div>
        </div>
      </div>

      <div className="border-b border-line px-3 py-2">
        <p className="text-2xs uppercase tracking-wider text-text-faint">{t("Project")}</p>
        <p
          className={cn(
            "mt-0.5 truncate font-mono text-2xs",
            projectName ? "text-accent" : "text-text-faint",
          )}
          title={projectName ?? t("No project selected")}
        >
          {projectName ?? t("none selected")}
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-1.5">
        {NAV.map((entry) => {
          const Icon = entry.icon;
          const active =
            entry.href === "/"
              ? pathname === "/"
              : pathname.startsWith(entry.href);
          return (
            <Link
              key={entry.href}
              href={projectId ? `${entry.href}?project=${projectId}` : entry.href}
              className={cn("nav-item", active && "nav-item-active")}
              title={t(entry.description)}
              aria-current={active ? "page" : undefined}
            >
              <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
              <span className="truncate">{t(entry.label)}</span>
            </Link>
          );
        })}
      </div>

      <div className="border-t border-line px-3 py-2">
        <p className="text-2xs leading-relaxed text-text-faint">
          {t("Local secure mode. Every conclusion links to the bytes it came from.")}
        </p>
      </div>
    </nav>
  );
}