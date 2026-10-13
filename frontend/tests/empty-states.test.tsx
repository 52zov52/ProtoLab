/**
 * Empty states across the tool surface (§23).
 *
 * Every tool that needs a selection must say which selection it needs. A blank
 * panel reads as "no data", which is a different (and wrong) statement: these
 * render each page with nothing selected and assert the tool names what is
 * missing and, where one exists, links to the tool that provides it.
 *
 * The per-page behaviour that is more than an empty state is asserted in the
 * page tests for that tool (`captures`, `packets`, `sessions`, `streams`,
 * `reports`, `overview`).
 */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import AnomaliesPage from "@/app/anomalies/page";
import AssistantPage from "@/app/assistant/page";
import DiffPage from "@/app/diff/page";
import GraphPage from "@/app/graph/page";
import SecurityPage from "@/app/security/page";
import SettingsPage from "@/app/settings/page";
import TlsPage from "@/app/tls/page";
import WorkbenchPage from "@/app/workbench/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { api } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      getProject: vi.fn(),
      integrity: vi.fn(),
      updateProject: vi.fn(),
      projectCaptures: vi.fn(),
      anomaliesStatus: vi.fn(),
      assistantCapabilities: vi.fn(),
      securityReport: vi.fn(),
      securityCheck: vi.fn(),
      auditEvents: vi.fn(),
      verifyAudit: vi.fn(),
    },
  };
});

function renderPage(element: React.ReactElement) {
  (api.projectCaptures as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  (api.anomaliesStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ available: false });
  (api.assistantCapabilities as ReturnType<typeof vi.fn>).mockResolvedValue({
    external_ai: { enabled: false },
  });
  (api.securityReport as ReturnType<typeof vi.fn>).mockResolvedValue({
    checks: [],
    summary: {},
  });
  (api.auditEvents as ReturnType<typeof vi.fn>).mockResolvedValue({ items: [] });
  (api.verifyAudit as ReturnType<typeof vi.fn>).mockResolvedValue({ valid: true });
  return render(<WorkspaceProvider>{element}</WorkspaceProvider>);
}

describe("empty states", () => {
  it("Packet and protocol tools name the capture they need", () => {
    renderPage(<TlsPage />);
    expect(screen.getByText("No capture selected")).toBeInTheDocument();
  });

  it("the protocol workbench names the capture it needs", () => {
    renderPage(<WorkbenchPage />);
    expect(screen.getByText("No capture selected")).toBeInTheDocument();
  });

  it("project-scoped tools name the project they need", () => {
    renderPage(
      <>
        <DiffPage />
      </>,
    );
    expect(screen.getAllByText("No project selected").length).toBeGreaterThan(0);
  });

  it("the graph names the project it needs, rather than an empty canvas", () => {
    renderPage(<GraphPage />);
    expect(screen.getByText("No project selected")).toBeInTheDocument();
  });

  it("anomaly detection names the project it needs", () => {
    renderPage(<AnomaliesPage />);
    expect(screen.getByText("No project selected")).toBeInTheDocument();
  });

  it("project settings names the project it needs and links back", () => {
    renderPage(<SettingsPage />);
    expect(screen.getByText("No project selected")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Overview" })).toBeInTheDocument();
  });

  it("the assistant is usable without a result, not blank", () => {
    renderPage(<AssistantPage />);
    expect(screen.getByText("No result yet")).toBeInTheDocument();
  });

  it("the security centre reports 'no checks' instead of a green pass", async () => {
    renderPage(<SecurityPage />);
    expect(await screen.findByText("No checks available")).toBeInTheDocument();
  });
});
