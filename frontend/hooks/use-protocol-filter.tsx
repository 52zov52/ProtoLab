"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";

/**
 * Per-project protocol visibility.
 *
 * Detected protocol labels (`http1`, `tls`, `unknown_binary`, …) are not
 * entities that can be deleted — they are conclusions drawn from the bytes.
 * What an analyst can do is decide which of them to *show*. That choice is the
 * only thing stored here: a list of labels hidden from the graph and the stream
 * lists, persisted in the project's `settings.hidden_protocols`.
 *
 * Hiding a label removes it from view; it never changes the analysis, and the
 * underlying data always remains reachable by showing it again.
 */
interface ProtocolFilterState {
  /** Labels currently hidden. */
  hidden: Set<string>;
  isHidden: (label: string) => boolean;
  toggle: (label: string) => void;
  showAll: () => void;
  /** Whether the stored preference has been loaded for the active project. */
  ready: boolean;
}

const ProtocolFilterContext = createContext<ProtocolFilterState>({
  hidden: new Set(),
  isHidden: () => false,
  toggle: () => {},
  showAll: () => {},
  ready: false,
});

function parseHidden(settings: unknown): string[] {
  const value = (settings as Record<string, unknown> | null | undefined)?.hidden_protocols;
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
}

export function ProtocolFilterProvider({ children }: { children: ReactNode }) {
  const workspace = useWorkspace();
  const projectId = workspace.projectId;
  const [hidden, setHidden] = useState<string[]>([]);
  const [ready, setReady] = useState(false);

  // Load the stored preference whenever the project changes (or is invalidated
  // by a Settings edit).
  useEffect(() => {
    let cancelled = false;
    if (!projectId) {
      setHidden([]);
      setReady(false);
      return;
    }
    setReady(false);
    api
      .getProject(projectId)
      .then((project) => {
        if (cancelled) return;
        setHidden(parseHidden(project.settings));
        setReady(true);
      })
      .catch(() => {
        if (cancelled) return;
        setHidden([]);
        setReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, workspace.revision]);

  const persist = useCallback(
    (next: string[]) => {
      setHidden(next);
      if (!projectId) return;
      void api
        .updateProject(projectId, { settings: { hidden_protocols: next } })
        .catch(() => {
          /* Best effort: a failed save leaves the in-memory choice active. */
        });
    },
    [projectId],
  );

  const value = useMemo<ProtocolFilterState>(() => {
    const current = new Set(hidden);
    return {
      hidden: current,
      isHidden: (label: string) => current.has(label),
      toggle: (label: string) =>
        persist(
          current.has(label)
            ? hidden.filter((item) => item !== label)
            : [...hidden, label],
        ),
      showAll: () => persist([]),
      ready,
    };
  }, [hidden, persist, ready]);

  return (
    <ProtocolFilterContext.Provider value={value}>
      {children}
    </ProtocolFilterContext.Provider>
  );
}

export function useProtocolFilter(): ProtocolFilterState {
  return useContext(ProtocolFilterContext);
}
