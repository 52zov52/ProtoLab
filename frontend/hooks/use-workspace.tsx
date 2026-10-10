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

import { api, ApiError } from "@/lib/api";

interface WorkspaceState {
  projectId: string | null;
  projectName: string | null;
  captureId: string | null;
  sessionId: string | null;
  streamId: string | null;
  messageId: string | null;
  backendOnline: boolean;
  backendError: string | null;
  selectProject: (id: string, name: string) => void;
  selectCapture: (id: string | null) => void;
  selectSession: (id: string | null) => void;
  selectStream: (id: string | null) => void;
  selectMessage: (id: string | null) => void;
  refreshHealth: () => Promise<void>;
  /** Bumped whenever a mutation invalidates the current view. */
  revision: number;
  invalidate: () => void;
}

const WorkspaceContext = createContext<WorkspaceState | null>(null);

const STORAGE_KEY = "mplab.workspace";

interface Persisted {
  projectId: string | null;
  projectName: string | null;
}

function loadPersisted(): Persisted {
  if (typeof window === "undefined") {
    return { projectId: null, projectName: null };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { projectId: null, projectName: null };
    const parsed = JSON.parse(raw) as Partial<Persisted>;
    if (typeof parsed.projectId !== "string" || !/^[A-Za-z0-9]{1,64}$/.test(parsed.projectId)) {
      return { projectId: null, projectName: null };
    }
    return {
      projectId: parsed.projectId,
      projectName: typeof parsed.projectName === "string" ? parsed.projectName : null,
    };
  } catch {
    return { projectId: null, projectName: null };
  }
}

type WorkspaceSlice = Pick<
  WorkspaceState,
  | "projectId"
  | "projectName"
  | "captureId"
  | "sessionId"
  | "streamId"
  | "messageId"
  | "backendOnline"
  | "backendError"
  | "revision"
>;

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<WorkspaceSlice>(() => {
    const persisted = loadPersisted();
    return {
      ...persisted,
      captureId: null,
      sessionId: null,
      streamId: null,
      messageId: null,
      backendOnline: false,
      backendError: null,
      revision: 0,
    };
  });

  useEffect(() => {
    if (!state.projectId) return;
    try {
      window.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ projectId: state.projectId, projectName: state.projectName }),
      );
    } catch {
      /* storage unavailable; the app still works, the selection is just not sticky */
    }
  }, [state.projectId, state.projectName]);

  const refreshHealth = useCallback(async () => {
    try {
      await api.health();
      setState((s) => ({ ...s, backendOnline: true, backendError: null }));
    } catch (error) {
      setState((s) => ({
        ...s,
        backendOnline: false,
        backendError:
          error instanceof ApiError ? error.message : "Backend unreachable.",
      }));
    }
  }, []);

  useEffect(() => {
    void refreshHealth();
    const timer = window.setInterval(() => void refreshHealth(), 15000);
    return () => window.clearInterval(timer);
  }, [refreshHealth]);

  const value = useMemo<WorkspaceState>(
    () => ({
      ...state,
      selectProject: (id, name) =>
        setState((s) => ({
          ...s,
          projectId: id,
          projectName: name,
          captureId: null,
          sessionId: null,
          streamId: null,
          messageId: null,
        })),
      selectCapture: (id) =>
        setState((s) => ({ ...s, captureId: id, sessionId: null, streamId: null, messageId: null })),
      selectSession: (id) =>
        setState((s) => ({ ...s, sessionId: id, streamId: null, messageId: null })),
      selectStream: (id) => setState((s) => ({ ...s, streamId: id, messageId: null })),
      selectMessage: (id) => setState((s) => ({ ...s, messageId: id })),
      refreshHealth,
      invalidate: () => setState((s) => ({ ...s, revision: s.revision + 1 })),
    }),
    [state, refreshHealth],
  );

  return (
    <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
  );
}

export function useWorkspace(): WorkspaceState {
  const context = useContext(WorkspaceContext);
  if (!context) {
    throw new Error("useWorkspace must be used inside a WorkspaceProvider");
  }
  return context;
}

/** Convenience: the selected project id, or null. */
export function useProjectId(): string | null {
  return useWorkspace().projectId;
}