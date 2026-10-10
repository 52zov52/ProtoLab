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

/** Identifiers come from the URL, so they are validated before use. */
const ID_PATTERN = /^[A-Za-z0-9]{1,64}$/;

function validId(value: string | null): string | null {
  return value && ID_PATTERN.test(value) ? value : null;
}

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

  // Deep links: honour ?project=, ?capture=, ?session=, ?stream= on first
  // mount so a link from a report or a seeded script opens the right view.
  // Without this, every page independently re-reads the same query parameters
  // and the workspace never agrees with the URL.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const project = validId(params.get("project"));
    const capture = validId(params.get("capture"));
    const session = validId(params.get("session"));
    const stream = validId(params.get("stream"));
    if (!project && !capture && !session && !stream) return;
    setState((s) => ({
      ...s,
      projectId: project ?? s.projectId,
      projectName: project ? null : s.projectName,
      captureId: capture ?? (project ? null : s.captureId),
      sessionId: session ?? (project ? null : s.sessionId),
      streamId: stream ?? (project ? null : s.streamId),
    }));
    // Once on mount only; later navigation is driven by explicit selections.
  }, []);

  // A ?session= link carries no capture, but the stream tools need one to
  // fetch messages. Resolve it from the session rather than showing an error
  // the analyst cannot act on.
  useEffect(() => {
    const session = validId(new URLSearchParams(window.location.search).get("session"));
    if (!session) return;
    let cancelled = false;
    void (async () => {
      try {
        const { api } = await import("@/lib/api");
        const row = await api.getSession(session);
        if (cancelled) return;
        setState((s) => ({
          ...s,
          captureId: s.captureId ?? row.capture_id,
          sessionId: s.sessionId ?? row.id,
        }));
      } catch {
        // The page it links to reports the failure with the session id, which
        // is more useful than a silent no-op here.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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