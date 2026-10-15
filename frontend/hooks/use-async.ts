"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "@/lib/api";

export type LoadState = "idle" | "loading" | "ready" | "error";

export interface AsyncResult<T> {
  state: LoadState;
  data: T | null;
  error: string | null;
  reload: () => void;
  setData: (value: T | null) => void;
}

/**
 * Fetch-on-mount with cancellation and an explicit refresh handle.
 *
 * Errors are surfaced verbatim: the API already returns safe, user-facing
 * messages, so nothing is swallowed here.
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[],
  options: { enabled?: boolean } = {},
): AsyncResult<T> {
  const enabled = options.enabled ?? true;
  const [state, setState] = useState<LoadState>(enabled ? "loading" : "idle");
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const active = useRef(true);
  const loaderRef = useRef(loader);

  // Assign in an effect rather than during render: writing a ref while
  // rendering is a React anti-pattern (it mutates state a concurrent render
  // may never commit).
  useEffect(() => {
    loaderRef.current = loader;
  });

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  useEffect(() => {
    if (!enabled) {
      setState("idle");
      return;
    }
    setState("loading");
    setError(null);
    loaderRef
      .current()
      .then((value) => {
        if (!active.current) return;
        setData(value);
        setState("ready");
      })
      .catch((cause: unknown) => {
        if (!active.current) return;
        setError(cause instanceof ApiError ? cause.message : String(cause));
        setState("error");
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { state, data, error, reload, setData };
}

/** Track an in-flight mutation with progress and typed errors. */
export function useAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  /**
   * The last failure as an object, not just its message.
   *
   * A page that can only read `error` as a string cannot tell a rejected upload
   * from a corpus that is too small to learn from, and has to print whatever
   * English sentence the server sent. The API already distinguishes them by
   * `code` and carries the numbers in `details`; this is what makes that visible.
   */
  const [failure, setFailure] = useState<ApiError | null>(null);

  const run = useCallback(
    async <T,>(fn: () => Promise<T>, successMessage?: string): Promise<T | null> => {
      setPending(true);
      setError(null);
      setFailure(null);
      setNotice(null);
      try {
        const value = await fn();
        if (successMessage) setNotice(successMessage);
        return value;
      } catch (cause) {
        if (cause instanceof ApiError) {
          setError(cause.message);
          setFailure(cause);
        } else {
          setError(String(cause));
          setFailure(null);
        }
        return null;
      } finally {
        setPending(false);
      }
    },
    [],
  );

  const clear = useCallback(() => {
    setError(null);
    setFailure(null);
    setNotice(null);
  }, []);

  return { pending, error, notice, failure, run, clear, setError };
}

/** Poll a job until it reaches a terminal state. */
export function useJobPoller(jobId: string | null) {
  const [job, setJob] = useState<Record<string, unknown> | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (!jobId) {
      setJob(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const { api } = await import("@/lib/api");
        const value = await api.job(jobId);
        if (cancelled) return;
        setJob(value);
        if (["succeeded", "failed", "canceled"].includes(String(value.status))) {
          return;
        }
      } catch {
        /* a transient poll failure is not fatal; the next tick retries */
      }
      if (!cancelled) {
        timer.current = window.setTimeout(poll, 900);
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [jobId]);

  return job;
}