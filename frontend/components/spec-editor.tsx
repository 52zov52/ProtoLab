"use client";

import dynamic from "next/dynamic";
import { Component, useEffect, useState, type ReactNode } from "react";

/**
 * JSON editor for interpretation specifications (Этап 6, §4).
 *
 * Monaco is a progressive enhancement over a real control, not a replacement
 * that can disappear:
 *
 *  - it is loaded on demand, so only the tool that edits a rule pays for it;
 *  - it is configured through `loader.config` to use the **bundled** editor
 *    instead of the CDN default — a remote script would violate the
 *    offline-first CSP;
 *  - the textarea stays in charge until Monaco has actually mounted, and comes
 *    back if mounting fails, so an environment without a working layout engine
 *    still gets an editor rather than a broken one.
 */
const MonacoEditor = dynamic(
  () => import("@monaco-editor/react").then((module) => module.default),
  { ssr: false },
);

/** A Monaco crash must not take the tool down with it. */
class EditorBoundary extends Component<
  { children: ReactNode; fallback: () => ReactNode; onError: () => void },
  { failed: boolean }
> {
  state = { failed: false };

  componentDidCatch() {
    this.props.onError();
  }

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  render() {
    return this.state.failed ? this.props.fallback() : this.props.children;
  }
}

export function SpecEditor({
  value,
  onChange,
  ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  ariaLabel: string;
}) {
  const [monacoAvailable, setMonacoAvailable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [{ loader }, monaco] = await Promise.all([
          import("@monaco-editor/react"),
          import("monaco-editor"),
        ]);
        loader.config({ monaco });
        if (!cancelled) setMonacoAvailable(true);
      } catch {
        // The textarea stays in charge; nothing about editing is lost.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const textarea = () => (
    <textarea
      className="min-h-[420px] w-full flex-1 resize-none border-0 bg-surface-sunken p-3 font-mono text-2xs text-text outline-none"
      value={value}
      spellCheck={false}
      onChange={(event) => onChange(event.target.value)}
      aria-label={ariaLabel}
    />
  );

  if (!monacoAvailable) return textarea();

  return (
    <div className="h-full min-h-[420px]" role="group" aria-label={ariaLabel}>
      <EditorBoundary fallback={textarea} onError={() => setMonacoAvailable(false)}>
        <MonacoEditor
          height="100%"
          defaultLanguage="json"
          value={value}
          onChange={(next) => onChange(next ?? "")}
          theme="vs-dark"
          options={{
            minimap: { enabled: false },
            fontSize: 11,
            scrollBeyondLastLine: false,
            wordWrap: "on",
          }}
        />
      </EditorBoundary>
    </div>
  );
}
