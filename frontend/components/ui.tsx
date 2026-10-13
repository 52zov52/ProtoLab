"use client";

import { useEffect, useState, type ReactNode } from "react";

import { cn, toneClasses, type StatusTone } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

// --------------------------------------------------------------------------
// Primitives shared by every tool panel.
// --------------------------------------------------------------------------

export function Panel({
  title,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel flex min-h-0 flex-col", className)}>
      {(title || actions) && (
        <header className="panel-header shrink-0">
          <h2 className="panel-title">{title}</h2>
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={cn("min-h-0 flex-1 overflow-auto", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Badge({
  tone = "neutral",
  children,
  title,
}: {
  tone?: StatusTone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={cn("tag", toneClasses(tone))} title={title}>
      {children}
    </span>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex h-full min-h-[160px] flex-col items-center justify-center gap-2 p-6 text-center">
      <p className="text-sm font-medium text-text">{title}</p>
      {description && <p className="max-w-md text-xs text-text-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const { t } = useI18n();
  return (
    <div
      className="m-3 rounded-sm border border-status-bad/40 bg-status-bad/5 p-3"
      role="alert"
    >
      <p className="text-2xs font-semibold uppercase tracking-wider text-status-bad">
        {t("Request failed")}
      </p>
      <p className="mt-1 font-mono text-2xs text-text">{message}</p>
      {onRetry && (
        <button type="button" className="btn mt-2" onClick={onRetry}>
          {t("Retry")}
        </button>
      )}
    </div>
  );
}

export function Loading({ label }: { label?: string }) {
  const { t } = useI18n();
  return (
    <div className="flex h-full min-h-[120px] items-center justify-center gap-2 p-4">
      <span className="h-3 w-3 animate-spin rounded-full border border-line-strong border-t-accent" />
      <span className="text-2xs uppercase tracking-widest text-text-faint">
        {label ?? t("Loading")}
      </span>
    </div>
  );
}

export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-1.5 p-3" aria-hidden>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          className="h-3 animate-pulse rounded-sm bg-surface-raised"
          style={{ width: `${95 - (index % 4) * 12}%` }}
        />
      ))}
    </div>
  );
}

/**
 * A claim that needs a caveat always gets one rendered next to it.
 * This is the product's core promise: no conclusion without its limits.
 */
export function Caveat({ children, tone = "neutral" }: { children: ReactNode; tone?: StatusTone }) {
  return (
    <p
      className={cn(
        "border-l-2 py-1 pl-2 text-2xs leading-relaxed text-text-muted",
        tone === "warn" && "border-status-warn text-status-warn",
        tone === "bad" && "border-status-bad text-status-bad",
        tone === "info" && "border-status-info text-status-info",
      )}
    >
      {children}
    </p>
  );
}

export function Metric({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: StatusTone;
}) {
  return (
    <div className="rounded-sm border border-line bg-surface-raised px-2.5 py-2">
      <p className="text-2xs uppercase tracking-wider text-text-faint">{label}</p>
      <p
        className={cn(
          "mt-0.5 font-mono text-base leading-tight",
          tone === "ok" && "text-status-ok",
          tone === "warn" && "text-status-warn",
          tone === "bad" && "text-status-bad",
          !tone && "text-text",
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-0.5 text-2xs text-text-faint">{hint}</p>}
    </div>
  );
}

/**
 * A two-step control for destructive actions.
 *
 * The first click arms the button and swaps the label to `confirmLabel`;
 * only a second click calls `onConfirm`. Clicking elsewhere, or waiting,
 * disarms it. A single-click destructive button is a mis-click waiting to
 * delete an investigation, so the confirmation is not optional.
 */
export function ConfirmButton({
  label,
  confirmLabel,
  onConfirm,
  tone = "btn-danger",
  disabled,
}: {
  label: string;
  confirmLabel: string;
  onConfirm: () => void;
  tone?: string;
  disabled?: boolean;
}) {
  const { t } = useI18n();
  const [armed, setArmed] = useState(false);

  // Disarm on the next tick unless the user confirms, so the button cannot
  // stay armed after the pointer leaves it.
  useEffect(() => {
    if (!armed) return;
    const timer = window.setTimeout(() => setArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [armed]);

  if (armed) {
    return (
      <span className="inline-flex items-center gap-1">
        <button
          type="button"
          className={cn("btn", tone)}
          onClick={() => {
            setArmed(false);
            onConfirm();
          }}
        >
          {confirmLabel}
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => setArmed(false)}
          title={t("Cancel")}
        >
          {t("Cancel")}
        </button>
      </span>
    );
  }

  return (
    <button
      type="button"
      className={cn("btn", tone)}
      disabled={disabled || undefined}
      onClick={() => setArmed(true)}
    >
      {label}
    </button>
  );
}