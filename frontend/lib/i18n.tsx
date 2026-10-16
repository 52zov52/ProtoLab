"use client";

import { useSearchParams } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { setActiveLocale, type Locale } from "@/lib/format";
import { RU_MESSAGES } from "@/lib/i18n/ru";

export type { Locale };

/** Where the chosen language is remembered between visits. */
export const LOCALE_STORAGE_KEY = "mplab.locale";

export interface I18n {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  /**
   * Translate a message.
   *
   * The source string is the English text itself ("natural-language keys"):
   * English is the identity translation, so a missing Russian entry falls back
   * to readable English rather than to a key or a blank. `{name}` placeholders
   * are filled from `params`.
   */
  t: (source: string, params?: Record<string, string | number>) => string;
}

function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, key: string) =>
    Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : match,
  );
}

/**
 * Which grammatical form a counted noun takes in Russian.
 *
 * Russian counts in three: 1 пример / 2 примера / 5 примеров. A sentence that
 * interpolates a count into a fixed noun form is wrong for two of every three
 * numbers, which is exactly the kind of mistake a reader notices immediately
 * and stops trusting. The rule is the standard one: the last two digits decide,
 * with 11-14 always taking the "many" form because 11 примеров is correct and
 * not a typo.
 */
export function pluralForm(count: number): "one" | "few" | "many" {
  const absolute = Math.abs(Math.trunc(count));
  const mod10 = absolute % 10;
  const mod100 = absolute % 100;
  if (mod10 === 1 && mod100 !== 11) return "one";
  if (mod10 >= 2 && mod10 <= 4 && !(mod100 >= 12 && mod100 <= 14)) return "few";
  return "many";
}

/** Pure translation, usable outside React (and in tests). */
export function translate(
  locale: Locale,
  source: string,
  params?: Record<string, string | number>,
): string {
  let key = source;
  if (locale === "ru") {
    // A counted noun picks its form from `count`; the catalogue may hold up to
    // three variants as "<source> :: one|few|many". A source with no variants
    // falls through to the plain entry, so nothing breaks by omitting them.
    const count = params?.count;
    if (typeof count === "number" && Number.isFinite(count)) {
      const variant = `${source} :: ${pluralForm(count)}`;
      if (variant in RU_MESSAGES) key = variant;
    }
    key = RU_MESSAGES[key] ?? source;
  }
  return interpolate(key, params);
}

const DEFAULT_I18N: I18n = {
  locale: "en",
  setLocale: () => {},
  t: (source, params) => interpolate(source, params),
};

const I18nContext = createContext<I18n>(DEFAULT_I18N);

/**
 * The default when no stored preference exists: Russian on a Russian browser,
 * English otherwise. A machine is never forced into a language it did not ask
 * for, but the customer's primary audience lands in Russian by default.
 */
function resolveInitialLocale(stored: string | null): Locale {
  if (stored === "ru" || stored === "en") return stored;
  if (typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("ru")) {
    return "ru";
  }
  return "en";
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  // Start in English so the server and the first client render agree; the
  // stored/preferred locale is applied in an effect, which avoids a hydration
  // mismatch and costs at most one frame.
  const [locale, setLocaleState] = useState<Locale>("en");

  useEffect(() => {
    let stored: string | null = null;
    try {
      stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    } catch {
      /* storage unavailable: fall back to the browser language */
    }
    setLocaleState(resolveInitialLocale(stored));
  }, []);

  useEffect(() => {
    setActiveLocale(locale);
    document.documentElement.lang = locale;
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    } catch {
      /* the choice simply will not be sticky */
    }
  }, [locale]);

  const setLocale = useCallback((next: Locale) => setLocaleState(next), []);

  const t = useCallback<I18n["t"]>(
    (source, params) => translate(locale, source, params),
    [locale],
  );

  const value = useMemo<I18n>(() => ({ locale, setLocale, t }), [locale, setLocale, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  return useContext(I18nContext);
}

/**
 * Join the shell's streaming boundary.
 *
 * The shell renders inside a `<Suspense>` boundary, and pages that read the
 * query string suspend into it - which is why the boundary must be above them.
 * A page that never suspends is a problem there: the server renders it into the
 * fallback position and the client never replaces it, so the application sits on
 * "Loading…" forever. No error, no failed request, a server response that looks
 * correct - and reaching the same page by clicking through the interface works,
 * because the boundary is not re-entered.
 *
 * Found by loading `/tls` and `/sessions` directly. Verified: with this call
 * the page settles in about 30 ms; without it, it never settles at all.
 *
 * Not dead code, and not a workaround to be cleaned up later: it is how a page
 * without a `?project=` parameter takes part in the boundary the shell provides.
 */
export function useStreamingBoundary(): void {
  useSearchParams();
}

/** Convenience for components that only need the translator. */
export function useT(): I18n["t"] {
  return useContext(I18nContext).t;
}
