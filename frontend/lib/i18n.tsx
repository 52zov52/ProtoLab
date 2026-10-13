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

/** Pure translation, usable outside React (and in tests). */
export function translate(
  locale: Locale,
  source: string,
  params?: Record<string, string | number>,
): string {
  const template = locale === "ru" ? (RU_MESSAGES[source] ?? source) : source;
  return interpolate(template, params);
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

/** Convenience for components that only need the translator. */
export function useT(): I18n["t"] {
  return useContext(I18nContext).t;
}
