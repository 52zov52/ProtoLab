/**
 * No English words left inside Russian sentences.
 *
 * Found live on the anomaly page: "чем дальше entity от обычного вида корпуса".
 * A Russian sentence with an English noun in it reads as unfinished, and it is
 * the kind of defect that survives a key-coverage test - the translation exists,
 * it is just not translated.
 *
 * The allow-list is deliberate. Protocol names, cipher names, environment
 * variables and file extensions stay in Latin on purpose: translating
 * "Content-Length" or "AES-GCM" would make them unsearchable and would put a
 * word in the interface that does not exist in the traffic.
 */

import { describe, expect, it } from "vitest";

import { RU_MESSAGES } from "@/lib/i18n/ru";

/** Product vocabulary that is deliberately left in Latin script. */
const ALLOWED = new Set([
  // Protocols, ciphers, formats
  "AES-CBC",
  "AES-GCM",
  "ChaCha20-Poly1305",
  "GCM",
  "JA3",
  "JA3S",
  "JWT",
  "PCAP",
  "PCAPNG",
  "POST",
  "SHA-256",
  "SQL",
  "SSLKEYLOGFILE",
  "SYN",
  "TCP",
  "TLS",
  "Isolation",
  "Forest",
  "MAD",
  // Software, packages, services
  "analytics",
  "scikit-learn",
  "Ollama",
  "OpenAI",
  "OpenRouter",
  "vLLM",
  "API",
  "HTTP",
  "JSON",
  "Python",
  "Linux",
  "Windows",
  "macOS",
  "nginx",
  "npm",
  "backend",
  // Environment variables
  "MPLAB_ALLOW_EXTERNAL_AI",
  "MPLAB_LLM_API_KEY",
  "MPLAB_LLM_BASE_URL",
  "MPLAB_LLM_MODEL",
  "mplab",
]);

const LATIN_WORD = /[A-Za-z][A-Za-z0-9_]*(?:[-.][A-Za-z0-9]+)*/g;
const PLACEHOLDER = /\{[^}]*\}/g;
/** `MPLAB_ALLOW_EXTERNAL_AI=true` - the value is configuration, not prose. */
const ENV_ASSIGNMENT = /MPLAB_[A-Z_]+=[^\s,;.]+/g;

/**
 * Accepted, standard in Russian technical writing, or product vocabulary of this
 * application. Narrow on purpose: every entry here is a hole in the check.
 */
const ALSO_ACCEPTED = new Set([
  "hex", // «hex» is written this way in Russian technical text
  "Backend", // product term, matching the status bar
  "Explorer", // product module name
  "scope", // the assistant's own query-scope vocabulary
  "tuple", // «4-tuple» is how a TCP connection is named here
  "Click",
  "Ctrl",
  "Enter",
]);

function isAllowed(word: string): boolean {
  if (ALLOWED.has(word) || ALSO_ACCEPTED.has(word)) return true;
  // "AES-GCM" and "MPLAB_LLM_MODEL" may be listed whole, or as their parts.
  // Either way, every part has to be vocabulary we recognise.
  return word
    .split(/[-._]/)
    .filter((part) => part.length > 1)
    .every((part) => ALLOWED.has(part) || ALSO_ACCEPTED.has(part));
}

describe("Russian translations carry no stray English", () => {
  it("every Cyrillic translation is free of unexplained Latin words", () => {
    const offenders: string[] = [];
    for (const value of Object.values(RU_MESSAGES)) {
      if (!/[а-яА-ЯёЁ]/.test(value)) continue;
      // Placeholders are parameter names, not prose: `{count}` is not English.
      // Neither is the value of an environment variable an operator must type.
      const prose = value.replace(PLACEHOLDER, " ").replace(ENV_ASSIGNMENT, " ");
      for (const word of prose.match(LATIN_WORD) ?? []) {
        if (isAllowed(word)) continue;
        offenders.push(`${word}  ->  ${value.slice(0, 90)}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the detector would catch a word it has not seen", () => {
    const probe = "Оценка — расстояние до baseline профиля корпуса".replace(
      PLACEHOLDER,
      " ",
    );
    const found = (probe.match(LATIN_WORD) ?? []).filter((w) => !isAllowed(w));
    expect(found).toContain("baseline");
  });

  it("a protocol name in the allow-list is genuinely allowed", () => {
    // If the allow-list were empty of real terms, the check above would be
    // passing for the wrong reason.
    expect(ALLOWED.size).toBeGreaterThan(20);
    expect(isAllowed("Isolation")).toBe(true);
    expect(isAllowed("AES-GCM")).toBe(true);
  });
});