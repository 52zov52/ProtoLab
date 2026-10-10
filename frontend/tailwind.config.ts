import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Graphite / near-black laboratory surface.
        canvas: "#0b0d10",
        surface: "#12151a",
        "surface-raised": "#171b21",
        "surface-sunken": "#08090b",
        line: "#23282f",
        "line-strong": "#313842",
        // Restrained teal accent.
        accent: "#3fb6c8",
        "accent-dim": "#1f6a76",
        "accent-faint": "#0e2b31",
        text: {
          DEFAULT: "#d6dbe1",
          muted: "#8d97a3",
          faint: "#5d6772",
        },
        status: {
          ok: "#4ea87a",
          warn: "#c9a227",
          bad: "#c9584f",
          info: "#5b8fd6",
          unknown: "#7b8794",
        },
      },
      fontFamily: {
        mono: [
          "ui-monospace", "SFMono-Regular", "Menlo", "Consolas",
          "Liberation Mono", "monospace",
        ],
        sans: [
          "system-ui", "-apple-system", "Segoe UI", "Roboto",
          "Helvetica Neue", "Arial", "sans-serif",
        ],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
};

export default config;