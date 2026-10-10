// ESLint flat config.
//
// Next.js 16 removed `next lint`, so linting runs through the ESLint CLI
// directly. `@next/eslint-plugin-next` now defaults to the flat-config format,
// and `core-web-vitals` includes the React hooks rules.
//
// `eslint-plugin-react` is deliberately not installed: the current release does
// not yet declare support for ESLint 10, and forcing it would be worse than
// omitting it. The rule that matters most here - no untrusted text rendered as
// markup - is enforced directly by a test instead
// (backend/tests/test_frontend_safety.py), which is a stronger guarantee than
// a lint warning because it fails the suite.
//
// Style is not enforced: this codebase already has a consistent style, and a
// formatter disagreement is not worth a lint failure.

import nextPlugin from "@next/eslint-plugin-next";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: [".next/**", "node_modules/**", "out/**", "next-env.d.ts", "coverage/**"],
  },
  // In this plugin version `core-web-vitals` is a single flat-config object.
  nextPlugin.configs["core-web-vitals"],
  {
    // React hooks rules are not bundled with the Next plugin in this version,
    // but several files legitimately suppress `exhaustive-deps` (for effects
    // whose dependencies are genuinely covered by a revision counter), so the
    // rule must be registered for those suppressions to resolve.
    files: ["**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: reactHooks.configs.recommended.rules,
  },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // Unescaped quotes and stray console noise are not errors here; hooks
      // and Next.js correctness are.
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      // `useAsync` and `useJobPoller` are data-fetching hooks: transitioning
      // to "loading" inside the effect is the canonical fetch-on-mount
      // pattern, and this rule (from the React Compiler lint) targets
      // cascading renders that do not arise here. Turning it off is a
      // deliberate choice, not an oversight; the refs-during-render half of
      // the same lint is left on and fixed.
      "react-hooks/set-state-in-effect": "off",
    },
  },
];