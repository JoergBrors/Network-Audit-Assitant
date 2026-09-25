import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

/** Core modules must stay free of Azure SDKs, auth, CLI, UI and Node builtins (they run in the browser). */
const CORE_DIRS = [
  "models",
  "normalization",
  "addressing",
  "graph",
  "topology",
  "routing",
  "security",
  "dualstack",
  "assessment",
  "snapshots",
  "drift",
  "export",
  "pipeline",
];

const nodeBuiltins = {
  group: ["node:*", "fs", "fs/*", "path", "os", "crypto", "child_process", "process"],
  message: "Isomorphic modules must not import Node builtins; inject platform adapters instead.",
};

export default tseslint.config(
  { ignores: ["dist/", "output/", ".cache/", "coverage/", "node_modules/"] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // Read-only guarantee (second line of defence behind readOnlyGuardPolicy):
      // mutating Azure SDK operations must never be called. Plain `update`/`delete` are not matched here
      // because they collide with Map/Set/Hash APIs; the HTTP guard policy blocks those at runtime.
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "CallExpression[callee.type='MemberExpression'][callee.property.name=/^(begin[A-Z]\\w*|createOrUpdate\\w*|updateTags)$/]",
          message: "Mutating Azure operations are forbidden: this tool is strictly read-only.",
        },
      ],
    },
  },
  ...CORE_DIRS.map((dir) => ({
    files: [`src/${dir}/**/*.ts`],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            nodeBuiltins,
            {
              group: ["@azure/*", "**/azure/**", "**/auth/**", "**/cli/**", "**/ui/**", "**/discovery/**"],
              message: "Core modules must not depend on Azure SDKs, auth, discovery, CLI or UI.",
            },
          ],
        },
      ],
    },
  })),
  {
    files: [
      "src/azure/**/*.ts",
      "src/discovery/**/*.ts",
      "src/auth/*.ts",
      "src/logging/**/*.ts",
      "src/utils/**/*.ts",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            nodeBuiltins,
            {
              group: ["**/cli/**", "**/ui/**", "**/auth/browser/**", "**/auth/node/**"],
              message: "Layer violation.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["src/auth/browser/**/*.ts", "src/auth/browser/**/*.tsx"],
    rules: {
      "no-restricted-imports": ["error", { patterns: [nodeBuiltins, { group: ["@azure/identity"] }] }],
    },
  },
  {
    files: ["src/ui/**/*.ts", "src/ui/**/*.tsx"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [nodeBuiltins, { group: ["**/auth/node/**", "**/cli/**", "@azure/identity"] }] },
      ],
    },
  },
  {
    files: ["tests/**/*.ts", "tests/**/*.tsx"],
    rules: {
      "@typescript-eslint/unbound-method": "off",
      "@typescript-eslint/require-await": "off",
    },
  },
  {
    files: ["eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
