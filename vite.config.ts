import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Strict Content Security Policy for production builds (ENTRA-ID-SETUP.md § 7). Not applied to the
 * dev server because Vite's HMR relies on inline scripts and websockets. The Azure OpenAI endpoint
 * (KI-Analyse) is allowed only when configured; generated images are shown via blob: URLs.
 */
function csp(aiEndpoint: string | undefined): string {
  const ai = aiEndpoint ? ` ${new URL(aiEndpoint).origin}` : "";
  return [
    "default-src 'self'",
    `connect-src 'self' https://login.microsoftonline.com https://management.azure.com${ai}`,
    "frame-src https://login.microsoftonline.com",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

function contentSecurityPolicy(content: string): Plugin {
  return {
    name: "content-security-policy",
    apply: "build",
    transformIndexHtml: () => [
      {
        tag: "meta",
        attrs: { "http-equiv": "Content-Security-Policy", content },
        injectTo: "head-prepend",
      },
    ],
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    contentSecurityPolicy(csp(loadEnv(mode, process.cwd(), "VITE_").VITE_AZURE_OPENAI_ENDPOINT)),
  ],
  server: { port: 5173, strictPort: true },
  preview: { port: 4173, strictPort: true },
  build: {
    outDir: "dist",
    sourcemap: true,
    // Multi-page build: the MSAL v5 redirect bridge must be a separate page (ENTRA-ID-SETUP.md).
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
        redirect: fileURLToPath(new URL("redirect.html", import.meta.url)),
      },
    },
  },
}));
