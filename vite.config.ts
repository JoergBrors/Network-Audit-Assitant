import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Strict Content Security Policy for production builds (ENTRA-ID-SETUP.md § 7). Not applied to the
 * dev server because Vite's HMR relies on inline scripts and websockets.
 */
const CSP = [
  "default-src 'self'",
  "connect-src 'self' https://login.microsoftonline.com https://management.azure.com",
  "frame-src https://login.microsoftonline.com",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

function contentSecurityPolicy(): Plugin {
  return {
    name: "content-security-policy",
    apply: "build",
    transformIndexHtml: () => [
      {
        tag: "meta",
        attrs: { "http-equiv": "Content-Security-Policy", content: CSP },
        injectTo: "head-prepend",
      },
    ],
  };
}

export default defineConfig({
  plugins: [react(), contentSecurityPolicy()],
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
});
