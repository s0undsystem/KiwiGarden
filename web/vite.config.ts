import { defineConfig } from "vite";

export default defineConfig({
  // Output straight into the Go embed directory.
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
    target: "es2022",
    // No inline module-preload polyfill: the CSP forbids inline scripts.
    modulePreload: { polyfill: false },
    // Never inline assets as data: URIs; CSP img-src is 'self' only.
    assetsInlineLimit: 0,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: (id: string) => (id.includes("node_modules/three") ? "three" : undefined),
      },
    },
  },
  // Reproducible: no network at build time beyond node_modules.
  server: { host: "127.0.0.1" },
});
