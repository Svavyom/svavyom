/// <reference types="vitest/config" />
// Production build: index.html -> dist/. Test-only gallery: `vite build --mode gallery` -> dist-gallery/ (never shipped).
import { defineConfig } from "vite";

export default defineConfig(({ mode }) => {
  const gallery = mode === "gallery";
  return {
    esbuild: { jsx: "automatic" },
    server: { fs: { allow: [".."] } },
    build: {
      outDir: gallery ? "dist-gallery" : "dist",
      emptyOutDir: true,
      sourcemap: false,
      target: "es2022", // noVNC uses top-level await
      assetsInlineLimit: 0, // the CSP serves fonts from 'self' only: never inline an asset as a data: URL
      rollupOptions: { input: gallery ? "gallery.html" : "index.html" },
    },
    preview: { host: "127.0.0.1", strictPort: true },
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
      restoreMocks: true,
      css: true,
    },
  };
});
