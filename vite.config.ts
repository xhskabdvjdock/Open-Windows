import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // Ignore Rust build output: watching src-tauri/target crashes Vite on
      // Windows with EBUSY (locked .exe) while cargo compiles (tauri dev).
      ignored: ["**/src-tauri/**", "**/target/**", "**/node_modules/**", "**/dist/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2020",
    outDir: "dist",
    emptyOutDir: true
  }
});
