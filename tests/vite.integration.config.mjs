import { mergeConfig } from "vite";
import baseConfig from "../vite.config.js";

// Isolated browser verification uses same-origin requests without weakening CSP.
export default mergeConfig(baseConfig, {
  define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify("/api/v1") },
  server: {
    host: "127.0.0.1",
    port: 5175,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:8011", changeOrigin: true, ws: true } },
  },
});
