import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev-only proxy so the session cookie and CSRF double-submit stay same-origin.
// Production serves the built bundle from Express behind the same auth gate as
// the legacy console; nothing here runs in production.
const backend = process.env.REDACTWALL_DEV_PROXY || 'http://localhost:4000';

export default defineConfig({
  base: '/app/',
  plugins: [react()],
  build: {
    outDir: '../server/public/app',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': { target: backend, changeOrigin: false },
      '/login.html': backend,
      '/login.js': backend,
      '/console-base.css': backend,
      '/console-theme.css': backend,
      '/favicon.svg': backend,
    },
  },
});
