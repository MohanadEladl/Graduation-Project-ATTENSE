import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Defaults match running `npm run dev` directly on the host, proxying to the
// backend/target-agent containers' host-mapped ports. When this dev server
// itself runs inside Docker (infra/compose.dev.yml's hot-reload override),
// these are overridden via env vars to the docker-network service names,
// since "localhost" from inside that container would mean itself.
const BACKEND_URL = process.env.VITE_BACKEND_URL || 'http://localhost:8000'
const TARGET_URL = process.env.VITE_TARGET_URL || 'http://localhost:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    // Bind-mounted volumes into a Docker container (infra/compose.dev.yml's
    // hot-reload override) don't reliably propagate native filesystem change
    // events on Windows/Mac Docker Desktop, so Vite's default watcher never
    // sees host-side edits. Polling works everywhere at the cost of a bit of
    // CPU; only enabled when explicitly requested (i.e. from that override),
    // not for normal host-based `npm run dev`.
    watch: process.env.VITE_USE_POLLING === '1' ? { usePolling: true, interval: 300 } : undefined,
    proxy: {
      '/api':      { target: BACKEND_URL, changeOrigin: true },
      '/health':   { target: BACKEND_URL, changeOrigin: true },
      '/ws':       { target: BACKEND_URL.replace(/^http/, 'ws'), ws: true },
      // Vulnerable lab target — same-origin preview + deep links.
      // Inject X-Forwarded-Prefix so Flask emits prefixed URLs that keep
      // forms/links inside the /target/* path even when iframed.
      // Operator-mode lab browser, reverse-proxied through ZAP (Burp-style
      // Proxy History) via the backend's /zap-browse/{path} route - must be
      // declared BEFORE '/target' below since it's a more specific prefix.
      '/target-zap': {
        target: BACKEND_URL,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/target-zap/, '/zap-browse'),
      },
      // Operator-mode parallel target (HARDER backend, routes_op blueprints) —
      // must be declared BEFORE '/target' below since it's a more specific
      // prefix; matches nginx.conf's /target-op/ location (production) which
      // rewrites to /op/... on target-agent the same way.
      '/target-op': {
        target: TARGET_URL,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/target-op/, '/op'),
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('X-Forwarded-Prefix', '/target-op')
          })
          proxy.on('proxyRes', (proxyRes) => {
            delete proxyRes.headers['x-frame-options']
            delete proxyRes.headers['content-security-policy']
          })
        },
      },
      '/target':   {
        target: TARGET_URL,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/target/, ''),
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('X-Forwarded-Prefix', '/target')
          })
          proxy.on('proxyRes', (proxyRes) => {
            // Make iframable in dev too
            delete proxyRes.headers['x-frame-options']
            delete proxyRes.headers['content-security-policy']
          })
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
})
