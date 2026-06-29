import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api':      { target: 'http://localhost:8000', changeOrigin: true },
      '/health':   { target: 'http://localhost:8000', changeOrigin: true },
      '/ws':       { target: 'ws://localhost:8000',   ws: true },
      // Vulnerable lab target — same-origin preview + deep links.
      // Inject X-Forwarded-Prefix so Flask emits prefixed URLs that keep
      // forms/links inside the /target/* path even when iframed.
      '/target':   {
        target: 'http://localhost:8080',
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
