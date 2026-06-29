import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  assetsInclude: ['**/*.avif', '**/*.webp', '**/*.glb', '**/*.mp4'],
  server: {
    host: '0.0.0.0',
    proxy: {
      '/api': 'http://host.docker.internal:8020',
    },
  },
})
