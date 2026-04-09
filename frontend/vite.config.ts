import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  esbuild: {
    // Strip console.log and console.warn in production builds while keeping console.error
    drop: mode === 'production' ? ['console', 'debugger'] : [],
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8088',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8088',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'esbuild',
    cssMinify: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Split third-party libraries into separate chunks
          if (id.includes('node_modules/react-dom')) return 'vendor'
          if (id.includes('node_modules/react-router-dom')) return 'router'
          if (id.includes('node_modules/react/')) return 'vendor'
          // Split large page components into separate bundles to reduce first-load size
          if (id.includes('/email-security/EmailSecurity')) return 'page-email-security'
          if (id.includes('/email-security/SecurityAnalysisView')) return 'page-email-security'
          if (id.includes('/settings/Settings')) return 'page-settings'
          if (id.includes('/data-security/DataSecurity')) return 'page-data-security'
          if (id.includes('/auth/SetupWizard')) return 'page-setup'
          if (id.includes('/knowledge/')) return 'page-knowledge'
        },
      },
    },
  },
}))
