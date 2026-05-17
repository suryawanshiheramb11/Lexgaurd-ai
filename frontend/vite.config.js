import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Load .env variables so we can use them in the config itself
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = env.VITE_API_BASE_URL || 'http://localhost:8000'

  return {
    plugins: [react()],
    // Security headers for Vite dev server
    server: {
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Content-Security-Policy':
          `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss: ${apiBase}; frame-ancestors 'none'; base-uri 'self'; form-action 'self';`,
      },
      // Only listen on localhost in development
      host: '127.0.0.1',
    },
    build: {
      // Prevent source maps from leaking in production builds
      sourcemap: false,
      chunkSizeWarningLimit: 1000,
    },
  }
})
