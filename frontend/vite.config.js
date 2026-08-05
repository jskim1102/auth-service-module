import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Port comes from the project .env (FRONTEND_PORT), one dir up. Never hardcoded —
// the host/compose own the port allocation (RULES §4). No fallback: a missing var
// is a misconfiguration and must fail loud (parity with the F12 env-injection rule),
// not silently boot on a default that would mismatch the compose ${FRONTEND_PORT}:5176 map.
export default defineConfig(({ mode, command }) => {
  const env = loadEnv(mode, '..', '')
  const port = Number(env.FRONTEND_PORT)
  if (!port) {
    throw new Error('FRONTEND_PORT is not set in .env — refusing to guess a port.')
  }
  // Dev: vite replaces the prod nginx (frontend/nginx.conf), so it must reproduce
  // nginx's /auth/* → backend proxy. Without it the SPA's same-origin api.js calls
  // (BASE='') and the SNS <a href="/auth/oauth/..."> hit vite's SPA fallback (200
  // index.html) instead of the backend. The regex key proxies every /auth/* EXCEPT
  // /auth/callback, which the SPA history-fallback serves as index.html so
  // OAuthCallback.jsx can read ?code — matches nginx's `location = /auth/callback`.
  // BACKEND_PORT (and the proxy) are DEV-ONLY: the prod build is static files served by
  // nginx, which owns /auth/* proxying. Requiring BACKEND_PORT at build time would (and
  // did) break the `docker compose` frontend build, whose context is ./frontend and only
  // supplies FRONTEND_PORT. So enforce it + wire the proxy for `vite` (serve) ONLY, never
  // for `vite build`.
  const isDev = command === 'serve'
  const backendPort = Number(env.BACKEND_PORT)
  if (isDev && !backendPort) {
    throw new Error('BACKEND_PORT is not set in .env — refusing to guess the dev proxy target.')
  }
  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      port,
      strictPort: true, // 포트 점유 시 자동 +1 점프 금지 — 할당 포트 침범 방지 (RULES §4)
      proxy: isDev
        ? {
            '^/auth/(?!callback(?:$|[/?])).*': {
              target: `http://localhost:${backendPort}`,
              changeOrigin: true,
            },
          }
        : undefined,
    },
    preview: {
      host: '0.0.0.0',
      port,
      strictPort: true,
    },
  }
})
