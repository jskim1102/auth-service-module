import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Port comes from the project .env (FRONTEND_PORT), one dir up. Never hardcoded —
// the host/compose own the port allocation (RULES §4). No fallback: a missing var
// is a misconfiguration and must fail loud (parity with the F12 env-injection rule),
// not silently boot on a default that would mismatch the compose ${FRONTEND_PORT}:5176 map.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '..', '')
  const port = Number(env.FRONTEND_PORT)
  if (!port) {
    throw new Error('FRONTEND_PORT is not set in .env — refusing to guess a port.')
  }
  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      port,
    },
    preview: {
      host: '0.0.0.0',
      port,
    },
  }
})
