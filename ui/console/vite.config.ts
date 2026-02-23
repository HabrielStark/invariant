import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/v1/policysets': 'http://localhost:8082',
      '/v1/keys': 'http://localhost:8082',
      '/v1/beliefstate': 'http://localhost:8083',
      '/v1/state': 'http://localhost:8083',
      '/v1/audit': 'http://localhost:8080',
      '/v1/escrow': 'http://localhost:8080',
      '/v1/escrows': 'http://localhost:8080',
      '/v1/verdicts': 'http://localhost:8080',
      '/v1/stream': {
        target: 'http://localhost:8080',
        ws: true
      }
    }
  }
})
