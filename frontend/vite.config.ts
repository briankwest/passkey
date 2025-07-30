import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    allowedHosts: ['.ngrok.io', '.ngrok.app', 'localhost'],
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://backend:5001',
        changeOrigin: true,
        secure: false
      }
    }
  }
})