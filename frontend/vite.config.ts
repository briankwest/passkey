import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      '.ngrok.io',
      '.ngrok-free.app'
    ],
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://backend:5001',
        changeOrigin: true,
        secure: false
      }
    }
  }
})