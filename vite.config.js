// Recommended vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Move the allowedHosts array INSIDE the server object
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      'e0a4c1d3a04e.ngrok-free.app'
    ]
  }
})