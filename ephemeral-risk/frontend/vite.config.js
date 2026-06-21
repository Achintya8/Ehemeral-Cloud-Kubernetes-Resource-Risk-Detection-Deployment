import path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Check Vercel or CI environments reliably
  base: (process.env.VERCEL || process.env.VERCEL_ENV || process.env.CI) ? '/' : '/static/',
  build: {
    outDir: (process.env.VERCEL || process.env.VERCEL_ENV || process.env.CI) ? 'dist' : '../static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/login': 'http://127.0.0.1:8000',
      '/api': 'http://127.0.0.1:8000',
      '/stream': 'http://127.0.0.1:8000',
    },
  },
})
