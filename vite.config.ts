import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {defineConfig} from 'vite';

const currentDir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(currentDir, '.'),
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (
              id.includes('node_modules/react/') ||
              id.includes('node_modules/react-dom/') ||
              id.includes('node_modules/scheduler/')
            ) {
              return 'vendor-react';
            }
            if (id.includes('node_modules/jszip')) return 'vendor-jszip';
            if (id.includes('node_modules/lucide-react')) return 'vendor-icons';
            if (id.includes('/src/data/')) return 'data-catalogs';
            if (id.includes('/src/services/workbenchTemplate')) return 'dossier-templates';
            if (id.includes('/src/services/dossierGenerator')) return 'dossier-engine';
            if (
              id.includes('/src/engine/') ||
              id.includes('/src/forensics/') ||
              id.includes('/src/crypto/') ||
              id.includes('/src/services/forensicMathEngine') ||
              id.includes('/src/services/swarmOrchestrator')
            ) {
              return 'forensics-engine';
            }
          },
        },
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
