import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

const fromHere = (relativePath: string): string =>
  fileURLToPath(new URL(relativePath, import.meta.url))

// In the browser (dev server used by Playwright), swap the Node-only source
// modules for their browser counterparts. This mirrors what the published
// package's `browser` field does for `dist/` consumers. Vitest runs in Node and
// must keep the Node variants, so the aliases are skipped under VITEST.
const browserAliases = process.env.VITEST
  ? []
  : [
      {
        find: /^.*\/c20p\.js$/,
        replacement: fromHere('./src/algorithms/c20p-browser.ts')
      },
      {
        find: /^.*\/x25519-helper\.js$/,
        replacement: fromHere('./src/algorithms/x25519-helper-browser.ts')
      }
    ]

export default defineConfig({
  resolve: {
    alias: browserAliases
  },
  // Use a project-specific port so the dev server (and the Playwright browser
  // tests that drive it) don't collide with other local vite projects.
  // `strictPort` makes a clash fail loudly instead of silently falling back to
  // another port (or reusing a foreign server).
  server: {
    port: 5273,
    strictPort: true
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
})
