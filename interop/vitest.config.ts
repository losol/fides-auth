import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // One provider per file, on its own port: the files don't share state.
    testTimeout: 20_000,
    hookTimeout: 30_000,
  },
});
