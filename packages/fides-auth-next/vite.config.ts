import { defineNextLibConfig } from '@eventuras/vite-config/next-lib';

export default defineNextLibConfig({
  entry: {
    index: 'src/index.ts',
  },
  external: ['react', /^react\//, '@eventuras/fides-auth', /^@eventuras\/fides-auth\//],
});
