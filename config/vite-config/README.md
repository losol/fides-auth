# @eventuras/vite-config

Shared Vite configurations for Eventuras monorepo libraries.

## Overview

This package provides reusable Vite configuration presets for different types of libraries in the Eventuras monorepo. It helps maintain consistency, reduces duplication, and makes it easier to update build configurations across all libraries.

The presets build JavaScript only. Type declarations are emitted by each package's own `tsc --emitDeclarationOnly` step in its `build` script.

## Presets

### Vanilla Library (`vanilla-lib`)

For plain TypeScript libraries without React.

```typescript
// vite.config.ts
import { defineVanillaLibConfig } from '@eventuras/vite-config/vanilla-lib';
import { resolve } from 'path';

export default defineVanillaLibConfig({
  entry: 'src/index.ts',
  name: 'MyLibrary',
  external: ['some-external-dep'],
});
```

### React Library (`react-lib`)

For React component libraries and utilities.

```typescript
// vite.config.ts
import { defineReactLibConfig } from '@eventuras/vite-config/react-lib';
import { resolve } from 'path';

export default defineReactLibConfig({
  entry: 'src/index.ts',
  // Or use glob for multiple entry points:
  // entry: 'src/**/index.ts',
  external: ['@eventuras/ratio-ui'],
  tailwind: true, // Enable Tailwind CSS
  preserveModules: true, // Keep source structure in dist
  useSWC: false, // Use Babel (default) or SWC for React transform
});
```

**Features:**
- React plugin (Babel or SWC)
- Optional Tailwind CSS support
- 'use client' directive preservation for RSC
- Configurable module preservation

### Next.js Library (`next-lib`)

For React libraries compatible with Next.js (includes Next.js externals).

```typescript
// vite.config.ts
import { defineNextLibConfig } from '@eventuras/vite-config/next-lib';
import { resolve } from 'path';

export default defineNextLibConfig({
  entry: {
    'Image/index': resolve(__dirname, 'src/Image/index.ts'),
    'Link/index': resolve(__dirname, 'src/Link/index.ts'),
    index: resolve(__dirname, 'src/index.ts'),
  },
  external: ['@eventuras/ratio-ui'],
  tailwind: true,
});
```

**Features:**
- All React library features
- Next.js externals (next, next/image, next/link, etc.)
- Always preserves 'use client' directives

## Configuration Options

### Common Options

All presets support these options:

- **`entry`**: Library entry point(s)
  - String: `'src/index.ts'`
  - Object: `{ index: 'src/index.ts', utils: 'src/utils.ts' }`
  - Glob (React only): `'src/**/index.ts'`

- **`external`**: Additional dependencies to exclude from bundle
  - Array of strings or RegExp patterns
  - Common externals (react, next) are already included

- **`viteConfig`**: Additional Vite config to merge

### React-Specific Options

- **`tailwind`**: Enable Tailwind CSS support (default: `false`)
- **`preserveModules`**: Keep source structure in output (default: `true`)
- **`preserveUseClientDirectives`**: Preserve 'use client' for RSC (default: `true`)
- **`useSWC`**: Use SWC instead of Babel (default: `false`)

## Migration Guide

### Before (duplicated config in each library)

```typescript
// libs/my-lib/vite.config.ts
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      formats: ['es'],
    },
    rollupOptions: {
      external: ['react', 'react-dom', 'react/jsx-runtime'],
    },
  },
});
```

### After (using shared config)

```typescript
// libs/my-lib/vite.config.ts
import { defineReactLibConfig } from '@eventuras/vite-config/react-lib';

export default defineReactLibConfig({
  entry: 'src/index.ts',
});
```

## Best Practices

1. **Use the most specific preset**: If building for Next.js, use `next-lib` instead of `react-lib`
2. **Only specify what's different**: The presets have sensible defaults
3. **Use glob patterns for multi-entry libraries**: `entry: 'src/**/index.ts'`
4. **Enable SWC for faster builds**: `useSWC: true` (in development)
5. **Keep modules preserved**: `preserveModules: true` for better tree-shaking

## Troubleshooting

### Types not generated
- Declarations come from `tsc --emitDeclarationOnly` in each package's `build` script, not from the Vite presets
- Check the package tsconfig: `declaration: true`, `outDir`, and that sources are under `src/`

### 'use client' directives missing
- Ensure `preserveUseClientDirectives: true` (default for Next.js)
- Check that source files have 'use client' at the top

### Build errors with Next.js
- Use `next-lib` preset instead of `react-lib`
- Check that Next.js packages are in `external` array
