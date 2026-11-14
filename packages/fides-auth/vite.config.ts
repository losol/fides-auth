import { defineVanillaLibConfig } from '@eventuras/vite-config/vanilla-lib';

export default defineVanillaLibConfig({
  entry: {
    index: 'src/index.ts',
    'session-events': 'src/session-events.ts',
    oidc: 'src/oidc.ts',
    'server/index': 'src/server/index.ts',
    browser: 'src/browser.ts',
    'providers/vipps/index': 'src/providers/vipps/index.ts',
  },
});
