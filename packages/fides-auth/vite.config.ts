import { defineVanillaLibConfig } from '@eventuras/vite-config/vanilla-lib';

export default defineVanillaLibConfig({
  entry: {
    index: 'src/index.ts',
    cookies: 'src/cookies.ts',
    logger: 'src/logger.ts',
    'session-events': 'src/session-events.ts',
    oauth: 'src/oauth.ts',
    oidc: 'src/oidc.ts',
    'oidc-discovery': 'src/oidc-discovery.ts',
    'id-token': 'src/id-token.ts',
    pkce: 'src/pkce.ts',
    'oauth-browser': 'src/oauth-browser.ts',
    'oauth-logging': 'src/oauth-logging.ts',
    'silent-login': 'src/silent-login.ts',
    utils: 'src/utils.ts',
    types: 'src/types.ts',
    'rate-limit': 'src/rate-limit.ts',
    'server/cookie-store': 'src/server/cookie-store.ts',
    'server/index': 'src/server/index.ts',
    browser: 'src/browser.ts',
    'providers/vipps/index': 'src/providers/vipps/index.ts',
  },
});
