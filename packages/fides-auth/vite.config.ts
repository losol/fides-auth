import { defineVanillaLibConfig } from '@eventuras/vite-config/vanilla-lib';

export default defineVanillaLibConfig({
  entry: {
    index: 'src/index.ts',
    'activity-tracker': 'src/activity-tracker.ts',
    cookies: 'src/cookies.ts',
    heartbeat: 'src/heartbeat.ts',
    logger: 'src/logger.ts',
    'session-refresh': 'src/session-refresh.ts',
    'session-validation': 'src/session-validation.ts',
    'session-cookies': 'src/session-cookies.ts',
    oauth: 'src/oauth.ts',
    'oauth-browser': 'src/oauth-browser.ts',
    'oauth-logging': 'src/oauth-logging.ts',
    'silent-login': 'src/silent-login.ts',
    utils: 'src/utils.ts',
    types: 'src/types.ts',
    'rate-limit': 'src/rate-limit.ts',
    'server/cookie-store': 'src/server/cookie-store.ts',
    'server/index': 'src/server/index.ts',
    'providers/vipps/index': 'src/providers/vipps/index.ts',
  },
});
