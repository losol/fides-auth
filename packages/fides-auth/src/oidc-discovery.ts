// The `/oidc-discovery` entry. The code lives in protocol/discovery.ts.
export {
  clearDiscoveryCache,
  configureDiscoveryCache,
  discoverConfiguration,
  resolveClientAuth,
  type DiscoveryCacheOptions,
} from './protocol/discovery.js';
