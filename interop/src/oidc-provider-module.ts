// oidc-provider ships no types. The tests need its constructor, its request
// handler and a handful of settings, so that much is declared here. In a .ts
// file, not a .d.ts: the repository ignores those as build output.
declare module 'oidc-provider' {
  import type { IncomingMessage, ServerResponse } from 'node:http';

  export type Configuration = Record<string, unknown>;

  export default class Provider {
    constructor(issuer: string, configuration?: Configuration);
    callback(): (request: IncomingMessage, response: ServerResponse) => Promise<void>;
    on(event: string, listener: (...args: unknown[]) => void): this;
  }
}
