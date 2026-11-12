// Imports each package.json entry from dist/ in its own Node process and records
// which third-party packages it loads (ADR 0001 §2, "Dependency weight"). Bundlers
// drop unused code, but Node servers, edge isolates and test runners load the whole
// module graph, so this is what an entry costs there. Needs a build first; turbo
// runs one before `test`.

import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

const run = promisify(execFile);
const packageDir = new URL('../', import.meta.url);
const pkg = JSON.parse(readFileSync(new URL('package.json', packageDir), 'utf8')) as {
  exports: Record<string, { import: string }>;
};

/**
 * Third-party packages each entry loads today, transitive ones included. Lower
 * a row when a change makes an entry lighter; ADR 0001 has `.` and
 * `/session-events` load none by 1.0. A row that grows needs a reason.
 */
const expected: Record<string, string[]> = {
  '.': ['jose', 'oauth4webapi', 'openid-client'],
  './activity-tracker': [],
  './cookies': [],
  './heartbeat': [],
  './logger': [],
  './session-refresh': ['jose', 'oauth4webapi', 'openid-client'],
  './session-validation': ['jose'],
  './session-cookies': ['jose'],
  './session-events': [],
  './oauth': ['jose', 'oauth4webapi', 'openid-client'],
  './oidc-discovery': ['jose', 'oauth4webapi', 'openid-client'],
  './id-token': ['jose', 'oauth4webapi', 'openid-client'],
  './oauth-logging': [],
  './pkce': [],
  './oauth-browser': [],
  './silent-login': ['jose', 'oauth4webapi', 'openid-client'],
  './utils': ['jose'],
  './types': [],
  './rate-limit': [],
  './server': ['jose', 'oauth4webapi', 'openid-client'],
  './providers/vipps': ['jose', 'oauth4webapi', 'openid-client'],
};

// Runs in the child process: records every module the entry resolves, then
// prints the names of the packages under node_modules among them.
const probe = `
import * as module from 'node:module';
if (typeof module.registerHooks !== 'function') {
  throw new Error('The entry test needs module.registerHooks (Node 22.15 or later)');
}
const urls = new Set();
module.registerHooks({
  resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context);
    urls.add(result.url);
    return result;
  },
});
await import(process.argv[1]);
const names = new Set();
for (const url of urls) {
  const parts = url.split('/node_modules/');
  if (parts.length < 2) continue;
  const [first, second] = parts.at(-1).split('/');
  names.add(first.startsWith('@') ? first + '/' + second : first);
}
console.log(JSON.stringify([...names].sort()));
`;

async function thirdPartyLoadedBy(entryFile: string): Promise<string[]> {
  const url = new URL(entryFile, packageDir);
  if (!existsSync(url)) {
    throw new Error(`${fileURLToPath(url)} is missing. Build the package first (pnpm build).`);
  }
  const { stdout } = await run(
    process.execPath,
    ['--no-warnings', '--input-type=module', '-e', probe, url.href],
    { cwd: fileURLToPath(packageDir) },
  );
  return JSON.parse(stdout);
}

describe('package entries', () => {
  it('lists every package.json entry', () => {
    expect(Object.keys(expected).sort()).toEqual(Object.keys(pkg.exports).sort());
  });

  it('load only the third-party packages recorded for them', async () => {
    const entries = Object.entries(pkg.exports);
    const loaded = await Promise.all(entries.map(([, entry]) => thirdPartyLoadedBy(entry.import)));
    expect(Object.fromEntries(entries.map(([key], i) => [key, loaded[i]]))).toEqual(expected);
  }, 30_000);
});
