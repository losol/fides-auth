// Runs the conformance suite's relying-party tests for the FAPI 2.0 Security
// Profile against fides-auth: starts the suite, creates the test plan, runs the
// client under test once per module, and prints what the suite made of it.
//
//   pnpm --filter @eventuras/fides-auth-conformance conformance
//
// The verdicts are the suite's. This file adds one of its own: where the
// client stopped must be where that module is meant to stop it (see EXPECTED),
// so that a client broken in some other way can't pass a test that only asks
// it to give up.

import { execFile } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

import { exportJWK, generateKeyPair, type JWK } from 'jose';

import type { Input, Outcome, Stage } from './client.ts';
import {
  LOCAL_SUITE_URL,
  type LogEntry,
  type PlanModule,
  SUITE_RELEASE,
  Suite,
  startSuite,
  stopSuite,
  suiteCertificate,
  suiteLogs,
  type Variant,
} from './suite.ts';

const PLAN = 'fapi2-security-profile-final-client-test-plan';
const MODULE_PREFIX = 'fapi2-security-profile-final-client-test-';

/** The variant every run has: what `profile: 'fapi2'` of fides-auth is. */
const VARIANT: Variant = {
  fapi_profile: 'plain_fapi',
  client_auth_type: 'private_key_jwt',
  sender_constrain: 'dpop',
  authorization_request_type: 'simple',
};

/** With an ID token, and without: the plan is run once for each. */
const CLIENT_TYPES = {
  oidc: { scope: 'openid accounts' },
  plain_oauth: { scope: 'accounts' },
} as const;
type ClientType = keyof typeof CLIENT_TYPES;

/**
 * Where the client is meant to stop in each module of the pinned release, by
 * the module's own description: `done` for a login that must work, `login`
 * when the discovery document must be refused, `callback` when the
 * authorization response, the token response or the ID token must be.
 */
const EXPECTED: Record<string, Stage> = {
  'happy-path': 'done',
  'discovery-issuer-mismatch': 'login',
  'invalid-iss': 'callback',
  'invalid-aud': 'callback',
  'invalid-secondary-aud': 'callback',
  'invalid-null-alg': 'callback',
  'invalid-alternate-alg': 'callback',
  'invalid-expired-exp': 'callback',
  'invalid-missing-exp': 'callback',
  'invalid-missing-aud': 'callback',
  'invalid-missing-iss': 'callback',
  'valid-aud-as-array': 'done',
  'invalid-nonce': 'callback',
  'invalid-missing-nonce': 'callback',
  'invalid-authorization-response-iss': 'callback',
  'remove-authorization-response-iss': 'callback',
  'ensure-authorization-response-with-invalid-state-fails': 'callback',
  'ensure-authorization-response-with-invalid-missing-state-fails': 'callback',
  'token-endpoint-response-without-expires_in': 'done',
  'token-type-case-insensitivity': 'done',
  'rs-dpop-auth-scheme-case-insensitivity': 'done',
  'happy-path-no-dpop-nonce': 'done',
  'happy-path-no-mtls-endpoint-aliases': 'done',
};

/** The row of a module: the suite's verdict, and what the client did. */
interface Row {
  clientType: ClientType;
  module: string;
  /** The suite's result, or what kept it from giving one. */
  result: 'PASSED' | 'WARNING' | 'FAILED' | 'REVIEW' | 'SKIPPED' | 'UNKNOWN' | 'INTERRUPTED' | 'TIMEOUT' | 'ERROR';
  /** The stage the client stopped at, and whether that is the one EXPECTED. */
  client: Stage | '-';
  expected: Stage | '?';
  reason: string;
  /** The suite's own failures and warnings for the module. */
  findings: string[];
  testId?: string;
}

const resultsDir = new URL('../results/', import.meta.url);
const clientScript = new URL('./client.ts', import.meta.url).pathname;

/** Runs the client under test in a process of its own, and reads its outcome. */
function runClient(input: Input, caFile: string): Promise<Outcome> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', '--disable-warning=ExperimentalWarning', clientScript],
      {
        env: { ...process.env, CONFORMANCE_CLIENT: JSON.stringify(input), NODE_EXTRA_CA_CERTS: caFile },
        timeout: 60_000,
      },
      (error, stdout, stderr) => {
        const last = stdout.trim().split('\n').at(-1) ?? '';
        try {
          resolve(JSON.parse(last) as Outcome);
        } catch {
          resolve({ stage: 'login', reason: `the client script failed: ${(stderr || error?.message || last).slice(0, 500)}` });
        }
      },
    );
  });
}

/** One line for a failure or warning in the suite's log: the check, what it said, the clause. */
function finding(entry: LogEntry): string {
  const requirements = entry.requirements?.length ? ` [${entry.requirements.join(', ')}]` : '';
  return `${entry.result} ${entry.src ?? ''}: ${entry.msg ?? ''}${requirements}`;
}

async function runModule(
  suite: Suite,
  planId: string,
  module: PlanModule,
  clientType: ClientType,
  input: Input,
  caFile: string,
): Promise<Row> {
  const name = module.testModule.replace(MODULE_PREFIX, '');
  const row: Row = {
    clientType,
    module: name,
    result: 'ERROR',
    client: '-',
    expected: EXPECTED[name] ?? '?',
    reason: '',
    findings: [],
  };
  try {
    const { id } = await suite.createTest(planId, module);
    row.testId = id;

    // The suite sets the test up, then waits for the client to come.
    const waiting = await suite.waitFor(id, ['WAITING', 'FINISHED', 'INTERRUPTED'], 60);
    if (waiting?.status === 'WAITING') {
      const outcome = await runClient(input, caFile);
      row.client = outcome.stage;
      row.reason = outcome.reason;
    }

    // A test the client must give up on ends itself a few seconds after its bad answer.
    const finished = await suite.waitFor(id, ['FINISHED', 'INTERRUPTED'], 90);
    if (!finished) row.result = 'TIMEOUT';
    else if (finished.status === 'INTERRUPTED') row.result = 'INTERRUPTED';
    else row.result = finished.result ?? 'UNKNOWN';

    const log = await suite.log(id);
    row.findings = log.filter((entry) => entry.result === 'FAILURE' || entry.result === 'WARNING').map(finding);
    await writeFile(new URL(`logs/${clientType}-${name}.json`, resultsDir), JSON.stringify(log, null, 2));
  } catch (thrown) {
    row.reason = `${row.reason} runner: ${String(thrown)}`.trim();
  }
  return row;
}

/** A module is fine when the suite passed it and the client stopped where the module means it to. */
function verdict(row: Row): 'ok' | 'warning' | 'failed' {
  if (row.expected !== '?' && row.client !== row.expected) return 'failed';
  if (row.result === 'PASSED' || row.result === 'SKIPPED') return 'ok';
  if (row.result === 'WARNING' || row.result === 'REVIEW') return 'warning';
  return 'failed';
}

function table(rows: Row[]): string {
  const lines = [
    '| Client type | Module | Suite | Client stopped at | Expected | |',
    '|---|---|---|---|---|---|',
    ...rows.map((row) => {
      const mark = { ok: '', warning: 'warning', failed: '**FAILED**' }[verdict(row)];
      return `| ${row.clientType} | ${row.module} | ${row.result} | ${row.client} | ${row.expected} | ${mark} |`;
    }),
  ];
  return lines.join('\n');
}

function details(rows: Row[]): string {
  const parts: string[] = [];
  for (const row of rows) {
    if (!row.reason && row.findings.length === 0) continue;
    parts.push(`### ${row.clientType} / ${row.module}: ${row.result}`);
    if (row.reason) parts.push(`The client stopped at \`${row.client}\`: ${row.reason}`);
    for (const line of row.findings) parts.push(`- ${line}`);
    parts.push('');
  }
  return parts.join('\n');
}

async function main(): Promise<number> {
  const external = process.env.CONFORMANCE_SUITE_URL;
  const keep = process.env.CONFORMANCE_KEEP_SUITE === '1';
  const clientTypes = (process.env.CONFORMANCE_CLIENT_TYPES ?? 'oidc,plain_oauth').split(',').map((type) => {
    if (!(type in CLIENT_TYPES)) throw new Error(`Unknown client type ${type}: oidc or plain_oauth`);
    return type as ClientType;
  });

  await rm(resultsDir, { recursive: true, force: true });
  await mkdir(new URL('logs/', resultsDir), { recursive: true });
  const caFile = new URL('suite-ca.crt', resultsDir).pathname;

  const suite = new Suite(external ?? LOCAL_SUITE_URL);
  const rows: Row[] = [];
  const started = Date.now();
  try {
    // The suite's certificate is self-signed. It is trusted by name, here and in
    // the client's process, and nothing else about TLS is relaxed.
    let certificate: string;
    if (external) {
      const given = process.env.CONFORMANCE_SUITE_CA;
      if (!given) throw new Error('With CONFORMANCE_SUITE_URL, set CONFORMANCE_SUITE_CA to the PEM file of its certificate');
      certificate = await readFile(given, 'utf8');
    } else {
      console.log(`Starting the conformance suite (${SUITE_RELEASE}) with Docker...`);
      await startSuite();
      certificate = await suiteCertificate();
    }
    await writeFile(caFile, certificate);
    setDefaultCACertificates([...getCACertificates('default'), certificate]);

    await suite.ready();
    console.log('The suite is up.');

    for (const clientType of clientTypes) {
      // A key of its own for each plan. The suite gets the public half, as the client's registered key.
      const keys = await generateKeyPair('ES256', { extractable: true });
      const kid = `fides-auth-${clientType}`;
      const publicJwk: JWK = { ...(await exportJWK(keys.publicKey)), kid, alg: 'ES256', use: 'sig' };
      const alias = `fides-auth-${clientType.replace('_', '-')}`;
      const input: Input = {
        issuer: suite.issuer(alias),
        clientId: 'fides-auth-conformance',
        // Nothing listens here: the client script is the browser, and hands the redirect to the library.
        redirectUri: 'https://rp.fides-auth.test/auth/callback',
        scope: CLIENT_TYPES[clientType].scope,
        clientJwk: { ...(await exportJWK(keys.privateKey)), kid, alg: 'ES256' },
      };
      const config = {
        alias,
        description: `fides-auth, ${clientType}`,
        client: {
          client_id: input.clientId,
          scope: input.scope,
          redirect_uri: input.redirectUri,
          jwks: { keys: [publicJwk] },
        },
      };

      const variant = { ...VARIANT, fapi_client_type: clientType };
      const plan = await suite.createPlan(PLAN, variant, config);
      console.log(`\n${PLAN} ${JSON.stringify(variant)}: ${plan.modules.length} modules, plan ${plan.id}`);

      for (const module of plan.modules) {
        const row = await runModule(suite, plan.id, module, clientType, input, caFile);
        rows.push(row);
        console.log(`  ${row.result.padEnd(11)} ${row.module}  (client: ${row.client}${verdict(row) === 'failed' ? ', FAILED' : ''})`);
      }
    }
  } finally {
    if (!external) {
      await writeFile(new URL('suite-server.log', resultsDir), await suiteLogs().catch(String));
      if (!keep) await stopSuite();
    }
  }

  const failed = rows.filter((row) => verdict(row) === 'failed');
  const warnings = rows.filter((row) => verdict(row) === 'warning');
  const summary = `${rows.length} modules: ${rows.length - failed.length - warnings.length} passed, ${warnings.length} with warnings, ${failed.length} failed. ${Math.round((Date.now() - started) / 1000)} s.`;
  const report = [
    `# OpenID conformance suite: ${PLAN}`,
    '',
    `Suite ${SUITE_RELEASE}. Variant: ${Object.entries(VARIANT).map(([key, value]) => `${key}=${value}`).join(', ')}.`,
    '',
    summary,
    '',
    table(rows),
    '',
    '## What the client and the suite said',
    '',
    details(rows),
  ].join('\n');

  await writeFile(new URL('results.md', resultsDir), report);
  await writeFile(new URL('results.json', resultsDir), JSON.stringify({ suite: SUITE_RELEASE, plan: PLAN, variant: VARIANT, rows }, null, 2));
  console.log(`\n${report}`);
  console.log(`\nWritten to ${resultsDir.pathname}`);

  if (rows.length === 0) return 1;
  return failed.length > 0 ? 1 : 0;
}

process.exitCode = await main().catch((thrown) => {
  console.error(thrown);
  return 2;
});
