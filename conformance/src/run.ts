// Runs the conformance suite's relying-party tests against fides-auth: starts
// the suite, creates each test plan, runs the client under test once per
// module, and prints what the suite made of it.
//
//   pnpm --filter @eventuras/fides-auth-conformance conformance
//
// The verdicts are the suite's. This file adds one of its own: where the
// client stopped must be where that module is meant to stop it (see `expected`
// of each plan), so that a client broken in some other way can't pass a test
// that only asks it to give up.

import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

import { exportJWK, generateKeyPair, type JWK } from 'jose';

import type { Input, Kind, LogoutInput, Outcome, Stage } from './client.ts';
import {
  HOST_FROM_SUITE,
  hostAddressFromSuite,
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

/** One run of a test plan: the plan, its variant, and the client it is run with. */
interface PlanRun {
  /** The name of the run in the table and in the names of the logs. */
  label: string;
  plan: string;
  variant: Variant;
  /** What the names of the plan's modules begin with, left out of the table. */
  modulePrefix: string;
  /** Which client of src/client.ts. */
  kind: Kind;
  scope: string;
  /**
   * Where the client is meant to stop in each module of the pinned release, by
   * the module's own description. A module that is not here fails the run.
   */
  expected: Record<string, Stage>;
}

const FAPI2_PLAN = 'fapi2-security-profile-final-client-test-plan';

/** What `profile: 'fapi2'` of fides-auth is. */
const FAPI2_VARIANT: Variant = {
  fapi_profile: 'plain_fapi',
  client_auth_type: 'private_key_jwt',
  sender_constrain: 'dpop',
  authorization_request_type: 'simple',
};

/**
 * `done` for a login that must work, `login` when the discovery document must
 * be refused, `callback` when the authorization response, the token response
 * or the ID token must be.
 */
const FAPI2_EXPECTED: Record<string, Stage> = {
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

/** The FAPI plan, with an ID token and without: it is run once for each. */
const FAPI2_CLIENT_TYPES = {
  oidc: { scope: 'openid accounts' },
  plain_oauth: { scope: 'accounts' },
} as const;
type Fapi2ClientType = keyof typeof FAPI2_CLIENT_TYPES;

function fapi2(clientType: Fapi2ClientType): PlanRun {
  return {
    label: `fapi2-${clientType.replace('_', '-')}`,
    plan: FAPI2_PLAN,
    variant: { ...FAPI2_VARIANT, fapi_client_type: clientType },
    modulePrefix: 'fapi2-security-profile-final-client-test-',
    kind: 'fapi2',
    scope: FAPI2_CLIENT_TYPES[clientType].scope,
    expected: FAPI2_EXPECTED,
  };
}

/**
 * The two variants the OpenID Connect plans leave open: a client registered by
 * hand, as fides-auth has no dynamic registration, and an authorization
 * request in the query, as it sends no request object.
 */
const OIDCC_VARIANT: Variant = {
  client_registration: 'static_client',
  request_type: 'plain_http_request',
};

/**
 * The Basic RP certification profile: the code flow with `client_secret_basic`
 * (the plan fixes `response_type`, `response_mode` and `client_auth_type`).
 */
const BASIC: PlanRun = {
  label: 'basic',
  plan: 'oidcc-client-basic-certification-test-plan',
  variant: OIDCC_VARIANT,
  modulePrefix: 'oidcc-client-test-',
  kind: 'basic',
  // `profile email` is what oidcc-client-test-scope-userinfo-claims asks for.
  scope: 'openid profile email',
  expected: {
    'oidcc-client-test': 'done',
    'invalid-iss': 'callback',
    'missing-sub': 'callback',
    'invalid-aud': 'callback',
    'missing-iat': 'callback',
    'kid-absent-single-jwks': 'done',
    'idtoken-sig-rs256': 'done',
    // In the next three the suite takes either answer, and what the library
    // does follows from one thing: openid-client checks the claims and the
    // `alg` of an ID token that comes straight from the token endpoint, and
    // not its signature (OpenID Connect Core 3.1.3.7, step 6). So it never
    // has to choose between keys without a `kid`,
    'kid-absent-multiple-jwks': 'done',
    // it takes an unsigned ID token when the provider's metadata lists `none`,
    'idtoken-sig-none': 'done',
    // and it goes on to UserInfo with a signature that is wrong, where the
    // suite ends the test as SKIPPED and answers with an error.
    'invalid-sig-rs256': 'userinfo',
    // The suite can't see this one: UserInfo is the last request either way.
    // Only this table says the response for another `sub` was refused.
    'userinfo-invalid-sub': 'userinfo',
    'nonce-invalid': 'callback',
    'scope-userinfo-claims': 'done',
    'client-secret-basic': 'done',
  },
};

/**
 * Back-channel logout, for a code-flow client (the plan fixes
 * `response_type`). `logged-out`: the route answered 200 and the session is
 * gone. `logout-refused`: it answered 400 and the session is still there.
 */
const LOGOUT: PlanRun = {
  label: 'back-channel-logout',
  plan: 'oidcc-client-back-channel-logout-rp-basic',
  variant: { ...OIDCC_VARIANT, client_auth_type: 'client_secret_basic', response_mode: 'default' },
  modulePrefix: 'oidcc-client-test-',
  kind: 'logout',
  scope: 'openid profile email',
  expected: {
    'rp-backchannel-rpinitlogout': 'logged-out',
    'rp-backchannel-rpinitlogout-alg-none': 'logout-refused',
    'rp-backchannel-rpinitlogout-no-event': 'logout-refused',
    'rp-backchannel-rpinitlogout-with-nonce': 'logout-refused',
    'rp-backchannel-rpinitlogout-wrong-alg': 'logout-refused',
    'rp-backchannel-rpinitlogout-wrong-aud': 'logout-refused',
    'rp-backchannel-rpinitlogout-wrong-event': 'logout-refused',
    'rp-backchannel-rpinitlogout-wrong-iss': 'logout-refused',
  },
};

const PLAN_NAMES = ['fapi2', 'basic', 'logout'] as const;

/** The runs of this invocation, from CONFORMANCE_PLANS and CONFORMANCE_CLIENT_TYPES. */
function planRuns(): PlanRun[] {
  const runs: PlanRun[] = [];
  for (const name of (process.env.CONFORMANCE_PLANS ?? PLAN_NAMES.join(',')).split(',')) {
    if (name === 'fapi2') {
      for (const type of (process.env.CONFORMANCE_CLIENT_TYPES ?? 'oidc,plain_oauth').split(',')) {
        if (!(type in FAPI2_CLIENT_TYPES)) throw new Error(`Unknown client type ${type}: oidc or plain_oauth`);
        runs.push(fapi2(type as Fapi2ClientType));
      }
    } else if (name === 'basic') runs.push(BASIC);
    else if (name === 'logout') runs.push(LOGOUT);
    else throw new Error(`Unknown plan ${name}: ${PLAN_NAMES.join(', ')}`);
  }
  return runs;
}

/** The row of a module: the suite's verdict, and what the client did. */
interface Row {
  /** The label of the plan's run. */
  run: string;
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
  run: PlanRun,
  input: Input,
  caFile: string,
): Promise<Row> {
  // The module that is the prefix itself, less its dash, keeps its name.
  const name = module.testModule.replace(run.modulePrefix, '');
  const row: Row = {
    run: run.label,
    module: name,
    result: 'ERROR',
    client: '-',
    expected: run.expected[name] ?? '?',
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
    await writeFile(new URL(`logs/${run.label}-${name}.json`, resultsDir), JSON.stringify(log, null, 2));
  } catch (thrown) {
    row.reason = `${row.reason} runner: ${String(thrown)}`.trim();
  }
  return row;
}

/**
 * A module is fine when the suite passed it and the client stopped where the
 * module means it to. A module this file doesn't know fails: every module has
 * to say where the client is meant to stop.
 */
function verdict(row: Row): 'ok' | 'warning' | 'failed' {
  if (row.client !== row.expected) return 'failed';
  if (row.result === 'PASSED' || row.result === 'SKIPPED') return 'ok';
  if (row.result === 'WARNING' || row.result === 'REVIEW') return 'warning';
  return 'failed';
}

function table(rows: Row[]): string {
  const lines = [
    '| Run | Module | Suite | Client stopped at | Expected | |',
    '|---|---|---|---|---|---|',
    ...rows.map((row) => {
      const mark = { ok: '', warning: 'warning', failed: '**FAILED**' }[verdict(row)];
      return `| ${row.run} | ${row.module} | ${row.result} | ${row.client} | ${row.expected} | ${mark} |`;
    }),
  ];
  return lines.join('\n');
}

function details(rows: Row[]): string {
  const parts: string[] = [];
  for (const row of rows) {
    if (!row.reason && row.findings.length === 0) continue;
    parts.push(`### ${row.run} / ${row.module}: ${row.result}`);
    if (row.reason) parts.push(`The client stopped at \`${row.client}\`: ${row.reason}`);
    for (const line of row.findings) parts.push(`- ${line}`);
    parts.push('');
  }
  return parts.join('\n');
}

/** A port nothing listens on at `host`, or `null` when this machine has no such address. */
function freePort(host: string): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRNOTAVAIL') resolve(null);
      else reject(error);
    });
    probe.listen(0, host, () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });
}

/**
 * Where the client's back-channel logout route listens, and the URL the suite
 * posts to. The suite is in a container and the client is not, so the route
 * listens on the address the suite's container has for this machine: the
 * Docker bridge's, which nothing outside the machine can reach.
 */
async function backChannelRoute(external: boolean): Promise<{ listen: Pick<LogoutInput, 'host' | 'port' | 'path'>; uri: string }> {
  const path = '/auth/backchannel-logout';
  // A suite that was started some other way: on this machine unless told otherwise.
  const name = process.env.CONFORMANCE_RP_HOST ?? (external ? 'localhost' : HOST_FROM_SUITE);
  let host = process.env.CONFORMANCE_RP_BIND ?? (external ? '127.0.0.1' : await hostAddressFromSuite());
  let port = await freePort(host);
  if (port === null) {
    // Docker Desktop: the name leads into its virtual machine, which forwards to this machine's loopback.
    host = '127.0.0.1';
    port = await freePort(host);
  }
  if (port === null) throw new Error('No address to listen on for back-channel logout');
  // Plain http: the specification allows it for a confidential client, and it never leaves the machine.
  return { listen: { host, port, path }, uri: `http://${name}:${port}${path}` };
}

/** The client's input and the suite's configuration of that client, for one run of a plan. */
async function setUp(suite: Suite, run: PlanRun, external: boolean): Promise<{ input: Input; config: unknown }> {
  const alias = `fides-auth-${run.label}`;
  const input: Input = {
    kind: run.kind,
    issuer: suite.issuer(alias),
    clientId: 'fides-auth-conformance',
    // Nothing listens here: the client script is the browser, and hands the redirect to the library.
    redirectUri: 'https://rp.fides-auth.test/auth/callback',
    scope: run.scope,
  };
  const client: Record<string, unknown> = { client_id: input.clientId, redirect_uri: input.redirectUri };

  if (run.kind === 'fapi2') {
    // A key of its own for each run. The suite gets the public half, as the client's registered key.
    const keys = await generateKeyPair('ES256', { extractable: true });
    const kid = alias;
    const publicJwk: JWK = { ...(await exportJWK(keys.publicKey)), kid, alg: 'ES256', use: 'sig' };
    input.clientJwk = { ...(await exportJWK(keys.privateKey)), kid, alg: 'ES256' };
    client.scope = input.scope;
    client.jwks = { keys: [publicJwk] };
  } else {
    // A secret of its own for each run, for client_secret_basic.
    input.clientSecret = randomBytes(32).toString('base64url');
    client.client_secret = input.clientSecret;
  }

  if (run.kind === 'logout') {
    const route = await backChannelRoute(external);
    const postLogoutRedirectUri = 'https://rp.fides-auth.test/logged-out';
    input.logout = { ...route.listen, postLogoutRedirectUri };
    client.backchannel_logout_uri = route.uri;
    client.post_logout_redirect_uri = postLogoutRedirectUri;
  }

  return { input, config: { alias, description: `fides-auth, ${run.label}`, client } };
}

const variantText = (variant: Variant) =>
  Object.entries(variant)
    .map(([key, value]) => `${key}=${value}`)
    .join(', ');

async function main(): Promise<number> {
  const external = process.env.CONFORMANCE_SUITE_URL;
  const keep = process.env.CONFORMANCE_KEEP_SUITE === '1';
  const runs = planRuns();

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

    for (const run of runs) {
      const { input, config } = await setUp(suite, run, external !== undefined);
      const plan = await suite.createPlan(run.plan, run.variant, config);
      console.log(`\n${run.label}: ${run.plan} (${variantText(run.variant)}): ${plan.modules.length} modules, plan ${plan.id}`);

      for (const module of plan.modules) {
        const row = await runModule(suite, plan.id, module, run, input, caFile);
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
    '# OpenID conformance suite, relying-party tests',
    '',
    `Suite ${SUITE_RELEASE}.`,
    '',
    '| Run | Plan | Variant |',
    '|---|---|---|',
    ...runs.map((run) => `| ${run.label} | \`${run.plan}\` | ${variantText(run.variant)} |`),
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
  await writeFile(
    new URL('results.json', resultsDir),
    JSON.stringify(
      { suite: SUITE_RELEASE, runs: runs.map(({ label, plan, variant }) => ({ label, plan, variant })), rows },
      null,
      2,
    ),
  );
  console.log(`\n${report}`);
  console.log(`\nWritten to ${resultsDir.pathname}`);

  if (rows.length === 0) return 1;
  return failed.length > 0 ? 1 : 0;
}

process.exitCode = await main().catch((thrown) => {
  console.error(thrown);
  return 2;
});
