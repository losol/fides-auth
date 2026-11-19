// The conformance suite: starting it with Docker, and the few calls of its API
// a run needs. The API is the one the suite's own scripts/conformance.py uses.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/** The release of the suite the images in docker-compose.yml are pinned to. */
export const SUITE_RELEASE = 'release-v5.3.4';

/** Where the suite of docker-compose.yml listens, and the base of every issuer. */
export const LOCAL_SUITE_URL = 'https://localhost:8443';

const composeFile = new URL('../docker-compose.yml', import.meta.url).pathname;

async function compose(...args: string[]): Promise<string> {
  const { stdout } = await exec('docker', ['compose', '-f', composeFile, ...args], {
    maxBuffer: 64 * 1024 * 1024,
  });
  return stdout;
}

/** Starts the suite's containers, pulling the pinned images when they are not there. */
export async function startSuite(): Promise<void> {
  await compose('up', '--detach', '--wait');
}

/**
 * The certificate the suite's nginx serves, read from its container. It is
 * self-signed, made when the image was built, so this is the one thing to trust.
 */
export function suiteCertificate(): Promise<string> {
  return compose('exec', '-T', 'nginx', 'cat', '/etc/ssl/certs/nginx-selfsigned.crt');
}

/** What the suite's server printed, for the artifact of a run. */
export function suiteLogs(): Promise<string> {
  return compose('logs', '--no-color', 'server');
}

/** Stops the containers and removes them: nothing of a run is kept in Docker. */
export async function stopSuite(): Promise<void> {
  await compose('down', '--volumes');
}

export type Variant = Record<string, string>;

export interface PlanModule {
  testModule: string;
  variant?: Variant;
}

/** A test as the suite reports it. `result` is set once `status` is FINISHED. */
export interface TestInfo {
  status: 'CREATED' | 'CONFIGURED' | 'RUNNING' | 'WAITING' | 'INTERRUPTED' | 'FINISHED' | 'NOT_YET_CREATED' | 'UNKNOWN';
  result?: 'PASSED' | 'WARNING' | 'FAILED' | 'REVIEW' | 'SKIPPED' | 'UNKNOWN';
}

/** A line of a test's log. The ones with a `result` are the checks the suite made. */
export interface LogEntry {
  result?: 'SUCCESS' | 'FAILURE' | 'WARNING' | 'REVIEW' | 'INFO' | 'INTERRUPTED' | 'SKIPPED' | string;
  src?: string;
  msg?: string;
  requirements?: string[];
  [detail: string]: unknown;
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class Suite {
  private readonly base: string;

  constructor(base: string) {
    this.base = base.endsWith('/') ? base : `${base}/`;
  }

  /** The issuer the suite plays for a test with this alias. */
  issuer(alias: string): string {
    return `${this.base}test/a/${alias}/`;
  }

  private async call<T>(method: string, path: string, query: Record<string, string> = {}, body?: unknown): Promise<T> {
    const url = new URL(`api/${path}`, this.base);
    url.search = new URLSearchParams(query).toString();
    const response = await fetch(url, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`The suite answered ${response.status} to ${method} api/${path}: ${text.slice(0, 500)}`);
    return JSON.parse(text) as T;
  }

  /** Waits until the suite answers, database and all. It takes about half a minute to start. */
  async ready(timeoutSeconds = 300): Promise<void> {
    const deadline = Date.now() + timeoutSeconds * 1000;
    let last = '';
    while (Date.now() < deadline) {
      try {
        // The plan listing reads the database, so a server without one isn't ready.
        await this.call('GET', 'plan', { length: '1' });
        return;
      } catch (thrown) {
        last = String((thrown as Error).cause ?? thrown);
      }
      await delay(3000);
    }
    throw new Error(`The suite was not ready after ${timeoutSeconds} s: ${last}`);
  }

  /** Creates a test plan, and returns its id and the modules the variant leaves in it. */
  async createPlan(planName: string, variant: Variant, config: unknown): Promise<{ id: string; modules: PlanModule[] }> {
    return this.call('POST', 'plan', { planName, variant: JSON.stringify(variant) }, config);
  }

  /** Creates one test of a plan. The suite configures it and then waits for the client. */
  async createTest(planId: string, module: PlanModule): Promise<{ id: string }> {
    return this.call('POST', 'runner', {
      test: module.testModule,
      plan: planId,
      ...(module.variant ? { variant: JSON.stringify(module.variant) } : {}),
    });
  }

  info(testId: string): Promise<TestInfo> {
    return this.call('GET', `info/${testId}`);
  }

  log(testId: string): Promise<LogEntry[]> {
    return this.call('GET', `log/${testId}`);
  }

  /** Polls a test until it is in one of `states`, or `null` when it isn't in time. */
  async waitFor(testId: string, states: TestInfo['status'][], timeoutSeconds: number): Promise<TestInfo | null> {
    const deadline = Date.now() + timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      const info = await this.info(testId);
      if (states.includes(info.status)) return info;
      await delay(500);
    }
    return null;
  }
}
