import type { FidesLogger } from '../shared/logger.js';

/**
 * Validates a return URL against open redirect attacks: it must resolve on the
 * application's origin, or the default path is used instead.
 *
 * @param logger - Where a refused return URL is reported
 * @param returnTo - The raw returnTo path/URL to validate
 * @param applicationOrigin - The application's origin URL (e.g., 'https://example.com')
 * @param defaultPath - Fallback path if validation fails (default: '/')
 * @returns A safe, validated URL
 */
export function validateReturnUrl(
  logger: FidesLogger,
  returnTo: string | null | undefined,
  applicationOrigin: string,
  defaultPath: string = '/',
): URL {
  const redirectPath = returnTo ?? defaultPath;
  let redirectUrl: URL;

  try {
    redirectUrl = new URL(redirectPath, applicationOrigin);
  } catch {
    logger.warn({ returnTo: redirectPath }, 'Invalid returnTo URL, using default');
    return new URL(defaultPath, applicationOrigin);
  }

  // Enforce same-origin — cross-origin returnTo is a potential open redirect attack
  const originUrl = new URL(applicationOrigin);
  if (redirectUrl.origin !== originUrl.origin) {
    logger.error(
      { returnTo: redirectPath, redirectOrigin: redirectUrl.origin, applicationOrigin: originUrl.origin },
      'Possible open redirect attack: returnTo points outside application origin',
    );
    return new URL(defaultPath, applicationOrigin);
  }

  return redirectUrl;
}
