import { createLogger } from '../shared/logger.js';

// The namespace from before the split out of oauth.ts, so existing log filters still match.
const logger = createLogger({ namespace: 'fides-auth:oauth' });

/**
 * Validates a return URL against open redirect attacks.
 * Ensures the URL is same-origin and passes optional custom validation.
 *
 * @param returnTo - The raw returnTo path/URL to validate
 * @param applicationOrigin - The application's origin URL (e.g., 'https://example.com')
 * @param defaultPath - Fallback path if validation fails (default: '/')
 * @param validate - Optional custom validation function for the pathname
 * @returns A safe, validated URL
 */
export function validateReturnUrl(
  returnTo: string | null | undefined,
  applicationOrigin: string,
  defaultPath: string = '/',
  validate?: (pathname: string) => boolean,
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

  // Custom validation
  if (validate && !validate(redirectUrl.pathname)) {
    logger.warn(
      { pathname: redirectUrl.pathname },
      'returnTo failed custom validation, falling back to default',
    );
    return new URL(defaultPath, applicationOrigin);
  }

  return redirectUrl;
}
