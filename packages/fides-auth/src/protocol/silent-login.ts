/**
 * Reading the callback of a silent login, started with `OidcClient.silentLoginUrl`.
 *
 * Silent login (also called "prompt=none") attempts to authenticate the user
 * without any user interaction. This is useful for:
 * - Checking if a user has an active SSO session
 * - Refreshing authentication silently in the background
 * - Implementing "keep me logged in" features
 */

export interface SilentLoginResult {
  /** Whether silent login was successful */
  success: boolean;
  /** The authorization URL to use (only if success is true) */
  authorizationUrl?: URL;
  /** Error message if silent login failed */
  error?: string;
  /** Detailed error description from OAuth provider */
  errorDescription?: string;
}

/**
 * Checks if silent login is possible by examining the callback URL.
 *
 * After redirecting to the silent login URL, the OAuth provider will redirect back
 * with either a code (success) or an error (failure). This function parses the
 * callback URL to determine the result.
 *
 * @param callbackUrl - The URL the OAuth provider redirected to
 * @returns Result indicating success or failure with details
 *
 * @example
 * ```ts
 * // In your OAuth callback handler
 * const result = checkSilentLoginResult(new URL(request.url));
 *
 * if (result.success) {
 *   // User has active SSO session, proceed with token exchange
 *   const code = new URL(request.url).searchParams.get('code');
 *   // ... exchange code for tokens
 * } else if (result.error === 'login_required') {
 *   // User needs to log in interactively
 *   redirect('/login');
 * } else {
 *   // Other error
 *   console.error(result.errorDescription);
 * }
 * ```
 */
export function checkSilentLoginResult(callbackUrl: URL): SilentLoginResult {
  const error = callbackUrl.searchParams.get('error');
  const errorDescription = callbackUrl.searchParams.get('error_description');
  const code = callbackUrl.searchParams.get('code');

  if (error) {
    return {
      success: false,
      error,
      errorDescription: errorDescription ?? undefined,
    };
  }

  if (code) {
    return {
      success: true,
    };
  }

  return {
    success: false,
    error: 'invalid_callback',
    errorDescription: 'Callback URL missing both code and error parameters',
  };
}

/**
 * Common OAuth errors returned from silent login attempts.
 *
 * These can be used to handle specific error cases:
 * - login_required: User must log in interactively
 * - interaction_required: User interaction is needed (e.g., consent)
 * - consent_required: User must grant consent
 * - account_selection_required: User must select an account
 */
export const SilentLoginErrors = {
  LOGIN_REQUIRED: 'login_required',
  INTERACTION_REQUIRED: 'interaction_required',
  CONSENT_REQUIRED: 'consent_required',
  ACCOUNT_SELECTION_REQUIRED: 'account_selection_required',
} as const;

export type SilentLoginError = typeof SilentLoginErrors[keyof typeof SilentLoginErrors];

/**
 * Helper to check if an error requires interactive login.
 *
 * @param error - The error code from the OAuth provider
 * @returns True if the user must log in interactively
 *
 * @example
 * ```ts
 * const result = checkSilentLoginResult(callbackUrl);
 * if (!result.success && requiresInteractiveLogin(result.error)) {
 *   // Redirect to full login page
 *   redirect('/login');
 * }
 * ```
 */
export function requiresInteractiveLogin(error: string | undefined): boolean {
  if (!error) return false;

  return Object.values(SilentLoginErrors).includes(error as SilentLoginError);
}
