// The CSRF guard for state-changing endpoints that a cookie authenticates:
// logout and heartbeat. POST alone is no defence: a page on another site can
// auto-submit a form, and the browser attaches the session cookie. SameSite=Lax
// stops that across sites, but not from a same-site subdomain, so these
// endpoints also check where the request came from.

/**
 * Whether a request comes from the application's own pages.
 *
 * `Sec-Fetch-Site` is authoritative where the browser sends it: `same-origin`,
 * or `none` for a request the user started, such as a bookmark. Without it,
 * `Origin` must equal the application's origin. A request with neither header
 * is not a browser's form post or fetch, and passes: only a browser would
 * attach the victim's cookie.
 *
 * @param applicationUrl - Any URL on the application's public origin.
 */
export function isSameOriginRequest(request: Request, applicationUrl: string): boolean {
  const site = request.headers.get('sec-fetch-site');
  if (site) return site === 'same-origin' || site === 'none';

  const origin = request.headers.get('origin');
  if (!origin) return true;

  try {
    return new URL(origin).origin === new URL(applicationUrl).origin;
  } catch {
    return false;
  }
}
