/**
 * Shared application configuration.
 *
 * API_URL uses a relative path ("/api/v1") by default so that requests
 * are sent to the same host that served the dashboard.  The nginx reverse
 * proxy (see nginx.conf) forwards /api/* to the backend manager container.
 *
 * Override at build time with:
 *   VITE_API_URL=http://some-host:55000/api/v1 npm run build
 */
export const API_URL = import.meta.env.VITE_API_URL || '/api/v1'
