/**
 * Safely extract a human-readable error message from an Axios error.
 *
 * FastAPI / pydantic v2 can return `detail` as:
 *   - a string:  "Error message"
 *   - an array:  [{type, loc, msg, input, url}, ...]
 *   - an object: {msg: "...", ...}
 *
 * If `detail` is an array of pydantic validation errors and we pass it
 * directly to `toast.error()` or render it as `{error}` in JSX, React
 * throws Error #31 ("Objects are not valid as a React child"). This
 * function always returns a plain string.
 */
export function extractErrorDetail(error: any, fallback = 'An error occurred'): string {
  const detail = error?.response?.data?.detail

  if (typeof detail === 'string') return detail

  if (Array.isArray(detail) && detail.length > 0) {
    // Pydantic v2 validation error array — pick the first entry's msg
    const first = detail[0]
    if (typeof first === 'string') return first
    if (first && typeof first === 'object') {
      return first.msg || first.message || JSON.stringify(first)
    }
  }

  if (detail && typeof detail === 'object') {
    return detail.msg || detail.message || JSON.stringify(detail)
  }

  // Fall through to the Axios message or the caller's fallback
  return error?.message || fallback
}
