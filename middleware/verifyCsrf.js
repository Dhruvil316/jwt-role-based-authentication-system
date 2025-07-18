import { verifyAntiCsrfToken } from "../utils/jwt.js";

/**
 * Verifies Anti-CSRF token for non-GET requests
 * Requires `req.user` to already be set by the auth middleware
 */
export function verifyCsrf(req, res, next) {
  // Only verify CSRF for state-changing requests
  if (req.method === "GET" || req.method === "HEAD") return next();

  const csrf = req.headers["x-csrf-token"]?.toString().trim();
  if (!csrf) {
    return res
      .status(403)
      .json({ error: "CSRF_MISSING", message: "Missing CSRF token" });
  }

  try {
    const decoded = verifyAntiCsrfToken(csrf);

    // Match user & session from JWT and CSRF token
    if (
      !req.user ||
      decoded.sub !== req.user.id ||
      decoded.sessionId !== req.user.sessionId
    ) {
      return res
        .status(403)
        .json({ error: "CSRF_INVALID", message: "CSRF session mismatch" });
    }

    next();
  } catch (err) {
    return res
      .status(403)
      .json({ error: "CSRF_INVALID", message: "Invalid CSRF token" });
  }
}
