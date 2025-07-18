import express from "express";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { User } from "../models/User.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  generateAntiCsrfToken,
} from "../utils/jwt.js";
import { createAuthCookies, clearAuthCookies } from "../utils/cookies.js";
import { resetLimiter } from "../utils/rateLimit.js";
import { authenticate } from "../middleware/auth.js";
import jwt from "jsonwebtoken";
import { log } from "console";
const router = express.Router();
const ORIGIN = process.env.FRONTEND_ORIGIN;
const CSRF_SECRET = process.env.CSRF_SECRET;

// Signup
router.post("/signup", async (req, res) => {
  const { email, password, role } = req.body;

  try {
    // Check if email already exists
    if (await User.findOne({ email })) {
      return res.status(409).json({ error: "Email already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Only allow 'admin' if you’re explicitly assigning it
    // const safeRole = role === "admin" ? "admin" : "user";

    const user = await User.create({
      email,
      passwordHash,
      role,
    });

    res.status(201).json({
      message: "User created",
      user: { email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error during signup" });
  }
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const u = await User.findOne({ email });

    if (!u || !(await bcrypt.compare(password, u.passwordHash)))
      // return res.status(401).json({ error: "Invalid credentials" });
      return res.status(401).json({ error: "INVALID_CREDENTIALS", message: "invalid credentials" });

    const sessionId = crypto.randomUUID();
    u.sessionId = sessionId;
    await u.save();

    const accessToken = signAccessToken({ sub: u.id, role: u.role });
    const refreshToken = signRefreshToken({ sub: u.id, sessionId });
    const antiCsrfToken = generateAntiCsrfToken({ sub: u.id, sessionId });

    const cookies = createAuthCookies({ accessToken, refreshToken });
    res.cookie(
      "accessToken",
      cookies.accessToken.value,
      cookies.accessToken.options
    );
    res.cookie(
      "refreshToken",
      cookies.refreshToken.value,
      cookies.refreshToken.options
    );

    // res.setHeader("Access-Control-Allow-Origin", ORIGIN);
    // res.setHeader("Access-Control-Allow-Credentials", "true");

    console.log("====================================");
    console.log({
      antiCsrfToken,
      user: {
        id: u.id,
        email: u.email,
        role: u.role,
      },
    });
    console.log("====================================");

    return res.json({
      antiCsrfToken,
      user: {
        id: u.id,
        email: u.email,
        role: u.role,
      },
    });
  } catch (e) {
    console.log(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Refresh
router.post("/refresh", async (req, res) => {
  const { refreshToken } = req.cookies;
  const csrf = req.headers["x-csrf-token"]?.toString().trim();

  if (!refreshToken || !csrf) {
    return res.status(401).json({ error: "Missing auth" });
  }

  try {
    // ✅ Verify refreshToken normally
    const decodedRefresh = verifyRefreshToken(refreshToken);

    // ✅ Hybrid: Verify CSRF signature but ignore expiration
    let decodedCsrf;
    try {
      decodedCsrf = jwt.verify(csrf, CSRF_SECRET, { ignoreExpiration: true });
    } catch (err) {
      return res.status(403).json({ error: "Invalid CSRF token signature" });
    }

    // ✅ Match user and session between refresh token and CSRF token
    if (
      decodedRefresh.sub !== decodedCsrf.sub ||
      decodedRefresh.sessionId !== decodedCsrf.sessionId
    ) {
      return res.status(403).json({ error: "CSRF session mismatch" });
    }

    // ✅ Find user and validate session
    const u = await User.findById(decodedRefresh.sub);
    if (!u || u.sessionId !== decodedRefresh.sessionId) {
      return res.status(403).json({ error: "Invalid session" });
    }

    // 🔄 Generate new tokens
    const accessToken = signAccessToken({ sub: u.id, role: u.role });
    const refreshToken2 = signRefreshToken({
      sub: u.id,
      sessionId: u.sessionId,
    });
    const newCsrfToken = generateAntiCsrfToken({
      sub: u.id,
      sessionId: u.sessionId,
    });

    // 🍪 Set cookies
    const cookies = createAuthCookies({
      accessToken,
      refreshToken: refreshToken2,
    });
    res.cookie(
      "accessToken",
      cookies.accessToken.value,
      cookies.accessToken.options
    );
    res.cookie(
      "refreshToken",
      cookies.refreshToken.value,
      cookies.refreshToken.options
    );

    // ✅ Return new anti-CSRF token
    return res.json({
      antiCsrfToken: newCsrfToken,
      user: {
        id: u.id,
        email: u.email,
        role: u.role,
      },
    });
  } catch (err) {
    console.error("Refresh error:", err);
    return res.status(401).json({ error: "Invalid refresh" });
  }
});

// Logout
router.post("/logout", async (req, res) => {
  const { refreshToken } = req.cookies;

  try {
    if (!refreshToken) {
      throw new Error("No refresh token provided");
    }

    console.log("====================================");
    console.log(refreshToken);
    console.log("====================================");

    const decoded = verifyRefreshToken(refreshToken);
    const u = await User.findById(decoded.sub);

    if (u) {
      u.sessionId = null;
      await u.save();
      const cookies = clearAuthCookies();
      res.cookie(
        "accessToken",
        cookies.accessToken.value,
        cookies.accessToken.options
      );
      res.cookie(
        "refreshToken",
        cookies.refreshToken.value,
        cookies.refreshToken.options
      );

      // res.setHeader("Access-Control-Allow-Origin", ORIGIN);
      // res.setHeader("Access-Control-Allow-Credentials", "true");

      return res.status(200).json({ message: "Logout successful" });
    } else {
      throw new Error("User does not exist");
    }
  } catch (err) {
    const cookies = clearAuthCookies();
    res.cookie(
      "accessToken",
      cookies.accessToken.value,
      cookies.accessToken.options
    );
    res.cookie(
      "refreshToken",
      cookies.refreshToken.value,
      cookies.refreshToken.options
    );

    // res.setHeader("Access-Control-Allow-Origin", ORIGIN);
    // res.setHeader("Access-Control-Allow-Credentials", "true");

    return res.status(400).json({ error: err.message || "Logout failed" });
  }
});

// Password reset request
router.post("/request-reset", resetLimiter, async (req, res) => {
  const email = req.body.email?.toLowerCase().trim();
  if (!email) return res.status(400).json({ error: "Email is required" });

  const u = await User.findOne({ email });

  if (u) {
    const token = crypto.randomBytes(32).toString("hex");
    u.resetToken = token;
    u.resetTokenExpires = Date.now() + 15 * 60 * 1000; // 15 mins expiry
    await u.save();

    // TODO: Replace this with actual email sending
    console.log(
      `🔐 Reset link: ${process.env.FRONTEND_ORIGIN}/reset?token=${token}`
    );
  }

  // Always respond the same way for security
  return res.json({
    message:
      "If an account with that email exists, a reset link has been sent.",
  });
});

// Reset password
router.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });
  }

  const u = await User.findOne({
    resetToken: token,
    resetTokenExpires: { $gt: Date.now() },
  });

  if (!u) return res.status(400).json({ error: "Invalid or expired token" });

  u.passwordHash = await bcrypt.hash(newPassword, 10);
  u.resetToken = null;
  u.resetTokenExpires = null;
  u.sessionId = null; // 🔐 Invalidate old sessions

  await u.save();
  res.json({ message: "Password reset successful" });
});

let count = 0 ; 
// get new CSRF
router.get("/session", authenticate(), (req, res) => {
  count++;
  console.log("session called " , count , " times");
  const newCsrf = generateAntiCsrfToken({
    sub: req.user.id,
    sessionId: req.user.sessionId,
  });
  res.json({
    antiCsrfToken: newCsrf,
    user: {
      email: req.user.email,
      role: req.user.role,
    },
  });
});

export default router;
