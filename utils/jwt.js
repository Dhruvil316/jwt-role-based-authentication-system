import jwt from "jsonwebtoken";
import crypto from "crypto";
import "dotenv/config"

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;

export function signAccessToken(payload) {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: "15m" });
}

export function signRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: "7d" });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

export function generateAntiCsrfToken({ sub, sessionId }) {
  return jwt.sign({ sub, sessionId }, CSRF_SECRET, { expiresIn: "15m" });
}

export function verifyAntiCsrfToken(token) {
  return jwt.verify(token, CSRF_SECRET);
}