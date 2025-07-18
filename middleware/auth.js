import jwt from "jsonwebtoken";
import { User } from "../models/User.js";

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;

export function authenticate(roleRequired = null) {
  return async (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) {
      return res
        .status(401)
        .json({ error: "NOT_AUTHENTICATED", message: "Missing token" });
    }
    try {
      const decoded = jwt.verify(token, ACCESS_SECRET);
      const u = await User.findById(decoded.sub);
      if (!u) {
        return res
          .status(401)
          .json({ error: "NOT_AUTHENTICATED", message: "User not found" });
      }
      if (roleRequired && u.role !== roleRequired) {
        return res
          .status(403)
          .json({ error: "FORBIDDEN", message: "Insufficient permissions" });
      }
      req.user = u;
      next();
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "TOKEN_EXPIRED", message: "Access token expired" });
      } else {
        return res
          .status(401)
          .json({ error: "INVALID_TOKEN", message: "Invalid access token" });
      }
    }
  };
}

