import jwt from "jsonwebtoken";
import { User } from "../models/User.js";

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET;

export function authenticate(roleRequired = null) {
  return async (req, res, next) => {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
      const decoded = jwt.verify(token, ACCESS_SECRET);
      const u = await User.findById(decoded.sub);

      if (!u) return res.status(401).json({ error: "User not found" });
      if (roleRequired && u.role !== roleRequired)
        return res.status(403).json({ error: "Forbidden" });
      req.user = u;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}
