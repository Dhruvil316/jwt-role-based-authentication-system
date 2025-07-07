import express from "express";
import { clerkAuth } from "./auth.js";
import { User } from "../models/User.js";

const router = express.Router();

router.get("/me", clerkAuth, async (req, res) => {
  const { userId, emailAddresses } = getAuth(req);
  let user = await User.findOne({ clerkId: userId });
  if (!user) {
    const email = emailAddresses?.[0]?.emailAddress;
    user = await User.create({ clerkId: userId, email });
  }
  res.json({ clerk: getAuth(req), role: user.role });
});

export default router;
