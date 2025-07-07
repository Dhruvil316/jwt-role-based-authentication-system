// import express from "express";
// import { clerkAuth, requireRole } from "./auth.js";
// import User from "../models/user.js";
// import { clerkClient } from "@clerk/express";
// import { getAuth } from "@clerk/express";

// const router = express.Router();

// router.use([...clerkAuth, requireRole("admin")]);

// router.get("/users", async (req, res) => {
//   const users = await User.find();
//   res.json(users);
// });

// router.post("/set-role", express.json(), async (req, res) => {
//   const { clerkId, role } = req.body;
//   if (!["admin", "user"].includes(role)) {
//     return res.status(400).json({ error: "Invalid role" });
//   }

//   await User.updateOne({ clerkId }, { role });
//   await clerkClient.users.updateUserMetadata(clerkId, {
//     publicMetadata: { role },
//   });
//   res.json({ message: "Updated", clerkId, role });
// });

// export default router;
