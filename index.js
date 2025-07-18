import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import { authenticate } from "./middleware/auth.js";
import { verifyCsrf } from "./middleware/verifyCsrf.js";

const PORT = process.env.PORT || 8080;
const app = express();
app.use(express.json());
app.use(cookieParser());

console.log(process.env.FRONTEND_ORIGIN);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:3000";

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    allowedHeaders: ["Content-Type", "x-csrf-token"],
  })
);

app.use("/auth", authRoutes);
app.get("/user-dashboard", authenticate("user"), verifyCsrf, (req, res) => {
  res.json({ message: `Hello ${req.user.email}` });
});
app.get("/admin-only", authenticate("admin"), verifyCsrf, (req, res) => {
  res.json({ message: `Hello Admin ${req.user.email}` });
});
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error("MongoDB failed:", err));
