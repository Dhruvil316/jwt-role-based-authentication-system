import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import { authenticate } from "./middleware/auth.js";

const PORT = process.env.PORT || 8080;
const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN,
    credentials: true,
    allowedHeaders: ["Content-Type", "x-csrf-token"],
  })
);

app.use("/auth", authRoutes);
app.get("/user-dashboard", authenticate("user"), (req, res) => {
  res.json({ message: `Hello ${req.user.email}` });
});
app.get("/admin-only", authenticate("admin"), (req, res) => {
  res.json({ message: `Hello Admin ${req.user.email}` });
});
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error("MongoDB failed:", err));
