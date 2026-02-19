import express from "express";
import userRoute from "./routes/user.js";
import messageRoute from "./routes/messages.js"
import { createClient } from "redis";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import cookieParser from "cookie-parser";
import cors from "cors"
import {app,server} from "./Socket/Socket.js"
dotenv.config();

const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser())
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials:true,
  methods:["GET","POST","PUT","DELETE","OPTIONS"]
}))
app.use("/api/user", userRoute);
app.use("/api/messsages",messageRoute)
await connectDB();

const redisUrl = process.env.REDIS_URL;

if (!redisUrl) {
  console.log("missing redis");
  process.exit(1);
}

export const redisClint = createClient({
  url: redisUrl,
});

redisClint.on("error", (err) => {
  console.log("Redis error:", err.message);
});

try {
  await redisClint.connect();
  console.log("connected to redis");
} catch (err) {
  console.log("redis connect error:", err.message);
}

server.listen(PORT, () => {
  console.log(`your app is running at http://localhost:${PORT}`);
});
