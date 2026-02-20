import { loginSchema, registerSchema } from "../config/zod.js";
import { redisClint } from "../index.js";
import TryCatch from "../middlewares/trycatch.js";
import sanitize from "mongo-sanitize";
import { User } from "../models/user.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import sendMail from "../config/sendMail.js";
import { getOtpHtml, getVerifyEmailHtml } from "../config/html.js";

import { 
  genarateToken, 
  generateAccessToken, 
  revokeRefreshToken, 
  verifyRefreshToken 
} from "../config/genarateToken.js";

import { genarateCSRFToken } from "../config/csrfMiddleware.js";

// ==================== REGISTER ====================
export const registerUser = TryCatch(async (req, res) => {
  const sanitizeBody = sanitize(req.body);
  const validation = registerSchema.safeParse(sanitizeBody);

  if (!validation.success) return res.status(400).json({ message: validation.error });

  const { fullname, email, password } = validation.data;
  const retLimitKey = `register-rate-limit:${req.ip}:${email}`;

  if (await redisClint.get(retLimitKey)) {
    return res.status(429).json({ message: "Too many requests, try again later" });
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: "User already exists" });

  const hashPassword = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(32).toString("hex");
  const verifyKey = `verify:${verifyToken}`;
  const dataToStore = JSON.stringify({ fullname, email, password: hashPassword });

  await redisClint.set(verifyKey, dataToStore, { EX: 300 });

  const subject = "Verify your email for account creation";
  const html = getVerifyEmailHtml({ email, token: verifyToken });
  await sendMail({ email, subject, html });

  await redisClint.set(retLimitKey, "true", { EX: 60 });
  res.json({ message: "Verification email sent. It will expire in 5 minutes." });
});

// ==================== EMAIL VERIFICATION ====================
export const verifyUser = TryCatch(async (req, res) => {
  const { token } = req.params;
  if (!token) return res.status(400).json({ message: "Verification token is required" });

  const verifyKey = `verify:${token}`;
  const userDataJson = await redisClint.get(verifyKey);
  if (!userDataJson) return res.status(400).json({ message: "Verification link expired" });

  await redisClint.del(verifyKey);
  const userData = JSON.parse(userDataJson);

  const existingUser = await User.findOne({ email: userData.email });
  if (existingUser) return res.status(400).json({ message: "User already exists" });

  const newUser = await User.create({
    fullname: userData.fullname,
    email: userData.email,
    password: userData.password,
  });

  res.status(201).json({
    message: "Email verified successfully",
    user: { _id: newUser._id, fullname: newUser.fullname, email: newUser.email },
  });
});

// ==================== LOGIN ====================
export const loginUser = TryCatch(async (req, res) => {
  const sanitizeBody = sanitize(req.body);
  const validation = loginSchema.safeParse(sanitizeBody);
  if (!validation.success) return res.status(400).json({ message: validation.error });

  const { email, password } = validation.data;
  const retLimitKey = `rate-limit:${req.ip}:${email}`;
  if (await redisClint.get(retLimitKey)) return res.status(429).json({ message: "Too many requests" });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Invalid email" });

  const comparePass = await bcrypt.compare(password, user.password);
  if (!comparePass) return res.status(400).json({ message: "Wrong password" });

  // Send OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpKey = `otp:${email}`;
  await redisClint.set(otpKey, JSON.stringify(otp), { EX: 300 });

  const subject = "Your login OTP";
  const html = getOtpHtml({ email, otp });
  await sendMail({ email, subject, html });

  await redisClint.set(retLimitKey, "true", { EX: 60 });
  res.json({ message: "OTP sent, valid for 5 minutes" });
});

// ==================== VERIFY OTP ====================
export const verifyOtp = TryCatch(async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ message: "Invalid data" });

  const otpKey = `otp:${email}`;
  const storedOtpString = await redisClint.get(otpKey);
  if (!storedOtpString) return res.status(400).json({ message: "Expired OTP" });

  const storedOtp = JSON.parse(storedOtpString);
  if (storedOtp !== otp) return res.status(400).json({ message: "Invalid OTP" });

  await redisClint.del(otpKey);
  const user = await User.findOne({ email });
  const tokenData = await genarateToken(user._id, res);

  res.status(200).json({
    message: `Welcome ${user.fullname}`,
    accessToken: tokenData.accessToken,
    refreshToken: tokenData.refreshToken,
    csrfToken: tokenData.csrfToken,
    user,
    sessionInfo: {
      sessionId: tokenData.sessionId,
      loginTime: new Date().toISOString(),
    },
  });
});

// ==================== PROFILE ====================
export const myprofile = TryCatch(async (req, res) => {
  const user = req.user;
  const sessionId = req.sessionId;
  const sessionData = await redisClint.get(`session:${sessionId}`);
  let sessionInfo = null;
  if (sessionData) {
    const parsedSession = JSON.parse(sessionData);
    sessionInfo = {
      sessionId,
      loginTime: parsedSession.createdAt,
      lastActivity: parsedSession.lastActivity,
    };
  }
  res.json({ user, sessionInfo });
});

// ==================== REFRESH TOKEN ====================
export const refreshToken = TryCatch(async (req, res) => {
  const token = req.cookies.refreshToken || req.headers["x-refresh-token"];
  if (!token) return res.status(401).json({ message: "Refresh token missing" });

  const decode = await verifyRefreshToken(token);
  if (!decode) return res.status(401).json({ message: "Session expired, please login" });

  const newAccessToken = generateAccessToken(decode.id, decode.sessionId);
  res.status(200).json({ message: "Token refreshed", accessToken: newAccessToken });
});

// ==================== LOGOUT ====================
export const logoutUser = TryCatch(async (req, res) => {
  const userId = req.user._id;
  await revokeRefreshToken(userId);
  await redisClint.del(`user:${userId}`);
  res.json({ message: "Logout successful" });
});

// ==================== REFRESH CSRF ====================
export const refreshCSRF = TryCatch(async (req, res) => {
  const userId = req.user._id;
  const newCSRFToken = await genarateCSRFToken(userId, res);
  res.json({ message: "CSRF token refreshed", csrfToken: newCSRFToken });
});

// ==================== ADMIN ====================
export const adminController = TryCatch(async (req, res) => {
  res.json({ message: "Hello Admin" });
});

// ==================== FORGOT & RESET PASSWORD ====================
export const frogotPassword = TryCatch(async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Email not found" });

  const resetToken = crypto.randomBytes(32).toString("hex");
  const key = `reset:${resetToken}`;
  await redisClint.set(key, user._id.toString(), { EX: 600 });

  const resetLink = `https://spaytimes.xyz/reset-password/${resetToken}`;
  const html = `<p>Click here to reset password: <a href="${resetLink}">${resetLink}</a> (Expires in 10 min)</p>`;
  await sendMail({ email, subject: "Reset your password", html });

  res.status(200).json({ message: "Reset link sent to email" });
});

export const resetPassword = TryCatch(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!password) return res.status(400).json({ message: "Password required" });

  const key = `reset:${token}`;
  const userId = await redisClint.get(key);
  if (!userId) return res.status(400).json({ message: "Reset link expired" });

  const hash = await bcrypt.hash(password, 10);
  await User.findByIdAndUpdate(userId, { password: hash });
  await redisClint.del(key);

  res.status(200).json({ message: "Password reset successfully" });
});

// ==================== GET USERS ====================
export const getAllUsers = TryCatch(async (req, res) => {
  const users = await User.find({ _id: { $ne: req.user._id } }).select("fullname _id");
  res.json(users);
});

export const getUserById = TryCatch(async (req, res) => {
  const { id } = req.params;
  if (!id.match(/^[0-9a-fA-F]{24}$/)) return res.status(400).json({ message: "Invalid user ID" });

  const user = await User.findById(id).select("-password -__v");
  if (!user) return res.status(404).json({ message: "User not found" });

  res.status(200).json(user);
});