import express from "express";
import { 
  adminController,
  frogotPassword,
  getAllUsers,
  getUserById,
  loginUser,
  logoutUser,
  myprofile,
  refreshCSRF,
  refreshToken,
  registerUser,
  resetPassword,
  verifyOtp,
  verifyUser
} from "../controllers/user.js";

import { authorizedAdmin, isAuth } from "../middlewares/isAuth.js";
import { verifyCSRFToken } from "../config/csrfMiddleware.js";

const router = express.Router();

// Public Routes
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/verify/:token", verifyUser);
router.post("/verify", verifyOtp);
router.post("/forgot-password", frogotPassword);
router.post("/reset-password/:token", resetPassword);

// Protected Routes
router.get("/me", isAuth, myprofile);
router.post("/logout", isAuth, verifyCSRFToken, logoutUser);
router.post("/refresh-csrf", isAuth, refreshCSRF);
router.post("/refresh", refreshToken);
router.get("/users", isAuth, getAllUsers);
router.get("/profile/:id", isAuth, getUserById);

// Admin
router.get("/admin", isAuth, authorizedAdmin, adminController);

export default router;
