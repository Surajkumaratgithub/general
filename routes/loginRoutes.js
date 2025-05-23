import express from "express";
import {
  login,
  verifyOtp,
  changePassword,
  forgotPassword,
  resetPassword,
} from "../controller/loginController.js";
import { sendOtp } from "../controller/sendOtp.js";
import passport from "passport";
import { microsoftLogin } from "../controller/microsoftLoginController.js";
import { isAuth } from "../middleware/authMiddleware.js";
import sessionMiddleware from "../config/sessionConfig.js";

const router = express.Router();
router.get('/microsoft/login', isAuth,
  passport.authenticate('microsoft',{session:false,prompt:'select_account'})
);

router.post('/microsoft/callback', 
    passport.authenticate('microsoft', {
      // temporarly commented
    // failureRedirect: '/auth/failure',
    // successRedirect: '/dashboard' // Or wherever you want
  }),microsoftLogin
);
 router.post("/login", login);
// router.post("/send-otp", sendOtp);
 router.post("/verify-otp", verifyOtp);
router.post("/change-password", changePassword);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);


export default router;
