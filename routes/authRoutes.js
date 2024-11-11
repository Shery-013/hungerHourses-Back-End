const express = require('express');
const router = express.Router();
const authController = require('../controller/authController');

// Sign Up Route
router.post('/signup', authController.signup);

// Sign In Route
router.post('/signin', authController.signin);

// Forgot Password Route (Send OTP)
router.post('/forgot-password', authController.forgotPassword);

// Verify OTP Route
router.post('/verify-otp', authController.verifyOtp);

// Reset Password Route (After OTP verification)
router.post('/reset-password', authController.resetPassword);

module.exports = router;
