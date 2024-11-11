const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { SECRET_KEY, EMAIL, EMAIL_PASSWORD } = require('../config/config');

// Email Setup using Nodemailer (replace with your own SMTP credentials)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL,
    pass: EMAIL_PASSWORD,
  },
});

// Sign Up
exports.signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Sign In
exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Sign in successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Forgot Password (Send OTP)
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP and save it in the database
    const otp = crypto.randomInt(1000, 9999).toString();
    const otpExpiration = Date.now() + 20 * 60 * 1000; // OTP expires in 20 minutes

    user.resetPasswordOtp = otp;
    user.resetPasswordOtpExpires = otpExpiration;
    await user.save();

    // Send OTP to user's email
    const mailOptions = {
      from: EMAIL,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It will expire in 20 minutes.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: 'Error sending email' });
      }
      res.json({ message: 'OTP sent to your email' });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Verify OTP (to proceed with password reset)
exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.resetPasswordOtp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (user.resetPasswordOtpExpires < Date.now()) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    res.json({ message: 'OTP verified, proceed to reset password' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Reset Password (after OTP verification)
exports.resetPassword = async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordOtp = undefined;
    user.resetPasswordOtpExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
