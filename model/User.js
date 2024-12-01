const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    match: /^[a-zA-Z0-9_ ]+$/,
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    index: true,
    lowercase: true,
    match: [/.+@.+\..+/, 'Invalid email format'],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long'],
    maxlength: [128, 'Password cannot exceed 128 characters'],
  },
  otp: {
    type: String,
    match: [/^\d{6}$/, 'OTP must be a 6-digit number'],
    default: null,
  },
  otpExpires: {
    type: Date,
    default: () => Date.now() + 10 * 60 * 1000, // Expires in 10 minutes
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  blocked: {
    type: Boolean,
    default: false,
  },
  resetPasswordToken: {
    type: String,
    required: false,
  },
  resetPasswordExpires: {
    type: Date,
    required: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});


module.exports = mongoose.model('User', userSchema);
