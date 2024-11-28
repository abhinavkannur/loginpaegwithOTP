// Imports
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../model/User');
const crypto = require('crypto');
const router = express.Router();

const JWT_SECRET = 'your-very-secure-secret-key';

// Signup
router.get('/signup', (req, res) => {
  res.render('signup');
});

router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Validate required fields
    if (!username || !email || !password) {
      return res.status(400).render('signup', { message: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).render('signup', { message: 'Email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Create new user
    const newUser = new User({ username, email, password: hashedPassword, otp });
    await newUser.save();

    // Send OTP via email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'abhinavpp4326@gmail.com', 
        pass: 'tqht njlz yhsz muse', 
      },
    });

    const mailOptions = {
      to: email,
      from: 'your-email@gmail.com', // Change this
      subject: 'OTP Verification',
      text: `Your OTP is: ${otp}`,
    };

    try {
      await transporter.sendMail(mailOptions);
      res.render('otp', { message: null, email });
    } catch (error) {
      console.error(error);
      return res.status(500).render('signup', { message: 'Failed to send OTP' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).render('signup', { message: 'Server error' });
  }
});

// OTP Verification
router.get('/otp', (req, res) => {
  res.render('otp', { message: null, email: null });
});

router.post('/otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('otp', { message: 'User not found', email });
    }

    // Verify OTP
    if (user.otp !== otp) {
      return res.render('otp', { message: 'Invalid or expired OTP', email });
    }

    // Mark user as verified and clear OTP
    user.isVerified = true;
    user.otp = null; // Clear OTP from DB
    await user.save();
    console.log('User verified and OTP cleared:', user);

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies only in production
      sameSite: 'strict',
    });

    res.redirect('/home');
  } catch (error) {
    console.log(error.message);
    return res.status(500).render('otp', { message: 'Server error' });
  }
});

// Home
router.get('/home', async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || !user.isVerified) {
      return res.redirect('/login');
    }
    res.render('home', { user });
  } catch (error) {
    console.log(error);
    res.redirect('/login');
  }
});

// Login
router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log('Login failed: User not found');
      return res.render('login', { message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      console.log('Login failed: User not verified');
      return res.render('login', { message: 'Please verify your email first' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('Login failed: Invalid password');
      return res.render('login', { message: 'Invalid credentials' });
    }

    console.log('Login successful:', user.email);

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production', // Use secure cookies only in production
    });
    res.redirect('/home');
  } catch (error) {
    console.error('Error during login:', error.message);
    res.render('login', { message: 'Server error' });
  }
});

// Logout
router.get('/logout', (req, res) => {
  try {
    res.clearCookie('token');
    res.redirect('/login');
  } catch (error) {
    console.error('Error during logout:', error);
    res.redirect('/home');
  }
});

//user profile

// Route to view the user's profile
router.get('/profile', async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.isVerified) {
      return res.redirect('/login');
    }

    res.render('profile', { user }); // Render profile page with the user object
  } catch (error) {
    console.error('Error fetching user:', error);
    return res.redirect('/login');
  }
});


module.exports = router;
