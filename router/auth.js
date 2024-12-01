// Imports
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../model/User');
const crypto = require('crypto');
const { render } = require('ejs');
const router = express.Router();

const JWT_SECRET = 'your-very-secure-secret-key';


  // otp email transform configuration
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'abhinavpp4326@gmail.com', 
      pass: 'tqht njlz yhsz muse', 
    },
  });

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

  

    const mailOptions = {
      to: email,
      from: 'abhinavpp4326@gmail.com', 
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
    if(user.blocked){
      res.render('serverunavailable');
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
  console.log(req.body)

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

    console.log(password)
    console.log(user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log(isPasswordValid)
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

//forgotpassword



router.get('/forgot-password',(req,res)=>{
  const { email } = req.query;  
  res.render('forgot-password');
})

router.post('/forgot-password',async (req,res)=>{
  const {email}=req.body;
  try{
    const user= await User.findOne({email})
    if(!user){
      return res.status(400).message('user not found');
    }
    //otp generating
    const otp=crypto.randomInt(100000,999999).toString();
    user.otp=otp;
    user.otpExpires=Date.now()+15*60*1000;//otp expires in 15minutes
    await user.save();

    const mailOptions = {
      to: email,
      from: 'abhinavpp4326@gmail.com',
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}`,
    };
    await transporter.sendMail(mailOptions);


    res.render('otp-verify',{email});
  }catch(error){
    console.error(error);
    res.status(500).render('otp-verify',{message:'server error',email});
  }
    })

    //forgot password otp verifiaction

router.get('/otp-verify',(req,res)=>{``
  res.render('otp-verify');
});
router.post('/otp-verify',async(req,res)=>{
  const {email,otp}=req.body;
  try{
    const user=await User.findOne({email});
    if(!user || user.otp !==otp ||user.otpExpires<Date.now()){
      return res.render('otp-verify',{message:'invalid or expired otp',email});
    }
    user.otp=null;
    user.otpExpires=null;
    await user.save()
    res.render('set-new-password',{email});
  
  }catch(error){
    console.log(error);
    res.status(500).render('otp-verify',{message:'server error',email});
  }
});

//set new password

router.get('/set-new-password', (req, res) => {
  const { email } = req.query;  // Get email from query params
  res.render('set-new-password', { email });  // Pass the email to the template
});
router.post('/set-new-password', async (req, res) => {
  const { email, 'new-password': newPassword, 'confirm-password': confirmPassword } = req.body;
  // Debugging
  console.log('Received form data:', req.body); 
  console.log('Email for password reset:', email);


  // Validate password match
  if (newPassword !== confirmPassword) {
    return res.render('set-new-password', { message: 'Passwords do not match', email });
  }

  try {
    // Find user by email
    const user = await User.findOne({ email });
    console.log('user found',user)
    if (!user) {
      return res.render('set-new-password', { message: 'User not found', email });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
   console.log('hashhed password:',hashedPassword)
    // Update the user's password
    user.password = hashedPassword;
    await user.save();
    console.log('Password updated successfully for user:', user.email);

    // Redirect to login
    res.redirect('/login');
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).render('set-new-password', { message: 'Server error', email });
  }
});




module.exports = router;
