const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../model/User');

const router = express.Router();

// Render the admin login page
router.get('/adminlogin', (req, res) => {
  res.render('adminlogin');
});

// Handle admin login form submission
router.post('/adminlogin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const normalizedEmail = email.toLowerCase();
    const adminUser = await User.findOne({ email: normalizedEmail });

    if (!adminUser) {
      console.log('Admin login failed: Email not found');
      return res.status(400).render('adminlogin', { message: 'Incorrect email' });
    }

    if (adminUser.role === 'admin' && adminUser.password === password) {
      console.log('Admin login successful');
      
      const token = jwt.sign(
        { id: adminUser._id, role: adminUser.role },
        'your_secret_key',
        { expiresIn: '1h' }
      );

      res.cookie('token', token, { 
        httpOnly: true, 
        sameSite: 'strict', 
        secure: process.env.NODE_ENV === 'production',
      });

      return res.redirect('/admindashboard');
    } else {
      console.log('Admin login failed: Invalid password or role');
      return res.status(401).render('adminlogin', { message: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Error in admin login:', error);
    return res.status(500).render('adminlogin', { message: 'Internal server error' });
  }
});

router.get('/admindashboard', async (req, res) => {
  try {
    const users = await User.find({ role: 'user' });
    res.render('admindashboard', { users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).send('Internal server error');
  }
});
//search bar
router.get('/adminsearch', async (req, res) => {
  const searchQuery = req.query.q; // Get the search query from URL parameters
  
  try {
    // Find users with matching username or email (case-insensitive)
    const users = await User.find({
      role: 'user', // Only search for users with 'user' role
      $or: [
        { username: { $regex: searchQuery, $options: 'i' } }, // Match username
        { email: { $regex: searchQuery, $options: 'i' } }     // Match email
      ]
    });

    // Render the admin dashboard with the search results
    res.render('admindashboard', { users });
    
  } catch (error) {
    // Log and handle any errors
    console.error('Error searching users:', error);
    res.status(500).send('Internal server error');
  }
});

//user update

router.get('/updateUser/:id',async (req,res)=>{
  try{
    const user=await User.findById(req.params.id);//find user id
    if(!user){
      return res.status(404).send('user not found');
    }
    return res.render('updateUser',{user});
  }catch(error){
    console.error('error in user updating',error);
    re.status(500).redirect('admindashboard')
  }
})

router.post('/updateUser/:id',async(req,res)=>{
  const {username,email}=req.body;
  try{
    const user=await User.findByIdAndUpdate(
      req.params.id,
      {username,email},
      {new:true}
    );
    if(!user){
      res.status(404).send('user not found');
    }
    res.redirect('/admindashboard');
  }catch(error){
    console.error('error in user updating',error);
    res.status(500).send('server error');
  }

});
//logout
router.post('/adminlogout',(req,res)=>{
  res.clearCookie('token'); 
  res.redirect('/adminlogin')
})

// userblock and unblock
router.post('/toggleBlockUser/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).send('User not found');
    }

    user.blocked = !user.blocked; // Toggle the blocked status
    await user.save();

    const action = user.blocked ? 'blocked' : 'unblocked';
    console.log(`Admin ${action} user: ${user.username}`);

    res.redirect('/admindashboard'); // Redirect to the admin dashboard
  } catch (error) {
    console.error('Error toggling block status:', error);
    res.status(500).send('Server error');
  }
});


module.exports = router;
