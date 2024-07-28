const express = require('express');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const Vector = require('../models/Vector');
const upload = require('../middleware/multer'); // Ensure multer middleware is correctly imported
const { ensureAuthenticated } = require('../middleware/auth'); // Ensure auth middleware is correctly imported
const cloudinary = require('../config/cloudinary').default;
require('../config/passport-google')(passport);
require('../config/passport-local')(passport);

const router = express.Router();

// Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  console.log('User logged in:', req.user);
  res.redirect(`http://localhost:8000?user=${encodeURIComponent(JSON.stringify(req.user))}`);
});

// Check authentication status
router.get('/check-auth', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).json({ isAuthenticated: true, user: req.user });
  } else {
    res.status(401).json({ isAuthenticated: false });
  }
});

// Logout
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('connect.sid');
      res.status(200).json({ message: 'Logged out successfully' });
    });
  });
});

// Registration
router.post('/register', [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password must be 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, displayName } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
    }

    user = new User({
      email,
      password,
      displayName
    });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    res.status(201).json({ msg: 'User registered successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Login
router.post('/login', [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists()
], (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      res.json({ msg: 'Logged in successfully', user });
    });
  })(req, res, next);
});

// Vector upload route
router.post('/upload-vector', ensureAuthenticated, upload.single('vector'), async (req, res) => {
  try {
    console.log('File upload initiated.');

    if (!req.isAuthenticated()) {
      console.log('User not authenticated.');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    console.log('User authenticated:', req.user);
    console.log('File information:', req.file);
    console.log('Request body:', req.body);

    const {
      title,
      description,
      category,
      subcategory,
      culture,
      culturalSignificance,
      fileFormat,
      fileSize,
      dimensions,
      tags,
      labels,
      author,
      license,
      usageScenarios,
      accessibility
    } = req.body;

    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: 'raw', // Ensure resource type is set correctly
      folder: 'vectors'
    });

    console.log('Cloudinary upload result:', result);

    const newVector = new Vector({
      userId: req.user.id,
      title,
      description,
      fileName: req.file.originalname,
      fileUrl: result.secure_url,
      category,
      subcategory,
      culture,
      culturalSignificance,
      fileFormat,
      fileSize,
      dimensions,
      tags,
      labels,
      author,
      license,
      usageScenarios,
      accessibility,
      status: 'pending'
    });

    await newVector.save();
    console.log('Vector saved to database:', newVector);
    res.status(201).json({ message: 'Vector uploaded successfully', vector: newVector });
  } catch (err) {
    console.error('Error during file upload:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
