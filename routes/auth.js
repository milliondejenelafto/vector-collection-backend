const express = require('express');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const Vector = require('../models/Vector');
const { ensureAuthenticated } = require('../middleware/auth');

const router = express.Router();

// Handle OPTIONS requests to allow preflight for CORS
router.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

// Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  console.log('User logged in:', req.user);
  res.redirect(`https://main--glowing-sherbet-2fba6c.netlify.app?user=${encodeURIComponent(JSON.stringify(req.user))}`);
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

// File upload
router.post('/upload', ensureAuthenticated, async (req, res) => {
  try {
    console.log('File upload initiated.');

    if (!req.isAuthenticated()) {
      console.log('User not authenticated.');
      return res.status(401).json({ error: 'Unauthorized' });
    }

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
      accessibility,
      fileUrl, // Receiving secure_url from frontend
      fileName, // Optional: if you want to handle file name separately
    } = req.body;

    const newVector = new Vector({
      userId: req.user.id,
      title,
      description,
      fileName: fileName || '', // If fileName is not sent, use empty string or handle as needed
      fileUrl, // Save the secure_url to MongoDB
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

    const savedVector = await newVector.save();

    // Update user's vectors array
    await User.findByIdAndUpdate(req.user.id, { $push: { vectors: savedVector._id } });

    console.log('Vector saved to database:', savedVector);
    res.status(201).json({ message: 'Vector uploaded successfully', vector: savedVector });
  } catch (err) {
    console.error('Error during file upload:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get vectors for authenticated user
router.get('/user-vectors', ensureAuthenticated, async (req, res) => {
  try {
    const vectors = await Vector.find({ userId: req.user.id });
    res.status(200).json(vectors);
  } catch (err) {
    console.error('Error fetching user vectors:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all vectors
router.get('/all-vectors', async (req, res) => {
  try {
    const vectors = await Vector.find();
    res.status(200).json(vectors);
  } catch (err) {
    console.error('Error fetching all vectors:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
