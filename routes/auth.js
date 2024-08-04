const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const { generateToken, verifyToken } = require('../utils/jwt');
const { ensureAuthenticated } = require('../middleware/auth');
const router = express.Router();

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
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
    }

    const token = generateToken(user);
    res.json({ msg: 'Logged in successfully', user, token });
  })(req, res, next);
});

// Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  // User has been authenticated, generate a JWT
  const token = generateToken(req.user);
  res.redirect(`https://main--glowing-sherbet-2fba6c.netlify.app?token=${token}`);
});

// Check authentication status
router.get('/check-auth', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) {
      return res.status(200).json({ isAuthenticated: true, user: decoded });
    }
  }
  return res.status(401).json({ isAuthenticated: false });
});

// Logout
router.get('/logout', (req, res) => {
  res.status(200).json({ message: 'Logged out successfully' });
});



module.exports = router;
