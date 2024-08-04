// routes/auth.js
const express = require('express');
const User = require('../models/User');
const Vector = require('../models/Vector');
const { ensureAuthenticated } = require('../middleware/auth');

const router = express.Router();

// File upload
router.post('/upload', ensureAuthenticated, async (req, res) => {
  try {
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
router.get('/all-vectors', ensureAuthenticated, async (req, res) => {
  try {
    const vectors = await Vector.find();
    res.status(200).json(vectors);
  } catch (err) {
    console.error('Error fetching all vectors:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
