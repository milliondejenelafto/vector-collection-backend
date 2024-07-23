const express = require('express');
const router = express.Router();

// Test route
router.get('/', async (req, res) => {
  try {
    const message = "Hello from the server!";
    res.json({ message });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
