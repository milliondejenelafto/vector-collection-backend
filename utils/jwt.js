const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const generateToken = (user) => {
  const payload = {
    id: user._id,
    email: user.email,
    displayName: user.displayName
  };
  console.log("Generating token with payload:", payload);
  return jwt.sign(payload, process.env.SECRET, { expiresIn: '48h' });
};

const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.SECRET);
    console.log('Decoded Token:', decoded);
    return decoded;
  } catch (err) {
    console.error('Token verification failed:', err);
    return null;
  }
};

module.exports = { generateToken, verifyToken };
