const jwt = require('jsonwebtoken');
const secretKey = 'your-secret-key'; // Replace with your own secret key

exports.generateToken = (user) => {
  const payload = { id: user.id, username: user.username };
  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
};

exports.verifyToken = (token) => {
  try {
    return jwt.verify(token, secretKey);
  } catch (err) {
    return null;
  }
};
