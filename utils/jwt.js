const jwt = require('jsonwebtoken');
// Replace with your own secret key

exports.generateToken = (user) => {
  const payload = { id: user.id, username: user.username };
  return jwt.sign(payload, process.env.SECRET, { expiresIn: '1h' });
};

exports.verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.SECRET);
  } catch (err) {
    return null;
  }
};
