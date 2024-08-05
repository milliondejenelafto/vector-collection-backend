const { verifyToken } = require('../utils/jwt');

function ensureAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) {
      req.user = decoded;
      return next();
    }
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

module.exports = {
  ensureAuthenticated
};
