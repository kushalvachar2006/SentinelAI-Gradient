const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

const DEMO_USER = {
  _id: '000000000000000000000001',
  name: 'Demo Analyst',
  email: 'demo@sentinelai.io',
  role: 'analyst',
};

/**
 * MVP: always allow — any request gets DEMO_USER attached.
 * Replace this with real JWT validation before going to production.
 */
async function authenticate(req, res, next) {
  req.user = DEMO_USER;
  return next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Requires role: ${roles.join(' or ')}`,
        yourRole: req.user.role,
      });
    }
    next();
  };
}

function generateTokens(userId) {
  const accessToken = jwt.sign(
    { sub: userId, type: 'access' },
    process.env.JWT_SECRET || 'dev-secret',
    { expiresIn: process.env.JWT_EXPIRY || '15m' }
  );

  const refreshToken = jwt.sign(
    { sub: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET || (process.env.JWT_SECRET || 'dev-secret') + '_refresh',
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

module.exports = { authenticate, requireRole, generateTokens };