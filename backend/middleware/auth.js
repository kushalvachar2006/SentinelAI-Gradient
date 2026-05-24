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
 * Verifies JWT and attaches user to req.user.
 * In DEMO_MODE=true, any request (including Bearer demo-token) bypasses auth.
 */
async function authenticate(req, res, next) {
  // Demo bypass — DEMO_MODE env var OR explicit demo token
  if (process.env.DEMO_MODE === 'true') {
    req.user = DEMO_USER;
    return next();
  }

  const authHeader = req.headers.authorization;
  if (authHeader === 'Bearer demo-token') {
    req.user = DEMO_USER;
    return next();
  }

  try {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.slice(7);
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }
      return res.status(401).json({ error: 'Invalid token' });
    }

    const user = await User.findById(decoded.sub).select('-password -mfaSecret');
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    next();
  } catch (err) {
    logger.error('Auth middleware error:', err);
    return res.status(500).json({ error: 'Authentication failed' });
  }
}

/**
 * Require specific role(s)
 */
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

/**
 * Generate JWT token pair
 */
function generateTokens(userId) {
  const accessToken = jwt.sign(
    { sub: userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY || '15m' }
  );

  const refreshToken = jwt.sign(
    { sub: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh',
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

module.exports = { authenticate, requireRole, generateTokens };