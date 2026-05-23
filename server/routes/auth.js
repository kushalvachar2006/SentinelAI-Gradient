const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { generateTokens, authenticate } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

// POST /api/auth/register
router.post(
  '/register',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be 8+ chars'),
    body('name').trim().isLength({ min: 2 }),
    body('role').optional().isIn(['analyst', 'senior_analyst', 'admin']),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, name, role } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const user = await User.create({ email, password, name, role: role || 'analyst' });
    const tokens = generateTokens(user._id.toString());

    logger.info(`New analyst registered: ${email}`);
    res.status(201).json({ user: user.toSafeObject(), ...tokens });
  })
);

// POST /api/auth/login
router.post(
  '/login',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Account deactivated' });
    }

    user.lastLogin = new Date();
    await user.save();

    const tokens = generateTokens(user._id.toString());
    logger.info(`Analyst login: ${email}`);
    res.json({ user: user.toSafeObject(), ...tokens });
  })
);

// POST /api/auth/refresh
router.post('/refresh', asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  const jwt = require('jsonwebtoken');
  let decoded;
  try {
    decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + '_refresh'
    );
  } catch {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  const user = await User.findById(decoded.sub);
  if (!user || !user.isActive) return res.status(401).json({ error: 'User not found' });

  const tokens = generateTokens(user._id.toString());
  res.json(tokens);
}));

// GET /api/auth/me
router.get('/me', authenticate, asyncHandler(async (req, res) => {
  res.json({ user: req.user.toSafeObject() });
}));

// POST /api/auth/logout
router.post('/logout', authenticate, asyncHandler(async (req, res) => {
  // In production, add token to Redis blocklist
  res.json({ message: 'Logged out successfully' });
}));

module.exports = router;