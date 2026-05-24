const rateLimit = require('express-rate-limit');

const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts, please try again later.' },
});

const logIngestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Log ingest rate limit exceeded.' },
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Chat rate limit exceeded.' },
});

module.exports = { globalRateLimiter, authLimiter, logIngestLimiter, chatLimiter };