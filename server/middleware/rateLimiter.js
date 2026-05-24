const rateLimit = require('express-rate-limit');

// Shared handler: keeps CORS headers intact when rate limit fires
// Without this, the CORS middleware has already run but express-rate-limit
// short-circuits the response before the headers are copied, so browsers
// report it as a CORS error instead of a 429.
function rateLimitHandler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(429).json({ error: 'Too many requests, please try again later.' });
}

const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

const logIngestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  handler: rateLimitHandler,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  handler: rateLimitHandler,
});

module.exports = { globalRateLimiter, authLimiter, logIngestLimiter, chatLimiter };