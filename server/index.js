require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const { connectMongo } = require('./config/database');
const { initializeQueues } = require('./services/queueService');
const { setupSocketHandlers } = require('./services/socketService');
const logger = require('./utils/logger');

// Routes
const authRoutes = require('./routes/auth');
const logRoutes = require('./routes/logs');
const threatRoutes = require('./routes/threats');
const analyticsRoutes = require('./routes/analytics');
const chatRoutes = require('./routes/chat');
const reportRoutes = require('./routes/reports');
const approveRoutes = require('./routes/approve');
const demoRoutes = require('./routes/demo');

// Middleware
const { authenticate } = require('./middleware/auth');
const { globalRateLimiter } = require('./middleware/rateLimiter');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const server = http.createServer(app);

const ALLOWED_ORIGINS = [
  process.env.FRONTEND_URL || 'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

// Socket.io setup with CORS
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Make io accessible to routes
app.set('io', io);

// ─── Core Middleware ───────────────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(compression());
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, Postman, same-origin from Vite proxy)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(null, true); // Be permissive in dev
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));
app.use(globalRateLimiter);

// ─── Health Check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'sentinelai-node',
    timestamp: new Date(),
    demoMode: process.env.DEMO_MODE === 'true',
    pythonService: process.env.PYTHON_SERVICE_URL || 'http://localhost:8000',
  });
});

// ─── Public Routes ─────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/demo', demoRoutes);

// ─── Protected Routes ──────────────────────────────────────────────────────────
app.use('/api/logs', authenticate, logRoutes);
app.use('/api/threats', authenticate, threatRoutes);
app.use('/api/analytics', authenticate, analyticsRoutes);
app.use('/api/chat', authenticate, chatRoutes);
app.use('/api/reports', authenticate, reportRoutes);
app.use('/api/approve', authenticate, approveRoutes);

// ─── Error Handler ─────────────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Bootstrap ────────────────────────────────────────────────────────────────
async function bootstrap() {
  const PORT = process.env.PORT || 3001;

  // Try MongoDB — don't crash if unavailable in dev/demo
  try {
    await connectMongo();
    logger.info('MongoDB connected ✓');
  } catch (err) {
    logger.error('⚠️  MongoDB connection failed:', err.message);
    logger.warn('Starting in OFFLINE mode — DB operations will fail gracefully');
  }

  try {
    initializeQueues(io);
    setupSocketHandlers(io);
  } catch (err) {
    logger.warn('Queue/Socket init warning:', err.message);
  }

  server.listen(PORT, () => {
    logger.info(`✅ SentinelAI Node service running on http://localhost:${PORT}`);
    logger.info(`   Demo mode: ${process.env.DEMO_MODE === 'true' ? 'ON' : 'OFF'}`);
    logger.info(`   Python AI: ${process.env.PYTHON_SERVICE_URL || 'http://localhost:8000'}`);
    logger.info(`   Gemini fallback: ${process.env.GEMINI_API_KEY ? 'CONFIGURED ✓' : 'not set'}`);
  });
}

bootstrap();

module.exports = { app, server, io };