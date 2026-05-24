const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

function setupSocketHandlers(io) {
  // JWT auth for socket connections
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.query.token;
      if (!token) return next(new Error('Missing token'));

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.sub;
      socket.userRole = decoded.role;
      next();
    } catch (err) {
      next(new Error('Socket auth failed'));
    }
  });

  io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.id} (user: ${socket.userId})`);

    // Join analyst broadcast room
    socket.join('analysts');

    // Join personal room for user-specific events
    socket.join(`user:${socket.userId}`);

    // Subscribe to specific threat updates
    socket.on('watch_threat', (threatId) => {
      socket.join(`threat:${threatId}`);
      logger.debug(`${socket.id} watching threat ${threatId}`);
    });

    socket.on('unwatch_threat', (threatId) => {
      socket.leave(`threat:${threatId}`);
    });

    // Analyst presence
    socket.on('analyst_active', () => {
      socket.to('analysts').emit('analyst_joined', {
        userId: socket.userId,
        socketId: socket.id,
        timestamp: new Date(),
      });
    });

    socket.on('disconnect', (reason) => {
      logger.info(`Socket disconnected: ${socket.id} (${reason})`);
    });

    socket.on('error', (err) => {
      logger.error(`Socket error (${socket.id}):`, err.message);
    });
  });

  logger.info('Socket.io handlers registered');
}

/**
 * Emit threat_updated event to all room subscribers
 */
function emitThreatUpdated(io, threatId, payload) {
  io.to('analysts').emit('threat_updated', { threatId, ...payload });
  io.to(`threat:${threatId}`).emit('threat_updated', { threatId, ...payload });
}

module.exports = { setupSocketHandlers, emitThreatUpdated };