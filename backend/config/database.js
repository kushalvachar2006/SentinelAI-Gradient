const mongoose = require('mongoose');
const logger = require('../utils/logger');

let isConnected = false;

async function connectMongo() {
  if (isConnected) return;

  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/sentinelai';

  mongoose.connection.on('connected', () => {
    logger.info('MongoDB connected');
    isConnected = true;
  });

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB error:', err);
  });

  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected, attempting reconnect...');
    isConnected = false;
  });

  await mongoose.connect(uri, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  });
}

async function disconnectMongo() {
  await mongoose.disconnect();
  isConnected = false;
}

module.exports = { connectMongo, disconnectMongo };