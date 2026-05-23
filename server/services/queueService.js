// services/queueService.js
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const Threat = require('../models/Threat');
const { LogJob } = require('../models/Incident');

const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

let io = null;

function initializeQueues(socketIo) {
  io = socketIo;
  logger.info('Direct HTTP dispatcher initialized (no Redis)');
  return {};
}

/**
 * Process log ingestion directly via HTTP to Python service.
 * Called from routes/logs.js after creating the LogJob record.
 */
async function processLogJob(jobId, logs, source, userId) {
  try {
    await LogJob.findOneAndUpdate({ jobId }, { status: 'processing', startedAt: new Date() });

    const response = await axios.post(
      `${PYTHON_SERVICE_URL}/parse-and-detect`,
      { logs, source, job_id: jobId },
      { timeout: 300000 }
    );

    const { threats_detected, lines_processed } = response.data;

    const VALID_THREAT_TYPES = new Set(['brute_force','brute_force_ssh','brute_force_rdp','privilege_escalation','lateral_movement','exfiltration','data_exfiltration','impossible_travel','malware','ransomware_c2','sql_injection','xss','command_injection','port_scan','dns_tunneling','anomalous_login','failed_auth','unusual_process','anomaly','other']);

    for (const threat of threats_detected) {
      // Normalize threatType — never crash on an unknown value from Python
      if (threat.threatType && !VALID_THREAT_TYPES.has(threat.threatType)) {
        logger.warn('Unknown threatType normalised to other:', threat.threatType);
        threat.threatType = 'other';
      }
      const doc = await Threat.create(threat);

      // Async enrichment — fire and forget, no queue needed
      if (doc.sourceIP) {
        enrichThreatAsync(doc._id.toString(), doc.sourceIP);
      }
      if (['critical', 'high'].includes(doc.severity)) {
        explainThreatAsync(doc._id.toString());
      }
      if (doc.severity === 'critical' || doc.riskScore >= 80) {
        emitNewThreat(doc);
      }
    }

    const completedAt = new Date();
    const job = await LogJob.findOne({ jobId });
    await LogJob.findOneAndUpdate({ jobId }, {
      status: 'completed',
      linesProcessed: lines_processed,
      threatsDetected: threats_detected.length,
      completedAt,
      durationMs: completedAt - (job?.startedAt || completedAt),
    });

    logger.info(`Job ${jobId} complete: ${threats_detected.length} threats from ${lines_processed} lines`);
  } catch (err) {
    logger.error(`Job ${jobId} failed:`, err.message);
    await LogJob.findOneAndUpdate({ jobId }, { status: 'failed', errorMessage: err.message });
  }
}

async function enrichThreatAsync(threatId, ip) {
  try {
    const response = await axios.post(
      `${PYTHON_SERVICE_URL}/enrich`,
      { threat_id: threatId, ip },
      { timeout: 30000 }
    );
    const enrichment = response.data;
    const updated = await Threat.findByIdAndUpdate(threatId, { enrichment }, { new: true });
    if (updated && io) {
      io.to('analysts').emit('threat_updated', { threatId, type: 'enrichment_complete', enrichment });
    }
  } catch (err) {
    logger.warn(`Enrichment failed for ${threatId}:`, err.message);
  }
}

async function explainThreatAsync(threatId) {
  try {
    const threat = await Threat.findById(threatId);
    if (!threat) return;
    const response = await axios.post(
      `${PYTHON_SERVICE_URL}/agent/explain`,
      { threat: threat.toObject() },
      { timeout: 60000 }
    );
    const aiExplanation = response.data;
    await Threat.findByIdAndUpdate(threatId, { aiExplanation });
    if (io) {
      io.to('analysts').emit('threat_updated', { threatId, type: 'ai_explanation_ready', aiExplanation });
    }
  } catch (err) {
    logger.warn(`AI explanation failed for ${threatId}:`, err.message);
  }
}

function emitNewThreat(threat) {
  if (!io) return;
  io.to('analysts').emit('new_threat', {
    id: threat._id,
    threatType: threat.threatType,
    severity: threat.severity,
    riskScore: threat.riskScore,
    sourceIP: threat.sourceIP,
    timestamp: threat.timestamp,
    status: threat.status,
  });
}

function getQueues() {
  return {}; // No queues — kept for import compatibility
}

module.exports = { initializeQueues, getQueues, emitNewThreat, processLogJob, enrichThreatAsync, explainThreatAsync };