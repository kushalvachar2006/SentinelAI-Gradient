// services/queueService.js
const axios = require('axios');
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

// ─── Throttled enrich queue ───────────────────────────────────────────────────
// - Deduplicate by IP so the same IP is only looked up once per job.
// - Cap concurrency to 3 so we don't exhaust Windows file descriptors.
// - Cap total enrichments per job to 50 to keep background work bounded.
const _enrichQueue = [];
const _enrichedIPs = new Set();   // dedup within process lifetime (cached by Python anyway)
let _enrichActive = 0;
const ENRICH_CONCURRENCY = 3;
const ENRICH_MAX_PER_JOB = 50;

function scheduleEnrich(threatId, ip) {
  if (!ip || _enrichedIPs.has(ip)) return;          // already enriched this IP
  if (_enrichQueue.length >= ENRICH_MAX_PER_JOB) return; // cap total queue depth
  _enrichedIPs.add(ip);
  _enrichQueue.push({ threatId, ip });
  _drainEnrichQueue();
}

function _drainEnrichQueue() {
  while (_enrichActive < ENRICH_CONCURRENCY && _enrichQueue.length > 0) {
    const { threatId, ip } = _enrichQueue.shift();
    _enrichActive++;
    enrichThreatAsync(threatId, ip).finally(() => {
      _enrichActive--;
      _drainEnrichQueue();
    });
  }
}

// ─── Main ingestion pipeline ──────────────────────────────────────────────────
async function processLogJob(jobId, logs, source, userId) {
  try {
    await LogJob.findOneAndUpdate({ jobId }, { status: 'processing', startedAt: new Date() });

    const response = await axios.post(
      `${PYTHON_SERVICE_URL}/parse-and-detect`,
      { logs, source, job_id: jobId },
      { timeout: 300000 }
    );

    const { threats_detected, lines_processed } = response.data;

    const VALID_THREAT_TYPES = new Set([
      'brute_force','brute_force_ssh','brute_force_rdp','privilege_escalation',
      'lateral_movement','exfiltration','data_exfiltration','impossible_travel',
      'malware','ransomware_c2','sql_injection','xss','command_injection',
      'port_scan','dns_tunneling','anomalous_login','failed_auth','unusual_process',
      'anomaly','other',
    ]);

    let savedCount = 0;
    for (const threat of threats_detected) {
      try {
        if (threat.threatType && !VALID_THREAT_TYPES.has(threat.threatType)) {
          logger.warn('Unknown threatType normalised to other:', threat.threatType);
          threat.threatType = 'other';
        }

        // Only pass fields the Mongoose schema knows — extra Python fields
        // (description, source, bytes_sent …) cause strict-mode validation errors.
        const safeDoc = {
          threatType:       threat.threatType,
          severity:         (threat.severity || 'low').toLowerCase(),
          riskScore:        Number(threat.riskScore) || 0,
          status:           'open',
          sourceIP:         threat.sourceIP || undefined,
          destIP:           threat.destIP || threat.destip || undefined,
          targetAsset:      threat.targetAsset || threat.target || 'unknown',
          user:             threat.user || undefined,
          hostname:         threat.hostname || undefined,
          assetCriticality: threat.assetCriticality || 5,
          eventType:        threat.eventType || threat.event_type || undefined,
          action:           threat.action || undefined,
          result:           threat.result || undefined,
          timestamp: (() => {
            const d = new Date(threat.timestamp || threat.detectedAt);
            return isNaN(d) ? new Date() : d;
          })(),
          detectedAt:       new Date(),
          rawLogs:          Array.isArray(threat.rawLogs) ? threat.rawLogs : [],
          normalizedEvents: Array.isArray(threat.normalizedEvents) ? threat.normalizedEvents : [],
          evidenceCount:    threat.evidenceCount || 1,
          isFalsePositive:  threat.isFalsePositive || false,
          fpFeatureVector:  threat.fpFeatureVector || [],
        };

        const doc = await Threat.create(safeDoc);
        savedCount++;

        // Emit socket event for critical threats immediately (no AI call needed)
        if (doc.severity === 'critical' || doc.riskScore >= 80) emitNewThreat(doc);

        // Throttled enrichment — max 3 concurrent, queued
        if (doc.sourceIP) scheduleEnrich(doc._id.toString(), doc.sourceIP);

        // AI explanation is on-demand only (analyst clicks "Explain" on a threat).
        // Auto-explaining all ingested threats would exhaust the Gemini free-tier
        // quota and keep the backend running for hours after ingestion completes.

      } catch (itemErr) {
        logger.warn(`Skipping threat (validation error): ${itemErr.message}`, {
          threatType: threat.threatType, severity: threat.severity,
        });
      }
    }

    const completedAt = new Date();
    const job = await LogJob.findOne({ jobId });
    await LogJob.findOneAndUpdate({ jobId }, {
      status: 'completed',
      linesProcessed: lines_processed,
      threatsDetected: savedCount,
      completedAt,
      durationMs: completedAt - (job?.startedAt || completedAt),
    });

    logger.info(`Job ${jobId} complete: ${savedCount} threats saved from ${lines_processed} lines. AI explain queued for critical/high.`);
  } catch (err) {
    logger.error(`Job ${jobId} failed:`, err.message);
    await LogJob.findOneAndUpdate({ jobId }, { status: 'failed', errorMessage: err.message });
  }
}

// ─── Enrichment (IP reputation) ───────────────────────────────────────────────
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

// ─── AI Explanation (Gemini) ──────────────────────────────────────────────────
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
  return {}; // kept for import compatibility
}

module.exports = { initializeQueues, getQueues, emitNewThreat, processLogJob, enrichThreatAsync, explainThreatAsync };