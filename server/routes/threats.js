const express = require('express');
const axios = require('axios');
const { body, query, validationResult } = require('express-validator');
const Threat = require('../models/Threat');
const { Blocklist } = require('../models/Incident');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { emitThreatUpdated } = require('../services/socketService');
const logger = require('../utils/logger');

const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';
const router = express.Router();

/**
 * GET /api/threats
 * Paginated threat list with filters
 */
router.get(
  '/',
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 200 }),
    query('severity').optional().isIn(['critical', 'high', 'medium', 'low', 'info']),
    query('status').optional().isIn(['open', 'investigating', 'resolved', 'dismissed', 'false_positive']),
    query('type').optional().isString(),
    query('from').optional().isISO8601(),
    query('to').optional().isISO8601(),
    query('sourceIP').optional().isString(),
    query('assignedTo').optional().isString(),
    query('sort').optional().isIn(['riskScore', 'timestamp', 'detectedAt', 'severity']),
  ],
  asyncHandler(async (req, res) => {
    const {
      page = 1, limit = 25, severity, status, type,
      from, to, sourceIP, assignedTo,
      sort = 'detectedAt', order = 'desc',
    } = req.query;

    const filter = {};
    if (severity) filter.severity = severity;
    if (status) filter.status = status;
    if (type) filter.threatType = type;
    if (sourceIP) filter.sourceIP = { $regex: sourceIP, $options: 'i' };
    if (assignedTo) filter.assignedToName = { $regex: assignedTo, $options: 'i' };
    if (from || to) {
      filter.timestamp = {};
      if (from) filter.timestamp.$gte = new Date(from);
      if (to) filter.timestamp.$lte = new Date(to);
    }

    const sortObj = { [sort]: order === 'asc' ? 1 : -1 };
    const skip = (Number(page) - 1) * Number(limit);

    const [threats, total] = await Promise.all([
      Threat.find(filter)
        .select('-rawLogs -normalizedEvents -behaviorVector -fpFeatureVector')
        .populate('assignedTo', 'name email')
        .sort(sortObj)
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      Threat.countDocuments(filter),
    ]);

    res.json({
      threats,
      pagination: {
        total,
        page: Number(page),
        limit: Number(limit),
        pages: Math.ceil(total / Number(limit)),
      },
      filters: { severity, status, type, from, to, sourceIP },
    });
  })
);

/**
 * GET /api/threats/:id
 * Full threat detail with enrichment
 */
router.get('/:id', asyncHandler(async (req, res) => {
  const threat = await Threat.findById(req.params.id)
    .populate('assignedTo', 'name email')
    .populate('actions.analyst', 'name email')
    .populate('incidentId', 'title status severity');

  if (!threat) throw createError('Threat not found', 404);

  // Check blocklist status
  const isBlocked = await Blocklist.exists({ ip: threat.sourceIP, isActive: true });

  res.json({ threat, isSourceIPBlocked: !!isBlocked });
}));

/**
 * POST /api/threats/:id/action
 * block_ip | assign | resolve | dismiss
 */
router.post(
  '/:id/action',
  [
    body('action').isIn(['block_ip', 'assign', 'resolve', 'dismiss', 'reopen', 'generate_explanation']).withMessage('Invalid action'),
    body('note').optional().isString().trim(),
    body('assignTo').optional().isString(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const threat = await Threat.findById(req.params.id);
    if (!threat) throw createError('Threat not found', 404);

    const { action, note, assignTo } = req.body;
    const analyst = req.user;

    const actionRecord = {
      action,
      analyst: analyst._id,
      analystName: analyst.name,
      note,
      timestamp: new Date(),
    };

    switch (action) {
      case 'block_ip': {
        if (!threat.sourceIP) throw createError('Threat has no source IP', 400);

        // Add to blocklist
        await Blocklist.findOneAndUpdate(
          { ip: threat.sourceIP },
          {
            ip: threat.sourceIP,
            addedBy: analyst._id,
            threatId: threat._id,
            reason: note || `Blocked via threat ${threat._id}`,
            isActive: true,
          },
          { upsert: true, new: true }
        );

        // Notify Python agent to draft firewall rule
        try {
          const fwResp = await axios.post(
            `${PYTHON_SERVICE_URL}/agent/draft-firewall-rule`,
            { ip: threat.sourceIP, threat_id: threat._id.toString() },
            { timeout: 10000 }
          );
          actionRecord.metadata = { firewallRule: fwResp.data.rule };
          threat.firewallRuleDraft = fwResp.data.rule;
        } catch (err) {
          logger.warn('Firewall rule draft failed:', err.message);
        }

        threat.status = 'investigating';
        break;
      }

      case 'assign': {
        threat.assignedToName = assignTo || analyst.name;
        threat.assignedTo = analyst._id;
        threat.status = threat.status === 'open' ? 'investigating' : threat.status;
        actionRecord.metadata = { assignedTo: assignTo || analyst.name };
        break;
      }

      case 'resolve': {
        threat.status = 'resolved';
        break;
      }

      case 'dismiss': {
        threat.status = 'dismissed';
        threat.isFalsePositive = true;

        // Report false positive to Python agent (trains IsolationForest)
        try {
          await axios.post(`${PYTHON_SERVICE_URL}/feedback/false-positive`, {
            threat_id: threat._id.toString(),
            threat_type: threat.threatType,
            feature_vector: threat.fpFeatureVector,
          }, { timeout: 5000 });
        } catch (err) {
          logger.warn('FP feedback send failed:', err.message);
        }
        break;
      }

      case 'reopen': {
        threat.status = 'investigating';
        threat.isFalsePositive = false;
        break;
      }

      case 'generate_explanation': {
        // Trigger async AI explanation via Python or Node fallback
        const { explainThreatAsync } = require('../services/queueService');
        setImmediate(() => explainThreatAsync && explainThreatAsync(threat._id.toString()));
        break;
      }
    }

    threat.actions.push(actionRecord);
    await threat.save();

    // Emit real-time update
    const io = req.app.get('io');
    emitThreatUpdated(io, threat._id.toString(), {
      type: 'analyst_action',
      action,
      analyst: analyst.name,
      status: threat.status,
      timestamp: actionRecord.timestamp,
    });

    logger.info(`Threat ${threat._id}: action=${action} by ${analyst.email}`);
    res.json({ threat, action, message: `Action '${action}' applied successfully` });
  })
);

/**
 * GET /api/threats/:id/similar
 * Find similar threats via Gemini embeddings
 */
router.get('/:id/similar', asyncHandler(async (req, res) => {
  const response = await axios.post(
    `${PYTHON_SERVICE_URL}/agent/fingerprint`,
    { threat_id: req.params.id },
    { timeout: 30000 }
  );
  res.json(response.data);
}));

/**
 * GET /api/threats/:id/predict
 * Predict next attack window
 */
router.get('/:id/predict', asyncHandler(async (req, res) => {
  const threat = await Threat.findById(req.params.id).lean();
  if (!threat) throw createError('Threat not found', 404);

  // Gather historical timestamps for same type + source
  const historical = await Threat.find({
    threatType: threat.threatType,
    sourceIP: threat.sourceIP,
    status: { $ne: 'dismissed' },
  })
    .select('timestamp riskScore')
    .sort({ timestamp: 1 })
    .limit(50)
    .lean();

  const response = await axios.post(
    `${PYTHON_SERVICE_URL}/agent/predict`,
    {
      threat_type: threat.threatType,
      source_ip: threat.sourceIP,
      historical_timestamps: historical.map(h => h.timestamp),
    },
    { timeout: 30000 }
  );

  res.json(response.data);
}));

module.exports = router;