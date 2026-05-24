const express = require('express');
const axios = require('axios');
const Threat = require('../models/Threat');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { requireRole } = require('../middleware/auth');
const { emitThreatUpdated } = require('../services/socketService');
const logger = require('../utils/logger');

const router = express.Router();
const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

/**
 * GET /api/approve/pending
 * List threats pending autonomous response approval
 */
router.get('/pending', asyncHandler(async (req, res) => {
  const threats = await Threat.find({
    autonomousResponsePending: true,
    autonomousResponseApproved: { $ne: true },
    riskScore: { $gte: 85 },
  })
    .select('threatType severity riskScore sourceIP firewallRuleDraft detectedAt status actions')
    .sort({ riskScore: -1, detectedAt: 1 })
    .lean();

  res.json({ pending: threats, count: threats.length });
}));

/**
 * POST /api/approve/:threatId
 * Approve or reject autonomous agent action
 * Only senior_analyst or admin can approve
 */
router.post(
  '/:threatId',
  requireRole('senior_analyst', 'admin'),
  asyncHandler(async (req, res) => {
    const { decision, note } = req.body; // decision: 'approve' | 'reject'
    if (!['approve', 'reject'].includes(decision)) {
      throw createError('decision must be approve or reject', 400);
    }

    const threat = await Threat.findById(req.params.threatId);
    if (!threat) throw createError('Threat not found', 404);
    if (!threat.autonomousResponsePending) {
      throw createError('No pending autonomous action for this threat', 400);
    }

    threat.autonomousResponseApproved = decision === 'approve';
    threat.autonomousResponsePending = false;
    threat.actions.push({
      action: 'approve_autonomous',
      analyst: req.user._id,
      analystName: req.user.name,
      note: note || `Autonomous action ${decision}d`,
      metadata: { decision },
      timestamp: new Date(),
    });

    if (decision === 'approve') {
      // Trigger autonomous agent execution
      try {
        const agentResp = await axios.post(
          `${PYTHON_SERVICE_URL}/agent/execute-autonomous`,
          {
            threat_id: threat._id.toString(),
            approved_by: req.user._id.toString(),
          },
          { timeout: 30000 }
        );

        threat.ticketId = agentResp.data.ticket_id;
        logger.info(`Autonomous action approved for threat ${threat._id} by ${req.user.email}`);
      } catch (err) {
        logger.error('Autonomous agent execution failed:', err.message);
        throw createError(`Agent execution failed: ${err.message}`, 502);
      }
    }

    await threat.save();

    const io = req.app.get('io');
    emitThreatUpdated(io, threat._id.toString(), {
      type: 'autonomous_decision',
      decision,
      analyst: req.user.name,
    });

    res.json({
      message: `Autonomous action ${decision}d`,
      threatId: threat._id,
      ticketId: threat.ticketId,
    });
  })
);

module.exports = router;