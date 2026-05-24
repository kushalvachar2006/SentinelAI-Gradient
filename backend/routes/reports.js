const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { getQueues } = require('../services/queueService');
const { Incident } = require('../models/Incident');

const router = express.Router();
const PYTHON_SERVICE_URL = process.env.PYTHON_SERVICE_URL || 'http://localhost:8000';

/**
 * POST /api/reports/generate
 * Queue PDF report generation for an incident
 */
router.post('/generate', asyncHandler(async (req, res) => {
  const { incidentId } = req.body;
  if (!incidentId) throw createError('incidentId required', 400);

  const incident = await Incident.findById(incidentId);
  if (!incident) throw createError('Incident not found', 404);

  const { reportQueue } = getQueues();
  await reportQueue.add('generate-report', {
    incidentId,
    userId: req.user._id.toString(),
  }, {
    attempts: 2,
    removeOnComplete: 20,
  });

  res.json({ message: 'Report generation queued', incidentId });
}));

/**
 * GET /api/reports/:id
 * Fetch generated PDF report
 */
router.get('/:id', asyncHandler(async (req, res) => {
  const incidentId = req.params.id;

  // Fetch from Python service
  try {
    const response = await axios.get(
      `${PYTHON_SERVICE_URL}/reports/${incidentId}`,
      { responseType: 'arraybuffer', timeout: 30000 }
    );

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="incident-${incidentId}.pdf"`,
      'Content-Length': response.data.length,
    });
    res.send(Buffer.from(response.data));
  } catch (err) {
    if (err.response?.status === 404) {
      throw createError('Report not found or not yet generated', 404);
    }
    throw err;
  }
}));

/**
 * GET /api/reports/:id/markdown
 * Get markdown version of the report
 */
router.get('/:id/markdown', asyncHandler(async (req, res) => {
  const incident = await Incident.findById(req.params.id)
    .populate('threats')
    .populate('leadAnalyst', 'name email');

  if (!incident) throw createError('Incident not found', 404);
  if (!incident.reportMarkdown) throw createError('Report not yet generated', 404);

  res.json({ markdown: incident.reportMarkdown, incidentId: req.params.id });
}));

module.exports = router;