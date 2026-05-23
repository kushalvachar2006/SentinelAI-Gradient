const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { processLogJob } = require('../services/queueService');
const { LogJob } = require('../models/Incident');
const { logIngestLimiter } = require('../middleware/rateLimiter');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

// Multer config: accept log files up to 100MB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.log', '.txt', '.csv', '.json', '.gz'];
    const ext = '.' + file.originalname.split('.').pop().toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${ext}`));
    }
  },
});

/**
 * Parses file content into an array of log line strings.
 * Handles: JSON arrays, NDJSON (one JSON obj per line), plain text lines.
 */
function parseFileToLogLines(content, filename) {
  const ext = filename.split('.').pop().toLowerCase();

  if (ext === 'json') {
    // Try parsing as a JSON array of objects
    try {
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        // Each element becomes a JSON string line for the Python parser
        return parsed.map(item =>
          typeof item === 'string' ? item : JSON.stringify(item)
        );
      }
      // Single JSON object
      if (typeof parsed === 'object' && parsed !== null) {
        return [JSON.stringify(parsed)];
      }
    } catch (_) {
      // Not valid JSON array — fall through to NDJSON / line-by-line
    }

    // Try NDJSON: one JSON object per line
    const lines = content.split('\n').filter(l => l.trim());
    const ndjsonLines = lines.filter(l => {
      try { JSON.parse(l); return true; } catch (_) { return false; }
    });
    if (ndjsonLines.length > 0) return ndjsonLines;

    // Plain text fallback
    return lines;
  }

  // For all other formats: split by newline
  return content.split('\n').filter(line => line.trim());
}

/**
 * POST /api/logs/ingest
 * Accepts file upload OR JSON payload, dispatches to Python service
 */
router.post(
  '/ingest',
  logIngestLimiter,
  upload.single('logfile'),
  asyncHandler(async (req, res) => {
    const jobId = uuidv4();
    let logs = [];
    let source;
    let filename;
    let fileSize;

    // Normalize source value from frontend format selector to valid enum
    function normalizeSource(raw) {
      const map = {
        syslog: 'syslog',
        aws_cloudtrail: 'aws_cloudtrail',
        custom_json: 'custom_json',
        cef: 'cef',
        leef: 'leef',
        json_payload: 'json_payload',
        api_push: 'api_push',
        file_upload: 'file_upload',
      };
      return map[(raw || '').toLowerCase().replace(/ /g, '_')] || 'file_upload';
    }

    if (req.file) {
      // File upload path
      source = normalizeSource(req.body.source);
      filename = req.file.originalname;
      fileSize = req.file.size;
      const content = req.file.buffer.toString('utf-8');
      logs = parseFileToLogLines(content, filename);
    } else if (req.body.logs) {
      // JSON payload path
      source = 'json_payload';
      logs = Array.isArray(req.body.logs) ? req.body.logs : [req.body.logs];
    } else if (req.body.raw) {
      // Raw log string
      source = 'api_push';
      logs = req.body.raw.split('\n').filter(l => l.trim());
    } else {
      throw createError('Provide either a log file, logs array, or raw log string', 400);
    }

    if (logs.length === 0) throw createError('No log lines found in the uploaded file', 400);
    if (logs.length > 1_000_000) throw createError('Max 1M log lines per ingestion', 400);

    // Create job record
    await LogJob.create({
      jobId,
      status: 'queued',
      source,
      filename,
      fileSize,
      linesTotal: logs.length,
      submittedBy: req.user._id,
    });

    // Fire and forget — don't await so response returns immediately
    processLogJob(jobId, logs, source, req.user._id.toString()).catch(err =>
      logger.error('Background log processing error:', err.message)
    );

    logger.info(`Log job ${jobId} dispatched: ${logs.length} lines from ${req.user.email}`);

    res.status(202).json({
      jobId,
      status: 'queued',
      linesQueued: logs.length,
      message: 'Log ingestion started. Check job status for results.',
      statusUrl: `/api/logs/jobs/${jobId}`,
    });
  })
);

/**
 * GET /api/logs/jobs/:jobId
 * Check ingestion job status
 */
router.get('/jobs/:jobId', asyncHandler(async (req, res) => {
  const job = await LogJob.findOne({ jobId: req.params.jobId })
    .populate('submittedBy', 'name email');

  if (!job) return res.status(404).json({ error: 'Job not found' });

  res.json(job);
}));

/**
 * GET /api/logs/jobs
 * List recent ingestion jobs
 */
router.get('/jobs', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, status } = req.query;
  const filter = {};
  if (status) filter.status = status;

  const jobs = await LogJob.find(filter)
    .populate('submittedBy', 'name email')
    .sort({ createdAt: -1 })
    .limit(Number(limit))
    .skip((Number(page) - 1) * Number(limit));

  const total = await LogJob.countDocuments(filter);

  res.json({ jobs, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
}));

module.exports = router;