const mongoose = require('mongoose');

// ─── Incident Model ────────────────────────────────────────────────────────────
const IncidentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low'],
    required: true,
  },
  status: {
    type: String,
    enum: ['open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed'],
    default: 'open',
  },
  threats: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Threat' }],
  leadAnalyst: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timeline: [{
    event: String,
    actor: String,
    timestamp: { type: Date, default: Date.now },
    metadata: mongoose.Schema.Types.Mixed,
  }],
  reportGenerated: { type: Boolean, default: false },
  reportPath: String,
  reportMarkdown: String,
  affectedAssets: [String],
  iocs: [{
    type: { type: String, enum: ['ip', 'hash', 'domain', 'url', 'email'] },
    value: String,
    context: String,
  }],
  mitreTechniques: [{
    techniqueId: String,
    techniqueName: String,
    tacticName: String,
  }],
  tags: [String],
  closedAt: Date,
  meanTimeToDetect: Number, // minutes
  meanTimeToRespond: Number, // minutes
}, { timestamps: true });

// ─── Blocklist Model ───────────────────────────────────────────────────────────
const BlocklistSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true, index: true },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  addedByAgent: { type: Boolean, default: false },
  threatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Threat' },
  reason: String,
  expiresAt: Date,
  isActive: { type: Boolean, default: true },
  firewallRuleApplied: { type: Boolean, default: false },
  firewallRule: String,
}, { timestamps: true });

// ─── Log Ingestion Job Model ───────────────────────────────────────────────────
const LogJobSchema = new mongoose.Schema({
  jobId: { type: String, required: true, unique: true },
  status: {
    type: String,
    enum: ['queued', 'processing', 'completed', 'failed'],
    default: 'queued',
  },
  source: { type: String, enum: ['file_upload', 'json_payload', 'api_push', 'syslog', 'custom_json', 'aws_cloudtrail', 'cef', 'leef'], required: true },
  filename: String,
  fileSize: Number,
  linesTotal: Number,
  linesProcessed: { type: Number, default: 0 },
  threatsDetected: { type: Number, default: 0 },
  errorMessage: String,
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  startedAt: Date,
  completedAt: Date,
  durationMs: Number,
}, { timestamps: true });

module.exports = {
  Incident: mongoose.model('Incident', IncidentSchema),
  Blocklist: mongoose.model('Blocklist', BlocklistSchema),
  LogJob: mongoose.model('LogJob', LogJobSchema),
};