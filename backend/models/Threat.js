const mongoose = require('mongoose');

const EnrichmentSchema = new mongoose.Schema({
  abuseIPDB: {
    isAbusive: Boolean,
    abuseConfidenceScore: Number,
    totalReports: Number,
    countryCode: String,
    isp: String,
    domain: String,
    lastReportedAt: Date,
  },
  virusTotal: {
    malicious: Number,
    suspicious: Number,
    harmless: Number,
    undetected: Number,
    permalink: String,
  },
  geoIP: {
    lat: Number,
    lng: Number,
    country: String,
    city: String,
    asn: String,
    org: String,
    timezone: String,
  },
  cachedAt: { type: Date, default: Date.now },
}, { _id: false });

const MitreSchema = new mongoose.Schema({
  techniqueId: String,
  techniqueName: String,
  tacticName: String,
  url: String,
}, { _id: false });

const AIExplanationSchema = new mongoose.Schema({
  summary: String,
  what_happened: String,
  why_dangerous: String,
  recommended_action: String,
  eli5_version: String,
  mitre_technique: MitreSchema,
  generatedAt: { type: Date, default: Date.now },
}, { _id: false });

const AnalystActionSchema = new mongoose.Schema({
  action: {
    type: String,
    enum: ['block_ip', 'assign', 'resolve', 'dismiss', 'approve_autonomous'],
    required: true,
  },
  analyst: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  analystName: String,
  note: String,
  metadata: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
}, { _id: true });

const ThreatSchema = new mongoose.Schema({
  // Core detection fields
  threatType: {
    type: String,
    enum: ['brute_force', 'brute_force_ssh', 'brute_force_rdp', 'privilege_escalation', 'lateral_movement', 'exfiltration', 'data_exfiltration', 'impossible_travel', 'malware', 'ransomware_c2', 'sql_injection', 'xss', 'command_injection', 'port_scan', 'dns_tunneling', 'anomalous_login', 'failed_auth', 'unusual_process', 'anomaly', 'other'],
    required: true,
    index: true,
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    required: true,
    index: true,
  },
  riskScore: { type: Number, min: 0, max: 100, required: true, index: true },

  // Status
  status: {
    type: String,
    enum: ['open', 'investigating', 'resolved', 'dismissed', 'false_positive'],
    default: 'open',
    index: true,
  },

  // Network context
  sourceIP: { type: String, index: true },
  destIP: String,
  sourcePort: Number,
  destPort: Number,
  protocol: String,

  // Target context
  targetAsset: String,   // target asset / hostname / resource
  country: String,       // source country code (ISO-2)

  // Identity context
  user: String,
  hostname: String,
  assetCriticality: { type: Number, min: 1, max: 10, default: 5 },

  // Event details
  eventType: String,
  action: String,
  result: String,
  timestamp: { type: Date, required: true, index: true },
  detectedAt: { type: Date, default: Date.now },

  // Raw evidence
  rawLogs: [String],
  normalizedEvents: [mongoose.Schema.Types.Mixed],
  evidenceCount: { type: Number, default: 1 },

  // AI & enrichment
  enrichment: EnrichmentSchema,
  aiExplanation: AIExplanationSchema,
  behaviorVector: [Number], // Gemini embedding

  // Assignment
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assignedToName: String,

  // Analyst actions history
  actions: [AnalystActionSchema],

  // Autonomous response
  autonomousResponsePending: { type: Boolean, default: false },
  autonomousResponseApproved: Boolean,
  firewallRuleDraft: String,
  ticketId: String,

  // False positive ML
  isFalsePositive: { type: Boolean, default: false },
  fpFeatureVector: [Number],

  // Incident grouping
  incidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Incident' },

  // Metadata
  source: { type: String, default: 'log_ingestion' },
  tags: [String],
}, {
  timestamps: true,
  toJSON: { virtuals: true },
});

// Indexes
ThreatSchema.index({ timestamp: -1, severity: 1 });
ThreatSchema.index({ sourceIP: 1, threatType: 1 });
ThreatSchema.index({ status: 1, riskScore: -1 });
ThreatSchema.index({ createdAt: -1 });

// Virtual: age
ThreatSchema.virtual('ageMinutes').get(function () {
  return Math.floor((Date.now() - this.detectedAt) / 60000);
});

module.exports = mongoose.model('Threat', ThreatSchema);