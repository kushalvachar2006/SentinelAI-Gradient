const express = require("express");
const Threat = require("../models/Threat");
const { Blocklist, LogJob } = require("../models/Incident");
const { asyncHandler } = require("../middleware/errorHandler");

const router = express.Router();

/**
 * GET /api/analytics
 * Aggregated stats for charts
 */
router.get(
  "/",
  asyncHandler(async (req, res) => {
    const { from, to, granularity = "day" } = req.query;
    res.set({
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    });

    const dateFilter = {};
    if (from) dateFilter.$gte = new Date(from);
    if (to) dateFilter.$lte = new Date(to);
    const timeRange = Object.keys(dateFilter).length
      ? { timestamp: dateFilter }
      : {};

    const [
      severityBreakdown,
      threatTypeBreakdown,
      statusBreakdown,
      topSourceIPs,
      threatTimeline,
      riskScoreDistribution,
      avgRiskScore,
      totalThreats,
      openCritical,
      blockedIPs,
      recentJobs,
      mttd,
    ] = await Promise.all([
      // Severity breakdown
      Threat.aggregate([
        { $match: timeRange },
        { $group: { _id: "$severity", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      // Threat type breakdown
      Threat.aggregate([
        { $match: timeRange },
        {
          $group: {
            _id: "$threatType",
            count: { $sum: 1 },
            avgRisk: { $avg: "$riskScore" },
          },
        },
        { $sort: { count: -1 } },
      ]),

      // Status breakdown
      Threat.aggregate([
        { $match: timeRange },
        { $group: { _id: "$status", count: { $sum: 1 } } },
      ]),

      // Top attacking source IPs
      Threat.aggregate([
        { $match: { ...timeRange, sourceIP: { $exists: true, $ne: null } } },
        {
          $group: {
            _id: "$sourceIP",
            count: { $sum: 1 },
            maxRisk: { $max: "$riskScore" },
            threatTypes: { $addToSet: "$threatType" },
            lastSeen: { $max: "$timestamp" },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),

      // Threat timeline (by day/hour)
      Threat.aggregate([
        { $match: timeRange },
        {
          $group: {
            _id: {
              $dateToString: {
                format: granularity === "hour" ? "%Y-%m-%dT%H:00" : "%Y-%m-%d",
                date: "$timestamp",
              },
            },
            total: { $sum: 1 },
            critical: {
              $sum: { $cond: [{ $eq: ["$severity", "critical"] }, 1, 0] },
            },
            high: { $sum: { $cond: [{ $eq: ["$severity", "high"] }, 1, 0] } },
            medium: {
              $sum: { $cond: [{ $eq: ["$severity", "medium"] }, 1, 0] },
            },
            low: { $sum: { $cond: [{ $eq: ["$severity", "low"] }, 1, 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),

      // Risk score distribution (histogram buckets)
      Threat.aggregate([
        { $match: timeRange },
        {
          $bucket: {
            groupBy: "$riskScore",
            boundaries: [0, 20, 40, 60, 70, 80, 90, 100],
            default: "other",
            output: { count: { $sum: 1 } },
          },
        },
      ]),

      // Avg risk score
      Threat.aggregate([
        { $match: timeRange },
        {
          $group: {
            _id: null,
            avg: { $avg: "$riskScore" },
            max: { $max: "$riskScore" },
          },
        },
      ]),

      // Total threats
      Threat.countDocuments(timeRange),

      // Open critical count
      Threat.countDocuments({
        ...timeRange,
        severity: "critical",
        status: "open",
      }),

      // Blocked IPs count
      Blocklist.countDocuments({ isActive: true }),

      // Recent ingestion jobs
      LogJob.find().sort({ createdAt: -1 }).limit(5).lean(),

      // Mean time to detect (avg between log timestamp and detectedAt)
      Threat.aggregate([
        {
          $match: { ...timeRange, status: { $in: ["resolved", "dismissed"] } },
        },
        {
          $project: {
            mttdMs: { $subtract: ["$detectedAt", "$timestamp"] },
          },
        },
        {
          $group: {
            _id: null,
            avgMttdMs: { $avg: "$mttdMs" },
          },
        },
      ]),
    ]);

    res.json({
      summary: {
        totalThreats,
        openCritical,
        blockedIPs,
        avgRiskScore: avgRiskScore[0]?.avg?.toFixed(1) || 0,
        maxRiskScore: avgRiskScore[0]?.max || 0,
        meanTimeToDetectMinutes: mttd[0]
          ? Math.round(mttd[0].avgMttdMs / 60000)
          : null,
      },
      charts: {
        severityBreakdown: severityBreakdown.map((s) => ({
          severity: s._id,
          count: s.count,
        })),
        threatTypeBreakdown: threatTypeBreakdown.map((t) => ({
          type: t._id,
          count: t.count,
          avgRisk: Math.round(t.avgRisk),
        })),
        statusBreakdown: statusBreakdown.map((s) => ({
          status: s._id,
          count: s.count,
        })),
        topSourceIPs,
        threatTimeline,
        riskScoreDistribution,
      },
      recentJobs,
    });
  }),
);

/**
 * GET /api/analytics/blocklist
 */
router.get(
  "/blocklist",
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50 } = req.query;
    const [items, total] = await Promise.all([
      Blocklist.find({ isActive: true })
        .populate("addedBy", "name")
        .populate("threatId", "threatType severity riskScore")
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .skip((Number(page) - 1) * Number(limit))
        .lean(),
      Blocklist.countDocuments({ isActive: true }),
    ]);
    res.json({ items, total });
  }),
);

module.exports = router;
