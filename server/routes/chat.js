const express = require("express");
const axios = require("axios");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { body, validationResult } = require("express-validator");
const { asyncHandler } = require("../middleware/errorHandler");
const { chatLimiter } = require("../middleware/rateLimiter");
const Threat = require("../models/Threat");
const logger = require("../utils/logger");

const router = express.Router();
const PYTHON_SERVICE_URL =
  process.env.PYTHON_SERVICE_URL || "http://localhost:8000";
const PYTHON_CHAT_TIMEOUT_MS = 180000;
const PYTHON_HEALTH_TIMEOUT_MS = 130000;
const PYTHON_HEALTH_CACHE_MS = 150000;
const PYTHON_FAILURE_COOLDOWN_MS = 300000;

let pythonHealthCache = { checkedAt: 0, available: null };
let pythonServiceDownUntil = 0;
let pythonSkipLoggedUntil = 0;

// ── Initialise SDK once ───────────────────────────────────────────────────────
const genAI = process.env.GEMINI_API_KEY
  ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
  : null;

// Model cascade — each has a separate free-tier quota pool
const GEMINI_MODELS = [
  "gemini-2.5-flash", // Main stable production workhorse (fastest & cheapest)
  "gemini-1.5-flash", // Reliable legacy fallback model
  "gemini-2.5-pro", // Advanced model (slower, but useful for deep reasoning)
];

// ── Call Gemini via SDK with model cascade ────────────────────────────────────
async function callGemini(prompt) {
  if (!genAI) {
    logger.warn("GEMINI_API_KEY not set — skipping AI call");
    return null;
  }

  for (const modelName of GEMINI_MODELS) {
    try {
      const model = genAI.getGenerativeModel({ model: modelName });
      const result = await model.generateContent(prompt);
      const text = result.response.text();
      if (text) {
        logger.info(`Gemini responded via ${modelName}`);
        return text;
      }
    } catch (err) {
      const msg = err.message || "";
      if (msg.includes("429") || msg.includes("RESOURCE_EXHAUSTED")) {
        logger.warn(`Quota exhausted for ${modelName}, trying next model`);
        continue;
      }
      if (msg.includes("404") || msg.includes("NOT_FOUND")) {
        logger.warn(`Model ${modelName} not found, trying next`);
        continue;
      }
      logger.warn(`Gemini error on ${modelName}: ${msg}`);
      continue;
    }
  }

  logger.warn("All Gemini models failed — using rule-based fallback");
  return null;
}

// ── Build context string from live DB threats ─────────────────────────────────
function buildContext(threats) {
  if (!threats.length) return "No threats in the database yet.";
  return threats
    .slice(0, 15)
    .map(
      (t) =>
        `[${(t.severity || "?").toUpperCase()}] ${t.threatType} | IP: ${t.sourceIP || "N/A"} | ` +
        `Score: ${t.riskScore || 0} | Status: ${t.status} | Asset: ${t.targetAsset || "N/A"} | ` +
        `Time: ${t.timestamp ? new Date(t.timestamp).toISOString().slice(11, 19) : "N/A"}`,
    )
    .join("\n");
}

// ── Full AI-powered answer with live DB context ───────────────────────────────
async function askGemini(message, threats, conversationHistory = []) {
  const ctx = buildContext(threats);
  const history = conversationHistory
    .slice(-6)
    .map((m) => `${m.role === "user" ? "Analyst" : "SentinelAI"}: ${m.content}`)
    .join("\n");

  const prompt =
    `You are SentinelAI, an elite SOC AI analyst. Answer the analyst's question using ` +
    `the live alert data below. Reference specific IPs, threat types, and risk scores. ` +
    `Use MITRE ATT&CK terminology. Be concise and actionable.\n\n` +
    (history ? `Prior conversation:\n${history}\n\n` : "") +
    `Live alerts:\n${ctx}\n\n` +
    `Analyst: ${message}`;

  const aiText = await callGemini(prompt);
  return aiText || buildRuleBasedAnswer(message, threats);
}

// ── Rule-based answers using live DB data (always works, no quota) ────────────
function buildRuleBasedAnswer(message, threats) {
  const msg = message.toLowerCase();

  if (!threats.length) {
    return (
      "⚠️ No threats in the database yet.\n\nTo get started:\n" +
      "1. Go to the **Ingest** page\n2. Upload a log file (JSON, CSV, Syslog)\n" +
      "3. Return here to query your threat feed\n\nOr click **Load Demo Data** on the Dashboard."
    );
  }

  const critical = threats.filter((t) => t.severity === "critical");
  const high = threats.filter((t) => t.severity === "high");
  const medium = threats.filter((t) => t.severity === "medium");
  const open = threats.filter((t) => t.status === "open");

  const ipCount = threats.reduce((acc, t) => {
    if (t.sourceIP) acc[t.sourceIP] = (acc[t.sourceIP] || 0) + 1;
    return acc;
  }, {});
  const topIPs = Object.entries(ipCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const typeCount = threats.reduce((acc, t) => {
    if (t.threatType) acc[t.threatType] = (acc[t.threatType] || 0) + 1;
    return acc;
  }, {});
  const topTypes = Object.entries(typeCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const fmt = (s) => (s || "").replace(/_/g, " ");

  if (msg.includes("brute") || msg.includes("ssh") || msg.includes("rdp")) {
    const bf = threats.filter((t) => t.threatType?.includes("brute"));
    if (!bf.length)
      return "No brute-force events detected in the current dataset.";
    return (
      `🔴 **${bf.length} Brute-Force Event(s)**\n\n` +
      bf
        .map(
          (t) =>
            `• ${t.sourceIP} → ${t.targetAsset || "unknown"} | Score: ${t.riskScore} | ${t.status}`,
        )
        .join("\n") +
      "\n\n**Recommended:** Block source IPs, enforce MFA, rotate credentials."
    );
  }

  if (msg.includes("critical")) {
    if (!critical.length) return "✅ No critical threats currently active.";
    return (
      `🚨 **${critical.length} CRITICAL Threat(s) Active**\n\n` +
      critical
        .map(
          (t) =>
            `• **${fmt(t.threatType)}** | ${t.sourceIP} → ${t.targetAsset || "N/A"} | Score: ${t.riskScore}/100 | ${t.status}`,
        )
        .join("\n") +
      "\n\n**Immediate action required.**"
    );
  }

  if (msg.includes("ip") || msg.includes("repeat") || msg.includes("offend")) {
    if (!topIPs.length) return "No source IP data available.";
    return (
      `🌐 **Top Attacking IPs**\n\n` +
      topIPs
        .map(([ip, count], i) => `${i + 1}. \`${ip}\` — ${count} incident(s)`)
        .join("\n") +
      `\n\nConsider blocklisting \`${topIPs[0][0]}\` via Threat Detail → Block IP.`
    );
  }

  if (
    msg.includes("summar") ||
    msg.includes("overview") ||
    msg.includes("today") ||
    msg.includes("status")
  ) {
    const assets = [
      ...new Set(threats.map((t) => t.targetAsset).filter(Boolean)),
    ];
    return (
      `📊 **SOC Threat Summary**\n\n` +
      `| Severity | Count |\n|----------|-------|\n` +
      `| 🔴 Critical | ${critical.length} |\n| 🟠 High | ${high.length} |\n` +
      `| 🟡 Medium | ${medium.length} |\n| 🟢 Low | ${threats.length - critical.length - high.length - medium.length} |\n\n` +
      `**Open incidents:** ${open.length}  **Unique IPs:** ${Object.keys(ipCount).length}\n` +
      `**Top threat:** ${fmt(topTypes[0]?.[0]) || "N/A"}  **Most targeted:** ${assets[0] || "N/A"}`
    );
  }

  if (
    msg.includes("mitre") ||
    msg.includes("t11") ||
    msg.includes("technique") ||
    msg.includes("tactic")
  ) {
    const mitreMap = {
      brute_force: "T1110 — Brute Force",
      brute_force_ssh: "T1110.001 — Password Guessing",
      sql_injection: "T1190 — Exploit Public-Facing Application",
      ransomware_c2: "T1071 — Application Layer Protocol (C2)",
      data_exfiltration: "T1041 — Exfiltration Over C2 Channel",
      privilege_escalation: "T1068 — Exploitation for Privilege Escalation",
      port_scan: "T1046 — Network Service Discovery",
      dns_tunneling: "T1071.004 — DNS Tunneling",
      lateral_movement: "T1021 — Remote Services",
      anomalous_login: "T1078 — Valid Accounts",
      failed_auth: "T1110 — Brute Force",
    };
    const types = [...new Set(threats.map((t) => t.threatType))];
    return (
      `🎯 **MITRE ATT&CK Mapping**\n\n` +
      types
        .map(
          (t) =>
            `• **${fmt(t)}** → ${mitreMap[t] || "T1059 — Command and Scripting Interpreter"}`,
        )
        .join("\n")
    );
  }

  if (msg.includes("asset") || msg.includes("target")) {
    const assets = [
      ...new Set(threats.map((t) => t.targetAsset).filter(Boolean)),
    ];
    const ranked = assets
      .map((a) => {
        const related = threats.filter((t) => t.targetAsset === a);
        return {
          asset: a,
          count: related.length,
          maxRisk: Math.max(...related.map((t) => t.riskScore || 0)),
        };
      })
      .sort((a, b) => b.maxRisk - a.maxRisk);
    return (
      `🖥️ **Targeted Assets**\n\n` +
      ranked
        .slice(0, 8)
        .map(
          (a, i) =>
            `${i + 1}. \`${a.asset}\` — ${a.count} incident(s), max risk: ${a.maxRisk}/100`,
        )
        .join("\n")
    );
  }

  if (
    msg.includes("type") ||
    msg.includes("attack") ||
    msg.includes("pattern")
  ) {
    return (
      `⚔️ **Attack Pattern Breakdown**\n\n` +
      topTypes
        .map(([type, count]) => `• **${fmt(type)}** — ${count} event(s)`)
        .join("\n") +
      `\n\nMost prevalent: **${fmt(topTypes[0]?.[0])}** (${topTypes[0]?.[1]} occurrences)`
    );
  }

  // Default rich summary
  return (
    `📊 **Current Threat Status**\n\n` +
    `🔴 ${critical.length} critical | 🟠 ${high.length} high | ${open.length} open incidents\n\n` +
    `Top threats:\n` +
    threats
      .slice(0, 5)
      .map(
        (t) =>
          `• [${(t.severity || "?").toUpperCase()}] ${fmt(t.threatType)} — ${t.sourceIP} (Score: ${t.riskScore})`,
      )
      .join("\n") +
    `\n\nAsk me about: IPs, assets, MITRE techniques, attack patterns, or summaries.`
  );
}

// ── Check Python service availability ──────────────────────────────────────
async function isPythonServiceAvailable() {
  try {
    const response = await axios.get(`${PYTHON_SERVICE_URL}/health`, {
      timeout: PYTHON_HEALTH_TIMEOUT_MS,
    });
    return response.status === 200;
  } catch {
    return false;
  }
}

async function canUsePythonService() {
  const now = Date.now();
  if (now < pythonServiceDownUntil) {
    if (now >= pythonSkipLoggedUntil) {
      const secondsLeft = Math.ceil((pythonServiceDownUntil - now) / 1000);
      logger.warn(
        `Skipping Python service for ${secondsLeft}s due to recent failure`,
      );
      pythonSkipLoggedUntil = pythonServiceDownUntil;
    }
    return false;
  }

  const cacheFresh =
    pythonHealthCache.available !== null &&
    now - pythonHealthCache.checkedAt < PYTHON_HEALTH_CACHE_MS;
  if (cacheFresh) return pythonHealthCache.available;

  const available = await isPythonServiceAvailable();
  pythonHealthCache = { checkedAt: now, available };
  if (!available) {
    pythonServiceDownUntil = now + PYTHON_FAILURE_COOLDOWN_MS;
  }
  return available;
}

/**
 * POST /api/chat/health
 * Check Python and Gemini service availability
 */
router.get(
  "/health",
  asyncHandler(async (req, res) => {
    const pythonAvailable = await isPythonServiceAvailable();
    const geminiAvailable = !!genAI;

    return res.json({
      python_service: {
        available: pythonAvailable,
        url: PYTHON_SERVICE_URL,
      },
      gemini: {
        available: geminiAvailable,
        configured: !!process.env.GEMINI_API_KEY,
      },
      fallback: "rule-based (always available)",
    });
  }),
);

/**
 * POST /api/chat
 * 1. Try Python service (full RAG + Gemini)
 * 2. Node SDK: gemini-2.5-flash → 2.0-flash-lite → 2.0-flash
 * 3. Rich rule-based answers from live MongoDB
 */
router.post(
  "/",
  chatLimiter,
  [body("message").isString().trim().isLength({ min: 1, max: 2000 })],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { message, conversationHistory = [] } = req.body;

    // 1. Try Python service (with aggressive timeout) ────────────────────────
    const pythonAvailable = await canUsePythonService();
    if (pythonAvailable) {
      try {
        const response = await axios.post(
          `${PYTHON_SERVICE_URL}/agent/chat`,
          {
            message,
            conversation_history: conversationHistory,
            analyst_id: req.user._id.toString(),
            analyst_name: req.user.name,
          },
          { timeout: PYTHON_CHAT_TIMEOUT_MS }, // Reduced from 15s to 8s — fail fast if Python is slow
        );
        logger.info(
          `Python service responded successfully from ${PYTHON_SERVICE_URL}`,
        );
        return res.json(response.data);
      } catch (err) {
        const errorMsg = err.code || err.message || "Unknown error";
        const status = err.response?.status || "N/A";
        const isTimeout =
          err.code === "ECONNABORTED" || err.code === "ETIMEDOUT";
        pythonHealthCache = { checkedAt: Date.now(), available: false };
        pythonServiceDownUntil = Date.now() + PYTHON_FAILURE_COOLDOWN_MS;
        logger.warn(
          `Python service unavailable [${PYTHON_SERVICE_URL}] - ${errorMsg} (status: ${status})${isTimeout ? " [TIMEOUT - Python service may be starting or busy]" : ""}`,
          {
            code: err.code,
            message: err.message,
            url: PYTHON_SERVICE_URL,
            isTimeout,
          },
        );
      }
    }

    // 2 + 3. SDK cascade → rule-based ────────────────────────────────────────
    const threats = await Threat.find({})
      .select(
        "threatType severity riskScore sourceIP targetAsset status timestamp",
      )
      .sort({ riskScore: -1 })
      .limit(30)
      .lean();

    const answer = await askGemini(message, threats, conversationHistory);
    return res.json({ answer, sources_used: threats.length, fallback: true });
  }),
);

module.exports = router;
