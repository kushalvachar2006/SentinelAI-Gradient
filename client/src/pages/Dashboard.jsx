import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { format } from "date-fns";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  AlertTriangle,
  Eye,
  X,
  RefreshCw,
  Activity,
  Shield,
} from "lucide-react";
import Navbar from "../components/layout/Navbar";
import {
  SeverityBadge,
  PulseDot,
  MetricCard,
} from "../components/ui/SeverityBadge";
import SlideOver from "../components/dashboard/SlideOver";
import { useStore } from "../store/useStore";

function RealTimeClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const i = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(i);
  }, []);
  return (
    <div
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "13px",
        textAlign: "right",
      }}
    >
      <div
        style={{
          color: "var(--eclipse)",
          fontWeight: 700,
          textShadow: "0 0 12px rgba(255,107,0,0.5)",
          fontFamily: "var(--font-display)",
          fontSize: "15px",
        }}
      >
        {format(time, "HH:mm:ss")}
      </div>
      <div
        style={{
          fontSize: "10px",
          color: "var(--text-muted)",
          letterSpacing: "0.05em",
        }}
      >
        {format(time, "dd MMM yyyy")} UTC
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: "rgba(20,20,20,0.95)",
        border: "1px solid rgba(255,107,0,0.2)",
        borderRadius: "var(--radius-md)",
        padding: "10px 14px",
        fontSize: "12px",
        fontFamily: "var(--font-mono)",
        boxShadow: "0 0 20px rgba(255,107,0,0.1)",
      }}
    >
      <div style={{ color: "var(--text-muted)", marginBottom: "6px" }}>
        {label}
      </div>
      {payload.map((p) => (
        <div key={p.dataKey} style={{ color: p.stroke, marginBottom: "2px" }}>
          {p.dataKey}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

const FILTER_OPTIONS = [
  { key: "ALL", label: "All alerts" },
  { key: "CRITICAL", label: "Critical" },
  { key: "HIGH", label: "High" },
  { key: "MEDIUM", label: "Medium" },
  { key: "LOW", label: "Low" },
];
const FILTER_COLORS = {
  ALL: "var(--text-secondary)",
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};
const SEVERITY_COLORS = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

const toTitle = (value) => {
  if (!value) return "Unknown alert";
  return String(value)
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
};

const getSeverity = (value) => String(value || "LOW").toUpperCase();

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const buildAlertSummary = (threat) => {
  if (!threat) return "No alerts yet. Upload logs to see activity.";
  const type = toTitle(threat.threatType || threat.eventType || "Alert");
  const target = threat.targetAsset || threat.target || "a system";
  const source = threat.sourceIP || threat.sourceIp;
  const sourceText = source ? ` from ${source}` : "";
  return `${type} on ${target}${sourceText}`;
};

const getThreatTimestamp = (threat) => {
  const value =
    threat?.timestamp ||
    threat?.createdAt ||
    threat?.created_at ||
    threat?.time ||
    threat?.date;
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const buildTrendSeries = (threats) => {
  if (!Array.isArray(threats) || threats.length === 0) {
    return { trendData: [], trendRangeLabel: "NO DATA" };
  }

  const withTime = threats
    .map((threat) => ({
      time: getThreatTimestamp(threat),
      severity: getSeverity(threat?.severity),
    }))
    .filter((entry) => entry.time);

  if (!withTime.length) {
    return { trendData: [], trendRangeLabel: "NO DATA" };
  }

  const maxTime = withTime.reduce(
    (max, entry) => (entry.time > max ? entry.time : max),
    withTime[0].time,
  );
  const minTime = withTime.reduce(
    (min, entry) => (entry.time < min ? entry.time : min),
    withTime[0].time,
  );
  const useHourly = maxTime - minTime <= 24 * 60 * 60 * 1000;
  const bucketSizeMs = useHourly ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  const bucketCount = useHourly ? 24 : 7;

  const endBucketStart = new Date(maxTime);
  if (useHourly) {
    endBucketStart.setMinutes(0, 0, 0);
  } else {
    endBucketStart.setHours(0, 0, 0, 0);
  }
  const startTime = new Date(
    endBucketStart.getTime() - (bucketCount - 1) * bucketSizeMs,
  );

  const buckets = Array.from({ length: bucketCount }, () => ({
    total: 0,
    critical: 0,
  }));

  withTime.forEach((entry) => {
    const index = Math.floor((entry.time - startTime) / bucketSizeMs);
    if (index < 0 || index >= bucketCount) return;
    buckets[index].total += 1;
    if (entry.severity === "CRITICAL") buckets[index].critical += 1;
  });

  const trendData = buckets.map((bucket, index) => {
    const bucketTime = new Date(startTime.getTime() + index * bucketSizeMs);
    return {
      label: useHourly ? format(bucketTime, "HH:mm") : format(bucketTime, "MMM d"),
      total: bucket.total,
      critical: bucket.critical,
    };
  });

  return {
    trendData,
    trendRangeLabel: useHourly ? "LAST 24 HOURS" : "LAST 7 DAYS",
  };
};

const buildAssetSeries = (threats) => {
  if (!Array.isArray(threats) || threats.length === 0) return [];

  const byAsset = new Map();

  threats.forEach((threat) => {
    const name =
      threat?.targetAsset ||
      threat?.target ||
      threat?.asset ||
      threat?.destination ||
      threat?.host ||
      "Unknown asset";
    const severity = getSeverity(threat?.severity);
    const current = byAsset.get(name) || {
      name,
      count: 0,
      severity: "LOW",
    };

    current.count += 1;
    if ((severityRank[severity] || 0) > (severityRank[current.severity] || 0)) {
      current.severity = severity;
    }
    byAsset.set(name, current);
  });

  return [...byAsset.values()]
    .sort((a, b) => b.count - a.count || (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
    .slice(0, 5)
    .map((asset) => ({
      ...asset,
      label: asset.count === 1 ? "1 alert" : `${asset.count} alerts`,
    }));
};

export default function Dashboard() {
  const navigate = useNavigate();
  const {
    threats: allThreats,
    filteredThreats,
    activeFilter,
    setFilter,
    setSelectedThreat,
    dismissThreat,
    counts,
    refreshThreats,
  } = useStore();
  const threats = filteredThreats();
  const c = counts();
  const totalAlerts = c.CRITICAL + c.HIGH + c.MEDIUM + c.LOW;
  const topThreat = threats[0];
  const highlightSeverity = getSeverity(topThreat?.severity);
  const highlightColor =
    FILTER_COLORS[highlightSeverity] || "var(--text-secondary)";

  const { trendData, trendRangeLabel } = buildTrendSeries(allThreats);
  const assetData = buildAssetSeries(allThreats);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg-base)",
        paddingTop: "60px",
      }}
    >
      <Navbar />
      <SlideOver />

      {/* Ambient background */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 0,
          pointerEvents: "none",
          background:
            "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(255,107,0,0.04) 0%, transparent 60%)",
        }}
      />

      {/* Top bar */}
      <div
        style={{
          padding: "14px 28px",
          borderBottom: "1px solid rgba(255,107,0,0.08)",
          display: "flex",
          alignItems: "center",
          gap: "16px",
          background: "rgba(20,20,20,0.8)",
          backdropFilter: "blur(12px)",
          position: "relative",
          zIndex: 10,
        }}
      >
        <div>
          <div
            style={{
              fontSize: "10px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.12em",
              marginBottom: "2px",
            }}
          >
            SECURITY OVERVIEW
          </div>
          <div
            style={{
              fontSize: "16px",
              fontWeight: 600,
              color: "var(--text-primary)",
              fontFamily: "var(--font-ui)",
            }}
          >
            Apex Corp — Security Dashboard
          </div>
          <div
            style={{
              fontSize: "11px",
              color: "var(--text-muted)",
              marginTop: "2px",
              fontFamily: "var(--font-ui)",
            }}
          >
            A simple view of what needs attention right now.
          </div>
        </div>
        <div style={{ flex: 1 }} />

        <div
          style={{
            flex: 1,
            overflow: "hidden",
            maxWidth: "460px",
            background: "rgba(255,107,0,0.03)",
            border: "1px solid rgba(255,107,0,0.08)",
            borderRadius: "var(--radius-sm)",
            padding: "8px 12px",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
            }}
          >
            <AlertTriangle size={14} color={highlightColor} />
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  fontSize: "10px",
                  color: "var(--text-muted)",
                  letterSpacing: "0.08em",
                  fontFamily: "var(--font-mono)",
                  marginBottom: "2px",
                }}
              >
                TOP PRIORITY
              </div>
              <div
                style={{
                  fontSize: "12px",
                  color: "var(--text-primary)",
                  fontFamily: "var(--font-ui)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {buildAlertSummary(topThreat)}
              </div>
            </div>
          </div>
        </div>

        <div
          style={{
            background: "rgba(255,255,255,0.02)",
            border: "1px solid rgba(255,107,0,0.08)",
            borderRadius: "var(--radius-sm)",
            padding: "6px 10px",
            textAlign: "right",
            minWidth: "96px",
          }}
        >
          <div
            style={{
              fontSize: "9px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.08em",
            }}
          >
            OPEN ALERTS
          </div>
          <div
            style={{
              fontSize: "16px",
              fontWeight: 700,
              color: "var(--text-primary)",
              fontFamily: "var(--font-display)",
            }}
          >
            {String(totalAlerts).padStart(2, "0")}
          </div>
        </div>
        <RealTimeClock />
      </div>

      {/* Metric cards */}
      <div
        style={{
          padding: "20px 28px 0",
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "14px",
          position: "relative",
          zIndex: 1,
        }}
      >
        <MetricCard
          label="Critical alerts"
          count={c.CRITICAL}
          severity="CRITICAL"
        />
        <MetricCard label="High alerts" count={c.HIGH} severity="HIGH" />
        <MetricCard label="Medium alerts" count={c.MEDIUM} severity="MEDIUM" />
        <MetricCard label="Low alerts" count={c.LOW} severity="LOW" />
      </div>
      <div
        style={{
          padding: "8px 28px 0",
          fontSize: "12px",
          color: "var(--text-muted)",
          position: "relative",
          zIndex: 1,
        }}
      >
        Start with Critical and High alerts. Click any alert to see details and
        recommended actions.
      </div>

      {/* Main grid */}
      <div
        style={{
          padding: "20px 28px",
          display: "grid",
          gridTemplateColumns: "60% 1fr",
          gap: "18px",
          alignItems: "start",
          position: "relative",
          zIndex: 1,
        }}
      >
        {/* LEFT: Threat Feed */}
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid rgba(255,107,0,0.1)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
            boxShadow: "var(--shadow-card)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              padding: "16px 18px 8px",
            }}
          >
            <AlertTriangle size={16} color="var(--eclipse)" />
            <div>
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  fontFamily: "var(--font-ui)",
                }}
              >
                Recent alerts
              </div>
              <div
                style={{
                  fontSize: "11px",
                  color: "var(--text-muted)",
                  fontFamily: "var(--font-ui)",
                }}
              >
                Click an alert to see details and next steps.
              </div>
            </div>
          </div>
          {/* Filter tabs */}
          <div
            style={{
              display: "flex",
              gap: "4px",
              padding: "14px 18px",
              borderBottom: "1px solid rgba(255,107,0,0.08)",
              background: "rgba(255,107,0,0.02)",
              alignItems: "center",
            }}
          >
            {FILTER_OPTIONS.map(({ key, label }) => {
              const active = activeFilter === key;
              const col = FILTER_COLORS[key];
              return (
                <button
                  key={key}
                  onClick={() => setFilter(key)}
                  style={{
                    padding: "5px 14px",
                    borderRadius: "var(--radius-sm)",
                    border: "none",
                    background: active ? `${col}18` : "transparent",
                    color: active ? col : "var(--text-muted)",
                    fontSize: "10px",
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    cursor: "pointer",
                    letterSpacing: "0.1em",
                    border: active
                      ? `1px solid ${col}40`
                      : "1px solid transparent",
                    transition: "all 0.2s",
                    boxShadow: active ? `0 0 10px ${col}25` : "none",
                  }}
                >
                  {label}
                </button>
              );
            })}
            <div style={{ flex: 1 }} />
            <button
              onClick={() => refreshThreats()}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--text-muted)",
                display: "flex",
                alignItems: "center",
                gap: "4px",
                fontSize: "10px",
                fontFamily: "var(--font-mono)",
              }}
            >
              <RefreshCw size={10} /> Refresh list
            </button>
          </div>

          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "90px 180px 120px 160px 90px 70px 140px",
              padding: "10px 18px",
              borderBottom: "1px solid rgba(255,107,0,0.06)",
              fontSize: "10px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.1em",
            }}
          >
            {[
              "SEVERITY",
              "ALERT",
              "SOURCE",
              "AFFECTED SYSTEM",
              "TIME",
              "RISK",
              "ACTIONS",
            ].map((h) => (
              <div key={h}>{h}</div>
            ))}
          </div>

          {/* Rows */}
          <div style={{ maxHeight: "calc(100vh - 380px)", overflowY: "auto" }}>
            {!threats.length ? (
              <div
                style={{
                  padding: "18px",
                  fontSize: "12px",
                  color: "var(--text-muted)",
                }}
              >
                No alerts yet. Upload logs to start monitoring.
              </div>
            ) : (
              <AnimatePresence>
                {threats.map((threat, i) => {
                  const riskScore = Number.isFinite(Number(threat.riskScore))
                    ? Number(threat.riskScore)
                    : null;
                  const typeLabel = toTitle(
                    threat.threatType || threat.eventType || "Alert",
                  );
                  return (
                    <motion.div
                      key={threat._id || threat.id || i}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ delay: i * 0.03 }}
                      onClick={() => setSelectedThreat(threat)}
                      style={{
                        display: "grid",
                        gridTemplateColumns:
                          "90px 180px 120px 160px 90px 70px 140px",
                        padding: "11px 18px",
                        borderBottom: "1px solid rgba(255,107,0,0.05)",
                        cursor: "pointer",
                        alignItems: "center",
                        transition: "background 0.15s",
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.background =
                          "rgba(255,107,0,0.04)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.background = "transparent")
                      }
                    >
                      <SeverityBadge severity={threat.severity} />
                      <div
                        style={{
                          fontSize: "12px",
                          color: "var(--text-primary)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          fontFamily: "var(--font-ui)",
                        }}
                      >
                        {typeLabel}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "var(--solar)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {threat.sourceIP || threat.sourceIp || "—"}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "var(--text-secondary)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {threat.targetAsset || threat.target || "—"}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {threat.timestamp
                          ? format(new Date(threat.timestamp), "h:mm a")
                          : "—"}
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          fontFamily: "var(--font-mono)",
                          fontWeight: 700,
                          color:
                            riskScore === null
                              ? "var(--text-muted)"
                              : riskScore >= 80
                                ? "var(--sev-critical)"
                                : riskScore >= 60
                                  ? "var(--sev-high)"
                                  : "var(--sev-medium)",
                        }}
                      >
                        {riskScore === null ? "—" : riskScore}
                      </div>
                      <div style={{ display: "flex", gap: "6px" }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/threat/${threat._id || threat.id}`);
                          }}
                          style={{
                            padding: "4px 10px",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid rgba(255,107,0,0.2)",
                            background: "rgba(255,107,0,0.08)",
                            color: "var(--eclipse)",
                            fontSize: "10px",
                            fontWeight: 600,
                            fontFamily: "var(--font-mono)",
                            cursor: "pointer",
                            transition: "all 0.15s",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.background =
                              "rgba(255,107,0,0.15)";
                            e.currentTarget.style.boxShadow =
                              "0 0 10px rgba(255,107,0,0.2)";
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.background =
                              "rgba(255,107,0,0.08)";
                            e.currentTarget.style.boxShadow = "none";
                          }}
                        >
                          <Eye size={12} /> Details
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            dismissThreat(threat._id || threat.id);
                          }}
                          style={{
                            padding: "4px 8px",
                            borderRadius: "var(--radius-sm)",
                            background: "transparent",
                            border: "1px solid rgba(255,255,255,0.06)",
                            color: "var(--text-muted)",
                            fontSize: "10px",
                            cursor: "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                            transition: "all 0.15s",
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor =
                              "rgba(255,61,113,0.3)";
                            e.currentTarget.style.color = "var(--sev-critical)";
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor =
                              "rgba(255,255,255,0.06)";
                            e.currentTarget.style.color = "var(--text-muted)";
                          }}
                        >
                          <X size={10} /> Dismiss
                        </button>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            )}
          </div>
        </div>

        {/* RIGHT column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
          {/* Threat trend chart */}
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid rgba(255,107,0,0.1)",
              borderRadius: "var(--radius-lg)",
              padding: "20px",
              boxShadow: "var(--shadow-card)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginBottom: "16px",
              }}
            >
              <Activity size={16} color="var(--eclipse)" />
              <span
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  fontFamily: "var(--font-ui)",
                  letterSpacing: "0.02em",
                }}
                >
                  Alerts over time
                </span>
                <div
                  style={{
                    marginLeft: "auto",
                    fontSize: "10px",
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {trendRangeLabel}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="eclipseGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF6B00" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#FF6B00" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF3D71" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#FF3D71" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="label"
                  tick={{
                    fill: "#4A4A4A",
                    fontSize: 10,
                    fontFamily: "var(--font-mono)",
                  }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#4A4A4A", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  width={28}
                />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="total"
                  stroke="#FF6B00"
                  strokeWidth={2}
                  fill="url(#eclipseGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stroke="#FF3D71"
                  strokeWidth={1.5}
                  fill="url(#critGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginTop: "8px",
                fontSize: "11px",
                color: "var(--text-muted)",
                fontFamily: "var(--font-ui)",
              }}
            >
              <span style={{ color: "#FF6B00" }}>●</span> Total alerts
              <span style={{ color: "#FF3D71", marginLeft: "8px" }}>●</span>
              Critical alerts
            </div>
          </div>

          {/* Asset status */}
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid rgba(255,107,0,0.1)",
              borderRadius: "var(--radius-lg)",
              padding: "20px",
              boxShadow: "var(--shadow-card)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginBottom: "16px",
              }}
            >
              <Shield size={16} color="var(--eclipse)" />
              <span
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "var(--text-primary)",
                  fontFamily: "var(--font-ui)",
                }}
              >
                Asset Status
              </span>
            </div>
            <div
              style={{ display: "flex", flexDirection: "column", gap: "8px" }}
            >
              {assetData.length > 0 ? assetData.map((asset, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "10px 12px",
                    borderRadius: "var(--radius-md)",
                    background: "rgba(255,107,0,0.03)",
                    border: "1px solid rgba(255,107,0,0.06)",
                    transition: "all 0.2s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "rgba(255,107,0,0.15)";
                    e.currentTarget.style.background = "rgba(255,107,0,0.06)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "rgba(255,107,0,0.06)";
                    e.currentTarget.style.background = "rgba(255,107,0,0.03)";
                  }}
                >
                  <div
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background:
                        asset.status === "critical"
                          ? "var(--sev-critical)"
                          : asset.status === "warning"
                            ? "var(--sev-high)"
                            : "var(--sev-low)",
                      boxShadow: `0 0 6px ${asset.status === "critical" ? "var(--sev-critical)" : asset.status === "warning" ? "var(--sev-high)" : "var(--sev-low)"}`,
                      flexShrink: 0,
                    }}
                  />
                  <span
                    style={{
                      fontSize: "12px",
                      color: "var(--text-primary)",
                      flex: 1,
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {asset.name}
                  </span>
                  <span
                    style={{
                      fontSize: "10px",
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {asset.label}
                  </span>
                </div>
              )) : (
                <div style={{ color: "var(--text-muted)", fontSize: "12px", fontFamily: "var(--font-mono)" }}>
                  No asset data yet. Upload logs to see which systems are being targeted.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
