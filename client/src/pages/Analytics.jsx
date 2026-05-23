import { useCallback, useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { Calendar, TrendingUp, Clock, CheckCircle } from "lucide-react";
import Navbar from "../components/layout/Navbar";

const API = import.meta.env.VITE_API_URL || "";
const AUTH_HEADERS = { Authorization: "Bearer demo-token" };
const NO_CACHE = { cache: "no-store" };
const THREAT_PAGE_LIMIT = 200;

const getThreatTimestamp = (threat) => {
  const value =
    threat?.timestamp ||
    threat?.createdAt ||
    threat?.created_at ||
    threat?.detectedAt ||
    threat?.detected_at;
  if (!value) return null;

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const getThreatType = (threat) =>
  threat?.threatType || threat?.eventType || threat?._id || "unknown";

const buildAnalyticsFromThreats = (threats) => {
  if (!Array.isArray(threats) || threats.length === 0) {
    return {
      summary: {
        totalThreats: 0,
        openCritical: 0,
        meanTimeToDetectMinutes: null,
        truePositiveRate: null,
        avgRiskScore: 0,
        maxRiskScore: 0,
      },
      charts: {
        threatTimeline: [],
        threatTypeBreakdown: [],
      },
    };
  }

  const parsedThreats = threats
    .map((threat) => ({
      ...threat,
      timestampValue: getThreatTimestamp(threat),
      severityValue: String(threat?.severity || "low").toLowerCase(),
      typeValue: getThreatType(threat),
      riskValue: Number(threat?.riskScore ?? 0),
    }))
    .filter((threat) => threat.timestampValue);

  const sortedThreats = [...parsedThreats].sort(
    (a, b) => a.timestampValue - b.timestampValue,
  );

  const maxTime = sortedThreats.at(-1)?.timestampValue;
  const minTime = sortedThreats[0]?.timestampValue;
  const useHourly =
    maxTime && minTime ? maxTime - minTime <= 24 * 60 * 60 * 1000 : false;
  const bucketSizeMs = useHourly ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  const bucketCount = useHourly ? 24 : 7;

  const endBucketStart = new Date(maxTime || Date.now());
  if (useHourly) {
    endBucketStart.setMinutes(0, 0, 0);
  } else {
    endBucketStart.setHours(0, 0, 0, 0);
  }

  const startTime = new Date(
    endBucketStart.getTime() - (bucketCount - 1) * bucketSizeMs,
  );
  const timelineBuckets = Array.from({ length: bucketCount }, () => ({
    total: 0,
    critical: 0,
  }));

  const typeBuckets = new Map();
  let totalRisk = 0;
  let riskCount = 0;
  let totalDetectMinutes = 0;
  let detectCount = 0;
  let falsePositiveCount = 0;
  let openCritical = 0;

  sortedThreats.forEach((threat) => {
    const bucketIndex = Math.floor(
      (threat.timestampValue - startTime.getTime()) / bucketSizeMs,
    );
    if (bucketIndex >= 0 && bucketIndex < bucketCount) {
      timelineBuckets[bucketIndex].total += 1;
      if (threat.severityValue === "critical") {
        timelineBuckets[bucketIndex].critical += 1;
      }
    }

    if (threat.severityValue === "critical" && threat.status === "open") {
      openCritical += 1;
    }

    if (Number.isFinite(threat.riskValue)) {
      totalRisk += threat.riskValue;
      riskCount += 1;
    }

    const detectedAtValue = new Date(
      threat.detectedAt || threat.detected_at || threat.createdAt || threat.created_at,
    );
    if (!Number.isNaN(detectedAtValue.getTime())) {
      const detectMinutes = (detectedAtValue - threat.timestampValue) / 60000;
      if (Number.isFinite(detectMinutes) && detectMinutes >= 0) {
        totalDetectMinutes += detectMinutes;
        detectCount += 1;
      }
    }

    if (threat.status === "dismissed" || threat.isFalsePositive) {
      falsePositiveCount += 1;
    }

    const typeKey = threat.typeValue || "unknown";
    const current = typeBuckets.get(typeKey) || {
      type: typeKey,
      count: 0,
      riskTotal: 0,
      riskCount: 0,
    };
    current.count += 1;
    current.riskTotal += Number.isFinite(threat.riskValue) ? threat.riskValue : 0;
    current.riskCount += Number.isFinite(threat.riskValue) ? 1 : 0;
    typeBuckets.set(typeKey, current);
  });

  return {
    summary: {
      totalThreats: threats.length,
      openCritical,
      meanTimeToDetectMinutes:
        detectCount > 0 ? Math.round(totalDetectMinutes / detectCount) : null,
      truePositiveRate:
        threats.length > 0
          ? Math.round(((threats.length - falsePositiveCount) / threats.length) * 100)
          : null,
      avgRiskScore: riskCount > 0 ? (totalRisk / riskCount).toFixed(1) : 0,
      maxRiskScore: sortedThreats.reduce(
        (max, threat) => Math.max(max, threat.riskValue || 0),
        0,
      ),
    },
    charts: {
      threatTimeline: timelineBuckets.map((bucket, index) => {
        const bucketTime = new Date(
          startTime.getTime() + index * bucketSizeMs,
        );
        return {
          date: useHourly
            ? bucketTime.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })
            : bucketTime.toLocaleDateString([], {
                month: "short",
                day: "numeric",
              }),
          count: bucket.total,
          critical: bucket.critical,
        };
      }),
      threatTypeBreakdown: [...typeBuckets.values()]
        .sort((a, b) => b.count - a.count)
        .map((entry) => ({
          type: entry.type,
          count: entry.count,
          avgRisk:
            entry.riskCount > 0 ? Math.round(entry.riskTotal / entry.riskCount) : 0,
        })),
    },
  };
};

export default function Analytics() {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analytics, setAnalytics] = useState(null);

  const loadAnalytics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      let page = 1;
      let allThreats = [];
      let totalPages = 1;

      while (page <= totalPages) {
        const res = await fetch(
          `${API}/api/threats?limit=${THREAT_PAGE_LIMIT}&page=${page}&sort=timestamp&order=desc`,
          {
            headers: AUTH_HEADERS,
            ...NO_CACHE,
          },
        );
        if (!res.ok) throw new Error(`Failed to load threats (${res.status})`);

        const data = await res.json();
        const threats = Array.isArray(data?.threats) ? data.threats : [];
        allThreats = allThreats.concat(threats);
        totalPages = Number(data?.pagination?.pages || 1);
        page += 1;
      }

      setAnalytics(buildAnalyticsFromThreats(allThreats));
    } catch (err) {
      setError(err?.message || "Something went wrong while loading threats.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAnalytics();
  }, [loadAnalytics]);

  const summary = analytics?.summary || {};
  const trendData = (analytics?.charts?.threatTimeline || []).map((d) => ({
    date: d._id || d.date,
    count: d.total || d.count || 0,
  }));
  const typeData = (analytics?.charts?.threatTypeBreakdown || []).map((d) => ({
    type: d.type || d._id || "unknown",
    count: d.count || 0,
  }));

  const kpis = [
    {
      label: "Average time to detect",
      value:
        summary.meanTimeToDetectMinutes != null
          ? `${summary.meanTimeToDetectMinutes} min`
          : "—",
      description: "Average minutes from event to detection.",
      icon: Clock,
      color: "var(--eclipse)",
    },
    {
      label: "Total incidents",
      value:
        summary.totalThreats != null
          ? summary.totalThreats.toLocaleString()
          : "—",
      description: "All threats detected in this period.",
      icon: TrendingUp,
      color: "var(--sev-critical)",
    },
    {
      label: "Critical issues open",
      value: summary.openCritical != null ? String(summary.openCritical) : "—",
      description: "High-risk items still unresolved.",
      icon: Calendar,
      color: "var(--solar)",
    },
    {
      label: "Accuracy rate",
      value:
        summary.truePositiveRate != null ? `${summary.truePositiveRate}%` : "—",
      description: "Alerts that turned out to be real threats.",
      icon: CheckCircle,
      color: "var(--sev-low)",
    },
  ];

  const hasData = Boolean(analytics);

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg-base)",
        paddingTop: "60px",
      }}
    >
      <Navbar />
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 0,
          pointerEvents: "none",
          background:
            "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(255,107,0,0.03) 0%, transparent 60%)",
        }}
      />

      <div
        style={{
          padding: "28px",
          maxWidth: "1280px",
          margin: "0 auto",
          position: "relative",
          zIndex: 1,
        }}
      >
        <div style={{ marginBottom: "22px" }}>
          <div
            style={{
              fontSize: "11px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.12em",
              marginBottom: "8px",
            }}
          >
            ANALYTICS OVERVIEW
          </div>
          <h1
            style={{
              fontSize: "26px",
              fontFamily: "var(--font-display)",
              fontWeight: 700,
              letterSpacing: "0.02em",
              color: "var(--text-primary)",
            }}
          >
            Security Analytics
          </h1>
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "14px",
              lineHeight: 1.6,
              marginTop: "8px",
              maxWidth: "720px",
            }}
          >
            A simple, human‑friendly summary of security activity. Use this page
            to understand what happened, how fast it was detected, and which
            threats are most common.
          </p>
        </div>

        {isLoading && !hasData && (
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid rgba(255,107,0,0.1)",
              borderRadius: "var(--radius-lg)",
              padding: "20px",
              color: "var(--text-secondary)",
              fontSize: "14px",
            }}
          >
            Loading your analytics…
          </div>
        )}

        {error && !hasData && (
          <div
            style={{
              background: "rgba(255,107,0,0.05)",
              border: "1px solid rgba(255,107,0,0.2)",
              borderRadius: "var(--radius-lg)",
              padding: "18px",
              color: "var(--text-primary)",
              fontSize: "14px",
            }}
          >
            We couldn’t load your analytics. {error}
            <div style={{ marginTop: "12px" }}>
              <button
                onClick={loadAnalytics}
                className="eclipse-btn-primary"
                style={{ padding: "10px 18px", fontSize: "13px" }}
              >
                Try again
              </button>
            </div>
          </div>
        )}

        {error && hasData && (
          <div
            style={{
              background: "rgba(255,107,0,0.05)",
              border: "1px solid rgba(255,107,0,0.2)",
              borderRadius: "var(--radius-md)",
              padding: "10px 14px",
              color: "var(--text-secondary)",
              fontSize: "12px",
              marginBottom: "14px",
            }}
          >
            Showing the last loaded data. We couldn’t refresh right now.
          </div>
        )}

        {hasData && (
          <>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "14px",
                marginBottom: "24px",
              }}
            >
              {kpis.map(({ label, value, icon: Icon, color, description }) => (
                <div
                  key={label}
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid rgba(255,107,0,0.1)",
                    borderRadius: "var(--radius-lg)",
                    padding: "18px",
                    position: "relative",
                    overflow: "hidden",
                    boxShadow: "var(--shadow-card)",
                  }}
                >
                  <div
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      right: 0,
                      height: 2,
                      background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
                    }}
                  />
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      marginBottom: "10px",
                    }}
                  >
                    <div
                      style={{
                        width: 34,
                        height: 34,
                        borderRadius: "var(--radius-sm)",
                        background: `${color}12`,
                        border: `1px solid ${color}25`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <Icon size={16} color={color} />
                    </div>
                    <span
                      style={{
                        fontSize: "12px",
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-mono)",
                        letterSpacing: "0.05em",
                      }}
                    >
                      {label}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: "28px",
                      fontFamily: "var(--font-display)",
                      fontWeight: 700,
                      color,
                    }}
                  >
                    {value}
                  </div>
                  <div
                    style={{
                      marginTop: "6px",
                      fontSize: "12px",
                      color: "var(--text-secondary)",
                      lineHeight: 1.5,
                    }}
                  >
                    {description}
                  </div>
                </div>
              ))}
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: "16px",
              }}
            >
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
                    fontSize: "13px",
                    fontWeight: 600,
                    color: "var(--text-primary)",
                    marginBottom: "6px",
                    fontFamily: "var(--font-ui)",
                  }}
                >
                  Incidents over time
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: "var(--text-secondary)",
                    marginBottom: "14px",
                  }}
                >
                  Daily count of detected incidents.
                </div>
                {trendData.length ? (
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={trendData}>
                      <defs>
                        <linearGradient id="aGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop
                            offset="5%"
                            stopColor="#FF6B00"
                            stopOpacity={0.3}
                          />
                          <stop
                            offset="95%"
                            stopColor="#FF6B00"
                            stopOpacity={0}
                          />
                        </linearGradient>
                      </defs>
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="rgba(255,107,0,0.06)"
                      />
                      <XAxis
                        dataKey="date"
                        tick={{
                          fill: "#4A4A4A",
                          fontSize: 10,
                          fontFamily: "monospace",
                        }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <YAxis
                        tick={{ fill: "#4A4A4A", fontSize: 10 }}
                        axisLine={false}
                        tickLine={false}
                        width={30}
                      />
                      <Tooltip
                        formatter={(value) => [value, "Incidents"]}
                        labelFormatter={(label) => `Date: ${label}`}
                      />
                      <Area
                        type="monotone"
                        name="Incidents"
                        dataKey="count"
                        stroke="#FF6B00"
                        strokeWidth={2}
                        fill="url(#aGrad)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div
                    style={{ color: "var(--text-secondary)", fontSize: "13px" }}
                  >
                    No timeline data available for this period.
                  </div>
                )}
              </div>

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
                    fontSize: "13px",
                    fontWeight: 600,
                    color: "var(--text-primary)",
                    marginBottom: "6px",
                    fontFamily: "var(--font-ui)",
                  }}
                >
                  Most common incident types
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: "var(--text-secondary)",
                    marginBottom: "14px",
                  }}
                >
                  Which categories appear most often.
                </div>
                {typeData.length ? (
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={typeData} layout="vertical">
                      <XAxis
                        type="number"
                        tick={{ fill: "#4A4A4A", fontSize: 10 }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <YAxis
                        dataKey="type"
                        type="category"
                        tick={{
                          fill: "#8B8B8B",
                          fontSize: 10,
                          fontFamily: "monospace",
                        }}
                        axisLine={false}
                        tickLine={false}
                        width={110}
                      />
                      <Tooltip
                        formatter={(value) => [value, "Incidents"]}
                        labelFormatter={(label) => `Type: ${label}`}
                      />
                      <Bar
                        name="Incidents"
                        dataKey="count"
                        fill="#FF6B00"
                        radius={[0, 4, 4, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div
                    style={{ color: "var(--text-secondary)", fontSize: "13px" }}
                  >
                    No category breakdown available for this period.
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
