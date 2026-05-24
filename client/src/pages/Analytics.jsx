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
import { Calendar, TrendingUp, Clock, CheckCircle, RefreshCw, Trash2 } from "lucide-react";
import Navbar from "../components/layout/Navbar";

const API = import.meta.env.VITE_API_URL || "";
const AUTH_HEADERS = { Authorization: "Bearer demo-token" };
const NO_CACHE = { cache: "no-store" };



export default function Analytics() {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analytics, setAnalytics] = useState(null);

  const loadAnalytics = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Use the backend's pre-aggregated analytics endpoint directly
      const res = await fetch(`${API}/api/analytics`, {
        headers: AUTH_HEADERS,
        ...NO_CACHE,
      });
      if (!res.ok) throw new Error(`Failed to load analytics (${res.status})`);
      const data = await res.json();

      // Map backend response shape → internal analytics shape
      const summary = data.summary || {};
      const charts = data.charts || {};

      // Backend doesn't compute truePositiveRate — derive from statusBreakdown
      const statusBreakdown = charts.statusBreakdown || [];
      const dismissed = statusBreakdown.find(s => s.status === 'dismissed')?.count || 0;
      const total = summary.totalThreats || 0;
      const truePositiveRate = total > 0 ? Math.round(((total - dismissed) / total) * 100) : null;

      setAnalytics({
        summary: {
          totalThreats: summary.totalThreats ?? 0,
          openCritical: summary.openCritical ?? 0,
          meanTimeToDetectMinutes: summary.meanTimeToDetectMinutes ?? null,
          truePositiveRate,
          avgRiskScore: summary.avgRiskScore ?? 0,
          maxRiskScore: summary.maxRiskScore ?? 0,
        },
        charts: {
          // threatTimeline from backend: [{ _id: "2025-05-24", total, critical, high, medium, low }]
          threatTimeline: (charts.threatTimeline || []).map(d => ({
            date: d._id,
            count: d.total || 0,
            critical: d.critical || 0,
          })),
          // threatTypeBreakdown from backend: [{ type, count, avgRisk }]
          threatTypeBreakdown: (charts.threatTypeBreakdown || []).map(d => ({
            type: d.type || d._id || 'unknown',
            count: d.count || 0,
            avgRisk: d.avgRisk || 0,
          })),
        },
      });
    } catch (err) {
      setError(err?.message || "Something went wrong while loading analytics.");
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
        <div style={{ marginBottom: "22px", display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px", flexWrap: "wrap" }}>
          <div>
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
          <div style={{ display: "flex", gap: "10px", alignItems: "center", paddingTop: "28px", flexShrink: 0 }}>
            <button
              onClick={loadAnalytics}
              disabled={isLoading}
              className="eclipse-btn-secondary"
              style={{ padding: "9px 16px", fontSize: "12px", display: "flex", alignItems: "center", gap: "6px", opacity: isLoading ? 0.5 : 1 }}
            >
              <RefreshCw size={13} style={{ animation: isLoading ? "spin 1s linear infinite" : "none" }} />
              Refresh
            </button>
            <button
              onClick={async () => {
                if (!window.confirm("This will delete ALL threat records from the database and start fresh. Are you sure?")) return;
                try {
                  await fetch(`${API}/api/threats/clear-all`, {
                    method: "DELETE",
                    headers: { ...AUTH_HEADERS, "Content-Type": "application/json" },
                  });
                  await loadAnalytics();
                } catch (e) {
                  alert("Clear failed: " + e.message);
                }
              }}
              className="eclipse-btn-secondary"
              style={{ padding: "9px 16px", fontSize: "12px", display: "flex", alignItems: "center", gap: "6px", borderColor: "rgba(255,61,113,0.25)", color: "var(--sev-critical)" }}
            >
              <Trash2 size={13} />
              Clear All Data
            </button>
          </div>
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