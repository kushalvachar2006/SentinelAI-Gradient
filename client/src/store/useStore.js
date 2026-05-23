import { create } from "zustand";

const API = import.meta.env.VITE_API_URL || "";
const NO_CACHE = { cache: "no-store" };

// Demo auth header — matches the backend DEMO_MODE / demo-token bypass
const AUTH = {
  Authorization: "Bearer demo-token",
  "Content-Type": "application/json",
};

export const useStore = create((set, get) => ({
  // Data — empty by default, populated by button click
  threats: [],
  analytics: null,
  activeFilter: "ALL",
  selectedThreat: null,
  slideOverOpen: false,
  isLoaded: false,
  isLoading: false,
  error: null,

  analyst: { name: "Demo Analyst", role: "Senior SOC Analyst", avatar: "DA" },

  // ── Actions ──────────────────────────────────────────────────────────────
  setFilter: (filter) => set({ activeFilter: filter }),
  setSelectedThreat: (threat) =>
    set({ selectedThreat: threat, slideOverOpen: !!threat }),
  closeSlideOver: () => set({ slideOverOpen: false, selectedThreat: null }),

  dismissThreat: async (id) => {
    // Optimistic update
    set((state) => ({
      threats: state.threats.filter((t) => t._id !== id && t.id !== id),
    }));
    try {
      await fetch(`${API}/api/threats/${id}/action`, {
        method: "POST",
        headers: AUTH,
        body: JSON.stringify({ action: "dismiss" }),
      });
    } catch (e) {
      console.warn("Dismiss failed:", e);
    }
  },

  // ── The main load trigger — called by "Analyse" button ───────────────────
  loadDashboard: async () => {
    set({ isLoading: true, error: null });
    try {
      const [threatsRes, analyticsRes] = await Promise.all([
        fetch(`${API}/api/threats?limit=50&sort=createdAt&order=desc&ts=${Date.now()}`, {
          headers: AUTH,
          ...NO_CACHE,
        }),
        fetch(`${API}/api/analytics`, {
          headers: AUTH,
          ...NO_CACHE,
        }),
      ]);

      const threatsData = await threatsRes.json();
      const analyticsData = analyticsRes.ok ? await analyticsRes.json() : null;
      const threatItems = threatsData.threats || threatsData || [];

      if (!threatsRes.ok)
        throw new Error(`Failed to fetch threats: ${threatsRes.status}`);

      set({
        threats: threatItems,
        analytics: analyticsData,
        isLoaded: true,
        isLoading: false,
      });
    } catch (err) {
      set({ isLoading: false, error: err.message });
    }
  },

  refreshThreats: async () => {
  try {
    const res = await fetch(
      `${API}/api/threats?limit=50&sort=createdAt&order=desc&ts=${Date.now()}`,
      {
        headers: AUTH,
        cache: "no-store",
      }
    );

    const data = await res.json();

    const threats = data.threats || data || [];

    threats.sort(
      (a, b) =>
        new Date(
          b.createdAt || b.detectedAt || b.timestamp
        ) -
        new Date(
          a.createdAt || a.detectedAt || a.timestamp
        )
    );

    set({ threats });

  } catch (e) {
    console.warn("Refresh failed:", e);
  }
},

  // ── Computed ──────────────────────────────────────────────────────────────
  filteredThreats: () => {
    const { threats, activeFilter } = get();
    if (activeFilter === "ALL") return threats;
    return threats.filter(
      (t) => (t.severity || "").toUpperCase() === activeFilter,
    );
  },

  counts: () => {
    const { threats } = get();
    const s = (sev) =>
      threats.filter((t) => (t.severity || "").toUpperCase() === sev).length;
    return {
      CRITICAL: s("CRITICAL"),
      HIGH: s("HIGH"),
      MEDIUM: s("MEDIUM"),
      LOW: s("LOW"),
    };
  },
}));
