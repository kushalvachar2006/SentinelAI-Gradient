import { create } from "zustand";

// Empty string = relative URL → Vite dev proxy forwards /api/* to localhost:3001
// Set VITE_API_URL in .env only for production deployments
const API = import.meta.env.VITE_API_URL || '';
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

  // ── Fetch ALL threats across pages (backend page size = 1000) ───────────────
  _fetchAllThreats: async () => {
    const PAGE = 1000;
    let page = 1,
      allItems = [];
    while (true) {
      const res = await fetch(
        `${API}/api/threats?limit=${PAGE}&page=${page}&sort=riskScore&order=desc&ts=${Date.now()}`,
        { headers: AUTH, ...NO_CACHE },
      );
      if (!res.ok) throw new Error(`Failed to fetch threats: ${res.status}`);
      const data = await res.json();
      const items = data.threats || data || [];
      allItems = allItems.concat(items);
      // Stop when we have all pages
      const total = data.pagination?.total ?? items.length;
      if (allItems.length >= total || items.length === 0) break;
      page++;
    }
    return allItems;
  },

  // ── The main load trigger — called on mount ────────────────────────────────
  loadDashboard: async () => {
    set({ isLoading: true, error: null });
    try {
      const store = get();
      const [threatItems, analyticsRes] = await Promise.all([
        store._fetchAllThreats(),
        fetch(`${API}/api/analytics`, { headers: AUTH, ...NO_CACHE }),
      ]);
      const analyticsData = analyticsRes.ok ? await analyticsRes.json() : null;
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
      const store = get();
      const threats = await store._fetchAllThreats();
      set({ threats, isLoaded: true });
    } catch (e) {
      console.warn("Refresh failed:", e);
    }
  },

  clearAllData: async () => {
    try {
      await fetch(`${API}/api/threats/clear-all`, {
        method: "DELETE",
        headers: AUTH,
      });
      // Reset all data state immediately
      set({
        threats: [],
        analytics: null,
        isLoaded: false,
        activeFilter: "ALL",
        selectedThreat: null,
        slideOverOpen: false,
      });
    } catch (e) {
      console.warn("Clear failed:", e);
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