import { useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AnimatePresence } from 'framer-motion';
import Landing from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import ThreatDetail from './pages/ThreatDetail';
import Chat from './pages/Chat';
import Analytics from './pages/Analytics';
import Ingest from './pages/Ingest';

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchInterval: 10000, staleTime: 5000 } },
});

const API = import.meta.env.VITE_API_URL || '';

// Ping the backend on load so Render wakes up before the user needs it.
// Re-pings every 4 minutes to prevent cold sleep (Render free tier sleeps after ~5 min).
function useWarmBackend() {
  useEffect(() => {
    const ping = () =>
      fetch(`${API}/health`, { method: 'GET' })
        .then(() => console.log('[warm] backend alive'))
        .catch(() => console.warn('[warm] backend still waking up…'));

    ping(); // immediate ping on mount
    const interval = setInterval(ping, 4 * 60 * 1000); // every 4 min
    return () => clearInterval(interval);
  }, []);
}

export default function App() {
  useWarmBackend();

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/threat/:id" element={<ThreatDetail />} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/ingest" element={<Ingest />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}