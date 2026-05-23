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

export default function App() {
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