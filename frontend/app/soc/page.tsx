"use client";

import useSWR from "swr";
import { AlertCircle, Activity, ServerCrash } from "lucide-react";
// Import your Recharts/react-simple-maps components here
// import { AttackGraphAreaChart } from "@/components/charts"; 

// A lightweight generic fetcher for SWR
const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function SOCDashboard() {
  // SWR automatically handles caching, retries, and background refetching
  // Polling every 5 seconds (5000ms) to keep SOC metrics live
  const { data: metrics, error, isLoading } = useSWR(
    "http://localhost:8000/api/v1/metrics/live", 
    fetcher,
    { refreshInterval: 5000 }
  );

  if (error) {
    return (
      <div className="flex h-screen items-center justify-center text-red-500 bg-gray-950">
        <ServerCrash className="mr-2" />
        <span>Backend Connection Failed - Check Docker Status</span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center text-emerald-500 bg-gray-950 animate-pulse">
        <Activity className="mr-2" />
        <span>Initializing SentinelAI SOC Dashboard...</span>
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <header className="mb-8 flex items-center justify-between border-b border-gray-800 pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-emerald-400">
          SentinelAI Command Center
        </h1>
        {metrics?.activeScans > 0 && (
          <span className="flex items-center text-amber-400 text-sm font-mono animate-pulse">
            <AlertCircle className="w-4 h-4 mr-1" />
            {metrics.activeScans} Scans Active
          </span>
        )}
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Render metric cards dynamically from the SWR data */}
        <MetricCard title="Monitored Targets" value={metrics?.totalTargets || 0} />
        <MetricCard title="Critical Vulns" value={metrics?.criticalVulns || 0} alert={metrics?.criticalVulns > 0} />
        <MetricCard title="AI Playbooks Generated" value={metrics?.playbooks || 0} />
      </div>

      {/* Insert your lucide-react, recharts, and map visualizations below */}
      <section className="h-[400px] border border-gray-800 rounded-lg bg-gray-900/50 p-4">
        {/* <AttackGraphAreaChart data={metrics?.timelineData} /> */}
      </section>
    </main>
  );
}

// Simple internal component for the dashboard tiles
function MetricCard({ title, value, alert = false }: { title: string; value: number; alert?: boolean }) {
  return (
    <div className={`p-4 rounded-lg border ${alert ? 'border-red-900 bg-red-950/20 text-red-400' : 'border-gray-800 bg-gray-900'}`}>
      <h3 className="text-sm text-gray-400 uppercase tracking-wider mb-2">{title}</h3>
      <span className="text-3xl font-mono font-semibold">{value}</span>
    </div>
  );
}
