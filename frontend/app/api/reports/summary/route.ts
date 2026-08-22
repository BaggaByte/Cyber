import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET() {
  const risk_breakdown = {
    CRITICAL: store.scans.filter(s => s.risk_score === 'CRITICAL').length,
    HIGH: store.scans.filter(s => s.risk_score === 'HIGH').length,
    MEDIUM: store.scans.filter(s => s.risk_score === 'MEDIUM').length,
    LOW: store.scans.filter(s => s.risk_score === 'LOW').length,
    INFO: store.scans.filter(s => s.risk_score === 'INFO').length,
  };

  const daily_trend = [
    { date: "Aug 1", scans: 6 },
    { date: "Aug 2", scans: 9 },
    { date: "Aug 3", scans: 7 },
    { date: "Aug 4", scans: 14 },
    { date: "Aug 5", scans: 11 },
    { date: "Aug 6", scans: store.scans.length },
  ];

  const top_assets = store.assets.map(a => ({
    target: a.target,
    scans: a.scan_count,
    risk: a.last_risk_score,
  }));

  const toolCounts: Record<string, number> = {};
  store.scans.forEach(s => {
    const t = s.tool_used.toUpperCase();
    toolCounts[t] = (toolCounts[t] || 0) + 1;
  });

  const top_tools = Object.entries(toolCounts).map(([tool, count]) => ({ tool, count }));

  return NextResponse.json({
    total_scans: store.scans.length,
    total_assets: store.assets.length,
    risk_breakdown,
    daily_trend,
    top_assets,
    top_tools,
  });
}
