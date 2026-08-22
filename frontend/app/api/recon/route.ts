import { NextResponse } from 'next/server';
import { store, Scan } from '@/app/api/_store';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const target = body.target || "example.com";
    const tool = body.tool || "nmap";

    const newScan: Scan = {
      scan_id: `SCN-${1000 + store.scans.length + 1}`,
      target,
      tool_used: tool,
      risk_score: "HIGH",
      status: "completed",
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      findings: {
        open_ports: [{ port: 80, service: "http" }, { port: 443, service: "https" }],
        notes: `On-demand ${tool} scan executed on ${target}`
      }
    };

    store.scans.unshift(newScan);

    // Update asset tracking
    const existingAsset = store.assets.find(a => a.target === target);
    if (existingAsset) {
      existingAsset.scan_count += 1;
      existingAsset.last_risk_score = "HIGH";
    } else {
      store.assets.push({
        asset_id: `AST-${100 + store.assets.length + 1}`,
        target,
        asset_type: "On-demand Scan Host",
        scan_count: 1,
        last_risk_score: "HIGH",
        discovered_at: new Date().toISOString()
      });
    }

    return NextResponse.json({
      scan_id: newScan.scan_id,
      status: "completed",
      target,
      tool,
      risk_score: newScan.risk_score
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed to trigger scan";
    return NextResponse.json({ detail: msg }, { status: 400 });
  }
}
