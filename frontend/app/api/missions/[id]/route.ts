import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const mission = store.missions.find(m => m.mission_id === id || m.mission_id === `MIS-${id}`);

  if (!mission) {
    return NextResponse.json({
      mission_id: id,
      target: "example.com",
      goal: "Automated vulnerability scan and attack surface analysis",
      scan_count: 2,
      created_at: new Date().toISOString(),
      decision_log: [
        { action: "Target Profiling", reason: "Analyzing target IP and host parameters", timestamp: new Date().toISOString(), confidence: "99%" },
        { action: "Port Scan Dispatch", reason: "Launching Nmap service detection", timestamp: new Date().toISOString(), confidence: "95%" }
      ],
      scans: [
        { scan_id: "SCN-1092", tool_used: "nmap", risk_score: "HIGH", status: "completed" },
        { scan_id: "SCN-1093", tool_used: "nuclei", risk_score: "CRITICAL", status: "completed" }
      ]
    });
  }

  return NextResponse.json(mission);
}
