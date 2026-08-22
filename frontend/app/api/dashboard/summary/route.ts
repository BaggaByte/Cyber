import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET() {
  const completed = store.scans.filter(s => s.status === 'completed').length;
  const failed = store.scans.filter(s => s.status === 'failed').length;

  const risk_breakdown = {
    CRITICAL: store.scans.filter(s => s.risk_score === 'CRITICAL').length,
    HIGH: store.scans.filter(s => s.risk_score === 'HIGH').length,
    MEDIUM: store.scans.filter(s => s.risk_score === 'MEDIUM').length,
    LOW: store.scans.filter(s => s.risk_score === 'LOW').length,
    INFO: store.scans.filter(s => s.risk_score === 'INFO').length,
  };

  return NextResponse.json({
    total_assets: store.assets.length,
    total_scans: store.scans.length,
    completed_scans: completed,
    failed_scans: failed,
    risk_breakdown,
  });
}
