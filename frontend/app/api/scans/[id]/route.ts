import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  // Look up from in-memory store first (real scans land here)
  const scan = store.scans.find(s => s.scan_id === id || s.scan_id === `SCN-${id}`);
  if (scan) {
    return NextResponse.json(scan);
  }

  // 404 — scan not found
  return NextResponse.json(
    { detail: `Scan ${id} not found` },
    { status: 404 }
  );
}
