import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET() {
  return NextResponse.json(store.schedules);
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const newSchedule = {
      id: `SCH-${100 + store.schedules.length + 1}`,
      target: body.target || "example.com",
      tool: body.tool || "nmap",
      cron_expression: body.cron_expression || "0 0 * * *",
      next_run: new Date(Date.now() + 86400000).toISOString(),
    };
    store.schedules.push(newSchedule);
    return NextResponse.json(newSchedule);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed to schedule scan";
    return NextResponse.json({ detail: msg }, { status: 400 });
  }
}
