import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  // All real scans are stored in the in-memory store
  const scan = store.scans.find(s => s.scan_id === id || s.scan_id === `SCN-${id}`);
  if (scan) {
    return NextResponse.json({ status: scan.status, progress: 100, message: 'Scan complete' });
  }

  // Stream simulated progress (scan not found = default running state)
  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    start(controller) {
      let count = 0;
      const send = (data: object) =>
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));

      send({ status: 'running', message: 'Scan initializing...', progress: 0, timestamp: new Date().toISOString() });

      const iv = setInterval(() => {
        count++;
        send({ status: 'running', message: `Scanning... step ${count}`, progress: count * 15, timestamp: new Date().toISOString() });

        if (count >= 6) {
          send({ status: 'completed', message: 'Scan finished.', progress: 100, timestamp: new Date().toISOString() });
          clearInterval(iv);
          controller.close();
        }
      }, 2000);

      request.signal.addEventListener('abort', () => { clearInterval(iv); });
    }
  });

  return new Response(readable, {
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' }
  });
}
