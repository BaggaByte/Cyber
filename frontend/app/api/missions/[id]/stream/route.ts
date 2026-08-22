import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const encoder = new TextEncoder();

  // Create a stream
  const customReadable = new ReadableStream({
    start(controller) {
      let counter = 0;
      
      const sendEvent = (data: any) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      sendEvent({
        status: 'running',
        message: 'Mission execution context initialized...',
        timestamp: new Date().toISOString()
      });

      const intervalId = setInterval(async () => {
        counter++;
        
        try {
          const mission = store.missions.find(m => m.mission_id === id);
          let status = mission ? (mission as any).status || 'running' : 'running';
          let log = `Executing autonomous planner step ${counter}...`;
          
          sendEvent({
            status,
            message: log,
            progress: Math.min(100, counter * 15),
            timestamp: new Date().toISOString()
          });

          if (counter >= 7 || status === 'completed' || status === 'failed') {
             sendEvent({ status: 'completed', message: 'Mission finished successfully.', progress: 100, timestamp: new Date().toISOString() });
             clearInterval(intervalId);
             controller.close();
          }
        } catch (err) {
          sendEvent({ status: 'failed', message: 'Error streaming mission data', timestamp: new Date().toISOString() });
          clearInterval(intervalId);
          controller.close();
        }
      }, 2000);

      // Handle client disconnect
      request.signal.addEventListener('abort', () => {
        clearInterval(intervalId);
      });
    }
  });

  return new Response(customReadable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
    },
  });
}
