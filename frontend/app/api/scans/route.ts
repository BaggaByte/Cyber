import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const limit = parseInt(searchParams.get('limit') || '50');
  return NextResponse.json(store.scans.slice(0, limit));
}
