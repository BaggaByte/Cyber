import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET() {
  return NextResponse.json(store.assets);
}
