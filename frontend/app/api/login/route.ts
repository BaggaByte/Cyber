import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => ({}));
    if (body.email) store.currentUser.email = body.email;
    return NextResponse.json({
      access_token: "sentinel_jwt_token_" + Date.now(),
      token_type: "bearer",
      user: store.currentUser,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : "Login failed";
    return NextResponse.json({ detail: msg }, { status: 400 });
  }
}
