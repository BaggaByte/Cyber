import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => ({}));
    if (body.email) store.currentUser.email = body.email;
    if (body.org_name) store.currentUser.org_name = body.org_name;
    if (body.first_name) store.currentUser.first_name = body.first_name;
    if (body.last_name) store.currentUser.last_name = body.last_name;
    if (body.job_title) store.currentUser.job_title = body.job_title;

    return NextResponse.json({
      access_token: "sentinel_jwt_token_" + Date.now(),
      token_type: "bearer",
      user: store.currentUser,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : "Registration failed";
    return NextResponse.json({ detail: msg }, { status: 400 });
  }
}
