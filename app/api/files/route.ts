import { NextResponse } from 'next/server';
import { ensureDirs, listAll } from '@/lib/fs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  await ensureDirs();
  const files = await listAll();
  return NextResponse.json({ files });
}
