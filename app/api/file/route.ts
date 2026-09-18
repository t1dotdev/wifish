import { NextResponse } from 'next/server';
import { promises as fs } from 'node:fs';
import { isDir, safeFile, ensureDirs } from '@/lib/fs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// download: /api/file?dir=pcap&name=foo.pcap
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const f = safeFile(searchParams.get('dir'), searchParams.get('name') || '');
  if (!f) return NextResponse.json({ error: 'bad path' }, { status: 400 });
  let data: Buffer;
  try { data = await fs.readFile(f.abs); }
  catch { return NextResponse.json({ error: 'not found' }, { status: 404 }); }
  return new NextResponse(new Uint8Array(data), {
    headers: {
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="${f.base}"`,
    },
  });
}

// upload: multipart form { dir, file }
export async function POST(req: Request) {
  await ensureDirs();
  const form = await req.formData();
  const dir = form.get('dir');
  const file = form.get('file');
  if (!isDir(dir) || !file || typeof file === 'string') {
    return NextResponse.json({ error: 'bad upload' }, { status: 400 });
  }
  const f = safeFile(dir, file.name);
  if (!f) return NextResponse.json({ error: 'bad name' }, { status: 400 });
  const buf = Buffer.from(await file.arrayBuffer());
  await fs.writeFile(f.abs, buf);
  return NextResponse.json({ ok: true, name: f.base, size: buf.length });
}

// delete: { dir, name }
export async function DELETE(req: Request) {
  const body = await req.json().catch(() => ({}));
  const f = safeFile(body.dir, body.name || '');
  if (!f) return NextResponse.json({ error: 'bad path' }, { status: 400 });
  try { await fs.unlink(f.abs); }
  catch { return NextResponse.json({ error: 'not found' }, { status: 404 }); }
  return NextResponse.json({ ok: true });
}
