import { NextResponse } from 'next/server';
import { execFile, type ExecFileException } from 'node:child_process';
import { safeFile, writeCracked, type CrackResult } from '@/lib/fs';
import { POTFILE } from '@/lib/sessions';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));

  // aircrack path: caller already parsed the key from the stream — persist it.
  if (Array.isArray(body.results)) {
    const saved = await writeCracked(body.name || '', body.results).catch(() => null);
    return NextResponse.json({ results: body.results, saved });
  }

  // hashcat path: authoritative read from the potfile.
  const hash = safeFile('hc22000', body.hash || '');
  if (!hash) return NextResponse.json({ error: 'bad hash name' }, { status: 400 });
  const out = await new Promise<{ err: ExecFileException | null; stdout: string; stderr: string }>((resolve) => {
    execFile('hashcat', ['-m', '22000', hash.abs, '--show', '--potfile-path', POTFILE],
      { timeout: 30_000 }, (err, stdout, stderr) => resolve({ err, stdout: stdout || '', stderr: stderr || '' }));
  });
  if (out.err && (out.err as NodeJS.ErrnoException).code === 'ENOENT') {
    return NextResponse.json({ error: 'hashcat not installed' }, { status: 500 });
  }
  const results = out.stdout.trim().split('\n').filter(Boolean).map(parseShow);
  const saved = await writeCracked(hash.base, results).catch(() => null);
  return NextResponse.json({ results, saved, raw: out.stdout.trim() });
}

// potfile line: <22000-hashline>:<password>  (hashline uses '*' internally)
function parseShow(line: string): CrackResult {
  const i = line.lastIndexOf(':');
  const hashline = i >= 0 ? line.slice(0, i) : line;
  const password = i >= 0 ? line.slice(i + 1) : '';
  const parts = hashline.split('*');
  let bssid: string | null = null, ssid: string | null = null;
  if (parts.length >= 6) {
    bssid = fmtMac(parts[3]);
    try { ssid = Buffer.from(parts[5], 'hex').toString('utf8'); } catch {}
  }
  return { ssid, bssid, password };
}
function fmtMac(hex: string | null | undefined): string | null {
  const h = hex || '';
  if (!/^[0-9a-f]{12}$/i.test(h)) return null;
  return (h.match(/../g) ?? []).join(':').toUpperCase();
}
