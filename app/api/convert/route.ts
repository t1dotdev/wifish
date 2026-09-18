import { NextResponse } from 'next/server';
import { execFile, type ExecFileException } from 'node:child_process';
import path from 'node:path';
import { DIRS, safeFile, ensureDirs } from '@/lib/fs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface ConvertMeta {
  handshakes: number;
  pmkids: number;
  ssid: string | null;
  bssid: string | null;
}

export async function POST(req: Request) {
  await ensureDirs();
  const body = await req.json().catch(() => ({}));
  const src = safeFile('pcap', body.name || '');
  if (!src) return NextResponse.json({ error: 'bad pcap name' }, { status: 400 });

  const base = src.base.replace(/\.[^.]+$/, '');
  const out = path.join(DIRS.hc22000.path, `${base}.hc22000`);

  const run = () =>
    new Promise<{ err: ExecFileException | null; stdout: string; stderr: string }>((resolve) => {
      execFile('hcxpcapngtool', ['-o', out, src.abs], { timeout: 60_000 },
        (err, stdout, stderr) => resolve({ err, stdout, stderr }));
    });

  const { err, stdout, stderr } = await run();
  const log = `${stdout || ''}${stderr || ''}`.trim();

  if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
    return NextResponse.json({ error: 'hcxpcapngtool not installed', log }, { status: 500 });
  }
  // hcxpcapngtool exits non-zero when nothing usable found.
  const meta = parseMeta(log);
  const ok = !err && meta.handshakes + meta.pmkids > 0;
  return NextResponse.json({
    ok,
    out: ok ? path.basename(out) : null,
    ...meta,
    log,
  }, { status: ok ? 200 : 422 });
}

function parseMeta(log: string): ConvertMeta {
  const num = (re: RegExp) => { const m = log.match(re); return m ? parseInt(m[1], 10) : 0; };
  const str = (re: RegExp) => { const m = log.match(re); return m ? m[1].trim() : null; };
  return {
    handshakes: num(/EAPOL pairs written[^\d]*(\d+)/i) || num(/handshakes?[^\d]*(\d+)/i),
    pmkids:     num(/PMKID.*written[^\d]*(\d+)/i) || num(/PMKID\(s\)[^\d]*(\d+)/i),
    ssid:       str(/ESSID[^:]*:\s*(.+)/i),
    bssid:      str(/(?:BSSID|AP)[^:]*:\s*([0-9a-f:]{17})/i),
  };
}
