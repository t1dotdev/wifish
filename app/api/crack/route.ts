import { promises as fs } from 'node:fs';
import { safeFile, writeCracked } from '@/lib/fs';
import { createSessionStore, POTFILE, type Method } from '@/lib/sessions';
import { createLogStream } from '@/lib/session-stream';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Keep ownership through Next development reloads; metadata and output also live on disk.
const store = globalThis.__wifishSessions ??= createSessionStore({ onResults: writeCracked });
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
const errorResponse = (error: any) => json({ error: error.message }, error.status || 500);

export async function GET(req: Request) {
  try {
    const params = new URL(req.url).searchParams;
    const id = params.get('id');
    if (id && params.get('stream') === '1') {
      const session = await store.get(id);
      if (session.source !== 'panel') return json({ error: 'Live output is unavailable for externally started sessions' }, 409);
      return new Response(createLogStream(session.id, req.signal), { headers: {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-store, no-transform',
        'x-accel-buffering': 'no',
      } });
    }
    return json(id ? { session: await store.get(id) } : await store.list());
  } catch (error) { return errorResponse(error); }
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const method: Method = body.method === 'aircrack' ? 'aircrack' : 'hashcat';
  const target = safeFile(method === 'aircrack' ? 'pcap' : 'hc22000', body.target || body.hash || '');
  const list = safeFile('wordlists', body.wordlist || '');
  if (!target || !list) return json({ error: 'bad target/wordlist name' }, 400);
  try {
    const stats = await Promise.all([fs.stat(target.abs), fs.stat(list.abs)]);
    if (stats.some((s) => !s.isFile())) return json({ error: 'target and wordlist must be files' }, 400);
  } catch { return json({ error: 'target or wordlist does not exist' }, 400); }
  const command = method === 'aircrack' ? 'aircrack-ng' : 'hashcat';
  const args = method === 'aircrack'
    ? ['-w', list.abs, target.abs]
    : ['-m', '22000', target.abs, list.abs, '--status', '--status-timer', '2', '--potfile-path', POTFILE, '-w', '3'];
  try {
    // Request cancellation only disconnects the viewer. DELETE is the explicit stop action.
    return json({ session: await store.start({ method, target: target.base, wordlist: list.base, command, args }) }, 201);
  } catch (error) { return errorResponse(error); }
}

export async function DELETE(req: Request) {
  const body = await req.json().catch(() => ({}));
  if (body.all === true) {
    try { return json(await store.clearFinished()); }
    catch (error) { return errorResponse(error); }
  }
  if (typeof body.id !== 'string') return json({ error: 'session id required' }, 400);
  try { return json({ session: await store.stop(body.id) }); }
  catch (error) { return errorResponse(error); }
}
