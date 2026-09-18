import { spawn, execFile, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import type { CrackResult } from './fs.ts';

const exec = promisify(execFile);
export const POTFILE = path.join(process.cwd(), 'hashcat.potfile');

export type Method = 'hashcat' | 'aircrack';
export type SessionStatus = 'running' | 'stopping' | 'aborted' | 'finished' | 'failed';

export interface EngineProcess {
  pid: number;
  identity: string;
  startedAt: string;
  method: Method;
  command: string;
  processState?: 'paused' | 'running';
}

export interface SessionRecord {
  id: string;
  source: 'panel' | 'system';
  method: Method;
  target: string | null;
  wordlist: string | null;
  command: string;
  startedAt: string;
  status: SessionStatus;
  pid: number | null;
  identity: string | null;
  exitCode?: number | null;
  signal?: NodeJS.Signals | null;
  endedAt?: string;
  results?: CrackResult[];
  processState?: 'paused' | 'running';
  canStop?: boolean;
}

export interface SessionDetail extends SessionRecord {
  log: string;
  logTruncated?: boolean;
  logAvailable: boolean;
}

export interface StartSpec {
  method: Method;
  target: string;
  wordlist: string;
  command: string;
  args: string[];
}

export interface StoreOptions {
  directory?: string;
  spawnProcess?: (command: string, args: string[], options: SpawnOptions) => ChildProcess;
  discover?: () => Promise<EngineProcess[]>;
  onResults?: (target: string, results: CrackResult[]) => unknown;
}

const active = (s: { status: string }) => ['running', 'stopping'].includes(s.status);
const clean = (s: string) => s.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/[\x00\x07\x08]/g, '');
const failure = (message: string, status = 500) => Object.assign(new Error(message), { status });

// Separate executable identity from arguments: never mistake a shell/grep for an engine.
export function parseProcesses(identities: string, commands: string): EngineProcess[] {
  const args = new Map<number, string>(commands.split('\n').map((line): [number, string] => {
    const m = line.match(/^\s*(\d+)\s+(.*)$/); return m ? [+m[1], m[2]] : [0, ''];
  }));
  return identities.split('\n').flatMap((line): EngineProcess[] => {
    const m = line.match(/^\s*(\d+)\s+(\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+(\S+)\s+(.+?)\s*$/);
    if (!m || /Z/.test(m[3])) return [];
    const binary = path.basename(m[4]);
    if (!/^(hashcat(?:\.bin)?|aircrack-ng)$/.test(binary)) return [];
    return [{ pid: +m[1], identity: m[2].replace(/\s+/g, ' '), startedAt: new Date(m[2]).toISOString(),
      method: binary.startsWith('hashcat') ? 'hashcat' : 'aircrack', command: args.get(+m[1]) || m[4],
      processState: /T/.test(m[3]) ? 'paused' : 'running' }];
  });
}

export async function discoverProcesses(): Promise<EngineProcess[]> {
  const [identities, commands] = await Promise.all([
    exec('ps', ['-axo', 'pid=,lstart=,stat=,comm='], { maxBuffer: 8 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' } }),
    exec('ps', ['-axww', '-o', 'pid=,args='], { maxBuffer: 8 * 1024 * 1024 }),
  ]);
  return parseProcesses(identities.stdout as string, commands.stdout as string);
}

export async function readSavedLog(directory: string, id: string): Promise<{ log: string; logTruncated: boolean }> {
    const file = await fs.open(path.join(directory, `${id}.log`), 'r');
    try {
      const { size } = await file.stat();
      const length = Math.min(size, 256 * 1024);
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await file.read(buffer, 0, length, size - length);
      return { log: clean(buffer.subarray(0, bytesRead).toString('utf8')), logTruncated: size > length };
    } finally { await file.close(); }
  }

export function createSessionStore({ directory = path.join(process.cwd(), '.wifish', 'sessions'), spawnProcess = spawn,
  discover = discoverProcesses, onResults = async () => {} }: StoreOptions = {}) {
  let starting = false;
  const children = new Map<string, ChildProcess>();
  const metaPath = (id: string) => path.join(directory, `${id}.json`);
  const logPath = (id: string) => path.join(directory, `${id}.log`);
  async function save(s: SessionRecord): Promise<void> {
    const temp = `${metaPath(s.id)}.${randomUUID()}.tmp`;
    await fs.writeFile(temp, JSON.stringify(s), { mode: 0o600 });
    await fs.rename(temp, metaPath(s.id));
  }
  async function records(): Promise<SessionRecord[]> {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const names = await fs.readdir(directory);
    const parsed = await Promise.all(names.filter((n) => n.endsWith('.json')).map(async (n): Promise<SessionRecord | null> => {
      try { return JSON.parse(await fs.readFile(path.join(directory, n), 'utf8')) as SessionRecord; } catch { return null; }
    }));
    return parsed.filter((s): s is SessionRecord => Boolean(s));
  }
  const readLog = (id: string) => readSavedLog(directory, id);
  async function list(): Promise<{ sessions: SessionRecord[]; discoveryError: string | null }> {
    const saved = await records();
    let processes: EngineProcess[] = [], discoveryError: string | null = null;
    try { processes = await discover(); } catch { discoveryError = 'Cannot inspect system processes. Retrying automatically.'; }
    const sessions: SessionRecord[] = [];
    for (const s of saved) {
      const live = processes.find((p) => p.pid === s.pid && p.method === s.method && (!s.identity || p.identity === s.identity));
      if (active(s) && !children.has(s.id) && !live && !discoveryError) {
        s.status = s.status === 'stopping' ? 'aborted' : 'finished';
        s.endedAt = new Date().toISOString();
        await save(s);
      }
      sessions.push({ ...s, processState: live?.processState, canStop: active(s) && (children.has(s.id) || Boolean(live && s.identity)) });
    }
    for (const p of processes) {
      if (sessions.some((s) => active(s) && s.pid === p.pid && (!s.identity || s.identity === p.identity))) continue;
      sessions.push({ ...p, id: `system-${p.pid}-${Date.parse(p.startedAt)}`, source: 'system', status: 'running',
        target: null, wordlist: null, canStop: false });
    }
    sessions.sort((a, b) => Number(active(b)) - Number(active(a)) || b.startedAt.localeCompare(a.startedAt));
    return { sessions, discoveryError };
  }
  async function get(id: string): Promise<SessionDetail> {
    const { sessions } = await list();
    const session = sessions.find((s) => s.id === id);
    if (!session) throw failure('Session no longer available', 404);
    if (session.source === 'system') return { ...session, log: '', logAvailable: false };
    return { ...session, ...await readLog(id), logAvailable: true };
  }
  async function start({ method, target, wordlist, command, args }: StartSpec): Promise<SessionRecord> {
    if (starting) throw failure('A session is already starting', 409);
    starting = true;
    try {
      const { sessions } = await list();
      if (sessions.some((s) => s.source === 'panel' && active(s))) throw failure('A panel session is already running', 409);
      const s: SessionRecord = { id: randomUUID(), source: 'panel', method, target, wordlist, command: [command, ...args].join(' '),
        startedAt: new Date().toISOString(), status: 'running', pid: null, identity: null, exitCode: null };
      const output = await fs.open(logPath(s.id), 'a', 0o600);
      await output.write(`» ${s.command}\n\n`);
      let child: ChildProcess;
      try {
        child = spawnProcess(command, args, { cwd: process.cwd(), detached: true, stdio: ['ignore', output.fd, output.fd] });
      } catch (error) { await output.close(); throw error; }
      s.pid = child.pid ?? null;
      children.set(s.id, child);
      // The child writes straight to disk, so browser disconnects and server reloads cannot close its output pipe.
      let spawnError: Error | null = null;
      child.on('error', (error) => { spawnError = error; });
      const initialized = (async () => {
        try { s.identity = (await discover()).find((p) => p.pid === s.pid)?.identity || null; } catch {}
        await save(s);
      })();
      child.on('close', async (code, signal) => {
        try {
          await initialized;
          if ((await records()).find((r) => r.id === s.id)?.status === 'stopping') s.status = 'stopping';
          s.exitCode = code; s.signal = signal; s.endedAt = new Date().toISOString();
          s.status = s.status === 'stopping' || signal ? 'aborted' : spawnError || (code !== 0 && code !== 1) ? 'failed' : 'finished';
          await fs.appendFile(logPath(s.id), spawnError ? `\n✗ ${(spawnError as NodeJS.ErrnoException).code === 'ENOENT' ? `${command} not installed` : spawnError.message}\n` : `\n── exit ${code ?? signal} ──\n`);
          if (method === 'aircrack') {
            const { log } = await readLog(s.id);
            const key = log.match(/KEY FOUND!\s*\[\s*(.*?)\s*\]/)?.[1];
            if (key != null) {
              const net = log.match(/\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s{2,}WPA/);
              s.results = [{ ssid: net?.[2]?.trim() || null, bssid: net?.[1]?.toUpperCase() || null, password: key }];
              await onResults(target, s.results);
            }
          }
          await save(s);
        } catch (error) { console.error('Could not finalize session', s.id, (error as Error).message); }
        finally { children.delete(s.id); }
      });
      child.unref();
      await output.close();
      await initialized;
      return { ...s, canStop: true };
    } finally { starting = false; }
  }
  // list() first, so stale records reconcile to finished before being judged.
  async function clearFinished(): Promise<{ cleared: number }> {
    const { sessions } = await list();
    const finished = sessions.filter((s) => s.source === 'panel' && !active(s));
    await Promise.all(finished.flatMap((s) => [
      fs.unlink(metaPath(s.id)).catch(() => {}),
      fs.unlink(logPath(s.id)).catch(() => {}),
    ]));
    return { cleared: finished.length };
  }
  async function stop(id: string): Promise<SessionRecord> {
    const s = (await records()).find((s) => s.id === id);
    if (!s) throw failure('Only sessions started by this panel can be stopped here', 404);
    if (!active(s)) return s;
    const child = children.get(id);
    if (!child) {
      const p = (await discover()).find((p) => p.pid === s.pid && p.method === s.method && p.identity === s.identity);
      if (!p || !s.identity || s.pid == null) throw failure('Session is no longer running or its process identity cannot be verified', 409);
    }
    s.status = 'stopping';
    await save(s);
    // Signal only this session, never a process selected merely by its name.
    try { if (child) child.kill('SIGTERM'); else process.kill(s.pid as number, 'SIGTERM'); }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ESRCH') throw e; }
    return s;
  }
  return { list, get, start, stop, clearFinished };
}

declare global {
  // The crack route pins the store here so Next dev hot-reloads keep ownership.
  // eslint-disable-next-line no-var
  var __wifishSessions: ReturnType<typeof createSessionStore> | undefined;
}
