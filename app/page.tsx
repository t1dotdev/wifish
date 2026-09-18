'use client';
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type ComponentType } from 'react';
import type { CrackResult, FileEntry } from '@/lib/fs';
import { Wifi, Hash, List, KeyRound, Zap, FileCog, Upload, Download, Trash2, Play, Square, Gauge } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Card, CardHeader, CardTitle, CardDescription, CardAction, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Empty, EmptyHeader, EmptyTitle, EmptyDescription } from '@/components/ui/empty';
import { Spinner } from '@/components/ui/spinner';
import { Toaster, toast } from '@/components/ui/toast';
import type { Terminal as XTerm } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { ThemeToggle } from '@/components/theme-toggle';

type DirKind = 'pcap' | 'hc22000' | 'wordlists' | 'cracked';
type Method = 'hashcat' | 'aircrack';
type IconType = ComponentType<{ className?: string }>;

const STATIONS: Record<DirKind, { idx: number; label: string; sub: string; icon: IconType }> = {
  pcap:      { idx: 1, label: 'capture',   sub: '.pcap',      icon: Wifi },
  hc22000:   { idx: 2, label: 'hashes',    sub: '.hc22000',   icon: Hash },
  wordlists: { idx: 3, label: 'wordlists', sub: 'candidates', icon: List },
  cracked:   { idx: 4, label: 'recovered', sub: 'keys',       icon: KeyRound },
};
const DIRS = Object.keys(STATIONS) as DirKind[];

interface SessionView {
  id: string;
  source?: 'panel' | 'system';
  method: Method;
  status: string;
  processState?: 'paused' | 'running';
  pid: number | null;
  target: string | null;
  wordlist: string | null;
  command?: string;
  startedAt: string;
  canStop?: boolean;
  log?: string;
  logTruncated?: boolean;
  logAvailable?: boolean;
  results?: CrackResult[];
}

interface CrackStatus {
  status: string | null;
  speed: string | null;
  candidate: string | null;
  recovered: string | null;
  eta: string | null;
  temp: string | null;
  util: string | null;
  pct: number | null;
  done: string | null;
  total: string | null;
  finished: boolean;
}

const RING_R = 79;
const RING_C = 2 * Math.PI * RING_R;

const fmt = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
};

// mirror of the server-side clean(): strip ANSI so the status parsers see plain text.
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/[\x00\x07\x08]/g, '');

function parseStatus(log: string, method: Method): CrackStatus | null {
  return method === 'aircrack' ? parseAircrack(log) : parseHashcat(log);
}

// aircrack-ng (ANSI already stripped server-side) — CPU dictionary attack.
function parseAircrack(log: string): CrackStatus | null {
  if (!log) return null;
  const m = (re: RegExp): string | null => { const x = log.match(re); return x ? x[1].trim() : null; };
  const mAll = (re: RegExp): RegExpExecArray | null => { const r = new RegExp(re.source, 'g'); let x: RegExpExecArray | null, l: RegExpExecArray | null = null; while ((x = r.exec(log))) l = x; return l; };
  const keys = mAll(/([\d,]+)\/([\d,]+)\s+keys tested/);
  const done = keys ? +keys[1].replace(/,/g, '') : null;
  const total = keys ? +keys[2].replace(/,/g, '') : null;
  const found = /KEY FOUND!/.test(log);
  const status = found ? 'Cracked' : /KEY NOT FOUND/.test(log) ? 'Exhausted' : 'Running';
  // aircrack repaints via cursor moves; after ANSI strip a frame collapses to one line,
  // so bound each field between its label and the next known token.
  const cand = (() => {
    const x = mAll(/Current passphrase:([\s\S]*?)Master Key/);
    if (x) { const v = x[1].trim(); return v || null; }
    const y = mAll(/Current passphrase:\s*(\S[^\n]*)/);
    return y ? (y[1].trim() || null) : null;
  })();
  const speed = (() => { const x = mAll(/\(([\d.]+\s*[kMG]?\/s)\)/); return x ? x[1].trim() : null; })();
  const eta = (() => {
    let x = mAll(/Time left:\s*(.*?)\s*Current passphrase/);
    if (!x) x = mAll(/Time left:\s*([^\n]+)/);
    const v = x ? x[1].trim() : null;
    return v && v !== '--' ? v : null;
  })();
  return {
    status, speed, candidate: cand,
    recovered: found ? '1/1' : '0/1',
    eta, temp: null, util: null,
    pct: total ? Math.min(100, (done! / total) * 100) : (found ? 100 : null),
    done: done != null ? String(done) : null,
    total: total != null ? String(total) : null,
    finished: /──\s*exit\s*-?\d+\s*──/.test(log),
  };
}

// key + network from an aircrack-ng run's cleaned log
function parseAircrackKey(log: string): CrackResult[] | null {
  const key = (log.match(/KEY FOUND!\s*\[\s*(.*?)\s*\]/) || [])[1];
  if (key == null) return null;
  const net = log.match(/\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s{2,}WPA/);
  return [{ ssid: net ? net[2].trim() : null, bssid: net ? net[1].toUpperCase() : null, password: key }];
}

function parseHashcat(log: string): CrackStatus | null {
  if (!log) return null;
  const last = (re: RegExp): RegExpExecArray | null => {
    const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m: RegExpExecArray | null, l: RegExpExecArray | null = null;
    while ((m = r.exec(log))) l = m;
    return l;
  };
  const g = (re: RegExp, i = 1): string | null => { const m = last(re); return m ? m[i].trim() : null; };
  const prog = last(/^\s*Progress\.+:\s*(\d+)\/(\d+)\s*\(([\d.]+)%\)/m);
  return {
    status:    g(/^\s*Status\.+:\s*(.+)$/m),
    speed:     g(/^\s*Speed\.#[*\d]+\.+:\s*([\d.]+\s*[kMGTP]?H\/s)/m),
    candidate: g(/^\s*Candidates\.#\d+\.+:\s*(.+)$/m),
    recovered: g(/^\s*Recovered\.+:\s*(\d+\/\d+)/m),
    eta:       (() => { const m = last(/^\s*Time\.Estimated\.+:.*?\(([^)]*)\)/m); return m ? m[1].split(';')[0].trim() : null; })(),
    temp:      g(/Temp:\s*(\d+)c/i),
    util:      g(/Util:\s*(\d+)%/i),
    pct:       prog ? parseFloat(prog[3]) : null,
    done:      prog ? prog[1] : null,
    total:     prog ? prog[2] : null,
    finished:  /──\s*exit\s*-?\d+\s*──/.test(log),
  };
}

// stock shadcn Select over a directory's files; value === filename.
function FileSelect({ icon: Icon, value, onValueChange, placeholder, files, ariaLabel }: {
  icon: IconType; value: string; onValueChange: (v: string) => void; placeholder: string; files: FileEntry[]; ariaLabel: string;
}) {
  return (
    <Select value={value} onValueChange={(v) => onValueChange(v as string)}>
      <SelectTrigger aria-label={ariaLabel} className="w-full flex-1">
        <Icon className="text-muted-foreground" />
        <SelectValue>{(v: string) => v || <span className="text-muted-foreground">{placeholder}</span>}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        {files.length === 0
          ? <div className="px-2 py-1.5 text-sm text-muted-foreground">no files</div>
          : files.map((f) => <SelectItem key={f.name} value={f.name}>{f.name}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

function Stat({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('rounded-lg border p-2.5', className)}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-0.5 text-sm font-medium tabular-nums">{children}</div>
    </div>
  );
}

// aircrack-ng paints its screen with absolute cursor codes, so raw output only
// reads correctly through a real VT emulator. xterm replays it as the terminal drew it.
// ponytail: 80x25 is aircrack-ng's assumed screen when stdout is not a TTY; tune if a build differs.
const TERM_COLS = 80;
const TERM_ROWS = 25;

function LogTerminal({ data }: { data: string }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const writtenRef = useRef('');
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let disposed = false;
    let term: XTerm | null = null;
    (async () => {
      const { Terminal } = await import('@xterm/xterm');
      if (disposed || !hostRef.current) return;
      term = new Terminal({
        cols: TERM_COLS, rows: TERM_ROWS, disableStdin: true, convertEol: true, scrollback: 2000,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 12,
        theme: { background: '#0a0a0a', foreground: '#e5e5e5' },
      });
      term.open(hostRef.current);
      termRef.current = term;
      setReady(true);
    })();
    return () => { disposed = true; term?.dispose(); termRef.current = null; writtenRef.current = ''; };
  }, []);

  // The log file only grows, so a matching prefix is a pure append — write just the delta;
  // otherwise (session switch, truncation window shift) reset and repaint.
  useEffect(() => {
    const term = termRef.current;
    if (!term || !ready) return;
    const prev = writtenRef.current;
    if (prev && data.startsWith(prev)) term.write(data.slice(prev.length));
    else { term.reset(); term.write(data); }
    writtenRef.current = data;
  }, [data, ready]);

  return <div ref={hostRef} className="w-fit max-w-full overflow-hidden rounded-lg border bg-[#0a0a0a] p-2" />;
}

export default function Page() {
  const [files, setFiles] = useState<Record<DirKind, FileEntry[]>>({ pcap: [], hc22000: [], wordlists: [], cracked: [] });
  const [selPcap, setSelPcap] = useState('');
  const [method, setMethod] = useState<Method>('aircrack');
  const [selHash, setSelHash] = useState('');   // hashcat target (.hc22000)
  const [selCap, setSelCap] = useState('');     // aircrack target (.pcap)
  const [shownHash, setShownHash] = useState('');
  const [selList, setSelList] = useState('');
  const [log, setLog] = useState('');
  const [tab, setTab] = useState<'status' | 'log'>('status');
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [session, setSession] = useState<SessionView | null>(null);
  const [sessionsLoaded, setSessionsLoaded] = useState(false);
  const [sessionError, setSessionError] = useState('');
  const [streamError, setStreamError] = useState('');
  const streamingRef = useRef<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [clearing, setClearing] = useState(false);
  const selectedRef = useRef<string | null>(null);
  const completedRef = useRef(new Set<string>());
  const running = session != null && ['running', 'stopping'].includes(session.status);
  const panelBusy = sessions.some((s) => s.source === 'panel' && ['running', 'stopping'].includes(s.status));
  const finishedCount = sessions.filter((s) => s.source === 'panel' && !['running', 'stopping'].includes(s.status)).length;
  const [results, setResults] = useState<CrackResult[] | null>(null);
  const preRef = useRef<HTMLPreElement | null>(null);

  const cleanLog = useMemo(() => stripAnsi(log), [log]);
  const st = useMemo(() => parseStatus(cleanLog, session?.method || method), [cleanLog, method, session?.method]);
  const pct = st?.pct ?? 0;

  const flash = (msg: string, err = false) => { toast.add({ title: msg, type: err ? 'error' : 'success' }); };

  const refresh = useCallback(async () => {
    try { setFiles((await (await fetch('/api/files', { cache: 'no-store' })).json()).files); }
    catch { flash('cannot reach panel API', true); }
  }, []);

  function selectSession(s: SessionView) {
    selectedRef.current = s.id;
    try { localStorage.setItem('wifish-session', s.id); } catch {}
    setSession(s); setLog(''); setResults(null); setTab('status');
    setMethod(s.method);
    if (s.source === 'panel') {
      if (s.method === 'aircrack') setSelCap(s.target ?? ''); else setSelHash(s.target ?? '');
      setSelList(s.wordlist ?? '');
    }
    completedRef.current.delete(s.id);
  }

  useEffect(() => {
    const id = session?.id;
    if (!id || session.source !== 'panel' || !running || typeof EventSource === 'undefined') return;
    const source = new EventSource(`/api/crack?id=${encodeURIComponent(id)}&stream=1`);
    let disposed = false;
    source.addEventListener('output', (event) => {
      if (disposed || selectedRef.current !== id) return;
      const output = JSON.parse((event as MessageEvent<string>).data) as { log?: string; append: string; logTruncated?: boolean };
      streamingRef.current = id;
      setStreamError('');
      setLog((previous) => output.log !== undefined ? output.log : previous + output.append);
      setSession((current) => current?.id === id ? { ...current, logTruncated: output.logTruncated } : current);
    });
    source.onerror = () => {
      if (disposed || selectedRef.current !== id) return;
      streamingRef.current = null;
      setStreamError('Live output reconnecting; using periodic updates.');
    };
    return () => {
      disposed = true;
      source.close();
      if (streamingRef.current === id) streamingRef.current = null;
      setStreamError('');
    };
  }, [session?.id, session?.source, running]);

  useEffect(() => {
    let disposed = false, initialized = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    try { selectedRef.current = localStorage.getItem('wifish-session'); } catch {}
    async function poll(): Promise<void> {
      try {
        const selectionAtRequest = selectedRef.current;
        const response = await fetch('/api/crack', { cache: 'no-store', signal: controller.signal });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Cannot load sessions');
        if (disposed || selectedRef.current !== selectionAtRequest) return;
        setSessions(data.sessions); setSessionsLoaded(true); setSessionError(data.discoveryError || '');
        let selected: SessionView | undefined = data.sessions.find((s: SessionView) => s.id === selectedRef.current);
        if (!selected && data.sessions.length) { selected = data.sessions[0]; selectSession(data.sessions[0]); }
        if (!selected) { setSession(null); return; }
        if (!initialized) { selectSession(selected); initialized = true; }
        const id = selected.id;
        const detailResponse = await fetch(`/api/crack?id=${encodeURIComponent(id)}`, { cache: 'no-store', signal: controller.signal });
        const detail = await detailResponse.json();
        if (!detailResponse.ok) throw new Error(detail.error || 'Cannot load session output');
        if (disposed || selectedRef.current !== id) return;
        const current: SessionView = detail.session;
        setSession(current);
        // A slow snapshot must never overwrite newer output already delivered by the stream.
        if (streamingRef.current !== id || !['running', 'stopping'].includes(current.status)) setLog(current.log || '');
        if (current.source === 'panel' && !['running', 'stopping'].includes(current.status) && !completedRef.current.has(id)) {
          let recovered: CrackResult[] = current.results || parseAircrackKey(stripAnsi(current.log || '')) || [];
          if (current.method === 'hashcat') {
            const response = await fetch('/api/cracked', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hash: current.target }), signal: controller.signal });
            const data = await response.json();
            if (!response.ok || data.error) throw new Error(data.error || 'Cannot load recovered keys');
            recovered = data.results || [];
          }
          if (disposed || selectedRef.current !== id) return;
          completedRef.current.add(id); setShownHash(current.target ?? ''); setResults(recovered); refresh();
        }
      } catch (error) {
        if (!disposed) setSessionError(`${(error as Error).message}. Retrying automatically.`);
      } finally { if (!disposed) timer = setTimeout(poll, 2000); }
    }
    poll();
    return () => { disposed = true; if (timer) clearTimeout(timer); controller.abort(); };
  }, [refresh]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { if (tab === 'log' && preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight; }, [log, tab]);

  async function upload(dir: DirKind, e: ChangeEvent<HTMLInputElement>) {
    const list = e.target.files;
    if (!list || !list.length) return;
    for (const file of list) {
      const fd = new FormData(); fd.append('dir', dir); fd.append('file', file);
      const r = await fetch('/api/file', { method: 'POST', body: fd });
      if (!r.ok) flash(`upload failed: ${file.name}`, true);
    }
    e.target.value = ''; flash(`uploaded to ${dir}/`); refresh();
  }

  async function del(dir: DirKind, name: string) {
    const r = await fetch('/api/file', { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ dir, name }) });
    if (r.ok) { flash(`deleted ${name}`); refresh(); } else flash('delete failed', true);
  }

  async function convert() {
    if (!selPcap) return flash('pick a capture first', true);
    flash(`converting ${selPcap} …`);
    const j = await (await fetch('/api/convert', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: selPcap }) })).json();
    if (j.ok) { flash(`wrote ${j.out}${j.ssid ? ` · ${j.ssid}` : ''}`); refresh(); }
    else flash(j.error || 'no handshake / PMKID found', true);
    if (!selectedRef.current) { setLog(j.log || ''); setTab('log'); }
  }

  async function crack() {
    const target = method === 'aircrack' ? selCap : selHash;
    if (!target || !selList) return flash(method === 'aircrack' ? 'pick a capture + wordlist' : 'pick a hash + wordlist', true);
    if (starting || panelBusy) return;
    setStarting(true);
    try {
      const response = await fetch('/api/crack', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method, target, wordlist: selList }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Cannot start session');
      setSessions((all) => [data.session, ...all]); selectSession(data.session);
    } catch (error) { flash((error as Error).message, true); }
    finally { setStarting(false); }
  }

  async function abort() {
    if (!session?.canStop || stopping) return;
    const id = session.id;
    setStopping(true);
    try {
      const response = await fetch('/api/crack', { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Cannot stop session');
      if (selectedRef.current === id) setSession(data.session);
    } catch (error) { flash((error as Error).message, true); }
    finally { setStopping(false); }
  }

  async function clearSessions() {
    if (clearing || !finishedCount) return;
    setClearing(true);
    try {
      const response = await fetch('/api/crack', { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ all: true }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Cannot clear sessions');
      if (session?.source === 'panel' && !running) {
        selectedRef.current = null;
        try { localStorage.removeItem('wifish-session'); } catch {}
        setSession(null); setLog(''); setResults(null);
      }
      flash(`cleared ${data.cleared} session${data.cleared === 1 ? '' : 's'}`);
    } catch (error) { flash((error as Error).message, true); }
    finally { setClearing(false); }
  }

  // hashcat: authoritative read from the potfile (also used by the hc22000 "show" button)
  async function showCracked(hash?: string) {
    const h = hash || selHash;
    if (!h) return flash('pick a hash', true);
    setSelHash(h); setShownHash(h);
    const j = await (await fetch('/api/cracked', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hash: h }) })).json();
    if (j.error) return flash(j.error, true);
    setResults(j.results || []); refresh();
  }

  const n = (d: DirKind) => files[d]?.length || 0;
  const stateWord = session?.status === 'stopping' ? 'Stopping' : session?.processState === 'paused' ? 'Paused' : session && !running ? (st?.status === 'Cracked' || st?.status === 'Exhausted' ? st.status : session.status) : st?.status ? st.status.split(' ')[0] : (running ? 'Running' : 'Ready');
  const tempVal = st?.temp ? +st.temp : null;
  const activeSessions = sessions.filter((s) => ['running', 'stopping'].includes(s.status)).length;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 p-4 md:p-6">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-baseline gap-2.5">
            <h1 className="font-[family-name:var(--font-pixel)] text-base tracking-tight">wifish</h1>
            <p className="text-sm text-muted-foreground">WPA · WPA2 handshake console</p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {DIRS.map((d) => (
              <Badge key={d} variant="secondary">
                {STATIONS[d].label}
                <span className="font-semibold tabular-nums">{n(d)}</span>
              </Badge>
            ))}
            <Badge variant={tempVal != null && tempVal > 85 ? 'destructive' : 'outline'}>gpu{tempVal ? ` ${tempVal}°` : ''}</Badge>
            <ThemeToggle />
          </div>
        </header>

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
          {/* ---- left: four stations ---- */}
          <div className="flex flex-col gap-4">
            {DIRS.map((dir) => {
              const s = STATIONS[dir];
              const Glyph = s.icon;
              return (
                <Card key={dir}>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <Glyph className="size-4 text-muted-foreground" />
                      <CardTitle className="lowercase">{s.label}</CardTitle>
                    </div>
                    <CardDescription>{n(dir)} · {s.sub}</CardDescription>
                    <CardAction><Badge variant="outline" className="tabular-nums">{s.idx}</Badge></CardAction>
                  </CardHeader>
                  <CardContent>
                    {n(dir) === 0 ? (
                      <Empty className="py-6">
                        <EmptyHeader>
                          <EmptyTitle className="text-sm">No files yet</EmptyTitle>
                          <EmptyDescription>Upload {s.sub} to get started.</EmptyDescription>
                        </EmptyHeader>
                      </Empty>
                    ) : (
                      <ul className="flex flex-col gap-0.5">
                        {(files[dir] || []).map((f) => (
                          <li key={f.name} className="group flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/60">
                            <span className="flex-1 truncate text-sm" title={f.name}>{f.name}</span>
                            <span className="text-xs text-muted-foreground tabular-nums">{fmt(f.size)}</span>
                            <div className="flex items-center gap-0.5">
                              {dir === 'hc22000' && (
                                <Button variant="ghost" size="icon-sm" aria-label="show cracked key" onClick={() => showCracked(f.name)}><KeyRound /></Button>
                              )}
                              <Button variant="ghost" size="icon-sm" aria-label="download" nativeButton={false} render={<a href={`/api/file?dir=${dir}&name=${encodeURIComponent(f.name)}`} />}><Download /></Button>
                              <Button variant="destructive" size="icon-sm" aria-label="delete" onClick={() => del(dir, f.name)}><Trash2 /></Button>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </CardContent>
                  {dir !== 'cracked' && (
                    <CardFooter>
                      <Button variant="outline" size="sm" className="w-full" nativeButton={false} render={<label />}>
                        <Upload data-icon="inline-start" /> add {s.label}
                        <input type="file" multiple className="sr-only" onChange={(e) => upload(dir, e)} />
                      </Button>
                    </CardFooter>
                  )}
                </Card>
              );
            })}
          </div>

          {/* ---- right: operate ---- */}
          <div className="flex flex-col gap-4">
            {/* convert */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <FileCog className="size-4 text-muted-foreground" />
                  <CardTitle className="lowercase">convert</CardTitle>
                </div>
                <CardDescription>pcap → .hc22000</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-2 sm:flex-row">
                <FileSelect icon={Wifi} value={selPcap} onValueChange={setSelPcap} placeholder="Select a capture…" files={files.pcap} ariaLabel="capture to convert" />
                <Button onClick={convert} disabled={!selPcap}><FileCog data-icon="inline-start" /> Convert</Button>
              </CardContent>
            </Card>

            {/* system sessions */}
            <Card aria-label="System sessions">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <List className="size-4 text-muted-foreground" />
                  <CardTitle>System sessions</CardTitle>
                </div>
                <CardDescription>{sessionsLoaded ? `${activeSessions} active · this system` : 'checking system…'}</CardDescription>
                <CardAction>
                  <Button variant="destructive" size="icon-sm" aria-label="clear finished sessions" onClick={clearSessions} disabled={clearing || !finishedCount}>
                    {clearing ? <Spinner /> : <Trash2 />}
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent className="flex flex-col gap-2">
                <p className="text-xs text-muted-foreground">Sessions keep running when you refresh or close this page.</p>
                {(sessionError || streamError) && (
                  <Alert variant="destructive"><AlertDescription>{sessionError || streamError}</AlertDescription></Alert>
                )}
                {sessionsLoaded && sessions.length === 0 && !sessionError && (
                  <p className="text-xs text-muted-foreground">No hashcat or aircrack-ng sessions running. Choose a target and wordlist below to start.</p>
                )}
                {sessions.length > 0 && (
                  <ul className="flex flex-col gap-1.5">
                    {sessions.map((s) => (
                      <li key={s.id}>
                        <button
                          type="button"
                          aria-pressed={session?.id === s.id}
                          onClick={() => selectSession(s)}
                          className={cn(
                            'flex w-full flex-col gap-1 rounded-lg border p-2.5 text-left transition-colors hover:bg-muted/60',
                            session?.id === s.id && 'border-ring bg-muted',
                          )}
                        >
                          <span className="flex items-center justify-between gap-2">
                            <span className="text-sm font-medium">{s.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'}</span>
                            <Badge variant={['running', 'stopping'].includes(s.status) ? 'default' : 'secondary'}>
                              {s.processState === 'paused' ? 'paused' : s.status}
                            </Badge>
                          </span>
                          <span className="truncate text-xs text-muted-foreground" title={s.target || s.command}>{s.target || s.command}</span>
                          <span className="text-xs text-muted-foreground">
                            PID {s.pid || '—'} · {s.source === 'panel' ? 'panel' : 'started outside panel'} · {new Date(s.startedAt).toLocaleString()}{s.wordlist ? ` · ${s.wordlist}` : ''}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* crack — hero (full width) */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Zap className="size-4 text-muted-foreground" />
                  <CardTitle className="lowercase">crack</CardTitle>
                </div>
                <CardDescription>{method === 'aircrack' ? 'aircrack-ng · dictionary' : 'hashcat -m 22000'}</CardDescription>
                <CardAction>
                  <Tabs value={method} onValueChange={(v) => setMethod(v as Method)}>
                    <TabsList>
                      <TabsTrigger value="aircrack">aircrack-ng</TabsTrigger>
                      <TabsTrigger value="hashcat">hashcat</TabsTrigger>
                    </TabsList>
                  </Tabs>
                </CardAction>
              </CardHeader>
              <CardContent className="flex flex-col gap-3">
                <div className="flex flex-col gap-2 sm:flex-row">
                  {method === 'aircrack'
                    ? <FileSelect icon={Wifi} value={selCap} onValueChange={setSelCap} placeholder="Capture…" files={files.pcap} ariaLabel="capture to crack" />
                    : <FileSelect icon={Hash} value={selHash} onValueChange={setSelHash} placeholder="Hash…" files={files.hc22000} ariaLabel="hash to crack" />}
                  <FileSelect icon={List} value={selList} onValueChange={setSelList} placeholder="Wordlist…" files={files.wordlists} ariaLabel="wordlist" />
                  {running && session?.source === 'panel'
                    ? (
                      <Button variant="destructive" onClick={abort} disabled={stopping || session.status === 'stopping' || !session.canStop}>
                        {stopping || session.status === 'stopping' ? <Spinner data-icon="inline-start" /> : <Square data-icon="inline-start" />}
                        {stopping || session.status === 'stopping' ? 'Stopping…' : 'Abort'}
                      </Button>
                    )
                    : (
                      <Button onClick={crack} disabled={starting || panelBusy || !sessionsLoaded || (method === 'aircrack' ? !selCap : !selHash) || !selList}>
                        {starting ? <Spinner data-icon="inline-start" /> : <Play data-icon="inline-start" />}
                        {starting ? 'Starting…' : 'Run'}
                      </Button>
                    )}
                </div>

                {session && <p className="text-xs text-muted-foreground">Viewing {session.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'} · PID {session.pid || '—'} · {session.target || 'system session'}</p>}
                {session?.source === 'system' && <p className="text-xs text-muted-foreground">Process detected on this system. Live output and stop controls are available only for sessions started by this panel.</p>}
                {session?.logTruncated && <p className="text-xs text-muted-foreground">Showing the latest 256 KB of output. Full log saved on disk.</p>}

                <Tabs value={tab} onValueChange={(v) => setTab(v as 'status' | 'log')}>
                  <TabsList>
                    <TabsTrigger value="status">
                      <Gauge data-icon="inline-start" /> Status
                      {running && <span className="ml-1 size-1.5 animate-pulse rounded-full bg-primary" />}
                    </TabsTrigger>
                    <TabsTrigger value="log">Log</TabsTrigger>
                  </TabsList>

                  <TabsContent value="status">
                    <div className="flex flex-col items-center gap-6 py-2 sm:flex-row sm:items-center sm:gap-8">
                      <div className="relative grid shrink-0 place-items-center">
                        <svg viewBox="0 0 184 184" className="size-40 -rotate-90">
                          <circle cx="92" cy="92" r={RING_R} fill="none" stroke="var(--muted)" strokeWidth="12" />
                          <circle
                            cx="92" cy="92" r={RING_R} fill="none" stroke="var(--primary)" strokeWidth="12" strokeLinecap="round"
                            strokeDasharray={RING_C} strokeDashoffset={RING_C * (1 - pct / 100)}
                            className="transition-[stroke-dashoffset] duration-500"
                          />
                        </svg>
                        <div className="absolute flex flex-col items-center gap-1">
                          <span className="text-3xl font-semibold tabular-nums">
                            {pct.toFixed(pct >= 100 ? 0 : 1)}<span className="text-lg text-muted-foreground">%</span>
                          </span>
                          <Badge variant={running ? 'default' : 'secondary'}>{stateWord}</Badge>
                        </div>
                      </div>
                      <div className="grid w-full grid-cols-2 gap-2 sm:grid-cols-3">
                        <Stat label="speed">{st?.speed || '—'}</Stat>
                        <Stat label="recovered">{st?.recovered || '—'}</Stat>
                        <Stat label="eta">{st?.eta || '—'}</Stat>
                        <Stat label="gpu">{tempVal ? `${tempVal}°C` : '—'}{st?.util ? ` · ${st.util}%` : ''}</Stat>
                        <Stat label="current phrase" className="col-span-2 sm:col-span-3">
                          <span className="font-mono break-all">{st?.candidate || (running ? 'warming up…' : 'awaiting run')}</span>
                        </Stat>
                        <Stat label="progress" className="col-span-2 sm:col-span-3">
                          {st?.done && st?.total ? `${(+st.done).toLocaleString()} / ${(+st.total).toLocaleString()}` : '—'}
                        </Stat>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="log">
                    {session?.source === 'system' ? (
                      <pre ref={preRef} className="max-h-96 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs leading-relaxed whitespace-pre">
                        {session.command}
                      </pre>
                    ) : log ? (
                      <LogTerminal key={session?.id ?? 'none'} data={log} />
                    ) : (
                      <div className="rounded-lg border bg-muted/30 p-3 font-mono text-xs text-muted-foreground">No output yet.</div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* recovered key readout */}
            {results && (
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <KeyRound className="size-4 text-muted-foreground" />
                    <CardTitle className="lowercase">recovered key</CardTitle>
                  </div>
                  <CardDescription className="truncate">{shownHash || selHash}</CardDescription>
                </CardHeader>
                <CardContent>
                  {results.length === 0 ? (
                    <Empty className="py-6">
                      <EmptyHeader>
                        <EmptyTitle className="text-sm">No recovered key</EmptyTitle>
                        <EmptyDescription>No recovered key found for this session.</EmptyDescription>
                      </EmptyHeader>
                    </Empty>
                  ) : (
                    <div className="flex flex-col gap-2">
                      {results.map((r, i) => (
                        <div key={i} className="rounded-lg border p-3">
                          <div className="font-mono text-base font-semibold break-all">{r.password}</div>
                          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
                            <span>{r.ssid || '—'}</span>
                            <span className="font-mono">{r.bssid || '—'}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
      </div>
      <Toaster />
    </div>
  );
}
