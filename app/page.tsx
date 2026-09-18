'use client';
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type ComponentType } from 'react';
import type { CrackResult, FileEntry } from '@/lib/fs';
import { Wifi, Hash, List, KeyRound, Zap, Upload, Download, Trash2, Play, Square, FolderOpen, Activity, Settings2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Card, CardHeader, CardTitle, CardDescription, CardAction, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { Badge } from '@/components/ui/badge';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Empty, EmptyHeader, EmptyTitle, EmptyDescription } from '@/components/ui/empty';
import { Terminal } from '@/components/ui/terminal';
import { Spinner } from '@/components/ui/spinner';
import { Toaster, toast } from '@/components/ui/toast';
import type { Terminal as XTerm } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { ThemeToggle } from '@/components/theme-toggle';
import { TooltipProvider } from '@/components/ui/tooltip';
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarHeader,
  SidebarInset, SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem,
  SidebarProvider, SidebarTrigger, SidebarGroupLabel, useSidebar,
} from '@/components/ui/sidebar';

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
  endedAt?: string;
  exitCode?: number | null;
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

const fmtDur = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h ${m}m ${sec}s` : m ? `${m}m ${sec}s` : `${sec}s`;
};
// Duration for a finished session; null while running or if timestamps are missing.
const sessionDuration = (s: { startedAt?: string; endedAt?: string }) =>
  s.endedAt && s.startedAt ? fmtDur(Date.parse(s.endedAt) - Date.parse(s.startedAt)) : null;

// Semantic color per session state; drives the status badge + sidebar dot.
// No success token in the theme, so cracked/aborted hardcode emerald/amber.
const statusTone = (word: string) => {
  const w = word.toLowerCase();
  if (w === 'cracked') return { dot: 'bg-emerald-500', badge: 'bg-emerald-500/15 text-emerald-500' };
  if (w === 'failed' || w === 'exhausted') return { dot: 'bg-destructive', badge: 'bg-destructive/10 text-destructive' };
  if (w === 'aborted' || w === 'stopping') return { dot: 'bg-amber-500', badge: 'bg-amber-500/15 text-amber-500' };
  if (w === 'running' || w === 'paused') return { dot: 'bg-primary', badge: 'bg-primary/15 text-primary' };
  return { dot: 'bg-muted-foreground', badge: 'bg-secondary text-secondary-foreground' };
};

// A cleanly finished run is really Cracked or Exhausted (running/aborted/failed pass through).
// hashcat exits 0 cracked / 1 exhausted; aircrack reports a key via results.
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const finishStatus = (s: { status: string; method: Method; exitCode?: number | null; results?: CrackResult[] }) => {
  if (s.status !== 'finished') return s.status;
  return (s.results?.length ?? 0) > 0 || (s.method === 'hashcat' && s.exitCode === 0) ? 'Cracked' : 'Exhausted';
};

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
      <SelectTrigger aria-label={ariaLabel} className="w-full min-w-0 flex-1">
        <Icon className="text-muted-foreground" />
        <SelectValue className="truncate">{(v: string) => v || <span className="text-muted-foreground">{placeholder}</span>}</SelectValue>
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
    <div className={cn('min-w-0 py-4', className)}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-2 text-lg font-medium tabular-nums break-words">{children}</div>
    </div>
  );
}

// aircrack-ng paints its screen with absolute cursor codes, so raw output only
// reads correctly through a real VT emulator. xterm replays it as the terminal drew it.
// ponytail: 80x25 is aircrack-ng's assumed screen when stdout is not a TTY; tune if a build differs.
const TERM_COLS = 80;
const TERM_ROWS = 25;

const isDarkTheme = () => document.documentElement.classList.contains('dark');
// ponytail: only default fg/bg flip; ANSI palette stays engine-default, so a few
// bright colors sit low-contrast on the light bg. Add a light 16-color palette here
// if that output ever needs it.
const xtermTheme = (dark: boolean) =>
  dark
    ? { background: '#0a0a0a', foreground: '#e5e5e5' }
    : { background: '#fafafa', foreground: '#1f2937' };

function LogTerminal({ data, title }: { data: string; title?: string }) {
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
        theme: xtermTheme(isDarkTheme()),
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

  // Follow the .dark class toggled by ThemeToggle — repaint xterm's bg/fg to match.
  useEffect(() => {
    const root = document.documentElement;
    const apply = () => { if (termRef.current) termRef.current.options.theme = xtermTheme(root.classList.contains('dark')); };
    apply();
    const obs = new MutationObserver(apply);
    obs.observe(root, { attributes: true, attributeFilter: ['class'] });
    return () => obs.disconnect();
  }, [ready]);

  return (
    <Terminal title={title}>
      <div ref={hostRef} className="max-w-full" />
    </Terminal>
  );
}

function SessionHistory({ sessions, selectedId, loaded, onSelect }: {
  sessions: SessionView[]; selectedId?: string; loaded: boolean; onSelect: (session: SessionView) => void;
}) {
  const { setOpenMobile } = useSidebar();
  const active = (session: SessionView) => ['running', 'stopping'].includes(session.status);
  const groups = [
    { label: 'Active sessions', items: sessions.filter(active) },
    { label: 'Recent sessions', items: sessions.filter((session) => !active(session)) },
  ];
  return (
    <>
      {!loaded && <p className="px-4 py-3 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">Checking sessions…</p>}
      {loaded && sessions.length === 0 && <p className="px-4 py-3 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">No sessions yet. Start a crack to see it here.</p>}
      {groups.filter((group) => group.items.length > 0).map((group) => (
        <SidebarGroup key={group.label}>
          <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {[...group.items].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt)).map((session) => {
                const engine = session.method === 'aircrack' ? 'aircrack-ng' : 'hashcat';
                const status = cap(session.processState === 'paused' ? 'paused' : finishStatus(session));
                const name = session.target || `${engine} · PID ${session.pid || '—'}`;
                const dur = sessionDuration(session);
                return (
                  <SidebarMenuItem key={session.id}>
                    <SidebarMenuButton size="lg" isActive={selectedId === session.id} aria-pressed={selectedId === session.id}
                      tooltip={`${name} · ${status}`} title={`${name}\n${engine} · ${status} · PID ${session.pid || '—'}\n${new Date(session.startedAt).toLocaleString()}${session.wordlist ? `\n${session.wordlist}` : ''}`}
                      onClick={() => { onSelect(session); setOpenMobile(false); }}>
                      {active(session) ? <Activity /> : <Hash />}
                      <span className="flex min-w-0 flex-1 flex-col gap-0.5 group-data-[collapsible=icon]:hidden">
                        <span className="truncate">{name}</span>
                        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <span className={cn('size-1.5 shrink-0 rounded-full', statusTone(status).dot)} />
                          <span className="truncate">{status} · {engine}{dur ? ` · ${dur}` : ''}{session.source === 'system' ? ' · external' : ''}</span>
                        </span>
                      </span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </>
  );
}

export default function Page() {
  const [files, setFiles] = useState<Record<DirKind, FileEntry[]>>({ pcap: [], hc22000: [], wordlists: [], cracked: [] });
  const [method, setMethod] = useState<Method>('aircrack');
  const [selHash, setSelHash] = useState('');   // hashcat target (.hc22000)
  const [selCap, setSelCap] = useState('');     // aircrack target (.pcap)
  const [shownHash, setShownHash] = useState('');
  const [selList, setSelList] = useState('');
  const [log, setLog] = useState('');
  const [view, setView] = useState<'overview' | 'files' | 'keys' | 'settings'>('overview');
  const [workload, setWorkload] = useState(1);      // hashcat -w (1-4)
  const [statusTimer, setStatusTimer] = useState(1); // hashcat --status-timer seconds
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

  // Panel settings live in the browser (single local console); sent with each crack start.
  useEffect(() => {
    try {
      const s = JSON.parse(localStorage.getItem('wifish-settings') || '{}');
      if (Number.isFinite(s.workload)) setWorkload(Math.min(4, Math.max(1, Math.floor(s.workload))));
      if (Number.isFinite(s.statusTimer)) setStatusTimer(Math.min(3600, Math.max(1, Math.floor(s.statusTimer))));
    } catch {}
  }, []);
  useEffect(() => {
    try { localStorage.setItem('wifish-settings', JSON.stringify({ workload, statusTimer })); } catch {}
  }, [workload, statusTimer]);
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
    setSession(s); setLog(''); setResults(null);
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
  useEffect(() => { if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight; }, [log]);

  async function uploadFiles(dir: DirKind, list: FileList | File[]): Promise<string[]> {
    const items = Array.from(list);
    if (!items.length) return [];
    const names: string[] = [];
    for (const file of items) {
      const fd = new FormData(); fd.append('dir', dir); fd.append('file', file);
      const r = await fetch('/api/file', { method: 'POST', body: fd });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) flash(`upload failed: ${file.name}`, true);
      else names.push(j.name ?? file.name);
    }
    flash(`uploaded to ${dir}/`); refresh();
    return names;
  }

  // dropzone: upload each capture, then convert it straight to .hc22000
  async function dropCapture(list: FileList) {
    const names = await uploadFiles('pcap', list);
    for (const name of names) await convertName(name);
    if (names.length) refresh();
  }

  async function upload(dir: DirKind, e: ChangeEvent<HTMLInputElement>) {
    await uploadFiles(dir, e.target.files || []);
    e.target.value = '';
  }

  async function del(dir: DirKind, name: string) {
    const r = await fetch('/api/file', { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ dir, name }) });
    if (r.ok) { flash(`deleted ${name}`); refresh(); } else flash('delete failed', true);
  }

  async function convertName(name: string): Promise<boolean> {
    flash(`converting ${name} …`);
    const j = await (await fetch('/api/convert', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }) })).json();
    if (j.ok) flash(`wrote ${j.out}${j.ssid ? ` · ${j.ssid}` : ''}`);
    else flash(j.error || `no handshake / PMKID in ${name}`, true);
    if (!selectedRef.current) { setLog(j.log || ''); }
    return !!j.ok;
  }


  async function crack() {
    const target = method === 'aircrack' ? selCap : selHash;
    if (!target || !selList) return flash(method === 'aircrack' ? 'pick a capture + wordlist' : 'pick a hash + wordlist', true);
    if (starting || panelBusy) return;
    setStarting(true);
    try {
      const response = await fetch('/api/crack', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method, target, wordlist: selList, workload, statusTimer }) });
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
    setResults(j.results || []); setView('keys'); refresh();
  }

  const n = (d: DirKind) => files[d]?.length || 0;
  const totalFiles = DIRS.reduce((a, d) => a + n(d), 0);
  const stateWord = cap(session?.status === 'stopping' ? 'Stopping' : session?.processState === 'paused' ? 'Paused' : session && !running ? (st?.status === 'Cracked' || st?.status === 'Exhausted' ? st.status : finishStatus(session)) : st?.status ? st.status.split(' ')[0] : (running ? 'Running' : 'Ready'));
  const tempVal = st?.temp ? +st.temp : null;
  const activeSessions = sessions.filter((s) => ['running', 'stopping'].includes(s.status)).length;

  const NAV = [
    { key: 'overview', label: 'Crack', icon: Zap, badge: 0 },
    { key: 'files', label: 'Files', icon: FolderOpen, badge: totalFiles },
    { key: 'keys', label: 'Recovered keys', icon: KeyRound, badge: results?.length || 0 },
    { key: 'settings', label: 'Settings', icon: Settings2, badge: 0 },
  ] as const;
  const title = view === 'files' ? 'Files' : view === 'keys' ? 'Recovered keys' : view === 'settings' ? 'Settings' : 'Crack';

  // ---- four directory stations ----
  const stationsGrid = (
    <div className="grid gap-4 md:grid-cols-2">
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
  );

  const target = method === 'aircrack' ? selCap : selHash;
  const startHint = !sessionsLoaded ? 'Checking for active sessions…'
    : panelBusy ? 'A panel session is active. Stop it before starting another.'
    : !target ? `Select a ${method === 'aircrack' ? 'capture' : 'hash'} to continue.`
    : !selList ? 'Select a wordlist to continue.' : 'Ready to start a dictionary attack.';
  const progressKnown = st?.pct != null;

  const crackWorkspace = (
    <section aria-labelledby="crack-title" className="overflow-hidden rounded-xl border bg-card text-card-foreground">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div className="flex items-center gap-3">
          <Zap className="size-5 text-muted-foreground" />
          <h2 id="crack-title" className="text-lg font-medium">crack</h2>
          <span className="hidden text-sm text-muted-foreground sm:inline">Dictionary attack</span>
        </div>
        <Badge variant="outline">one panel run at a time</Badge>
      </header>
      <div className="grid min-w-0 lg:grid-cols-[260px_minmax(0,1fr)]">
        <div className={cn("flex min-w-0 flex-col gap-6 border-b bg-muted/20 p-5 lg:order-first lg:border-r lg:border-b-0", session && "order-last border-t lg:border-t-0")}>
          <fieldset className="flex min-w-0 flex-col gap-2">
            <legend className="mb-2 text-sm font-medium">Engine</legend>
            <ToggleGroup aria-label="Crack engine" value={[method]} onValueChange={(values) => { if (values.length) setMethod(values[0] as Method); }} variant="outline" spacing={0} className="w-full">
              <ToggleGroupItem value="aircrack" className="flex-1">aircrack-ng</ToggleGroupItem>
              <ToggleGroupItem value="hashcat" className="flex-1">hashcat</ToggleGroupItem>
            </ToggleGroup>
            <p className="text-xs text-muted-foreground">{method === 'aircrack' ? 'CPU · pcap handshake' : 'GPU · hashcat -m 22000'}</p>
          </fieldset>
          <div className="flex min-w-0 flex-col gap-2">
            <div className="flex items-center justify-between gap-2 text-sm">
              <span className="font-medium">{method === 'aircrack' ? 'Capture' : 'Hash'}</span>
              <span className="font-mono text-xs text-muted-foreground">{method === 'aircrack' ? '.pcap' : '.hc22000'}</span>
            </div>
            {method === 'aircrack'
              ? <FileSelect icon={Wifi} value={selCap} onValueChange={setSelCap} placeholder="Select capture" files={files.pcap} ariaLabel="capture to crack" />
              : <FileSelect icon={Hash} value={selHash} onValueChange={setSelHash} placeholder="Select hash" files={files.hc22000} ariaLabel="hash to crack" />}
            <Button variant="ghost" size="sm" className="self-start" nativeButton={false} render={<label />}>
              <Upload data-icon="inline-start" /> Upload capture
              <input aria-label="Upload capture" type="file" accept=".pcap,.cap,.pcapng" multiple className="sr-only"
                onChange={(e) => { if (e.target.files?.length) dropCapture(e.target.files); e.target.value = ''; }} />
            </Button>
          </div>
          <div className="flex min-w-0 flex-col gap-2">
            <span className="text-sm font-medium">Wordlist</span>
            <FileSelect icon={List} value={selList} onValueChange={setSelList} placeholder="Select wordlist" files={files.wordlists} ariaLabel="wordlist" />
            {files.wordlists.length === 0 && <p className="text-xs text-muted-foreground">Add a wordlist in Files to start.</p>}
          </div>
          <div className="flex flex-col gap-3 pt-2">
            <Button onClick={crack} className="w-full" disabled={starting || panelBusy || !sessionsLoaded || !target || !selList}>
              {starting ? <Spinner data-icon="inline-start" /> : <Play data-icon="inline-start" />}
              {starting ? 'Starting…' : 'Run crack'}
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">{startHint}</p>
          </div>
        </div>

        <div className="flex min-w-0 flex-col gap-5 p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-medium">{session ? 'Selected session' : 'Session monitor'}</h3>
                <Badge variant="secondary" className={statusTone(stateWord).badge}>{stateWord}</Badge>
              </div>
              <p className="mt-2 truncate font-mono text-sm" title={session?.target || session?.command || undefined}>
                {session?.target || (session ? 'System process' : 'No session selected')}
              </p>
              <p className="mt-1 break-all text-xs text-muted-foreground">
                {session ? `${session.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'} · PID ${session.pid || '—'}${session.wordlist ? ` · ${session.wordlist}` : ''}${sessionDuration(session) ? ` · ran ${sessionDuration(session)}` : ''}` : 'Choose an engine, target and wordlist to start.'}
              </p>
            </div>
            {running && session?.source === 'panel' && (
              <Button variant="destructive" size="sm" onClick={abort} disabled={stopping || session.status === 'stopping' || !session.canStop}>
                {stopping || session.status === 'stopping' ? <Spinner data-icon="inline-start" /> : <Square data-icon="inline-start" />}
                {stopping || session.status === 'stopping' ? 'Stopping…' : 'Abort'}
              </Button>
            )}
          </div>
          {session?.source === 'system' && <Alert><AlertDescription>Process detected on this system. Live output and stop controls are available only for sessions started by this panel.</AlertDescription></Alert>}
          <div className="min-w-0" aria-label="Session status">
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-sm text-muted-foreground">Progress</span>
                <span className="font-mono text-4xl tabular-nums sm:text-5xl">{progressKnown ? `${pct.toFixed(pct >= 100 ? 0 : 1)}%` : '—'}</span>
              </div>
              <div role="progressbar" aria-label="Crack progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progressKnown ? Math.min(100, Math.max(0, pct)) : undefined} aria-valuetext={progressKnown ? `${pct.toFixed(1)}%` : running ? 'Waiting for engine progress' : 'No progress reported'} className="my-3 h-2.5 overflow-hidden rounded-full bg-muted">
                <div className="h-full rounded-full bg-primary transition-[width] duration-500 motion-reduce:transition-none" style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
              </div>
              <p className="font-mono text-xs text-muted-foreground tabular-nums">{st?.done && st?.total ? `${(+st.done).toLocaleString()} / ${(+st.total).toLocaleString()}` : running ? 'Waiting for engine progress…' : 'No progress reported'}</p>
              <div className="mt-5 grid grid-cols-2 gap-x-4 border-y sm:grid-cols-4">
                <Stat label="Speed">{st?.speed || '—'}</Stat>
                <Stat label="ETA">{st?.eta || '—'}</Stat>
                <Stat label="Recovered">{st?.recovered || '—'}</Stat>
                <Stat label="GPU">{tempVal != null ? `${tempVal}°C` : '—'}{st?.util ? ` · ${st.util}%` : ''}</Stat>
              </div>
              <div className="pt-5">
                <p className="text-xs text-muted-foreground">Current candidate</p>
                <p className="mt-2 break-all font-mono text-base">{st?.candidate || (running ? 'Waiting for engine output…' : '—')}</p>
              </div>
          </div>
          <section aria-labelledby="engine-output-title" className="min-w-0 border-t pt-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 id="engine-output-title" className="text-sm font-medium">{session?.source === 'system' ? 'Process command' : 'Engine output'}</h3>
              <span className="text-xs text-muted-foreground">{session?.source === 'system' ? 'Output unavailable' : running ? 'Following saved output' : 'Saved output'}</span>
            </div>
              {session?.source === 'system' ? (
                <Terminal title="process command">
                  <pre ref={preRef} className="max-h-96 overflow-auto p-0 font-mono text-xs leading-relaxed whitespace-pre text-neutral-700 dark:text-neutral-200">{session.command}</pre>
                </Terminal>
              ) : log ? <LogTerminal key={session?.id ?? 'none'} data={log} title={`${session?.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'} · ${running ? 'live' : 'saved output'}`} /> : (
                <Empty className="min-h-52"><EmptyHeader><EmptyTitle>No output yet</EmptyTitle><EmptyDescription>Saved engine output appears here when a session starts.</EmptyDescription></EmptyHeader></Empty>
              )}
              {session?.logTruncated && <p className="mt-3 text-xs text-muted-foreground">Showing the latest 256 KB of output. Full log saved on disk.</p>}
          </section>
          <p className="mt-auto pt-2 text-xs text-muted-foreground">Sessions keep running when you refresh or close this page.</p>
        </div>
      </div>
    </section>
  );

  const resultsCard = results && (
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
  );

  const settingsCard = (
    <Card className="max-w-xl">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Settings2 className="size-4 text-muted-foreground" />
          <CardTitle className="lowercase">crack settings</CardTitle>
        </div>
        <CardDescription>Applied to hashcat runs started from this panel. Saved in this browser.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2 text-sm">
            <span className="font-medium">Workload</span>
            <span className="font-mono text-xs text-muted-foreground">-w</span>
          </div>
          <ToggleGroup aria-label="hashcat workload" value={[String(workload)]} onValueChange={(v) => { if (v.length) setWorkload(Number(v[0])); }} variant="outline" spacing={0} className="w-full">
            <ToggleGroupItem value="1" className="flex-1">1 · low</ToggleGroupItem>
            <ToggleGroupItem value="2" className="flex-1">2 · default</ToggleGroupItem>
            <ToggleGroupItem value="3" className="flex-1">3 · high</ToggleGroupItem>
            <ToggleGroupItem value="4" className="flex-1">4 · nightmare</ToggleGroupItem>
          </ToggleGroup>
          <p className="text-xs text-muted-foreground">Low keeps the machine responsive; higher taxes the GPU harder.</p>
        </div>
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2 text-sm">
            <span className="font-medium">Status timer</span>
            <span className="font-mono text-xs text-muted-foreground">--status-timer</span>
          </div>
          <div className="flex items-center gap-2">
            <Input type="number" min={1} max={3600} value={statusTimer}
              onChange={(e) => setStatusTimer(Math.min(3600, Math.max(1, Math.floor(Number(e.target.value) || 1))))}
              className="w-28" aria-label="status timer seconds" />
            <span className="text-sm text-muted-foreground">seconds between progress updates</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <TooltipProvider>
      <SidebarProvider>
        <Sidebar collapsible="icon">
          <SidebarHeader>
            <div className="flex items-center gap-2 px-2 py-1">
              <img src="/wifish-logo.png" alt="wifish" className="h-8 w-auto invert dark:invert-0 group-data-[collapsible=icon]:hidden" />
            </div>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  {NAV.map((item) => (
                    <SidebarMenuItem key={item.key}>
                      <SidebarMenuButton isActive={view === item.key} tooltip={item.label} onClick={() => setView(item.key)}>
                        <item.icon />
                        <span>{item.label}</span>
                      </SidebarMenuButton>
                      {item.badge ? <SidebarMenuBadge className="tabular-nums">{item.badge}</SidebarMenuBadge> : null}
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
            <SessionHistory sessions={sessions} selectedId={session?.id} loaded={sessionsLoaded}
              onSelect={(session) => { selectSession(session); setView('overview'); }} />
          </SidebarContent>
          <SidebarFooter>
            <div className="flex items-center justify-between gap-2 px-2 group-data-[collapsible=icon]:hidden">
              <span className="text-xs text-muted-foreground">{activeSessions} active</span>
              <Button variant="ghost" size="icon-sm" aria-label="Clear finished sessions" title="Clear finished sessions" onClick={clearSessions} disabled={clearing || !finishedCount}>
                {clearing ? <Spinner /> : <Trash2 />}
              </Button>
            </div>
          </SidebarFooter>
        </Sidebar>

        <SidebarInset>
          <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
            <SidebarTrigger className="-ml-1" />
            <div className="flex flex-1 items-baseline gap-2.5">
              <h1 className="text-base font-medium">{title}</h1>
              <p className="hidden text-sm text-muted-foreground sm:block">WPA · WPA2 handshake console</p>
            </div>
            <ThemeToggle />
          </header>
          <main className="flex min-w-0 flex-1 flex-col gap-6 px-5 py-7 md:px-8 md:py-8">
            {(sessionError || streamError) && <Alert variant="destructive"><AlertDescription>{sessionError || streamError}</AlertDescription></Alert>}
            {view === 'files' && stationsGrid}
            {view === 'overview' && crackWorkspace}
            {view === 'settings' && settingsCard}
            {view === 'keys' && (resultsCard ?? (
              <Empty className="min-h-52">
                <EmptyHeader>
                  <EmptyTitle>No recovered key</EmptyTitle>
                  <EmptyDescription>Recovered keys for the selected session appear here. You can also show a hash’s key from Files.</EmptyDescription>
                </EmptyHeader>
                <Button variant="outline" onClick={() => setView('files')}><FolderOpen data-icon="inline-start" /> Open files</Button>
              </Empty>
            ))}
          </main>
        </SidebarInset>
      </SidebarProvider>
      <Toaster />
    </TooltipProvider>
  );
}
