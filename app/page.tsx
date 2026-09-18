'use client';
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import type { CrackResult, FileEntry } from '@/lib/fs';

/* ---------- authored icon set (one stroke language, SF-ish) ---------- */
const ICONS: Record<string, { el: ReactNode }> = {
  wifi:     { el: <><path d="M2 6.2c3.6-3 8.4-3 12 0"/><path d="M4.3 8.8c2.3-1.9 5.1-1.9 7.4 0"/><path d="M6.6 11.4c.9-.8 1.9-.8 2.8 0"/><circle cx="8" cy="13.4" r="0.9" fill="currentColor" stroke="none"/></> },
  hash:     { el: <><path d="M6.2 2.5 4.4 13.5M11.6 2.5 9.8 13.5M3 6h11M2.5 10h11"/></> },
  list:     { el: <><circle cx="3.5" cy="4" r="1" fill="currentColor" stroke="none"/><circle cx="3.5" cy="8" r="1" fill="currentColor" stroke="none"/><circle cx="3.5" cy="12" r="1" fill="currentColor" stroke="none"/><path d="M6.5 4h7M6.5 8h7M6.5 12h7"/></> },
  key:      { el: <><circle cx="5.4" cy="5.4" r="2.9"/><path d="M7.5 7.5 13.5 13.5M11.6 11.6l1.6-1.6M13.4 13.4l1.3-1.3"/></> },
  bolt:     { el: <><path d="M8.8 1.6 3.6 9.2h3.4l-1 5.2 5.4-8h-3.5z" fill="currentColor" stroke="none"/></> },
  convert:  { el: <><path d="M8 2.6v7.6M5.2 7.4 8 10.2l2.8-2.8"/><path d="M2.8 13.4h10.4"/></> },
  upload:   { el: <><path d="M8 10.5V3M5.2 7.6 8 2.8l2.8 2.8"/><path d="M2.8 12.6h10.4"/></> },
  download: { el: <><path d="M8 2.8v7.6M5.2 7.6 8 10.4l2.8-2.8"/><path d="M2.8 13h10.4"/></> },
  trash:    { el: <><path d="M3.4 4.4h9.2M6 4.4V2.9h4v1.5M4.4 4.4l.7 9.1h5.8l.7-9.1"/></> },
  play:     { el: <><path d="M5 3.4 12.6 8 5 12.6z" fill="currentColor" stroke="none"/></> },
  stop:     { el: <><rect x="4.2" y="4.2" width="7.6" height="7.6" rx="2.2" fill="currentColor" stroke="none"/></> },
  check:    { el: <><path d="M3 8.4 6.4 12 13 4.4"/></> },
  chev:     { el: <><path d="M4.5 6.2 8 9.6l3.5-3.4"/></> },
  gauge:    { el: <><path d="M2.5 12a5.5 5.5 0 0 1 11 0"/><path d="M8 12 11 7.2"/><circle cx="8" cy="12" r="1" fill="currentColor" stroke="none"/></> },
};
function Icon({ name, size = 16 }: { name: string; size?: number }) {
  const g = ICONS[name];
  if (!g) return null;
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
      strokeWidth="1.55" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{g.el}</svg>
  );
}

type DirKind = 'pcap' | 'hc22000' | 'wordlists' | 'cracked';
type Method = 'hashcat' | 'aircrack';

const STATIONS: Record<DirKind, { idx: number; tint: string; label: string; sub: string; icon: string }> = {
  pcap:      { idx: 1, tint: 'blue',   label: 'capture',   sub: '.pcap',      icon: 'wifi' },
  hc22000:   { idx: 2, tint: 'amber',  label: 'hashes',    sub: '.hc22000',   icon: 'hash' },
  wordlists: { idx: 3, tint: 'violet', label: 'wordlists', sub: 'candidates', icon: 'list' },
  cracked:   { idx: 4, tint: 'green',  label: 'recovered', sub: 'keys',       icon: 'key' },
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
  const [toast, setToast] = useState<{ msg: string; err: boolean } | null>(null);
  const preRef = useRef<HTMLPreElement | null>(null);

  const st = useMemo(() => parseStatus(log, session?.method || method), [log, method, session?.method]);
  const pct = st?.pct ?? 0;

  const flash = (msg: string, err = false) => { setToast({ msg, err }); setTimeout(() => setToast(null), 3500); };

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
          let recovered: CrackResult[] = current.results || parseAircrackKey(current.log || '') || [];
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
  const stateClass = stateWord.toLowerCase();
  const tempVal = st?.temp ? +st.temp : null;

  return (
    <div className="cc">
      <header className="hpill glass">
        <div className="brand">
          <span className="mark">wi<span className="dotwifi">fi</span>sh</span>
          <span className="tag">WPA · WPA2 handshake console</span>
        </div>
        <div className="chips">
          {DIRS.map((d) => (
            <span className="chip" data-tint={STATIONS[d].tint} key={d}>
              <span className="dot" />{STATIONS[d].label} <b>{n(d)}</b>
            </span>
          ))}
        </div>
        <div className="lamps">
          <span className="lamp"><span className="led" />hashcat</span>
          <span className={`lamp ${tempVal != null && tempVal > 85 ? 'off' : tempVal != null && tempVal > 75 ? 'warn' : ''}`}>
            <span className="led" />gpu{tempVal ? ` ${tempVal}°` : ''}
          </span>
        </div>
      </header>

      <div className="board">
        {/* ---- left: four stations ---- */}
        <div className="stations">
          {DIRS.map((dir) => {
            const s = STATIONS[dir];
            return (
              <article className="tile station" data-tint={s.tint} key={dir}>
                <div className="tilehead">
                  <span className="glyph"><Icon name={s.icon} size={17} /></span>
                  <div className="tiletitle"><b>{s.label}</b><span>{n(dir)} · {s.sub}</span></div>
                  <span className="idx">{s.idx}</span>
                </div>
                <ul className="filelist">
                  {n(dir) === 0 && <li className="empty">no files yet</li>}
                  {(files[dir] || []).map((f) => (
                    <li className="frow" key={f.name}>
                      <span className="fname" title={f.name}>{f.name}</span>
                      <span className="fsize">{fmt(f.size)}</span>
                      <span className="rowacts">
                        {dir === 'hc22000' && (
                          <button className="iact tintact" title="show cracked key" onClick={() => showCracked(f.name)}><Icon name="key" /></button>
                        )}
                        <a className="iact" title="download" href={`/api/file?dir=${dir}&name=${encodeURIComponent(f.name)}`}><Icon name="download" /></a>
                        <button className="iact danger" title="delete" onClick={() => del(dir, f.name)}><Icon name="trash" /></button>
                      </span>
                    </li>
                  ))}
                </ul>
                {dir !== 'cracked' && (
                  <div className="upload">
                    <label><Icon name="upload" /> add {s.label}<input type="file" multiple onChange={(e) => upload(dir, e)} /></label>
                  </div>
                )}
              </article>
            );
          })}
        </div>

        {/* ---- right: operate ---- */}
        <div className="ops">
          {/* convert */}
          <article className="tile convert" data-tint="amber">
            <div className="tilehead">
              <span className="glyph"><Icon name="convert" size={17} /></span>
              <div className="tiletitle"><b>convert</b><span>pcap → .hc22000</span></div>
            </div>
            <div className="convgrid">
              <div className="sel">
                <span className="selglyph"><Icon name="wifi" size={15} /></span>
                <select aria-label="capture to convert" value={selPcap} onChange={(e) => setSelPcap(e.target.value)}>
                  <option value="">Select a capture…</option>
                  {files.pcap.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
                </select>
                <span className="chev"><Icon name="chev" size={15} /></span>
              </div>
              <button className="btn amberbtn" onClick={convert} disabled={!selPcap}><Icon name="convert" /> Convert</button>
            </div>
          </article>

          <article className="tile sessions" data-tint="blue" aria-label="System sessions">
            <div className="tilehead">
              <span className="glyph"><Icon name="list" size={17} /></span>
              <div className="tiletitle"><b>System sessions</b><span>{sessionsLoaded ? `${sessions.filter((s) => ['running', 'stopping'].includes(s.status)).length} active · this system` : 'checking system…'}</span></div>
              <button className="iact danger" title="clear finished sessions" aria-label="clear finished sessions" onClick={clearSessions} disabled={clearing || !finishedCount}><Icon name="trash" /></button>
            </div>
            <p className="sessionhint">Sessions keep running when you refresh or close this page.</p>
            {(sessionError || streamError) && <p className="sessionerror" role="status">{sessionError || streamError}</p>}
            {sessionsLoaded && sessions.length === 0 && !sessionError && <p className="sessionhint">No hashcat or aircrack-ng sessions running. Choose a target and wordlist below to start.</p>}
            <ul className="sessionlist">
              {sessions.map((s) => (
                <li key={s.id}>
                  <button type="button" className={`sessionrow ${session?.id === s.id ? 'selected' : ''}`} aria-pressed={session?.id === s.id} onClick={() => selectSession(s)}>
                    <span className="sessiontop"><b>{s.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'}</b><span className={`state ${s.status}`}>{s.processState === 'paused' ? 'paused' : s.status}</span></span>
                    <span className="sessiontarget" title={s.target || s.command}>{s.target || s.command}</span>
                    <span className="sessionmeta">PID {s.pid || '—'} · {s.source === 'panel' ? 'panel' : 'started outside panel'} · {new Date(s.startedAt).toLocaleString()}{s.wordlist ? ` · ${s.wordlist}` : ''}</span>
                  </button>
                </li>
              ))}
            </ul>
          </article>

          {/* crack — hero */}
          <article className="tile crack" data-tint={running ? 'amber' : 'blue'}>
            <div className="tilehead">
              <span className="glyph" style={{ '--tint': 'var(--red)', '--tint2': 'var(--red-2)' } as React.CSSProperties}><Icon name="bolt" size={17} /></span>
              <div className="tiletitle"><b>crack</b><span>{method === 'aircrack' ? 'aircrack-ng · dictionary' : 'hashcat -m 22000'}</span></div>
              <div className="seg engine" role="radiogroup" aria-label="crack engine">
                <button type="button" className={method === 'aircrack' ? 'on' : ''} role="radio" aria-checked={method === 'aircrack'} onClick={() => setMethod('aircrack')}>aircrack-ng</button>
                <button type="button" className={method === 'hashcat' ? 'on' : ''} role="radio" aria-checked={method === 'hashcat'} onClick={() => setMethod('hashcat')}>hashcat</button>
              </div>
            </div>

            <div className="crackctl">
              {method === 'aircrack' ? (
                <div className="sel">
                  <span className="selglyph"><Icon name="wifi" size={15} /></span>
                  <select aria-label="capture to crack" value={selCap} onChange={(e) => setSelCap(e.target.value)}>
                    <option value="">Capture…</option>
                    {files.pcap.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
                  </select>
                  <span className="chev"><Icon name="chev" size={15} /></span>
                </div>
              ) : (
                <div className="sel">
                  <span className="selglyph"><Icon name="hash" size={15} /></span>
                  <select aria-label="hash to crack" value={selHash} onChange={(e) => setSelHash(e.target.value)}>
                    <option value="">Hash…</option>
                    {files.hc22000.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
                  </select>
                  <span className="chev"><Icon name="chev" size={15} /></span>
                </div>
              )}
              <div className="sel">
                <span className="selglyph"><Icon name="list" size={15} /></span>
                <select aria-label="wordlist" value={selList} onChange={(e) => setSelList(e.target.value)}>
                  <option value="">Wordlist…</option>
                  {files.wordlists.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
                </select>
                <span className="chev"><Icon name="chev" size={15} /></span>
              </div>
              {running && session?.source === 'panel'
                ? <button className="btn stop runbtn" onClick={abort} disabled={stopping || session.status === 'stopping' || !session.canStop}><Icon name="stop" /> {stopping || session.status === 'stopping' ? 'Stopping…' : 'Abort'}</button>
                : <button className="btn go runbtn" onClick={crack} disabled={starting || panelBusy || !sessionsLoaded || (method === 'aircrack' ? !selCap : !selHash) || !selList}><Icon name="play" /> {starting ? 'Starting…' : 'Run'}</button>}
            </div>

            {session && <p className="sessionhint">Viewing {session.method === 'aircrack' ? 'aircrack-ng' : 'hashcat'} · PID {session.pid || '—'} · {session.target || 'system session'}</p>}
            {session?.source === 'system' && <p className="sessionhint">Process detected on this system. Live output and stop controls are available only for sessions started by this panel.</p>}
            {session?.logTruncated && <p className="sessionhint">Showing the latest 256 KB of output. Full log saved on disk.</p>}
            <div className="seg" role="tablist" aria-label="crack readout">
              <button className={tab === 'status' ? 'on' : ''} onClick={() => setTab('status')} role="tab" aria-selected={tab === 'status'} id="tab-status" aria-controls="panel-readout">
                <Icon name="gauge" size={14} /> Status{running && <span className="livedot" />}
              </button>
              <button className={tab === 'log' ? 'on' : ''} onClick={() => setTab('log')} role="tab" aria-selected={tab === 'log'} id="tab-log" aria-controls="panel-readout">Log</button>
            </div>

            <div role="tabpanel" id="panel-readout" aria-labelledby={tab === 'status' ? 'tab-status' : 'tab-log'}>
            {tab === 'status' ? (
              <div className="dash">
                <div className="ringwrap">
                  <svg className="ring" viewBox="0 0 184 184">
                    <defs>
                      <linearGradient id="ccgrad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0" stopColor="var(--blue)" />
                        <stop offset="1" stopColor="var(--green)" />
                      </linearGradient>
                    </defs>
                    <circle className="track" cx="92" cy="92" r={RING_R} />
                    <circle className="prog" cx="92" cy="92" r={RING_R}
                      strokeDasharray={RING_C} strokeDashoffset={RING_C * (1 - pct / 100)} />
                  </svg>
                  <div className="ringlabel">
                    <span className="big">{pct.toFixed(pct >= 100 ? 0 : 1)}<i>%</i></span>
                    <span className={`state ${stateClass}`}>{stateWord}</span>
                  </div>
                </div>
                <div className="livegrid">
                  <div className="lstat"><label>speed</label><b>{st?.speed || '—'}</b></div>
                  <div className="lstat"><label>recovered</label><b>{st?.recovered || '—'}</b></div>
                  <div className="lstat"><label>eta</label><b>{st?.eta || '—'}</b></div>
                  <div className="lstat"><label>gpu</label><b className={tempVal != null && tempVal > 85 ? 'hot' : tempVal != null && tempVal > 75 ? 'warm' : ''}>{tempVal ? `${tempVal}°C` : '—'}{st?.util ? ` · ${st.util}%` : ''}</b></div>
                  <div className="lstat span"><label>current phrase</label><b className="cand" key={st?.candidate}>{st?.candidate || (running ? 'warming up…' : 'awaiting run')}</b></div>
                  <div className="lstat span"><label>progress</label><b>{st?.done && st?.total ? `${(+st.done).toLocaleString()} / ${(+st.total).toLocaleString()}` : '—'}</b></div>
                </div>
              </div>
            ) : (
              <pre className={`logpre ${log || session?.source === 'system' ? '' : 'empty'}`} ref={preRef}>{session?.source === 'system' ? session.command : log}</pre>
            )}
            </div>
          </article>

          {/* recovered key readout */}
          {results && (
            <article className="tile keyout" data-tint="green">
              <div className="tilehead">
                <span className="glyph"><Icon name="key" size={17} /></span>
                <div className="tiletitle"><b>recovered key</b><span>{shownHash || selHash}</span></div>
              </div>
              {results.length === 0
                ? <div className="keyempty">No recovered key found for this session.</div>
                : (
                  <div className="keylist">
                    {results.map((r, i) => (
                      <div className="keycard" key={i}>
                        <span className="kpw">{r.password}</span>
                        <span className="kmeta"><span className="kssid">{r.ssid || '—'}</span><span className="kbssid">{r.bssid || '—'}</span></span>
                      </div>
                    ))}
                  </div>
                )}
            </article>
          )}
        </div>
      </div>

      {toast && <div className={`toast ${toast.err ? 'err' : ''}`}><span className="tled" />{toast.msg}</div>}
    </div>
  );
}
