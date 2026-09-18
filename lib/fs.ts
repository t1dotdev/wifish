import { promises as fs } from 'node:fs';
import path from 'node:path';

// Operator data lives under .wifish/ (cwd = project root when `next` runs);
// public/ is reserved for static assets.
const ROOT = process.cwd();
const DATA = path.join(ROOT, '.wifish');

export interface DirSpec {
  path: string;
  exts: string[];
  output?: boolean;
}

export const DIRS: Record<string, DirSpec> = {
  pcap:      { path: path.join(DATA, 'pcap'),      exts: ['.pcap', '.pcapng', '.cap'] },
  hc22000:   { path: path.join(DATA, 'hc22000'),   exts: ['.hc22000', '.22000'] },
  wordlists: { path: path.join(DATA, 'wordlists'), exts: ['.txt', '.dic', '.lst', ''] },
  cracked:   { path: path.join(DATA, 'cracked'),   exts: ['.txt', ''], output: true },
};

export function isDir(kind: unknown): kind is string {
  return typeof kind === 'string' && Object.prototype.hasOwnProperty.call(DIRS, kind);
}

export interface SafeFile {
  base: string;
  abs: string;
  dir: string;
}

// Resolve <kind>/<name> safely. basename() strips any path, so traversal
// (../, absolute, nested) cannot escape the data dir. Returns null if invalid.
export function safeFile(kind: unknown, name: unknown): SafeFile | null {
  if (!isDir(kind) || typeof name !== 'string') return null;
  const base = path.basename(name.trim());
  if (!base || base === '.' || base === '..') return null;
  return { base, abs: path.join(DIRS[kind].path, base), dir: DIRS[kind].path };
}

export async function ensureDirs(): Promise<void> {
  await Promise.all(Object.values(DIRS).map((d) => fs.mkdir(d.path, { recursive: true })));
}

export interface FileEntry {
  name: string;
  size: number;
  mtime: number;
}

export async function listDir(kind: string): Promise<FileEntry[]> {
  const d = DIRS[kind];
  let entries: import('node:fs').Dirent[] = [];
  try {
    entries = await fs.readdir(d.path, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: FileEntry[] = [];
  for (const e of entries) {
    if (!e.isFile() || e.name.startsWith('.')) continue;
    let size = 0, mtime = 0;
    try {
      const st = await fs.stat(path.join(d.path, e.name));
      size = st.size; mtime = st.mtimeMs;
    } catch { /* skip unreadable */ }
    files.push({ name: e.name, size, mtime });
  }
  files.sort((a, b) => b.mtime - a.mtime);
  return files;
}

export async function listAll(): Promise<Record<string, FileEntry[]>> {
  const out: Record<string, FileEntry[]> = {};
  for (const kind of Object.keys(DIRS)) out[kind] = await listDir(kind);
  return out;
}

export interface CrackResult {
  ssid: string | null;
  bssid: string | null;
  password: string;
}

// persist parsed cracked results to .wifish/cracked/<hashbase>.txt
export async function writeCracked(hashBase: string, results: CrackResult[]): Promise<string | null> {
  if (!results || !results.length) return null;
  await fs.mkdir(DIRS.cracked.path, { recursive: true });
  const base = path.basename(hashBase).replace(/\.[^.]+$/, '');
  const file = path.join(DIRS.cracked.path, `${base}.txt`);
  const body = results
    .map((r) => `${r.ssid || '?'}\t${r.bssid || '?'}\t${r.password}`)
    .join('\n') + '\n';
  await fs.writeFile(file, body);
  return `${base}.txt`;
}
