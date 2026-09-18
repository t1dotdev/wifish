import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { createSessionStore, parseProcesses, type EngineProcess, type StartSpec } from '../lib/sessions.ts';

async function fixture(t: test.TestContext, code = "console.log('fixture output'); setInterval(() => {}, 1000)") {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'wifish-test-'));
  const processes = new Map<number, EngineProcess>();
  const children: ChildProcess[] = [];
  const options = { directory, discover: async () => [...processes.values()], spawnProcess: (_cmd: string, _args: string[], config: SpawnOptions) => {
    const child = spawn(process.execPath, ['-e', code], config);
    children.push(child);
    processes.set(child.pid!, { pid: child.pid!, identity: 'fixture-start', method: 'hashcat', startedAt: new Date().toISOString(), command: 'hashcat fixture' });
    child.on('close', () => processes.delete(child.pid!));
    return child;
  } };
  t.after(async () => {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill();
    await new Promise((r) => setTimeout(r, 100));
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { directory, options, processes, store: createSessionStore(options) };
}
const spec: StartSpec = { method: 'hashcat', target: 'fixture.hc22000', wordlist: 'fixture.txt', command: 'hashcat', args: [] };
async function until(fn: () => Promise<boolean>) {
  for (let i = 0; i < 60; i++) { if (await fn()) return; await new Promise((r) => setTimeout(r, 25)); }
  assert.fail('Timed out waiting for session state');
}

test('system discovery includes both engines, excludes shells and zombies, preserves paused state', () => {
  const identities = ' 11 Fri Sep 18 12:00:00 2026 R /opt/homebrew/bin/hashcat\n 12 Fri Sep 18 12:00:01 2026 T aircrack-ng\n 13 Fri Sep 18 12:00:02 2026 S /bin/zsh\n 14 Fri Sep 18 12:00:03 2026 Z hashcat';
  const result = parseProcesses(identities, '11 hashcat --session demo\n12 aircrack-ng -w list capture\n13 zsh -c hashcat');
  assert.deepEqual(result.map((p) => p.method), ['hashcat', 'aircrack']);
  assert.equal(result[1].processState, 'paused');
  assert.equal(result[0].command, 'hashcat --session demo');
});

test('session and log survive a fresh store; managed process is not duplicated as external', async (t) => {
  const { store, options } = await fixture(t);
  const session = await store.start(spec);
  await until(async () => (await store.get(session.id)).log.includes('fixture output'));
  const reloaded = createSessionStore(options);
  const recovered = await reloaded.get(session.id);
  assert.equal(recovered.pid, session.pid);
  assert.equal(recovered.status, 'running');
  assert.match(recovered.log, /fixture output/);
  assert.equal((await reloaded.list()).sessions.length, 1);
  await reloaded.stop(session.id);
  await until(async () => (await store.get(session.id)).status === 'aborted');
});

test('concurrent starts keep one panel session; explicit stop ends it', async (t) => {
  const { store } = await fixture(t);
  const results = await Promise.allSettled([store.start(spec), store.start(spec)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  const session = (results.find((r) => r.status === 'fulfilled') as PromiseFulfilledResult<any>).value;
  await assert.rejects(store.start(spec), { status: 409 });
  await store.stop(session.id);
  await until(async () => (await store.get(session.id)).status === 'aborted');
});

test('external engines are listed and cannot be stopped through the panel', async (t) => {
  const { store, processes } = await fixture(t);
  processes.set(99901, {pid:99901,identity:'external',method:'aircrack',startedAt:new Date().toISOString(),command:'aircrack-ng capture.cap'});
  const { sessions } = await store.list();
  assert.equal(sessions[0].source, 'system');
  assert.equal(sessions[0].canStop, false);
  assert.equal((await store.get(sessions[0].id)).logAvailable, false);
  await assert.rejects(store.stop(sessions[0].id), { status: 404 });
});

test('missing engine records failure and releases the run lock', async (t) => {
  const { options } = await fixture(t);
  const store = createSessionStore({ ...options, spawnProcess: spawn });
  const session = await store.start({ ...spec, command: '/nonexistent/wifish-engine' });
  await until(async () => (await store.get(session.id)).status === 'failed');
  assert.match((await store.get(session.id)).log, /not installed/);
  const second = await store.start({ ...spec, command: '/nonexistent/wifish-engine' });
  await until(async () => (await store.get(second.id)).status === 'failed');
});

test('aircrack results are saved without a browser connected', async (t) => {
  const { options } = await fixture(t, "console.log('KEY FOUND! [ fixture-key ]')");
  let persisted: { target: string; results: unknown } | undefined;
  const store = createSessionStore({ ...options, onResults: async (target: string, results: any) => { persisted = {target, results}; } });
  const session = await store.start({ ...spec, method: 'aircrack', target: 'fixture.cap' });
  await until(async () => Boolean((await store.get(session.id)).results));
  assert.equal(persisted!.target, 'fixture.cap');
  assert.equal((persisted!.results as any[])[0].password, 'fixture-key');
});

test('process discovery errors preserve running state and report incomplete discovery', async (t) => {
  const { store, options } = await fixture(t);
  const session = await store.start(spec);
  const reloaded = createSessionStore({ ...options, discover: async () => { throw new Error('denied'); } });
  const result = await reloaded.list();
  assert.ok(result.discoveryError);
  assert.equal(result.sessions[0].status, 'running');
  assert.equal(result.sessions[0].canStop, false);
  await store.stop(session.id);
});

test('clearFinished removes finished panel records and logs, keeps running sessions', async (t) => {
  const { store, directory } = await fixture(t);
  const first = await store.start(spec);
  await store.stop(first.id);
  await until(async () => (await store.get(first.id)).status === 'aborted');
  const second = await store.start(spec);
  await store.stop(second.id);
  await until(async () => (await store.get(second.id)).status === 'aborted');
  const live = await store.start(spec);

  const { cleared } = await store.clearFinished();
  assert.equal(cleared, 2);
  await assert.rejects(store.get(first.id), { status: 404 });
  const names = await fs.readdir(directory);
  assert.ok(!names.includes(`${first.id}.json`) && !names.includes(`${first.id}.log`));
  assert.ok(names.includes(`${live.id}.json`) && names.includes(`${live.id}.log`));
  assert.deepEqual((await store.list()).sessions.filter((s) => s.source === 'panel').map((s) => s.id), [live.id]);
  await store.stop(live.id);
});

test('request abort does not terminate a session; fresh GET recovers it', async (t) => {
  const { store, directory } = await fixture(t);
  globalThis.__wifishSessions = store;
  let source = await fs.readFile(new URL('../app/api/crack/route.ts', import.meta.url), 'utf8');
  source = source.replace("import { promises as fs } from 'node:fs';", 'const fs = { stat: async () => ({isFile: () => true}) };')
    .replace("import { safeFile, writeCracked } from '@/lib/fs';", "const safeFile = (_: unknown, base: string) => ({base, abs: base}); const writeCracked = () => {};")
    .replace("import { createSessionStore, POTFILE, type Method } from '@/lib/sessions';", "type Method = 'hashcat' | 'aircrack'; const POTFILE = '/fixture/potfile';")
    .replace("import { createLogStream } from '@/lib/session-stream';", '');
  // Load the rewritten route as a real file: Node strips types on disk, not in data: URLs.
  const routeFile = path.join(directory, 'route.fixture.ts');
  await fs.writeFile(routeFile, source);
  const route = await import(pathToFileURL(routeFile).href);
  const controller = new AbortController();
  const request = new Request('http://localhost/api/crack', { method:'POST', body:JSON.stringify(spec), signal:controller.signal });
  const response = await route.POST(request);
  assert.equal(response.status, 201);
  const { session } = await response.json();
  controller.abort();
  const recovered = await (await route.GET(new Request(`http://localhost/api/crack?id=${session.id}`))).json();
  assert.equal(recovered.session.status, 'running');
  assert.equal(recovered.session.pid, session.pid);
  const stopped = await route.DELETE(new Request('http://localhost/api/crack', {method:'DELETE', body:JSON.stringify({id:session.id})}));
  assert.equal(stopped.status, 200);
  await until(async () => (await store.get(session.id)).status === 'aborted');
  delete (globalThis as any).__wifishSessions;
});
