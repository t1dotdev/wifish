import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createLogStream } from '../lib/session-stream.ts';

async function readEvent(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<any> {
  const next = reader.read();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const { value, done } = await Promise.race([next, new Promise<never>((_, reject) => {
      timeout = setTimeout(() => reject(new Error('Output was not pushed within 700 ms')), 700);
    })]);
    assert.equal(done, false);
    return JSON.parse(new TextDecoder().decode(value).match(/data: (.+)/)![1]);
  } finally { clearTimeout(timeout); }
}

test('saved output is replayed immediately; new output is pushed without the two-second poll', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'wifish-stream-'));
  const file = path.join(directory, 'fixture.log');
  await fs.writeFile(file, 'existing output\n');
  const controller = new AbortController();
  t.after(async () => { controller.abort(); await fs.rm(directory, { recursive: true, force: true }); });
  const reader = createLogStream('fixture', controller.signal, { directory }).getReader();
  assert.equal((await readEvent(reader)).log, 'existing output\n');
  await fs.appendFile(file, 'live output\n');
  assert.equal((await readEvent(reader)).append, 'live output\n');
  controller.abort();
  assert.equal((await reader.read()).done, true);
  // Disconnect only removes the viewer. The saved log remains writable and replayable.
  await fs.appendFile(file, 'output after disconnect\n');
  const reconnected = createLogStream('fixture', new AbortController().signal, { directory }).getReader();
  assert.match((await readEvent(reconnected)).log, /output after disconnect/);
  await reconnected.cancel();
});
