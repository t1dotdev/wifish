import { watch, type FSWatcher } from 'node:fs';
import path from 'node:path';
import { readSavedLog } from './sessions.ts';

// Only observes the durable log. Disconnecting a viewer never signals the engine.
export function createLogStream(id: string, signal: AbortSignal | undefined, { directory = path.join(process.cwd(), '.wifish', 'sessions') }: { directory?: string } = {}): ReadableStream<Uint8Array> {
  let dispose: (closeController?: boolean) => void;
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const encoder = new TextEncoder();
      let closed = false, reading = false, dirty = false;
      let timer: ReturnType<typeof setTimeout> | undefined, watcher: FSWatcher | undefined, fallback: ReturnType<typeof setInterval> | undefined, heartbeat: ReturnType<typeof setInterval> | undefined;
      let previous: string | null = null;
      const close = () => dispose();
      dispose = (closeController = true) => {
        if (closed) return;
        closed = true;
        if (timer) clearTimeout(timer);
        if (fallback) clearInterval(fallback);
        if (heartbeat) clearInterval(heartbeat);
        watcher?.close(); signal?.removeEventListener('abort', close);
        if (closeController) { try { controller.close(); } catch {} }
      };
      const send = (event: string, data: unknown) => {
        if (closed) return;
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };
      async function publish(): Promise<void> {
        timer = undefined;
        if (closed) return;
        if (reading) { dirty = true; return; }
        if (controller.desiredSize !== null && controller.desiredSize <= 0) return;
        reading = true;
        try {
          const current = await readSavedLog(directory, id, true);
          if (closed) return;
          if (current.log !== previous) {
            const data = previous !== null && current.log.startsWith(previous)
              ? { append: current.log.slice(previous.length), logTruncated: current.logTruncated }
              : current;
            send('output', data);
            previous = current.log;
          }
        } catch {
          if (!closed) { send('stream-error', { error: 'Live output disconnected. Reconnecting…' }); dispose(); }
        } finally {
          reading = false;
          if (dirty && !closed) { dirty = false; schedule(); }
        }
      }
      function schedule(): void {
        if (!closed && !timer) timer = setTimeout(publish, 40);
      }
      signal?.addEventListener('abort', close, { once: true });
      if (signal?.aborted) { dispose(); return; }
      try {
        watcher = watch(path.join(directory, `${id}.log`), schedule);
        watcher.on('error', () => { watcher?.close(); });
      } catch { /* The periodic check also covers filesystems without watch support. */ }
      fallback = setInterval(schedule, 1000);
      heartbeat = setInterval(() => {
        if (!closed && controller.desiredSize !== null && controller.desiredSize > 0) controller.enqueue(encoder.encode(': keep-alive\n\n'));
      }, 15000);
      void publish();
    },
    cancel() { dispose?.(false); },
  });
}
