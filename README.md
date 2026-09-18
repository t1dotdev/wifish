<div align="center">

<img src="public/wifish-logo.png" width="420" alt="wifish" />

**A local, single-screen console for the WPA/WPA2 handshake-cracking pipeline.**

Capture → convert → crack → recovered key — driven from one screen, no shell required.

<sub>Next.js 15 · React 19 · TypeScript · Tailwind v4 · runs fully offline on your own hardware</sub>

</div>

---

`wifish` turns a captured Wi-Fi handshake into a recovered network key. It's a thin, honest operator console over the real toolchain — `hcxpcapngtool`, `hashcat`, `aircrack-ng` — that surfaces each engine's own live output (speed, progress, current candidate) instead of a simulated one. It manages the files those tools consume and produce, and never hides the tools underneath.

It runs on `localhost:3200` for a single operator, against handshakes **you are authorized to test**.

## The pipeline

```
 ┌── pcap ──────┐   ┌── hc22000 ─────┐   ┌── crack ──────────┐   ┌── cracked ──┐
 │  captures    │ → │ hcxpcapngtool  │ → │ hashcat -m 22000  │ → │ ssid        │
 │  .pcap       │   │ → .hc22000     │   │   or aircrack-ng  │   │ bssid       │
 └──────────────┘   └────────────────┘   └───────────────────┘   │ password    │
                                                                  └─────────────┘
```

Four stages, four directories, one screen. The operator always knows what stage a file is at.

## Features

- **File management per stage** — list, upload, download, delete captures, hashes and wordlists (`cracked/` is output-only).
- **Convert** — `pcap` → `.hc22000` via `hcxpcapngtool`, surfacing parsed SSID / BSSID / handshake count, with a clear failure when there's no EAPOL/PMKID.
- **Two engines** — GPU-bound `hashcat -m 22000` against the `.hc22000`, or CPU-bound `aircrack-ng` straight on the `.pcap`.
- **Live status from the engine's own text** — percent, speed (H/s or k/s), current candidate, recovered count, ETA, GPU temp/util. aircrack-ng's cursor-painted curses TUI is replayed faithfully through an embedded `xterm` terminal.
- **Durable runs** — a crack spawns detached and writes straight to its log file, so page refreshes and disconnects leave the process running; the session is restored on reload. Stop is explicit. One panel-started crack at a time.
- **Full process visibility** — hashcat/aircrack-ng processes started outside the panel are listed too, with command, PID and state.
- **Show cracked** — `hashcat --show` (potfile) and aircrack-ng's `KEY FOUND!` parsed into `ssid / bssid / password`, persisted one file per hash.
- **Dark terminal aesthetic** with a light/dark theme switcher.

## Prerequisites

The app shells out to these — install whatever you plan to use. Missing binaries surface in-app as a `500 "not installed"`.

| Tool | Used for |
|------|----------|
| [`hcxpcapngtool`](https://github.com/ZerBea/hcxtools) | convert `pcap` → `.hc22000` |
| [`hashcat`](https://hashcat.net/hashcat/) | GPU cracking (`-m 22000`) |
| [`aircrack-ng`](https://www.aircrack-ng.org/) | CPU cracking |

Plus Node.js v22+ — the tests rely on native TypeScript type stripping.

## Quick start

```bash
npm install            # bun install also works — both lockfiles are kept in sync
npm run dev            # dev server on http://localhost:3200
```

Then open the panel, drop a `.pcap` into the capture stage, and work it down the pipeline.

```bash
npm run build && npm start   # production, also on port 3200 (build doubles as the typecheck)
npm test                     # node --test over tests/*.test.ts — no server or real tools needed
```

Operator data lives under `.wifish/` in the repo root (gitignored), with the hashcat potfile pinned alongside it:

```
.wifish/
├── pcap/        captures (.pcap)
├── hc22000/     converted hashes (.hc22000)
├── wordlists/   candidate lists (rockyou.txt, digit lists, … up to multi-GB)
├── cracked/     recovered keys, one file per hash: ssid ⇥ bssid ⇥ password
└── sessions/    crack session metadata + logs
hashcat.potfile  pinned via --potfile-path — never ~/.hashcat
```

## Project layout

The whole app is small and deliberately flat:

- `app/page.tsx` — the entire UI (one client component, including the hashcat/aircrack log parsing).
- `app/api/{files,file,convert,crack,cracked}/route.ts` — the entire backend.
- `lib/` — domain logic and the only thing the tests import: `fs.ts` (data dirs + path safety), `sessions.ts` (session/process store), `session-stream.ts` (SSE over the saved log).

See **[AGENTS.md](AGENTS.md)** for build invariants and conventions, and **[PRODUCT.md](PRODUCT.md)** for product scope, exact terminology and voice.

## Security & legal

Cracking a Wi-Fi handshake you do not own or have written permission to test is illegal in most jurisdictions. `wifish` is for authorized security testing, research, and recovering keys to networks you control — nothing else. You are responsible for how you use it.

It's built to stay local: single operator, offline by nature, all file access confined to the data directories through a basename guard (no path traversal), and no data leaves your machine.
