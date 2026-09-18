# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Primary user: the tool's owner — a security-minded operator (pentester / Wi-Fi security hobbyist) running it locally on their own machine against handshakes they are authorized to test. Single operator, not a multi-tenant or shared product. Sits at a workstation with an active GPU while a crack runs.

## Product Purpose
`wifish` is a local control panel for the WPA/WPA2 handshake-cracking pipeline. It turns captured Wi-Fi handshakes into recovered network keys through four stages the operator drives from one screen: manage capture files, convert `pcap` → hashcat `.hc22000`, run `hashcat -m 22000` against a wordlist, and read the recovered key. Success = the operator can go from a capture to a cracked key (or a confident "not found") without touching the shell.

## Positioning
A single-screen operator console over the real `hcxpcapngtool` + `hashcat` / `aircrack-ng` toolchain, running fully offline on the operator's own hardware. Not a hosted service, not a cloud cracker, not a wrapper that hides the tools — it surfaces the chosen engine's live truth (speed, progress, current candidate) as a first-class readout while managing the files those tools consume and produce.

## Operating Context
Runs as a Next.js app on `localhost:3200`. Four data directories under `.wifish/` are the working set: `pcap/` (captures), `hc22000/` (converted hashes), `wordlists/` (candidate lists, up to multi-GB), `cracked/` (recovered keys, persisted one file per hash). Actions shell out to `hcxpcapngtool`, `hashcat`, and `aircrack-ng`; a crack is long-running and its saved output streams to the selected viewer as the log changes; a ~2s poll recovers session metadata and provides an output fallback. One panel-started crack at a time (single run lock). Session metadata and logs live in `.wifish/sessions/`; page refreshes and disconnects leave the process running. Cracked keys are also written to disk as `ssid ⇥ bssid ⇥ password`.

## Capabilities and Constraints
- File management per directory: list, upload, download, delete (`cracked/` is output-only, no upload).
- Convert: `pcap` → `.hc22000`, surfaces parsed SSID/BSSID/handshake count; fails clearly when no EAPOL/PMKID.
- Crack: choose an engine — `hashcat -m 22000` on the `.hc22000`, or `aircrack-ng` on the `.pcap` directly — then pick target + wordlist, read live saved output, explicitly abortable; one panel run at a time. Restore the selected session on refresh and list all hashcat/aircrack-ng processes visible on the system. Processes started outside the panel show command/PID/state; their terminal output and stop controls are unavailable in the panel.
- Live status parsed from the engine's own text (hashcat status, or aircrack-ng's ANSI-stripped curses TUI): percent, speed (H/s or k/s), current candidate phrase, recovered, ETA, GPU temp/util, progress counts.
- Show cracked: `hashcat --show` (potfile) parsed into ssid / bssid / password; aircrack-ng's `KEY FOUND!` parsed from the saved server log, even with no page open. Both persisted to `cracked/`.
- Constraints: local single-user; path access confined to the four dirs (basename guard, no traversal); tool availability (`hcxpcapngtool` for convert; `hashcat` and/or `aircrack-ng` for cracking) required; GPU-bound (hashcat) or CPU-bound (aircrack-ng) throughput.
- Terminology (exact, preserve): `pcap`, `hc22000`, `wordlist`, `handshake`, `PMKID`, `EAPOL`, `BSSID`, `ESSID/SSID`, `candidate`, `hashcat -m 22000`, `aircrack-ng`, `potfile`.

## Brand Commitments
- Name: `wifish` (lowercase). Binding visual constraint volunteered by the user: dark hacker / terminal aesthetic.
- Voice: terse, technical, exact — no marketing tone. States outcomes plainly (cracked / not found / failed).

## Evidence on Hand
Real working files on disk: `.wifish/pcap/*.pcap`, `.wifish/hc22000/*.hc22000`, `.wifish/wordlists/*` (incl. `rockyou.txt`, phone-number lists, `8digits.txt`), `crack.sh` (legacy CLI predecessor). Real hashcat v7.1.2 + hcxpcapngtool installed. No fabricated crack results, benchmarks, or customer claims — recovered keys come only from actual `hashcat --show` output.

## Product Principles
- Surface the tool's real state, never a simulated one — hashcat's own numbers are the readout.
- One screen, four stages, no shell required; the operator always knows what stage a file is at.
- Honest outcomes: a miss is shown as plainly as a hit.
- Local and offline by nature; the file working-set is the product's spine.
- Terse and exact over decorative copy.
