#!/usr/bin/env bash
# WPA crack helper. Layout:  pcap/  hc22000/  wordlists/
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p pcap hc22000 wordlists

# ---- colors (auto-off when not a tty) ----
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'
  C=$'\e[36m'; M=$'\e[35m'; W=$'\e[97m'; DIM=$'\e[2m'; BOLD=$'\e[1m'; RST=$'\e[0m'
else
  R= G= Y= B= C= M= W= DIM= BOLD= RST=
fi

ok()   { printf "${G}${BOLD}✓${RST} %s\n" "$*"; }
err()  { printf "${R}${BOLD}✗${RST} %s\n" "$*" >&2; }
info() { printf "${C}»${RST} %s\n" "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { err "missing: $1"; return 1; }; }

banner() {
  clear 2>/dev/null || true
  printf "${M}${BOLD}"
  cat <<'ART'
  ┌──────────────────────────────────────────┐
  │  █ █ █ █ █▀▀ █ █▀ █ █    WPA / WPA2       │
  │  ▀▄▀▄▀ █ █▀  █ ▄█ █▀█    handshake crack  │
  └──────────────────────────────────────────┘
ART
  printf "${RST}"
}

# count files in a dir (globs, no dotfiles)
count() { local n; shopt -s nullglob; local a=("$1"/*); n=${#a[@]}; shopt -u nullglob; echo "$n"; }

status() {
  printf "${DIM}  pcap:${RST}${W}%s${RST}${DIM}  hc22000:${RST}${W}%s${RST}${DIM}  wordlists:${RST}${W}%s${RST}\n" \
    "$(count pcap)" "$(count hc22000)" "$(count wordlists)"
}

# pick "prompt" file...  -> chosen file on stdout, menu on stderr
pick() {
  local prompt="$1"; shift
  (($#)) || { err "none found — add files to the folder first"; return 1; }
  local f
  PS3=$'\n'"${Y}${prompt}${RST} "
  select f in "$@"; do
    [[ -n $f ]] && { printf '%s\n' "$f"; return 0; }
    err "invalid choice"
  done
}

convert() {
  need hcxpcapngtool || return
  local src
  read -e -rp "${Y}pcap path:${RST} " src || return
  src="${src%\"}"; src="${src#\"}"
  src="${src%\'}"; src="${src#\'}"
  src="${src/#\~/$HOME}"
  [[ -f $src ]] || { err "no such file: $src"; return; }
  cp -f "$src" pcap/ || return
  local in="pcap/$(basename "$src")"
  local out="hc22000/$(basename "${in%.*}").hc22000"
  info "converting $(basename "$src") ..."
  if hcxpcapngtool -o "$out" "$in"; then
    ok "copied to $in"
    ok "wrote $out"
  else
    err "conversion failed"
  fi
}

crack() {
  need hashcat || return
  shopt -s nullglob
  local hashes=(hc22000/*) lists=(wordlists/*)
  shopt -u nullglob
  local h l
  h=$(pick "hash file #:" "${hashes[@]+"${hashes[@]}"}") || return
  l=$(pick "wordlist #:" "${lists[@]+"${lists[@]}"}") || return
  info "cracking $(basename "$h") with $(basename "$l") ..."
  hashcat -m 22000 "$h" "$l" || true
  printf "\n${G}${BOLD}── cracked ──${RST}\n"
  hashcat -m 22000 "$h" --show || true
}

show() {
  need hashcat || return
  shopt -s nullglob
  local hashes=(hc22000/*)
  shopt -u nullglob
  local h
  h=$(pick "hash file #:" "${hashes[@]+"${hashes[@]}"}") || return
  printf "\n${G}${BOLD}── cracked ──${RST}\n"
  hashcat -m 22000 "$h" --show || true
}

banner
while true; do
  echo
  status
  echo
  printf "  ${C}${BOLD}1${RST}) ${W}convert${RST} pcap ${DIM}->${RST} hashcat ${DIM}(.hc22000)${RST}\n"
  printf "  ${C}${BOLD}2${RST}) ${W}run hashcat${RST} with wordlist\n"
  printf "  ${C}${BOLD}3${RST}) ${W}show cracked${RST} ${DIM}(potfile)${RST}\n"
  printf "  ${R}${BOLD}q${RST}) quit\n"
  read -rp "${M}${BOLD}❯${RST} " c || exit 0
  case "$c" in
    1) convert ;;
    2) crack ;;
    3) show ;;
    q|Q) ok "bye"; exit 0 ;;
    *) err "unknown: $c" ;;
  esac
done
