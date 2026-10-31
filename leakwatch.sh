#!/usr/bin/env bash
# LeakWatch - gestione sul server.
# Uso: ./leakwatch.sh {install|start|stop|restart|status|logs|update|autounlock on|off|tunnel|uninstall}
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; DIM=$'\e[2m'; RST=$'\e[0m'
info() { echo "${GRN}▸${RST} $*"; }
warn() { echo "${YLW}!${RST} $*"; }
die()  { echo "${RED}✗${RST} $*" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
else DC=(); fi

need_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker non installato: https://docs.docker.com/engine/install/"
  [[ ${#DC[@]} -gt 0 ]] || die "Docker Compose v2 non trovato (pacchetto docker-compose-plugin)."
  docker info >/dev/null 2>&1 || die "Non riesco a usare Docker: aggiungi l'utente al gruppo docker o usa sudo."
}

as_root() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

set_env() {   # set_env CHIAVE valore  (crea o sostituisce la riga in .env)
  local k=$1 v=$2
  if grep -q "^${k}=" .env 2>/dev/null; then
    v=${v//\\/\\\\}; v=${v//|/\\|}; v=${v//&/\\&}   # escape per sed
    sed -i "s|^${k}=.*|${k}=${v}|" .env
  else
    echo "${k}=${v}" >> .env
  fi
}

random_hex() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

check_disk_encryption() {
  if command -v lsblk >/dev/null 2>&1 && lsblk -no TYPE 2>/dev/null | grep -q crypt; then
    info "Rilevato un volume cifrato (LUKS)."
  else
    warn "Nessun volume LUKS rilevato. Il vault è cifrato, ma con il disco in chiaro"
    warn "un furto del server espone più facilmente il sistema. Consigliato: cifrare il disco."
  fi
}

cmd_install() {
  need_docker
  info "Configurazione in $(pwd)"
  touch .env && chmod 600 .env

  if ! grep -q "^SEARXNG_SECRET=[0-9a-f]\{64\}$" .env; then
    set_env SEARXNG_SECRET "$(random_hex)"
    info "Chiave SearXNG generata."
  fi

  if ! grep -q "^LW_TELEGRAM_TOKEN=." .env; then
    echo
    echo "Bot Telegram (invio vuoto per saltare; puoi aggiungerlo dopo in .env)."
    read -rsp "  Token di @BotFather: " tok; echo
    if [[ -n $tok ]]; then
      read -rp "  Il tuo chat ID: " chat
      [[ $chat =~ ^-?[0-9]+$ ]] || die "Il chat ID deve essere un numero."
      set_env LW_TELEGRAM_TOKEN "$tok"
      set_env LW_TELEGRAM_CHAT_ID "$chat"
    fi
  fi
  if ! grep -q "^TZ=." .env; then
    local tz; tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    set_env TZ "${tz:-Europe/Rome}"
  fi

  check_disk_encryption
  if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl enable --now docker >/dev/null 2>&1 && info "Docker si avvia al boot del server."
  fi

  info "Build e avvio dei container (la prima volta richiede qualche minuto)…"
  "${DC[@]}" up -d --build
  echo
  cmd_tunnel
  echo "Poi apri http://127.0.0.1:8765, crea il vault e compila il profilo."
  echo "${DIM}Tor impiega 1-2 minuti a connettersi al primo avvio.${RST}"
}

cmd_status() {
  need_docker
  "${DC[@]}" ps --format "table {{.Service}}\t{{.Status}}"
  echo
  local st
  st=$(curl -s -m 3 -H "Host: 127.0.0.1" http://127.0.0.1:8765/api/state 2>/dev/null || true)
  if [[ -n $st ]]; then
    python3 - "$st" <<'EOF' 2>/dev/null || echo "$st"
import json, sys, datetime
d = json.loads(sys.argv[1])
ts = d.get("next_scan_at")
print("Vault:", "sbloccato" if d["vault_unlocked"] else "BLOCCATO (sbloccalo dalla dashboard)")
print("Telegram:", "attivo" if d["telegram"] else "non configurato")
print("Scansione in corso:", "sì" if d["scan"]["running"] else "no")
if ts: print("Prossima scansione:", datetime.datetime.fromtimestamp(ts).strftime("%d/%m %H:%M"))
EOF
  else
    warn "La dashboard non risponde ancora."
  fi
}

cmd_update() {
  need_docker
  info "Aggiornamento immagini (SearXNG, Debian, Python)…"
  "${DC[@]}" pull searxng
  "${DC[@]}" build --pull
  "${DC[@]}" up -d
  docker image prune -f >/dev/null
  info "Aggiornato. Dopo il riavvio il vault è bloccato: sbloccalo dalla dashboard."
}

cmd_autounlock() {
  case "${1:-}" in
    on)
      warn "La passphrase verrà salvata su disco: chi ha accesso al disco ha accesso al vault."
      read -rp "Continuare? [s/N] " ok; [[ $ok =~ ^[sS]$ ]] || exit 0
      read -rsp "Passphrase del vault: " p1; echo
      read -rsp "Ripeti: " p2; echo
      [[ $p1 == "$p2" && ${#p1} -ge 12 ]] || die "Le passphrase non coincidono o sono troppo corte."
      mkdir -p secrets && chmod 700 secrets
      ( umask 077; printf '%s' "$p1" > secrets/lw_passphrase.txt )
      as_root chown 10001:10001 secrets/lw_passphrase.txt   # utente del container
      set_env COMPOSE_FILE "docker-compose.yml:docker-compose.autounlock.yml"
      "${DC[@]}" up -d
      info "Sblocco automatico attivo."
      ;;
    off)
      sed -i '/^COMPOSE_FILE=/d' .env
      if [[ -f secrets/lw_passphrase.txt ]]; then
        as_root shred -u secrets/lw_passphrase.txt 2>/dev/null || as_root rm -f secrets/lw_passphrase.txt
      fi
      "${DC[@]}" up -d
      info "Sblocco automatico disattivato. Dopo ogni riavvio dovrai sbloccare il vault."
      ;;
    *) die "Uso: $0 autounlock on|off" ;;
  esac
}

cmd_tunnel() {
  local ip; ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "La dashboard ascolta solo sul server. Dal tuo PC apri un tunnel SSH:"
  echo
  echo "    ssh -N -L 8765:127.0.0.1:8765 $(id -un)@${ip:-IP_DEL_SERVER}"
  echo
}

cmd_uninstall() {
  warn "Elimina container, immagini locali e il vault con tutti i dati. Irreversibile."
  read -rp "Scrivi CANCELLA TUTTO per confermare: " ok
  [[ $ok == "CANCELLA TUTTO" ]] || exit 0
  need_docker
  "${DC[@]}" down -v --rmi local
  [[ -f secrets/lw_passphrase.txt ]] && { as_root shred -u secrets/lw_passphrase.txt 2>/dev/null || true; }
  info "Rimosso. Il file .env (token Telegram) è ancora qui: cancellalo se non ti serve."
}

case "${1:-}" in
  install)    cmd_install ;;
  start)      need_docker; "${DC[@]}" up -d ;;
  stop)       need_docker; "${DC[@]}" stop ;;
  restart)    need_docker; "${DC[@]}" restart ;;
  status)     cmd_status ;;
  logs)       need_docker; "${DC[@]}" logs --tail 100 -f "${2:-app}" ;;
  update)     cmd_update ;;
  autounlock) cmd_autounlock "${2:-}" ;;
  tunnel)     cmd_tunnel ;;
  uninstall)  cmd_uninstall ;;
  *) echo "Uso: $0 {install|start|stop|restart|status|logs [servizio]|update|autounlock on|off|tunnel|uninstall}"; exit 1 ;;
esac
