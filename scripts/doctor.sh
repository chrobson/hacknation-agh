#!/usr/bin/env bash
# Preflight before make up*: checks what would otherwise end as a cryptic
# compose error or a silent --wait timeout. Exits 1 only on fatal problems;
# warnings never stop the start.
#   scripts/doctor.sh            UI port (ASI_PORT)
#   scripts/doctor.sh --db-port  also the database port published by
#                                compose.host.yml (ASI_DB_PORT)
set -uo pipefail
cd "$(dirname "$0")/.."

fatal=0
ok()   { printf '  ok     %s\n' "$*"; }
warn() { printf '  UWAGA  %s\n' "$*"; }
bad()  { printf '  BŁĄD   %s\n' "$*"; fatal=1; }

check_db=0
[ "${1:-}" = --db-port ] && check_db=1

# envval NAME DEFAULT: shell environment first (compose does the same), then .env.
envval() {
  local v="${!1:-}"
  if [ -z "$v" ] && [ -f .env ]; then
    v="$(sed -n "s/^$1=//p" .env | tail -n 1 | tr -d '"'"'"' \r')"
  fi
  printf '%s' "${v:-$2}"
}

echo "make doctor: sprawdzenie środowiska"

if ! command -v docker >/dev/null 2>&1; then
  bad "brak polecenia docker: zainstaluj Docker Engine (np. apt-get install docker.io docker-compose-v2)"
  echo "Przerwano: popraw błędy powyżej."
  exit 1
fi
ok "docker: $(command -v docker)"

docker_ok=0
if err="$(docker info 2>&1 >/dev/null)"; then
  docker_ok=1
  ok "demon Dockera odpowiada"
else
  case "$err" in
    *"permission denied"*|*"Permission denied"*)
      bad "brak uprawnień do demona Dockera: dodaj użytkownika do grupy docker (sudo usermod -aG docker \$USER, potem wyloguj się i zaloguj) albo uruchom make przez sudo" ;;
    *)
      bad "demon Dockera nie odpowiada: uruchom go (sudo systemctl start docker) lub Docker Desktop/OrbStack" ;;
  esac
fi

if ver="$(docker compose version --short 2>/dev/null)" && [ -n "$ver" ]; then
  major="${ver#v}"; major="${major%%.*}"
  if [ "${major:-0}" -ge 2 ] 2>/dev/null; then
    ok "docker compose $ver"
  else
    bad "docker compose $ver: wymagany Compose v2"
  fi
elif command -v docker-compose >/dev/null 2>&1; then
  bad "jest tylko docker-compose (v1); wymagany plugin Compose v2: polecenie 'docker compose' (np. apt-get install docker-compose-v2)"
else
  bad "brak 'docker compose' (Compose v2): zainstaluj plugin, np. apt-get install docker-compose-v2"
fi

if command -v openssl >/dev/null 2>&1; then
  ok "openssl"
else
  bad "brak openssl (make env losuje nim hasła i klucz): zainstaluj pakiet openssl"
fi

# port_holder PORT: prints the listening socket(s) on PORT, empty when free.
# Returns 2 when no tool can tell.
port_holder() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$1" 2>/dev/null | tail -n +2
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | tail -n +2
  else
    return 2
  fi
}

# check_port NAME SERVICE DEFAULT: fatal when the port is held by something
# other than this stack (the service of project "asi" already running).
check_port() {
  local name="$1" svc="$2" port
  port="$(envval "$name" "$3")"
  if [ "$docker_ok" = 1 ] && [ -n "$(docker compose ps -q "$svc" 2>/dev/null)" ]; then
    ok "port $port ($name): używa go działający serwis $svc tego stosu"
    return
  fi
  local holder rc
  holder="$(port_holder "$port")"; rc=$?
  if [ "$rc" = 2 ]; then
    warn "nie sprawdzono portu $port ($name): brak ss i lsof"
  elif [ -n "$holder" ]; then
    bad "port $port ($name) jest zajęty przez inny proces; zwolnij go albo ustaw inny $name w .env:"
    printf '%s\n' "$holder" | sed 's/^/           /'
  else
    ok "port $port ($name) wolny"
  fi
}

check_port ASI_PORT app 9080
[ "$check_db" = 1 ] && check_port ASI_DB_PORT db 55432

if [ -r /proc/net/if_inet6 ]; then
  if grep -q '^00000000000000000000000000000001 ' /proc/net/if_inet6; then
    ok "loopback IPv6 (::1)"
  else
    warn "brak loopbacku IPv6 (::1): cel localhost może dawać nieudany fragment dla ::1; użyj celu 127.0.0.1"
  fi
fi

if [ -r /proc/meminfo ]; then
  avail_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
  if [ -n "$avail_kb" ] && [ "$avail_kb" -lt 2097152 ]; then
    warn "wolnej pamięci RAM mniej niż 2 GB ($((avail_kb / 1024)) MB): budowanie obrazu i baza mogą działać wolno"
  fi
fi

if [ "$fatal" = 1 ]; then
  echo "Przerwano: popraw błędy powyżej."
  exit 1
fi
echo "Środowisko gotowe."
