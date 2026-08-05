#!/usr/bin/env bash
# dev.sh — 호스트 dev 러너 표준 템플릿 (RULES §13·§5.5 규격, 2026-08-04 통일)
#
# 사용: ./dev.sh up | ./dev.sh down
# 계약 (전 프로젝트 공통 — 이 파일의 "가변부" 밖은 수정하지 않는다):
#   up   = 사전 port-free 체크 → 서비스들 백그라운드(setsid) 기동 → pid 기록
#          → 기동 직후 생존 확인. stale pidfile 은 자가치유.
#   down = pid 로 프로세스그룹 종료 → **포트가 실제로 비워질 때까지 대기**
#          (reloader/워커 잔존 레이스 방지 — §5.5).
#   로그 = .dev-logs/<service>.log, pid = .dev.pids
#
# ── 가변부: 이 프로젝트의 서비스 정의 (CTO/Codex 는 여기만 채운다) ──────────
# SERVICES: "이름|작업디렉토리|기동커맨드" 한 줄씩. 커맨드는 exec 로 끝나는
# bash -c 문자열 — env 치환(DB/MTX 호스트 등 §5.5 미러링)은 커맨드 안에서.
project_services() {
  # native uvicorn 은 docker DNS(harness-shared-postgres)를 못 푼다 → 공유 pg 게시포트로 override.
  local db_native="${DATABASE_URL/@harness-shared-postgres:5432/@localhost:5435}"
  SERVICES=(
    "auth|.|source .venv/bin/activate && export DATABASE_URL='${db_native}' && alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT} --reload"
    "frontend|frontend|exec npm run dev -- --host 0.0.0.0 --port ${FRONTEND_PORT}"
  )
  PORTS=("${BACKEND_PORT}" "${FRONTEND_PORT}")
}

pre_up()    {
  # mailhog 만 docker(image-only 예외). postgres 는 공유 클러스터(외부 관리) — 안 띄움.
  docker compose up -d mailhog
}
post_down() { docker compose stop mailhog; }
project_extra() { echo "usage: ./dev.sh up|down"; exit 2; }
# ── 가변부 끝 ───────────────────────────────────────────────────────────────

set -euo pipefail
cd "$(dirname "$0")"
# .env 로드 — `source` 대신 리터럴 KEY=VALUE 파싱: 따옴표 없는 공백값
# (예: GOOGLE_SCOPE=openid email profile)이 bash 명령으로 실행돼 즉사하는
# 사고 방지 + docker env_file 파싱과 의미 동치 (§5.5 env 미러링).
if [ -f .env ]; then
  set -a
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    case "$line" in *=*) export "${line%%=*}=${line#*=}" ;; esac
  done < .env
  set +a
fi
PIDFILE=.dev.pids
LOGDIR=.dev-logs

port_in_use() { python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.1)
sys.exit(0 if s.connect_ex(('127.0.0.1',int('$1')))==0 else 1)"; }

wait_port_free() {
  for _ in $(seq 1 50); do port_in_use "$1" || return 0; sleep 0.1; done
  echo "warn: port $1 이 비워지지 않음" >&2; return 1
}

case "${1:-}" in
  up)
    project_services
    # stale pidfile 자가치유: 살아있는 pid 있으면 거부, 전부 죽었으면 정리 후 진행.
    if [ -f "$PIDFILE" ]; then
      alive=""
      while read -r p; do kill -0 "$p" 2>/dev/null && alive=1 || true; done <"$PIDFILE"
      if [ -n "$alive" ]; then echo "already up — ./dev.sh down 먼저"; exit 1; fi
      echo "stale $PIDFILE 정리 후 재기동"; rm -f "$PIDFILE"
    fi
    for port in "${PORTS[@]}"; do
      if port_in_use "$port"; then echo "error: port $port 사용중 — 선점 프로세스 확인" >&2; exit 1; fi
    done
    mkdir -p "$LOGDIR"
    pre_up
    for svc in "${SERVICES[@]}"; do
      name="${svc%%|*}"; rest="${svc#*|}"; dir="${rest%%|*}"; cmd="${rest#*|}"
      setsid bash -c "cd '$dir' && $cmd" >"$LOGDIR/$name.log" 2>&1 &
      pid=$!
      echo "$pid" >>"$PIDFILE"
      sleep 0.7
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "error: $name 기동 실패 — $LOGDIR/$name.log 확인" >&2; exit 1
      fi
    done
    echo "up — ports: ${PORTS[*]} (logs: $LOGDIR/)"
    ;;
  down)
    project_services
    [ -f "$PIDFILE" ] || { echo "not running"; exit 0; }
    while read -r pid; do kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; done <"$PIDFILE"
    rm -f "$PIDFILE"
    for port in "${PORTS[@]}"; do wait_port_free "$port"; done
    post_down
    echo "down — ports free: ${PORTS[*]}"
    ;;
  *) project_extra "$@" ;;
esac
