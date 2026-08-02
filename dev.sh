#!/usr/bin/env bash
# 호스트 dev 러너 (하이브리드) — auth(FastAPI)+frontend(vite)=native(venv uvicorn+vite),
#   mailhog=docker(image-only). postgres 는 공유 클러스터(harness-shared-postgres, 외부 관리)라
#   여기서 기동/정지하지 않는다 (이미 떠있다고 가정).
# .env 를 backend 프로세스에 통째 주입한다 (compose env_file 과 동치): app 은 JWT키/SMTP/
#   OAuth 크레덴셜/쿠키/redirect_base 등 ~20개 변수를 os.environ 으로 읽고, pydantic Settings 는
#   3개 필드(DATABASE_URL/ALLOWED_REDIRECT_URIS/CORS_ORIGINS)만 self-load 한다.
#   `source .env` 는 GOOGLE_SCOPE/NAVER_SCOPE 의 따옴표 없는 공백값(openid email profile)을
#   bash 가 명령으로 실행해 즉사(exit 127)하므로, KEY=VALUE 를 리터럴 파싱해 export 한다.
set -euo pipefail
cd "$(dirname "$0")"
set -a
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac           # 빈 줄·주석 skip
  case "$line" in *=*) export "${line%%=*}=${line#*=}" ;; esac
done < .env
set +a
# native uvicorn 은 docker DNS 호스트(harness-shared-postgres)를 못 푼다 → 공유 pg 게시포트
#   localhost:5435 로 override (pydantic 은 환경변수가 .env file 보다 우선 → backend 서브셸에만 다시 export).
DB_NATIVE="${DATABASE_URL/@harness-shared-postgres:5432/@localhost:5435}"
PIDFILE=.dev.pids
case "${1:-up}" in
  up)
    # stale pidfile 자가치유: 프로세스 없으면(run.sh down·크래시·재부팅이 pidfile 잔존) 정리 후 재기동.
    if [ -f "$PIDFILE" ]; then
      alive=""
      while read -r p; do kill -0 "$p" 2>/dev/null && alive=1 || true; done <"$PIDFILE"
      if [ -n "$alive" ]; then echo "already up — ./dev.sh down 먼저"; exit 1; fi
      echo "stale $PIDFILE (프로세스 없음) — 정리하고 재기동"; rm -f "$PIDFILE"
    fi
    mkdir -p .dev-logs
    # mailhog 만 docker. postgres 는 공유 클러스터(외부)라 여기서 안 띄운다.
    docker compose up -d mailhog
    # backend: docker-entrypoint 와 동일하게 alembic upgrade head 후 uvicorn (RULES §9 — alembic 정본).
    #   DATABASE_URL 만 공유 pg 게시포트 localhost:5435 로 override, 나머지 env 는 위에서 상속.
    setsid bash -c "source .venv/bin/activate && export DATABASE_URL='${DB_NATIVE}' && alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT} --reload" >.dev-logs/auth.log 2>&1 & echo $! >>"$PIDFILE"
    # frontend: vite. vite.config 의 server.proxy 가 /auth/* 를 backend 로 넘긴다 (prod nginx 동치).
    setsid bash -c "cd frontend && exec npm run dev -- --host 0.0.0.0 --port ${FRONTEND_PORT}" >.dev-logs/frontend.log 2>&1 & echo $! >>"$PIDFILE"
    echo "up — auth :${BACKEND_PORT}, frontend :${FRONTEND_PORT}, mailhog(docker) | postgres=공유(harness-shared-postgres @localhost:5435) (logs: .dev-logs/)"
    ;;
  down)
    [ -f "$PIDFILE" ] || { echo "not running"; exit 0; }
    while read -r pid; do kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; done <"$PIDFILE"
    rm -f "$PIDFILE"
    docker compose stop mailhog   # mailhog 만 (공유 postgres 는 외부 관리 — 건드리지 않음)
    echo "down"
    ;;
  *) echo "usage: ./dev.sh up|down"; exit 1 ;;
esac
