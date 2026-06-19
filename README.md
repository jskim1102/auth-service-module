# auth-service

어떤 웹서비스에도 HTTP로 붙일 수 있는 독립 인증 마이크로서비스(FastAPI + PostgreSQL). 로컬 가입/로그인/로그아웃·비밀번호 찾기(이메일) + Naver/Kakao/Google SNS 제로마찰 로그인(첫 로그인이 곧 가입). 보안 최우선 — argon2 해싱, RS256 JWT + JWKS, refresh 회전·재사용탐지, 단회 토큰 atomic 소비, 계정열거 방지, OAuth state+PKCE + redirect 화이트리스트. 데모 프론트(React)는 flow 시연용.

---

# 로컬 실행

backend(FastAPI) + frontend(React/Vite)를 직접 구동. postgres는 docker로 띄운다.

```bash
# 1. clone
git clone <repo-URL> auth-service
cd auth-service

# 2. 환경변수 (placeholder라 값 채워야 함 — secret/포트/키경로)
cp .env.example .env
#   .env 편집: POSTGRES_PASSWORD / DATABASE_URL / JWT_*_KEY_PATH / (선택) provider·SMTP

# 3. RS256 서명키 생성 (이미지에 안 들어감 — 직접 생성해 keys/ 에)
mkdir -p keys
openssl genrsa -out keys/jwt_private.pem 2048
openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem

# 4. postgres (스키마 적용용)
docker compose up -d postgres

# 5. 백엔드 (venv + alembic 스키마 + uvicorn)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8003

# 6. 프론트엔드 (새 터미널)
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5176
```

> 비밀번호 찾기 메일은 기본 MailHog(개발용 SMTP sink)로 간다 — 실제 발송은 `.env`의 SMTP를 실 서비스(Gmail/SES 등)로 바꾸면 된다(코드 변경 없음).

---

# Docker (전체 스택)

auth + postgres + mailhog + frontend 4컨테이너를 한 번에 기동.

```bash
# 1. clone
git clone <repo-URL> auth-service
cd auth-service

# 2. 환경변수 + RS256 키 (위 로컬실행 2·3번과 동일)
cp .env.example .env          # 값 채우기
mkdir -p keys && openssl genrsa -out keys/jwt_private.pem 2048 \
  && openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem

# 3. 빌드 + 기동
docker compose up -d --build

# 4. DB 스키마 적용 (최초 1회)
docker compose exec auth alembic upgrade head
# → frontend http://localhost:5176 · backend :8003/docs · MailHog :8028
```

종료: `docker compose down` (볼륨 보존). **데이터 삭제 금지**면 `down -v` 쓰지 말 것.

> 서명키(`keys/*.pem`)는 이미지에 안 굽고 런타임 볼륨 마운트(`./keys:ro`)로 주입한다 — clone 후 키를 직접 생성해야 한다.

---

## 포트

| 서비스 | 포트 |
|---|---|
| Frontend (데모) | 5176 |
| Backend (FastAPI) | 8003 |
| PostgreSQL | 5435 |
| MailHog SMTP / Web UI | 1028 / 8028 |

모든 포트는 `.env` 변수(`BACKEND_PORT` 등) 참조 — 하드코딩 없음. 외부 접속 시 방화벽/포워딩은 frontend(5176)·backend(8003)만 열면 된다.

---
