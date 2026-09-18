# Дастури Насб (Deployment Guide)
# Барои Бонк / For Bank Infrastructure

**Лоиҳа:** Tajik Fintech Credit Engine
**Версия:** 3.8.1
**Барои:** Дастаи IT-и бонк

---

## 1. Талаботҳо ба Сервери Бонк

| Чиз | Ҳадди ақал | Тавсия |
|-----|-----------|--------|
| RAM | 8 GB | 16 GB |
| CPU | 4 vCPU | 8 vCPU |
| Диск | 50 GB SSD | 100 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Docker | 24.0+ | 24.0+ |
| PostgreSQL | 15+ | 15+ (managed) |
| Network | 100 Mbit/s | 1 Gbit/s |

---

## 2. Тағйирёбандаҳои Муҳит

### 2.1. Ҳатмист

DB_HOST=localhost
DB_PORT=5432
DB_NAME=bank_db
DB_USER=bank_user
DB_PASSWORD=<bank_strong_password>
DB_POOL_MIN=5
DB_POOL_MAX=100

API_KEY=<bank_32_char_api_key>
INTERNAL_API_KEY=<bank_internal_key>
API_PORT=8000
ENV=production
LOG_LEVEL=INFO
LOG_FORMAT=json
RATE_LIMIT_PER_HOUR=5

MASTER_KEY_HEX=<64_hex_chars>
HMAC_KEY_HEX=<64_hex_chars>
CARD_SIGNATURE_KEY_HEX=<64_hex_chars>

CIB_URL=https://cib.bank.tj
CIB_API_KEY=<bank_cib_key>

FACE_ID_URL=https://faceid.bank.tj
FACE_ID_API_KEY=<bank_faceid_key>

ABS_URL=https://abs.bank.tj
ABS_API_KEY=<bank_abs_key>

PAYMENT_URL=https://payment.bank.tj
PAYMENT_API_KEY=<bank_payment_key>

SMS_URL=https://sms.bank.tj
SMS_API_KEY=<bank_sms_key>

INTERNAL_CLIENT_CERT=/certs/client.crt
INTERNAL_CLIENT_KEY=/certs/client.key
INTERNAL_CA_CERT=/certs/ca.crt

TRUSTED_PROXY_IPS=<bank_proxy_ips>
LEADER_ELECTION_ENABLED=true

### 2.2. Чӣ тавр калидҳоро тавлид кунем

openssl rand -hex 32

Ҳамин фармонро барои:
- API_KEY
- INTERNAL_API_KEY
- MASTER_KEY_HEX
- HMAC_KEY_HEX
- CARD_SIGNATURE_KEY_HEX

---

## 3. Насб (Қадам ба Қадам)

### 3.1. Сервер (Ubuntu 22.04)

sudo apt update && sudo apt upgrade -y

curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

sudo apt install docker-compose-plugin -y

sudo ufw allow 22
sudo ufw allow 443
sudo ufw enable

### 3.2. Кодро clone кун

git clone https://github.com/seyfi-123/bank-credit-engine.git
cd bank-credit-engine

### 3.3. .env созед

cp .env.example .env
nano .env
# Қимматҳои бонкро гузор

### 3.4. Database schema-ро иҷро кун

psql -h localhost -U bank_user -d bank_db -f 1schema.sql

---

## 4. docker-compose.yml

version: '3.9'

services:
  postgres:
    image: postgres:15
    restart: always
    environment:
      POSTGRES_DB: bank_db
      POSTGRES_USER: bank_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data
      - ./1schema.sql:/docker-entrypoint-initdb.d/schema.sql
    ports:
      - "127.0.0.1:5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bank_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  credit_engine:
    build: .
    restart: always
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    ports:
      - "127.0.0.1:8000:8000"

  nginx:
    image: nginx:alpine
    restart: always
    depends_on:
      - credit_engine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost/health"]
      interval: 30s

volumes:
  pg_data:

---

## 5. Dockerfile

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY credit_engine.py .

EXPOSE 8000

CMD ["uvicorn", "credit_engine:app", "--host", "0.0.0.0", "--port", "8000"]

---

## 6. nginx.conf

events { worker_connections 1024; }

http {
    upstream credit_engine {
        server credit_engine:8000;
    }

    server {
        listen 443 ssl http2;
        server_name api.bank.tj;

        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://credit_engine;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 60s;
        }

        location /health {
            proxy_pass http://credit_engine/api/v1/system/health;
        }
    }
}

---

## 7. SSL Certificates

sudo apt install certbot -y
sudo certbot certonly --standalone -d api.bank.tj

Ё аз дохили бонк сертификати расмӣ гиред.

---

## 8. Оғози Система

docker compose up -d

docker compose ps

curl https://api.bank.tj/health

Ҷавоб:

{
  "status": "HEALTHY",
  "checks": {
    "database": "OK",
    "encryption": "OK",
    "version": "3.8.1",
    "env": "production"
  }
}

---

## 9. Backup

### 9.1. DB Backup (рӯзона)

#!/bin/bash

DATE=$(date +%Y%m%d)
pg_dump -h localhost -U bank_user bank_db | gzip > /backups/db_$DATE.sql.gz

find /backups -name "db_*.sql.gz" -mtime +30 -delete

### 9.2. Backup ба сервери дигари бонк

scp /backups/db_$DATE.sql.gz backup-server:/backups/

---

## 10. Мониторинг

### 10.1. Health Check (ҳар 5 дақиқа)

#!/bin/bash

HEALTH=$(curl -s https://api.bank.tj/health | jq -r '.status')
if [ "$HEALTH" != "HEALTHY" ]; then
    echo "ALERT: Health check failed!"
fi

### 10.2. Logs

docker compose logs -f credit_engine

---

## 11. Хулоса — Ки Чиро Медиҳад

| Қисм | Ки медиҳад |
|------|-----------|
| Код | Таҳиягар |
| Сервер | Бонк |
| Database | Бонк |
| Backup | Бонк |
| Мониторинг | Бонк |
| Дастгирии 24/7 | Бонк |
| SSL Certificates | Бонк |

---

Тайёр: Sayfiddin Alikulov
Контакт: seifddinalikulov@gmail.com
Телефон: +992 01 416 12 12