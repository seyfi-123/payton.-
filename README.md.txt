# Tajik Fintech Credit Engine

**Version:** 3.8.1
**Target:** PostgreSQL 13+ | Python 3.9+
**Author:** Alikulov Sayfiddin Bakhriddinovich
**Contact:** +992 01 416 12 12 | seifddinalikulov@gmail.com

---

## 1. Overview

Full automation platform for microcredit issuance for commercial banks of the Republic of Tajikistan.

### Products

| Product | Amount (TJS) | Term | Commission | Interest | Penalty after due |
|---------|--------------|------|------------|----------|-------------------|
| StudentPay | 3,000 – 12,000 | 10 months | 0% | 12% + 2% insurance | none |
| RentPay | 500 – 5,000 | 15 days | 8% | 0% | 0.5% / day |
| DailyPay | 200 – 2,000 | 7 days | 4% | 0% | 0.5% / day |

---

## 2. Architecture

```
External clients
    ↓ HTTPS + X-API-KEY
FastAPI (credit_engine)
    ↓
PostgreSQL 15
    ↓ mTLS
Bank systems: ABS | CIB | Face ID | Payment | SMS
```

### Application processing — 4 stages

1. **Stage 1** (< 100 ms) — rate limit, advisory lock, create application
2. **Stage 2** (< 5 s) — Face ID + CIB score check
3. **Stage 3** (< 15 s) — ABS contract creation
4. **Stage 4** (< 500 ms) — upsert user, create loan, schedule, guarantor

### Background workers

| Worker | Interval | Purpose |
|--------|----------|---------|
| Auto-debit | every hour | automatic debit of due installments |
| TTL expiry | every 10 min | close expired guarantees |
| Overdue marking | every hour | mark overdue + apply penalty |
| Cleanup | every hour | delete stale idempotency + OTP records |

All workers use **PostgreSQL advisory locks** (Leader Election) — only one instance runs at a time.

---

## 3. Server requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 core | 4 core |
| RAM | 4 GB | 8 GB |
| SSD | 100 GB | 200 GB |
| OS | Ubuntu 20.04+ | Ubuntu 22.04 |
| PostgreSQL | 13+ | 15 |
| Python | 3.9+ | 3.11 |

---

## 4. Installation

### 4.1 Docker (recommended)

```bash
cp 6_env.example .env
# Edit .env — set DB_PASSWORD, API_KEY, INTERNAL_API_KEY, keys, bank URLs

mkdir -p certs logs
# Place client.crt, client.key, ca.crt in ./certs/

docker compose up -d
```

### 4.2 Manual

```bash
# 1. PostgreSQL
sudo -u postgres createdb bank_db
sudo -u postgres psql bank_db -f 1schema.sql

# 2. Python environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r 3_requirements.txt

# 3. Configure
cp 6_env.example .env
# Edit .env

# 4. Certificates
mkdir -p /app/certs
cp client.crt client.key ca.crt /app/certs/

# 5. Run
uvicorn credit_engine:app --host 0.0.0.0 --port 8000
```

---

## 5. Environment variables

See `6_env.example` for full list.

### Required in production

- `DB_PASSWORD`, `API_KEY`, `INTERNAL_API_KEY`
- `MASTER_KEY_HEX`, `HMAC_KEY_HEX`, `CARD_SIGNATURE_KEY_HEX` (64 hex each)
- `CIB_URL`, `CIB_API_KEY`
- `FACE_ID_URL`, `FACE_ID_API_KEY`
- `ABS_URL`, `ABS_API_KEY`
- `PAYMENT_URL`, `PAYMENT_API_KEY`
- `SMS_URL`, `SMS_API_KEY`
- `INTERNAL_CLIENT_CERT`, `INTERNAL_CLIENT_KEY`, `INTERNAL_CA_CERT`

### Rules

- `API_KEY` ≥ 32 characters
- `INTERNAL_API_KEY` ≥ 32 characters and ≠ `API_KEY`
- All hex keys must be exactly 64 hex characters

---

## 6. API endpoints

### External (X-API-KEY)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/credit/apply` | Submit credit application |
| POST | `/api/v1/guarantor/approve` | Approve guarantee (OTP) |
| POST | `/api/v1/guarantor/reject` | Reject guarantee |
| POST | `/api/v1/guarantor/resend-otp` | Resend OTP |
| POST | `/api/v1/guarantor/register-card` | Register card for auto-debit |
| POST | `/api/v1/repayment/pay` | Pay installment |

### Internal (INTERNAL_API_KEY)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/internal/guarantees/expire` | Force TTL expiry |
| POST | `/api/v1/internal/auto-debit/run` | Run auto-debit batch |
| POST | `/api/v1/internal/auto-debit/recover` | Resolve NEEDS_RECOVERY |
| GET | `/api/v1/internal/auto-debit/needs-recovery` | List NEEDS_RECOVERY |
| POST | `/api/v1/internal/overdue/run` | Mark overdue + penalty |
| POST | `/api/v1/internal/cleanup/run` | Cleanup stale records |

### System

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/system/health` | Health check |
| GET | `/api/v1/system/ready` | Readiness for load balancer |

---

## 7. Example request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/credit/apply \
  -H "X-API-KEY: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "passport_series": "AB",
    "passport_number": "1234567",
    "date_of_birth": "1990-01-01",
    "amount": 5000.00,
    "product_type": "RentPay",
    "face_id_data": "base64...",
    "user_phone": "+992901234567",
    "guarantor_phone": "+992901234568",
    "guarantor_relation": "FATHER",
    "request_id": "req-uuid-1234",
    "landlord_iban": "TJ8712345678901234567890",
    "landlord_name": "Landlord LLC"
  }'
```

Response:

```json
{
  "code": "E0001",
  "status": "PENDING_GUARANTOR_APPROVAL",
  "application_id": 1,
  "loan_id": 1,
  "abs_contract_id": "ABS-2026-000123",
  "commission": "400.00",
  "net": "4600.00",
  "guarantor_id": 1,
  "http_status": 200
}
```

---

## 8. Security

| Layer | Technology |
|-------|------------|
| PII at rest | AES-256-GCM + AAD |
| Blind index | HMAC-SHA256 |
| Database | ACID + advisory locks |
| Transport | mTLS (bank CA) |
| Key storage | HSM / Vault |
| Perimeter | WAF / Firewall |
| AuthZ | X-API-KEY (constant-time) |
| Key rotation | KMS |

---

## 9. Tests

```
Unit (Crypto)           : 25 PASSED
Unit (Business Logic)   : 29 PASSED
Unit (Config + API)     : 38 PASSED
Integration (PostgreSQL): 10 PASSED
E2E Flow                : 10 PASSED
Adversarial             : 7  PASSED
Load test               : 98 PASSED
TOTAL                   : 217 PASSED
```

Acceptance criteria:

1. All 217 tests PASSED
2. Bandit HIGH = 0
3. Pip-audit (project) = 0
4. Load test ≥ 50 inserts/sec
5. E2E Flow SUCCESS
6. Adversarial 7/7 PASSED
7. All 5 bank services integrated
8. mTLS working
9. SLA 99.5%
10. DailyPay = 7 days, RentPay = 15 days, StudentPay = 10 months

---

## 10. SLA

- Uptime: **99.5%**
- Support: **24/7**
- Bug fixes: **free**
- Security updates: **free**
- Response time: **< 4 hours**
  - Critical incident: **30 min**
  - Major incident: **2 hours**
  - Medium incident: **4 hours**
  - Information request: **24 hours**

---

## 11. License

Proprietary — Tajik Fintech Credit Engine.
All rights reserved by the author.