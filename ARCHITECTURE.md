# Архитектураи Система (System Architecture)

**Лоиҳа:** Tajik Fintech Credit Engine
**Версия:** 3.8.1

---

## 1. Диаграммаи Умумӣ (C4 Model)

Корбарон (Мобилӣ, Веб, Бонк, Терминал)
    |
    | HTTPS + X-API-KEY
    v
API GATEWAY (FastAPI)
    • Authentication
    • Rate Limiting
    • Request Validation
    • PII Scrubbing
    |
    v
CREDIT ENGINE
    ┌─ Credit Service
    ├─ Guarantor Service
    ├─ Repayment Service
    └─ Background Workers (4 loops)
    |
    ├──> CIB (Кредит бюро)
    ├──> Face-ID (Биометрия)
    ├──> ABS (Бонк система)
    ├──> Payment (Пардохт)
    ├──> SMS (Огоҳинома)
    |
    v
PostgreSQL 13+ (asyncpg pool)

---

## 2. Қисмҳои Асосӣ

### 2.1. API Gateway (FastAPI)

| Хусусият | Тавзеҳ |
|----------|--------|
| Framework | FastAPI 0.115 + Uvicorn |
| Порт | 8000 |
| Authentication | X-API-KEY |
| Validation | Pydantic v2 |

### 2.2. Background Workers

| Worker | Давомнокӣ | Вазифа |
|--------|-----------|--------|
| auto_debit_loop | 1 соат | Дебитҳои худкор |
| ttl_loop | 10 дақиқа | Гузаштани гарантияҳо |
| overdue_loop | 1 соат | Муҳлати гузашта |
| cleanup_loop | 1 соат | Тоза кардан |

Leader Election: PostgreSQL advisory locks.

### 2.3. Сервисҳои Беруна

| Сервис | Timeout | Circuit Breaker |
|--------|---------|-----------------|
| CIB | 5s | 5 fails / 60s |
| Face-ID | 10s | 5 fails / 60s |
| ABS | 15s | 5 fails / 60s |
| Payment | 10s | 3 fails / 60s |
| SMS | 5s | 10 fails / 60s |

### 2.4. Database

| Параметр | Қиммат |
|----------|--------|
| Версия | 13+ |
| Pool min | 2 |
| Pool max | 20 (тавсия: 100 бонк) |
| Timeout | 30s |
| Драйвер | asyncpg |

---

## 3. Ҷараёни Корбар

### 3.1. Қабули Кредит (4 марҳила)

[1] POST /api/v1/credit/apply
     • Validation
     • Rate limit check
     • Stage 1: Сохтани ариза (PENDING_CHECKS)

[2] Stage 2: Face-ID + CIB (беруни транзаксия)
     • Face-ID verify
     • CIB check (score >= 500)

[3] Stage 3: ABS contract
     • ABS create_contract

[4] Stage 4: Финалнок (дар транзаксия)
     • Upsert user
     • Check blocked
     • Check active loan
     • Calculate commission
     • Create loan + schedule
     • Create guarantee

[5] Интизори тасдиқи гарантор
     • SMS OTP ба гарантор

### 3.2. Пардохт

POST /api/v1/repayment/pay
     • Idempotency check
     • Installment FOR UPDATE
     • Update amount_paid
     • Агар ҳама пардохт шуд — CLOSED

### 3.3. Auto-Debit

Ҳар соат:
     • Find due installments
     • Payment gateway debit
     • Агар муваффақ — mark PAID
     • Агар ноком — retry 3 бор

---

## 4. Бехатарӣ

### 4.1. Network
- TLS 1.3 (HTTPS)
- mTLS барои сервисҳои дохилӣ
- Rate limiting

### 4.2. Application
- API Key (constant-time)
- Pydantic validation
- SQL injection: параметрҳои параметрӣ
- XSS: JSON only

### 4.3. Data
- AES-256-GCM барои PII
- HMAC-SHA256 барои blind index
- PII scrubbing дар логҳо

### 4.4. Audit
- Ҳар амал дар audit_log

---

## 5. Тобоварӣ

| Корбарон | RAM | vCPU | DB Pool |
|----------|-----|------|---------|
| 100 | 2 GB | 2 | 20 |
| 500 | 4 GB | 2 | 50 |
| 1,000 | 4 GB | 4 | 100 |
| 5,000 | 8 GB | 8 | 200 |
| 10,000+ | 16 GB | 16 | 400 + Celery |

---

## 6. Роҳи Рушд

### Версия 3.8.1 (Ҳозира)
- Async DB (asyncpg)
- 4 background workers
- Leader election
- mTLS production

### Версия 4.0 (Оянда)
- Microservices
- Celery + Redis
- Multi-region
- Kubernetes

---

Тайёр: Sayfiddin Alikulov
Контакт: seifddinalikulov@gmail.com
Телефон: +992 01 416 12 12