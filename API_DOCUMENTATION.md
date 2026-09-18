# Ҳуҷҷати API (API Documentation)

**Base URL:** https://api.bank.tj
**Версия:** 3.8.1
**Формат:** JSON
**Auth:** X-API-KEY

---

## 1. Authentication

Ҳамаи дархостҳо X-API-KEY дар header талаб мекунанд:

X-API-KEY: your_api_key_here
Content-Type: application/json

Калидҳо:

- API_KEY — барои эндпоинтҳои беруна
- INTERNAL_API_KEY — барои эндпоинтҳои дохилӣ

Хатогии 401:

{ "detail": "Invalid API key." }

---

## 2. Эндпоинтҳои Асосӣ

### 2.1. POST /api/v1/credit/apply

Вазифа: Қабули аризаи кредит

Request:

{
  "passport_series": "A",
  "passport_number": "1234567",
  "date_of_birth": "1990-01-01",
  "amount": 5000,
  "product_type": "StudentPay",
  "face_id_data": "base64_face_image",
  "user_phone": "+992901234567",
  "guarantor_phone": "+992901234568",
  "guarantor_relation": "FATHER",
  "request_id": "unique-request-001",
  "university_iban": "TJ0735010123456789012345",
  "university_name": "ДМТ",
  "landlord_iban": "",
  "landlord_name": "",
  "self_iban": ""
}

Майдонҳо:

| Майдон | Навъ | Ҳатмист | Тавзеҳ |
|--------|------|---------|--------|
| passport_series | string | ҲА | 1-2 аломат |
| passport_number | string | ҲА | 7-9 рақам |
| date_of_birth | string | ҲА | YYYY-MM-DD |
| amount | decimal | ҲА | 200-50000 |
| product_type | enum | ҲА | StudentPay/DailyPay/RentPay |
| face_id_data | string | ҲА | Базаи 64 расм |
| user_phone | string | ҲА | +992XXXXXXXXX |
| guarantor_phone | string | ҲА | Барои StudentPay/RentPay |
| guarantor_relation | enum | ҲА | FATHER/MOTHER |
| request_id | string | НЕ | Барои idempotency |
| university_iban | string | НЕ | Барои StudentPay |
| landlord_iban | string | НЕ | Барои RentPay |
| self_iban | string | НЕ | Барои DailyPay |

Response 200 OK:

{
  "code": "E0001",
  "status": "PENDING_GUARANTOR_APPROVAL",
  "application_id": 1,
  "loan_id": 1,
  "guarantor_id": 1,
  "gross_loan": "5100",
  "insurance": "100",
  "interest": "600",
  "transfer_commission": "0",
  "net_transferred": "5000",
  "target_iban": "TJ0735010123456789012345",
  "abs_contract_id": "ABS-2025-123456",
  "http_status": 200
}

Хатогиҳо:

| Код | HTTP | Сабаб |
|-----|------|-------|
| E1001 | 400 | Маблағ нодуруст |
| E1006 | 400 | IBAN нодуруст |
| E1008 | 400 | Биометрия ноком |
| E1009 | 400 | CIB score кам |
| E1012 | 400 | Синну сол < 18 |
| E1013 | 409 | Қарзи фаъол дорад |
| E1014 | 400 | Гарантор = қарзгир |
| E2001 | 503 | ABS дастнорас |
| E2002 | 500 | Хатогии DB |

---

### 2.2. POST /api/v1/guarantor/approve

Вазифа: Тасдиқи гарантор бо OTP

Request:

{
  "application_guarantor_id": 1,
  "otp_code": "123456",
  "face_id_data": "base64_face_image",
  "passport_series": "B",
  "passport_number": "7654321"
}

Response 200 OK:

{
  "application_id": 1,
  "status": "APPROVED",
  "http_status": 200
}

---

### 2.3. POST /api/v1/guarantor/reject

Вазифа: Рад кардани гарантор

Request:

{
  "application_guarantor_id": 1,
  "reason": "Не могу быть гарантом"
}

---

### 2.4. POST /api/v1/guarantor/resend-otp

Вазифа: Фиристодани OTP-и нав

Request:

{
  "application_guarantor_id": 1
}

Response 200 OK:

{
  "status": "SENT",
  "send_count": 2,
  "http_status": 200
}

Маҳдудиятҳо:

- Максимум 3 бор
- Cooldown 60 сония
- TTL 10 дақиқа

---

### 2.5. POST /api/v1/guarantor/register-card

Вазифа: Сабти корт барои auto-debit

Request:

{
  "passport_series": "B",
  "passport_number": "7654321",
  "card_token": "tok_abcdef1234567890",
  "card_masked": "****1234",
  "signature": "64_hex_chars"
}

---

### 2.6. POST /api/v1/repayment/pay

Вазифа: Пардохти installment

Request:

{
  "installment_id": 1,
  "amount": 500,
  "idempotency_key": "repay-2025-001"
}

Response 200 OK:

{
  "status": "PAID",
  "installment_id": 1,
  "amount_paid": "500.00",
  "loan_closed": false,
  "http_status": 200
}

---

## 3. Эндпоинтҳои Дохилӣ (Internal)

Инҳо INTERNAL_API_KEY талаб мекунанд:

| Эндпоинт | Вазифа |
|----------|--------|
| POST /api/v1/internal/guarantees/expire | Гузаштани гарантияҳо |
| POST /api/v1/internal/auto-debit/run | Иҷрои auto-debit |
| POST /api/v1/internal/auto-debit/recover | Барқарорсозӣ |
| GET /api/v1/internal/auto-debit/needs-recovery | Рӯйхати барқарорсозӣ |
| POST /api/v1/internal/overdue/run | Муҳлати гузашта |
| POST /api/v1/internal/cleanup/run | Тоза кардан |

---

## 4. Эндпоинтҳои Системавӣ

### 4.1. GET /api/v1/system/health

Response:

{
  "status": "HEALTHY",
  "timestamp": "2025-01-01T00:00:00+00:00",
  "checks": {
    "database": "OK",
    "encryption": "OK",
    "version": "3.8.1",
    "env": "production",
    "leader_election_enabled": true,
    "auto_debit_worker": "RUNNING",
    "ttl_worker": "RUNNING",
    "overdue_worker": "RUNNING",
    "cleanup_worker": "RUNNING"
  }
}

### 4.2. GET /api/v1/system/ready

Ҳамон health аст, аммо агар UNHEALTHY — 503.

---

## 5. Маҳсулотҳо (Products)

| Маҳсулот | Маблағ (TJS) | Муҳлат | Комиссия | Фоиз |
|----------|--------------|--------|----------|------|
| StudentPay | 3,000 - 12,000 | 10 моҳ | 0% | 12% |
| DailyPay | 200 - 2,000 | 7 рӯз | 4% | 0% |
| RentPay | 500 - 5,000 | 15 рӯз | 8% | 0% |

Ҷарима:

- DailyPay: 0.5% / рӯз (баъд аз 7 рӯз)
- RentPay: 0.5% / рӯз (баъд аз 15 рӯз)
- StudentPay: нест (фоиз дорад)

---

## 6. Кодҳои Хатогӣ

| Код | HTTP | Маънӣ |
|-----|------|-------|
| E0000 | 200 | Муваффақ |
| E0001 | 200 | Интизори гарантор |
| E0002 | 409 | Дархости такрорӣ |
| E1001-E1050 | 400 | Хатогии маълумот |
| E2001-E2006 | 500/503 | Хатогии система |

---

## 7. Rate Limits

| Эндпоинт | Ҳадди аксар |
|----------|-------------|
| credit/apply | 5 / соат / шиноснома |
| resend-otp | 3 / гарантия |
| OTP attempts | 3 / гарантия |

---

Swagger UI: /docs (танҳо дар ENV=development)
ReDoc: /redoc (танҳо дар ENV=development)