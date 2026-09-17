# -*- coding: utf-8 -*-
"""End-to-end flow test (RentPay) — 10 tests."""

import asyncio
import os
import sys
import uuid
from datetime import date
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import psycopg2

from credit_engine import (
    Config, CryptoService, DatabasePool, CreditEngine, Product,
)

DB = dict(
    host=os.environ.get('DB_HOST', '127.0.0.1'),
    port=int(os.environ.get('DB_PORT', 5432)),
    dbname=os.environ.get('DB_NAME', 'test_db'),
    user=os.environ.get('DB_USER', 'postgres'),
    password=os.environ.get('DB_PASSWORD', 'test'),
)

M = 'a' * 64
K = 'b' * 64
C = 'c' * 64

Config.DB_HOST = DB['host']
Config.DB_PORT = DB['port']
Config.DB_NAME = DB['dbname']
Config.DB_USER = DB['user']
Config.DB_PASSWORD = DB['password']

crypto = CryptoService(M, K, C)

passed = 0
failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  OK   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}")


# Clean DB
conn = psycopg2.connect(**DB)
conn.autocommit = True
with conn.cursor() as cur:
    cur.execute("""
        TRUNCATE audit_log, auto_debit_transactions, insurance_policies,
                 repayment_idempotency, repayment_schedule,
                 loan_disbursements, application_guarantors, guarantors,
                 applications, users, otp_rate_limit, guarantor_ttl_log
        RESTART IDENTITY CASCADE
    """)

# Pre-create guarantor user
GP = '+992901234568'
gph = crypto.blind_index(GP)
gpp = crypto.blind_index('AB7777777')
with conn.cursor() as cur:
    cur.execute("""
        INSERT INTO users (passport_sn_hmac, passport_sn_encrypted,
                           phone_hmac, phone_encrypted, monthly_income)
        VALUES (%s, %s, %s, %s, %s)
    """, (gpp, crypto.encrypt('AB7777777', aad=f'passport:{gpp}'),
          gph, crypto.encrypt(GP, aad=f'phone:{gph}'),
          '5000.00'))
conn.close()


async def run_e2e():
    db = DatabasePool(Config)
    db.initialize()

    cib = MagicMock()
    cib.check = AsyncMock(return_value=(720, Decimal('15000')))
    face = MagicMock()
    face.verify = AsyncMock(return_value=True)
    abs_c = MagicMock()
    abs_c.create_contract = AsyncMock(return_value='ABS-TEST-002')
    pay = MagicMock()
    pay.debit = AsyncMock(return_value={'success': True})
    sms = MagicMock()
    sms.send = AsyncMock(return_value=True)

    eng = CreditEngine(
        db_pool=db, crypto=crypto, cib_client=cib, face_client=face,
        abs_client=abs_c, payment_client=pay, sms_client=sms)

    r = await eng.process_loan_application(
        passport_sn='AB99999999',
        face_id_data='base64data',
        guarantor_phone=GP,
        product_type=Product.RENT_PAY,
        amount_val=Decimal('5000'),
        user_phone='+992901234567',
        date_of_birth='1990-01-01',
        relation_type='FATHER',
        extra_data={
            'landlord_iban': 'TJ8712345678901234567890',
            'landlord_name': 'Landlord LLC',
        },
        request_id='e2e-' + str(uuid.uuid4()))

    lid = r.get('loan_id')
    agid = r.get('guarantor_id')

    c2 = psycopg2.connect(**DB)
    with c2.cursor() as cur:
        cur.execute(
            "SELECT due_date, amount_due FROM repayment_schedule "
            "WHERE loan_id=%s", (lid,))
        due, amt = cur.fetchone()
        cur.execute(
            "SELECT approval_status FROM application_guarantors WHERE id=%s",
            (agid,))
        gst = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users")
        ucnt = cur.fetchone()[0]
        cur.execute(
            "SELECT status FROM loan_disbursements WHERE id=%s", (lid,))
        lstat = cur.fetchone()[0]
    c2.close()
    db.close_all()
    return r, due, amt, gst, ucnt, lstat


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
r, due, amt, gst, ucnt, lstat = loop.run_until_complete(run_e2e())
loop.close()

check("status = PENDING_GUARANTOR_APPROVAL",
      r.get('status') == 'PENDING_GUARANTOR_APPROVAL')
check("commission = 400.00", r.get('commission') == '400.00')
check("net = 4600.00", r.get('net') == '4600.00')
check("abs_contract_id = ABS-TEST-002",
      r.get('abs_contract_id') == 'ABS-TEST-002')
check("due_date = today + 15 days",
      (due - date.today()).days == 15)
check("amount_due = 5000.00", amt == Decimal('5000.00'))
check("guarantee status = PENDING", gst == 'PENDING')
check("users count = 2", ucnt == 2)
check("loan status = PENDING_DISBURSEMENT",
      lstat == 'PENDING_DISBURSEMENT')
check("response has loan_id and guarantor_id",
      r.get('loan_id') is not None and r.get('guarantor_id') is not None)

print(f"\nE2E: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)