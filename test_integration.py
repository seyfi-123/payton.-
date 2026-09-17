# -*- coding: utf-8 -*-
"""Integration tests (PostgreSQL) — 10 tests."""

import os
import sys
import psycopg2

DB = dict(
    host=os.environ.get('DB_HOST', '127.0.0.1'),
    port=int(os.environ.get('DB_PORT', 5432)),
    dbname=os.environ.get('DB_NAME', 'test_db'),
    user=os.environ.get('DB_USER', 'postgres'),
    password=os.environ.get('DB_PASSWORD', 'test'),
)

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


conn = psycopg2.connect(**DB)
conn.autocommit = True
cur = conn.cursor()

# 1. Table count
cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname='public'")
check("13 tables", cur.fetchone()[0] == 13)

# 2. Encrypted columns
cur.execute("""SELECT COUNT(*) FROM information_schema.columns
               WHERE table_schema='public' AND column_name LIKE '%_encrypted'""")
check("encrypted columns >= 2", cur.fetchone()[0] >= 2)

# 3. HMAC columns
cur.execute("""SELECT COUNT(*) FROM information_schema.columns
               WHERE table_schema='public' AND column_name LIKE '%_hmac'""")
check("hmac columns >= 5", cur.fetchone()[0] >= 5)

# 4. Foreign keys
cur.execute("SELECT COUNT(*) FROM pg_constraint WHERE contype='f'")
check("foreign keys >= 10", cur.fetchone()[0] >= 10)

# 5. CHECK constraints
cur.execute("SELECT COUNT(*) FROM pg_constraint WHERE contype='c'")
check("check constraints >= 2", cur.fetchone()[0] >= 2)

# 6. DailyPay = 7 days
cur.execute("SELECT term_days FROM product_config WHERE product_type='DAILY_PAY'")
check("DailyPay term_days = 7", cur.fetchone()[0] == 7)

# 7. RentPay = 15 days
cur.execute("SELECT term_days FROM product_config WHERE product_type='RENT_PAY'")
check("RentPay term_days = 15", cur.fetchone()[0] == 15)

# 8. RentPay commission = 8%
cur.execute("SELECT commission_rate FROM product_config WHERE product_type='RENT_PAY'")
check("RentPay commission 0.08", float(cur.fetchone()[0]) == 0.08)

# 9. Advisory lock works
cur.execute("SELECT pg_try_advisory_lock(99999)")
check("advisory lock acquired", cur.fetchone()[0] is True)
cur.execute("SELECT pg_advisory_unlock(99999)")

# 10. product_config_term_check
try:
    cur.execute("""INSERT INTO product_config
                   (product_type, min_amount, max_amount,
                    term_months, term_days)
                   VALUES ('DAILY_PAY', 1, 1, 5, 5)""")
    conn.rollback()
    check("term_check enforced", False)
except psycopg2.errors.CheckViolation:
    conn.rollback()
    check("term_check enforced", True)

cur.close()
conn.close()

print(f"\nIntegration: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)