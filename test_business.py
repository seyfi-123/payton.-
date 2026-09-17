# -*- coding: utf-8 -*-
"""Business logic unit tests — 29 tests."""

import sys
from datetime import date
from decimal import Decimal

from credit_engine import (
    CreditEngine, Product, add_months, add_days,
)

e = CreditEngine.__new__(CreditEngine)

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


# IBAN validation
check("valid IBAN", e._iban_format_ok('TJ8712345678901234567890'))
check("invalid checksum", not e._iban_format_ok('TJ0012345678901234567890'))
check("too short", not e._iban_format_ok('TJ12'))
check("bad prefix", not e._iban_format_ok('1J8712345678901234567890'))
check("lowercase ok", e._iban_format_ok('tj8712345678901234567890'))

# money_round
check("round .005 → 1.01", e.money_round('1.005') == Decimal('1.01'))
check("round 1.004 → 1.00", e.money_round('1.004') == Decimal('1.00'))
check("round 5 → 5.00", e.money_round(5) == Decimal('5.00'))
check("round -1.005 → -1.01", e.money_round('-1.005') == Decimal('-1.01'))

# add_months
check("add_months 2026-01-15 + 1",
      add_months(date(2026, 1, 15), 1) == date(2026, 2, 15))
check("add_months 2026-01-31 + 1 (leap)",
      add_months(date(2026, 1, 31), 1) == date(2026, 2, 28))
check("add_months 2026-12-15 + 1",
      add_months(date(2026, 12, 15), 1) == date(2027, 1, 15))
check("add_months 2026-01-01 + 10",
      add_months(date(2026, 1, 1), 10) == date(2026, 11, 1))

# add_days
check("add_days +7", add_days(date(2026, 1, 1), 7) == date(2026, 1, 8))
check("add_days +15", add_days(date(2026, 1, 1), 15) == date(2026, 1, 16))
check("add_days +30", add_days(date(2026, 1, 1), 30) == date(2026, 1, 31))

# PTI
check("PTI 50% ok",
      e._check_pti(10000, 5000, 5000, Decimal('0.5'))[0])
check("PTI 100% rejected",
      not e._check_pti(1000, 0, 1000, Decimal('0.5'))[0])
check("PTI zero income rejected",
      not e._check_pti(0, 0, 100, Decimal('0.5'))[0])
check("PTI 30% ok",
      e._check_pti(3000, 3000, 2000, Decimal('0.5'))[0])

# Product requirements
check("RENT_PAY without IBAN rejected",
      not e._validate_product_requirements('RENT_PAY', {})[0])
check("RENT_PAY bad IBAN rejected",
      not e._validate_product_requirements(
          'RENT_PAY', {'landlord_iban': 'bad'})[0])
check("RENT_PAY valid IBAN ok",
      e._validate_product_requirements(
          'RENT_PAY',
          {'landlord_iban': 'TJ8712345678901234567890'})[0])
check("STUDENT_PAY without IBAN rejected",
      not e._validate_product_requirements('STUDENT_PAY', {})[0])
check("DAILY_PAY without IBAN ok",
      e._validate_product_requirements('DAILY_PAY', {})[0])

# Product constants
check("STUDENT_PAY const", Product.STUDENT_PAY == 'STUDENT_PAY')
check("DAILY_PAY const", Product.DAILY_PAY == 'DAILY_PAY')
check("RENT_PAY const", Product.RENT_PAY == 'RENT_PAY')

print(f"\nBusiness: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)