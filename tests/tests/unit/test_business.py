"""Unit Tests for Business Logic"""
import pytest
from decimal import Decimal
from credit_engine.business import (
    calculate_commission,
    calculate_interest,
    calculate_penalty,
    validate_product_amount,
    validate_age,
    validate_guarantor,
    create_payment_schedule,
    calculate_installment,
    check_duplicate_application,
    validate_landlord_iban,
    validate_university_iban
)


class TestCommissionCalculation:
    """Тестҳои ҳисоби комиссия"""
    
    def test_dailypay_commission(self):
        """Комиссияи DailyPay (4%)"""
        amount = Decimal("1000")
        commission = calculate_commission("DailyPay", amount)
        assert commission == Decimal("40.00")
    
    def test_rentpay_commission(self):
        """Комиссияи RentPay (8%)"""
        amount = Decimal("3000")
        commission = calculate_commission("RentPay", amount)
        assert commission == Decimal("240.00")
    
    def test_studentpay_commission(self):
        """Комиссияи StudentPay (0%)"""
        amount = Decimal("5000")
        commission = calculate_commission("StudentPay", amount)
        assert commission == Decimal("0.00")


class TestInterestCalculation:
    """Тестҳои ҳисоби фоиз"""
    
    def test_studentpay_interest(self):
        """Фоизи StudentPay (12%)"""
        amount = Decimal("10000")
        months = 10
        interest = calculate_interest("StudentPay", amount, months)
        expected = Decimal("1200.00")  # 12% аз 10000
        assert interest == expected
    
    def test_dailypay_interest(self):
        """Фоизи DailyPay (0%)"""
        amount = Decimal("1000")
        interest = calculate_interest("DailyPay", amount, 7)
        assert interest == Decimal("0.00")
    
    def test_rentpay_interest(self):
        """Фоизи RentPay (0%)"""
        amount = Decimal("3000")
        interest = calculate_interest("RentPay", amount, 15)
        assert interest == Decimal("0.00")


class TestPenaltyCalculation:
    """Тестҳои ҳисоби ҷарима"""
    
    def test_dailypay_penalty(self):
        """Ҷаримаи DailyPay (0.5%/рӯз)"""
        amount = Decimal("1000")
        days_overdue = 5
        penalty = calculate_penalty("DailyPay", amount, days_overdue)
        expected = Decimal("25.00")  # 0.5% * 5 * 1000
        assert penalty == expected
    
    def test_rentpay_penalty(self):
        """Ҷаримаи RentPay (0.5%/рӯз)"""
        amount = Decimal("3000")
        days_overdue = 3
        penalty = calculate_penalty("RentPay", amount, days_overdue)
        expected = Decimal("45.00")  # 0.5% * 3 * 3000
        assert penalty == expected
    
    def test_studentpay_penalty(self):
        """Ҷаримаи StudentPay (несть)"""
        amount = Decimal("5000")
        penalty = calculate_penalty("StudentPay", amount, 10)
        assert penalty == Decimal("0.00")


class TestAmountValidation:
    """Тестҳои санҷиши маблағ"""
    
    def test_valid_dailypay_amount(self):
        """Маблағи дурусти DailyPay (200-2000)"""
        assert validate_product_amount("DailyPay", 200) is True
        assert validate_product_amount("DailyPay", 1000) is True
        assert validate_product_amount("DailyPay", 2000) is True
    
    def test_invalid_dailypay_amount(self):
        """Маблағи нодурусти DailyPay"""
        assert validate_product_amount("DailyPay", 100) is False
        assert validate_product_amount("DailyPay", 2500) is False
    
    def test_valid_rentpay_amount(self):
        """Маблағи дурусти RentPay (500-5000)"""
        assert validate_product_amount("RentPay", 500) is True
        assert validate_product_amount("RentPay", 3000) is True
        assert validate_product_amount("RentPay", 5000) is True
    
    def test_valid_studentpay_amount(self):
        """Маблағи дурусти StudentPay (3000-12000)"""
        assert validate_product_amount("StudentPay", 3000) is True
        assert validate_product_amount("StudentPay", 7500) is True
        assert validate_product_amount("StudentPay", 12000) is True


class TestAgeValidation:
    """Тестҳои санҷиши синну сол"""
    
    def test_valid_age(self):
        """Синну соли дуруст (>= 18)"""
        assert validate_age("2000-01-01") is True
        assert validate_age("1990-05-15") is True
    
    def test_invalid_age_under_18(self):
        """Синну соли нодуруст (< 18)"""
        # Агар имсол 2025 бошад, 2008 = 17 сол
        assert validate_age("2008-01-01") is False


class TestGuarantorValidation:
    """Тестҳои санҷиши гарантор"""
    
    def test_valid_guarantor_relation(self):
        """Нисбии дурусти гарантор"""
        assert validate_guarantor("FATHER") is True
        assert validate_guarantor("MOTHER") is True
    
    def test_invalid_guarantor_relation(self):
        """Нисбии нодурусти гарантор"""
        assert validate_guarantor("FRIEND") is False
        assert validate_guarantor("") is False
    
    def test_guarantor_cannot_be_borrower(self):
        """Гарантор наметавонад қарзгир бошад"""
        borrower_passport = "AA1234567"
        guarantor_passport = "AA1234567"
        with pytest.raises(ValueError, match="guarantor_cannot_be_borrower"):
            validate_guarantor("FATHER", borrower_passport, guarantor_passport)


class TestPaymentSchedule:
    """Тестҳои ҷадвали пардохт"""
    
    def test_dailypay_schedule(self):
        """Ҷадвали DailyPay (7 рӯз)"""
        schedule = create_payment_schedule("DailyPay", Decimal("1000"), 7)
        assert len(schedule) == 1  # Як пардохт
        assert schedule[0]["days"] == 7
    
    def test_rentpay_schedule(self):
        """Ҷадвали RentPay (15 рӯз)"""
        schedule = create_payment_schedule("RentPay", Decimal("3000"), 15)
        assert len(schedule) == 1
        assert schedule[0]["days"] == 15
    
    def test_studentpay_schedule(self):
        """Ҷадвали StudentPay (10 моҳ)"""
        schedule = create_payment_schedule("StudentPay", Decimal("10000"), 10)
        assert len(schedule) == 10  # 10 пардохти моҳона
        assert schedule[0]["month"] == 1
        assert schedule[-1]["month"] == 10


class TestDuplicateCheck:
    """Тестҳои санҷиши такрорӣ"""
    
    def test_no_duplicate(self):
        """Такрорӣ нест"""
        existing_requests = ["req-001", "req-002"]
        new_request = "req-003"
        assert check_duplicate_application(existing_requests, new_request) is False
    
    def test_has_duplicate(self):
        """Такрорӣ мавҷуд аст"""
        existing_requests = ["req-001", "req-002"]
        new_request = "req-001"
        assert check_duplicate_application(existing_requests, new_request) is True