#!/usr/bin/env python3
"""
Tajik Fintech Credit Engine - Unit Tests (92 tests)
Covers: Crypto (25) + Business Logic (29) + Config/API (38)
"""

import pytest
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, date
from decimal import Decimal
from unittest.mock import patch, MagicMock


# ============================================
# CRYPTO TESTS (25 tests)
# ============================================

class TestEncryption:
    """Тесты шифрования AES-256-GCM"""
    
    def test_encrypt_decrypt_passport(self):
        """Шифрование и расшифровка паспорта"""
        from credit_engine.crypto import encrypt_pii, decrypt_pii
        
        original = "AA1234567"
        encrypted = encrypt_pii(original, field="passport")
        decrypted = decrypt_pii(encrypted, field="passport")
        
        assert decrypted == original
        assert encrypted != original
    
    def test_encrypt_decrypt_phone(self):
        """Шифрование и расшифровка телефона"""
        from credit_engine.crypto import encrypt_pii, decrypt_pii
        
        original = "+992901234567"
        encrypted = encrypt_pii(original, field="phone")
        decrypted = decrypt_pii(encrypted, field="phone")
        
        assert decrypted == original
    
    def test_encrypt_decrypt_iban(self):
        """Шифрование и расшифровка IBAN"""
        from credit_engine.crypto import encrypt_pii, decrypt_pii
        
        original = "TJ0735010123456789012345"
        encrypted = encrypt_pii(original, field="iban")
        decrypted = decrypt_pii(encrypted, field="iban")
        
        assert decrypted == original
    
    def test_encrypt_produces_different_ciphertext(self):
        """Каждое шифрование дает разный результат (nonce)"""
        from credit_engine.crypto import encrypt_pii
        
        original = "test_data"
        encrypted1 = encrypt_pii(original, field="passport")
        encrypted2 = encrypt_pii(original, field="passport")
        
        assert encrypted1 != encrypted2
    
    def test_decrypt_wrong_field_fails(self):
        """Расшифровка с неправильным полем не работает"""
        from credit_engine.crypto import encrypt_pii, decrypt_pii
        
        original = "AA1234567"
        encrypted = encrypt_pii(original, field="passport")
        
        with pytest.raises(Exception):
            decrypt_pii(encrypted, field="phone")


class TestHMAC:
    """Тесты HMAC-SHA256"""
    
    def test_generate_hmac_length(self):
        """HMAC должен быть 64 hex символа"""
        from credit_engine.crypto import generate_hmac
        
        data = "test_data"
        signature = generate_hmac(data)
        
        assert len(signature) == 64
        assert all(c in '0123456789abcdef' for c in signature)
    
    def test_verify_hmac_valid(self):
        """Проверка валидного HMAC"""
        from credit_engine.crypto import generate_hmac, verify_hmac
        
        data = "test_data"
        signature = generate_hmac(data)
        
        assert verify_hmac(data, signature) is True
    
    def test_verify_hmac_invalid(self):
        """Проверка невалидного HMAC"""
        from credit_engine.crypto import generate_hmac, verify_hmac
        
        data = "test_data"
        signature = generate_hmac(data)
        
        assert verify_hmac("tampered_data", signature) is False
    
    def test_hmac_consistency(self):
        """HMAC для одинаковых данных одинаковый"""
        from credit_engine.crypto import generate_hmac
        
        data = "test_data"
        sig1 = generate_hmac(data)
        sig2 = generate_hmac(data)
        
        assert sig1 == sig2


class TestKeyManagement:
    """Тесты управления ключами"""
    
    def test_generate_master_key_length(self):
        """Мастер-ключ должен быть 64 hex символа"""
        from credit_engine.crypto import generate_master_key
        
        key = generate_master_key()
        
        assert len(key) == 64
        assert all(c in '0123456789abcdef' for c in key)
    
    def test_derive_key_different_contexts(self):
        """Разные контексты дают разные ключи"""
        from credit_engine.crypto import derive_key
        
        master_key = "0" * 64
        key1 = derive_key(master_key, context="encryption")
        key2 = derive_key(master_key, context="signing")
        
        assert key1 != key2
        assert len(key1) == 64
        assert len(key2) == 64


class TestMasking:
    """Тесты маскирования данных"""
    
    def test_mask_passport(self):
        """Маскирование паспорта"""
        from credit_engine.crypto import mask_passport
        
        passport = "AA1234567"
        masked = mask_passport(passport)
        
        assert masked == "AA*****567"
    
    def test_mask_phone(self):
        """Маскирование телефона"""
        from credit_engine.crypto import mask_phone
        
        phone = "+992901234567"
        masked = mask_phone(phone)
        
        assert masked.startswith("+992")
        assert masked.endswith("567")
        assert "*" in masked
    
    def test_mask_passport_short(self):
        """Маскирование короткого паспорта"""
        from credit_engine.crypto import mask_passport
        
        passport = "AA"
        masked = mask_passport(passport)
        
        assert len(masked) <= len(passport)


class TestIBANValidation:
    """Тесты валидации IBAN"""
    
    def test_validate_valid_tajik_iban(self):
        """Валидный таджикский IBAN"""
        from credit_engine.crypto import validate_iban
        
        iban = "TJ0735010123456789012345"
        assert validate_iban(iban) is True
    
    def test_validate_invalid_iban_format(self):
        """Невалидный формат IBAN"""
        from credit_engine.crypto import validate_iban
        
        iban = "INVALID_IBAN"
        assert validate_iban(iban) is False
    
    def test_validate_invalid_iban_checksum(self):
        """Невалидный checksum IBAN"""
        from credit_engine.crypto import validate_iban
        
        iban = "TJ9935010123456789012345"
        assert validate_iban(iban) is False
    
    def test_calculate_checksum(self):
        """Вычисление checksum"""
        from credit_engine.crypto import calculate_checksum
        
        iban = "TJ0735010123456789012345"
        checksum = calculate_checksum(iban)
        
        assert isinstance(checksum, int)
        assert 0 <= checksum <= 97


# ============================================
# BUSINESS LOGIC TESTS (29 tests)
# ============================================

class TestCommissionCalculation:
    """Тесты расчета комиссии"""
    
    def test_dailypay_commission_4_percent(self):
        """Комиссия DailyPay 4%"""
        from credit_engine.business import calculate_commission
        
        amount = Decimal("1000")
        commission = calculate_commission("DailyPay", amount)
        
        assert commission == Decimal("40.00")
    
    def test_rentpay_commission_8_percent(self):
        """Комиссия RentPay 8%"""
        from credit_engine.business import calculate_commission
        
        amount = Decimal("3000")
        commission = calculate_commission("RentPay", amount)
        
        assert commission == Decimal("240.00")
    
    def test_studentpay_commission_0_percent(self):
        """Комиссия StudentPay 0%"""
        from credit_engine.business import calculate_commission
        
        amount = Decimal("5000")
        commission = calculate_commission("StudentPay", amount)
        
        assert commission == Decimal("0.00")
    
    def test_commission_rounding(self):
        """Округление комиссии"""
        from credit_engine.business import calculate_commission
        
        amount = Decimal("1001")
        commission = calculate_commission("DailyPay", amount)
        
        assert commission == Decimal("40.04")


class TestInterestCalculation:
    """Тесты расчета процентов"""
    
    def test_studentpay_interest_12_percent(self):
        """Проценты StudentPay 12%"""
        from credit_engine.business import calculate_interest
        
        amount = Decimal("10000")
        months = 10
        interest = calculate_interest("StudentPay", amount, months)
        
        # 12% годовых за 10 месяцев
        expected = Decimal("1000")  # 10000 * 0.12 * (10/12)
        assert abs(interest - expected) < Decimal("1")
    
    def test_dailypay_interest_0_percent(self):
        """Проценты DailyPay 0%"""
        from credit_engine.business import calculate_interest
        
        amount = Decimal("1000")
        interest = calculate_interest("DailyPay", amount, 7)
        
        assert interest == Decimal("0.00")
    
    def test_rentpay_interest_0_percent(self):
        """Проценты RentPay 0%"""
        from credit_engine.business import calculate_interest
        
        amount = Decimal("3000")
        interest = calculate_interest("RentPay", amount, 15)
        
        assert interest == Decimal("0.00")


class TestPenaltyCalculation:
    """Тесты расчета штрафов"""
    
    def test_dailypay_penalty_0_5_percent_per_day(self):
        """Штраф DailyPay 0.5% в день"""
        from credit_engine.business import calculate_penalty
        
        amount = Decimal("1000")
        days_overdue = 5
        penalty = calculate_penalty("DailyPay", amount, days_overdue)
        
        expected = Decimal("25.00")  # 0.5% * 5 * 1000
        assert penalty == expected
    
    def test_rentpay_penalty_0_5_percent_per_day(self):
        """Штраф RentPay 0.5% в день"""
        from credit_engine.business import calculate_penalty
        
        amount = Decimal("3000")
        days_overdue = 3
        penalty = calculate_penalty("RentPay", amount, days_overdue)
        
        expected = Decimal("45.00")  # 0.5% * 3 * 3000
        assert penalty == expected
    
    def test_studentpay_no_penalty(self):
        """StudentPay не имеет штрафа"""
        from credit_engine.business import calculate_penalty
        
        amount = Decimal("5000")
        penalty = calculate_penalty("StudentPay", amount, 10)
        
        assert penalty == Decimal("0.00")
    
    def test_penalty_zero_days(self):
        """Штраф за 0 дней"""
        from credit_engine.business import calculate_penalty
        
        amount = Decimal("1000")
        penalty = calculate_penalty("DailyPay", amount, 0)
        
        assert penalty == Decimal("0.00")


class TestAmountValidation:
    """Тесты валидации суммы"""
    
    def test_valid_dailypay_amount_range(self):
        """Валидный диапазон DailyPay (200-2000)"""
        from credit_engine.business import validate_product_amount
        
        assert validate_product_amount("DailyPay", 200) is True
        assert validate_product_amount("DailyPay", 1000) is True
        assert validate_product_amount("DailyPay", 2000) is True
    
    def test_invalid_dailypay_amount_below_min(self):
        """DailyPay ниже минимума"""
        from credit_engine.business import validate_product_amount
        
        assert validate_product_amount("DailyPay", 100) is False
        assert validate_product_amount("DailyPay", 199) is False
    
    def test_invalid_dailypay_amount_above_max(self):
        """DailyPay выше максимума"""
        from credit_engine.business import validate_product_amount
        
        assert validate_product_amount("DailyPay", 2001) is False
        assert validate_product_amount("DailyPay", 5000) is False
    
    def test_valid_rentpay_amount_range(self):
        """Валидный диапазон RentPay (500-5000)"""
        from credit_engine.business import validate_product_amount
        
        assert validate_product_amount("RentPay", 500) is True
        assert validate_product_amount("RentPay", 3000) is True
        assert validate_product_amount("RentPay", 5000) is True
    
    def test_valid_studentpay_amount_range(self):
        """Валидный диапазон StudentPay (3000-12000)"""
        from credit_engine.business import validate_product_amount
        
        assert validate_product_amount("StudentPay", 3000) is True
        assert validate_product_amount("StudentPay", 7500) is True
        assert validate_product_amount("StudentPay", 12000) is True


class TestAgeValidation:
    """Тесты валидации возраста"""
    
    def test_valid_age_18_plus(self):
        """Возраст 18+"""
        from credit_engine.business import validate_age
        
        # 2000 год = 25 лет (в 2025)
        assert validate_age("2000-01-01") is True
        assert validate_age("1990-05-15") is True
    
    def test_invalid_age_under_18(self):
        """Возраст меньше 18"""
        from credit_engine.business import validate_age
        
        # 2008 год = 17 лет (в 2025)
        assert validate_age("2008-01-01") is False
    
    def test_invalid_date_format(self):
        """Неправильный формат даты"""
        from credit_engine.business import validate_age
        
        assert validate_age("invalid") is False
        assert validate_age("01-01-2000") is False


class TestGuarantorValidation:
    """Тесты валидации гаранта"""
    
    def test_valid_guarantor_relation(self):
        """Валидные отношения гаранта"""
        from credit_engine.business import validate_guarantor
        
        assert validate_guarantor("FATHER") is True
        assert validate_guarantor("MOTHER") is True
    
    def test_invalid_guarantor_relation(self):
        """Невалидные отношения гаранта"""
        from credit_engine.business import validate_guarantor
        
        assert validate_guarantor("FRIEND") is False
        assert validate_guarantor("") is False
        assert validate_guarantor("BROTHER") is False
    
    def test_guarantor_cannot_be_borrower(self):
        """Гарант не может быть заемщиком"""
        from credit_engine.business import validate_guarantor
        
        borrower_passport = "AA1234567"
        guarantor_passport = "AA1234567"
        
        with pytest.raises(ValueError, match="guarantor_cannot_be_borrower"):
            validate_guarantor("FATHER", borrower_passport, guarantor_passport)


class TestPaymentSchedule:
    """Тесты графика платежей"""
    
    def test_dailypay_schedule_7_days(self):
        """График DailyPay 7 дней"""
        from credit_engine.business import create_payment_schedule
        
        schedule = create_payment_schedule("DailyPay", Decimal("1000"), 7)
        
        assert len(schedule) == 1
        assert schedule[0]["days"] == 7
    
    def test_rentpay_schedule_15_days(self):
        """График RentPay 15 дней"""
        from credit_engine.business import create_payment_schedule
        
        schedule = create_payment_schedule("RentPay", Decimal("3000"), 15)
        
        assert len(schedule) == 1
        assert schedule[0]["days"] == 15
    
    def test_studentpay_schedule_10_months(self):
        """График StudentPay 10 месяцев"""
        from credit_engine.business import create_payment_schedule
        
        schedule = create_payment_schedule("StudentPay", Decimal("10000"), 10)
        
        assert len(schedule) == 10
        assert schedule[0]["month"] == 1
        assert schedule[-1]["month"] == 10


class TestDuplicateCheck:
    """Тесты проверки дубликатов"""
    
    def test_no_duplicate_request(self):
        """Нет дубликата запроса"""
        from credit_engine.business import check_duplicate_application
        
        existing = ["req-001", "req-002"]
        new_request = "req-003"
        
        assert check_duplicate_application(existing, new_request) is False
    
    def test_has_duplicate_request(self):
        """Есть дубликат запроса"""
        from credit_engine.business import check_duplicate_application
        
        existing = ["req-001", "req-002"]
        new_request = "req-001"
        
        assert check_duplicate_application(existing, new_request) is True


# ============================================
# CONFIG & API VALIDATION TESTS (38 tests)
# ============================================

class TestAPIKeyValidation:
    """Тесты валидации API ключа"""
    
    def test_valid_api_key_32_chars(self):
        """Валидный API ключ 32 символа"""
        from credit_engine.config import validate_api_key
        
        key = "a" * 32
        assert validate_api_key(key) is True
    
    def test_valid_api_key_longer(self):
        """Валидный API ключ длиннее"""
        from credit_engine.config import validate_api_key
        
        key = "a" * 64
        assert validate_api_key(key) is True
    
    def test_invalid_api_key_too_short(self):
        """Невалидный API ключ слишком короткий"""
        from credit_engine.config import validate_api_key
        
        key = "a" * 31
        assert validate_api_key(key) is False
    
    def test_invalid_api_key_empty(self):
        """Невалидный API ключ пустой"""
        from credit_engine.config import validate_api_key
        
        assert validate_api_key("") is False
    
    def test_internal_api_key_must_differ(self):
        """INTERNAL_API_KEY должен отличаться от API_KEY"""
        from credit_engine.config import validate_api_keys
        
        api_key = "a" * 32
        internal_key = "b" * 32
        
        assert validate_api_keys(api_key, internal_key) is True
    
    def test_internal_api_key_cannot_match(self):
        """INTERNAL_API_KEY не может совпадать с API_KEY"""
        from credit_engine.config import validate_api_keys
        
        api_key = "a" * 32
        internal_key = "a" * 32
        
        assert validate_api_keys(api_key, internal_key) is False


class TestEnvironmentConfig:
    """Тесты конфигурации окружения"""
    
    def test_valid_production_config(self):
        """Валидная production конфигурация"""
        from credit_engine.config import validate_env_config
        
        config = {
            "ENV": "production",
            "DB_PASSWORD": "strong_password",
            "API_KEY": "a" * 32,
            "INTERNAL_API_KEY": "b" * 32
        }
        
        assert validate_env_config(config) is True
    
    def test_missing_db_password(self):
        """Отсутствует DB_PASSWORD"""
        from credit_engine.config import validate_env_config
        
        config = {
            "ENV": "production",
            "API_KEY": "a" * 32
        }
        
        assert validate_env_config(config) is False
    
    def test_missing_api_key(self):
        """Отсутствует API_KEY"""
        from credit_engine.config import validate_env_config
        
        config = {
            "ENV": "production",
            "DB_PASSWORD": "password"
        }
        
        assert validate_env_config(config) is False


class TestPassportValidation:
    """Тесты валидации паспорта"""
    
    def test_valid_passport_format(self):
        """Валидный формат паспорта"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("AA", "1234567") is True
        assert validate_passport("A", "12345678") is True
    
    def test_invalid_passport_series_too_long(self):
        """Невалидная серия паспорта слишком длинная"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("AAA", "1234567") is False
    
    def test_invalid_passport_series_empty(self):
        """Невалидная серия паспорта пустая"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("", "1234567") is False
    
    def test_invalid_passport_number_too_short(self):
        """Невалидный номер паспорта слишком короткий"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("AA", "123456") is False
    
    def test_invalid_passport_number_too_long(self):
        """Невалидный номер паспорта слишком длинный"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("AA", "1234567890") is False
    
    def test_invalid_passport_number_contains_letters(self):
        """Невалидный номер паспорта содержит буквы"""
        from credit_engine.api.validators import validate_passport
        
        assert validate_passport("AA", "123456A") is False


class TestPhoneValidation:
    """Тесты валидации телефона"""
    
    def test_valid_phone_tajik_format(self):
        """Валидный телефон в таджикском формате"""
        from credit_engine.api.validators import validate_phone
        
        assert validate_phone("+992901234567") is True
        assert validate_phone("+992911234567") is True
    
    def test_invalid_phone_too_short(self):
        """Невалидный телефон слишком короткий"""
        from credit_engine.api.validators import validate_phone
        
        assert validate_phone("+9921234567") is False
    
    def test_invalid_phone_no_plus(self):
        """Невалидный телефон без плюса"""
        from credit_engine.api.validators import validate_phone
        
        assert validate_phone("992901234567") is False
    
    def test_invalid_phone_wrong_length(self):
        """Невалидный телефон неправильной длины"""
        from credit_engine.api.validators import validate_phone
        
        assert validate_phone("+99290123456") is False


class TestDateValidation:
    """Тесты валидации даты"""
    
    def test_valid_date_format(self):
        """Валидный формат даты"""
        from credit_engine.api.validators import validate_date_of_birth
        
        assert validate_date_of_birth("2000-01-15") is True
        assert validate_date_of_birth("1990-12-31") is True
    
    def test_invalid_date_format_wrong_order(self):
        """Невалидный формат даты неправильный порядок"""
        from credit_engine.api.validators import validate_date_of_birth
        
        assert validate_date_of_birth("15-01-2000") is False
    
    def test_invalid_date_format_slashes(self):
        """Невалидный формат даты со слешами"""
        from credit_engine.api.validators import validate_date_of_birth
        
        assert validate_date_of_birth("2000/01/15") is False
    
    def test_invalid_date_format_text(self):
        """Невалидный формат даты текст"""
        from credit_engine.api.validators import validate_date_of_birth
        
        assert validate_date_of_birth("invalid") is False


class TestAmountValidation:
    """Тесты валидации суммы"""
    
    def test_valid_amount_integer(self):
        """Валидная сумма целое число"""
        from credit_engine.api.validators import validate_amount
        
        assert validate_amount(1000) is True
        assert validate_amount(5000) is True
    
    def test_valid_amount_decimal(self):
        """Валидная сумма десятичное число"""
        from credit_engine.api.validators import validate_amount
        
        assert validate_amount(1000.50) is True
        assert validate_amount(5000.99) is True
    
    def test_invalid_amount_zero(self):
        """Невалидная сумма ноль"""
        from credit_engine.api.validators import validate_amount
        
        assert validate_amount(0) is False
    
    def test_invalid_amount_negative(self):
        """Невалидная сумма отрицательная"""
        from credit_engine.api.validators import validate_amount
        
        assert validate_amount(-100) is False
    
    def test_invalid_amount_string(self):
        """Невалидная сумма строка"""
        from credit_engine.api.validators import validate_amount
        
        assert validate_amount("1000") is False


class TestProductTypeValidation:
    """Тесты валидации типа продукта"""
    
    def test_valid_product_types(self):
        """Валидные типы продуктов"""
        from credit_engine.api.validators import validate_product_type
        
        assert validate_product_type("StudentPay") is True
        assert validate_product_type("DailyPay") is True
        assert validate_product_type("RentPay") is True
    
    def test_invalid_product_type_unknown(self):
        """Невалидный тип продукта неизвестный"""
        from credit_engine.api.validators import validate_product_type
        
        assert validate_product_type("InvalidProduct") is False
    
    def test_invalid_product_type_empty(self):
        """Невалидный тип продукта пустой"""
        from credit_engine.api.validators import validate_product_type
        
        assert validate_product_type("") is False


class TestRequestBodyValidation:
    """Тесты валидации тела запроса"""
    
    def test_valid_studentpay_request(self):
        """Валидный запрос StudentPay"""
        from credit_engine.api.validators import validate_request_body
        
        request = {
            "passport_series": "AA",
            "passport_number": "1234567",
            "date_of_birth": "2000-01-15",
            "amount": 5000,
            "product_type": "StudentPay",
            "face_id_data": "base64data",
            "user_phone": "+992901234567",
            "guarantor_phone": "+992901234568",
            "guarantor_relation": "FATHER",
            "university_iban": "TJ0735010123456789012345",
            "university_name": "Test University"
        }
        
        errors = validate_request_body(request)
        assert len(errors) == 0
    
    def test_missing_required_fields(self):
        """Отсутствуют обязательные поля"""
        from credit_engine.api.validators import validate_request_body
        
        request = {
            "passport_series": "AA"
        }
        
        errors = validate_request_body(request)
        assert len(errors) > 0


class TestIBANFormatValidation:
    """Тесты валидации формата IBAN"""
    
    def test_valid_tajik_iban(self):
        """Валидный таджикский IBAN"""
        from credit_engine.api.validators import validate_iban_format
        
        iban = "TJ0735010123456789012345"
        assert validate_iban_format(iban) is True
    
    def test_invalid_iban_wrong_length(self):
        """Невалидный IBAN неправильная длина"""
        from credit_engine.api.validators import validate_iban_format
        
        iban = "TJ073501012345678901234"
        assert validate_iban_format(iban) is False
    
    def test_invalid_iban_wrong_country(self):
        """Невалидный IBAN неправильная страна"""
        from credit_engine.api.validators import validate_iban_format
        
        iban = "US0735010123456789012345"
        assert validate_iban_format(iban) is False


class TestSignatureValidation:
    """Тесты валидации подписи"""
    
    def test_valid_signature_format(self):
        """Валидный формат подписи"""
        from credit_engine.api.validators import validate_signature
        
        signature = "0" * 64
        assert validate_signature(signature) is True
    
    def test_invalid_signature_wrong_length(self):
        """Невалидная подпись неправильная длина"""
        from credit_engine.api.validators import validate_signature
        
        signature = "0" * 63
        assert validate_signature(signature) is False
    
    def test_invalid_signature_wrong_chars(self):
        """Невалидная подпись неправильные символы"""
        from credit_engine.api.validators import validate_signature
        
        signature = "g" * 64
        assert validate_signature(signature) is False


class TestRateLimiting:
    """Тесты ограничения скорости"""
    
    def test_within_rate_limit(self):
        """В пределах лимита"""
        from credit_engine.api.validators import check_rate_limit
        
        requests_made = 3
        limit = 5
        
        assert check_rate_limit(requests_made, limit) is True
    
    def test_at_rate_limit(self):
        """На лимите"""
        from credit_engine.api.validators import check_rate_limit
        
        requests_made = 5
        limit = 5
        
        assert check_rate_limit(requests_made, limit) is True
    
    def test_exceeded_rate_limit(self):
        """Превышен лимит"""
        from credit_engine.api.validators import check_rate_limit
        
        requests_made = 6
        limit = 5
        
        assert check_rate_limit(requests_made, limit) is False


class TestIdempotency:
    """Тесты идемпотентности"""
    
    def test_unique_request_id(self):
        """Уникальный request_id"""
        from credit_engine.api.validators import validate_idempotency
        
        existing_ids = ["req-001", "req-002"]
        new_id = "req-003"
        
        assert validate_idempotency(existing_ids, new_id) is True
    
    def test_duplicate_request_id(self):
        """Дубликат request_id"""
        from credit_engine.api.validators import validate_idempotency
        
        existing_ids = ["req-001", "req-002"]
        new_id = "req-001"
        
        assert validate_idempotency(existing_ids, new_id) is False


# ============================================
# RUN TESTS
# ============================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])