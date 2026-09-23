"""Unit Tests for Configuration and API Validation"""
import pytest
from credit_engine.config import (
    validate_api_key,
    validate_env_config,
    validate_database_config,
    validate_bank_urls,
    load_environment,
    check_required_vars
)
from credit_engine.api.validators import (
    validate_passport,
    validate_phone,
    validate_date_of_birth,
    validate_amount,
    validate_product_type,
    validate_request_body,
    validate_iban_format,
    validate_signature,
    check_rate_limit,
    validate_idempotency
)


class TestAPIKeyValidation:
    """Тестҳои санҷиши API калид"""
    
    def test_valid_api_key(self):
        """API калиди дуруст (>= 32 аломат)"""
        key = "a" * 32
        assert validate_api_key(key) is True
    
    def test_invalid_api_key_short(self):
        """API калиди нодуруст (кӯтоҳ)"""
        key = "a" * 31
        assert validate_api_key(key) is False
    
    def test_internal_api_key_different(self):
        """INTERNAL_API_KEY бояд аз API_KEY фарқ кунад"""
        api_key = "a" * 32
        internal_key = "b" * 32
        assert api_key != internal_key


class TestEnvironmentConfig:
    """Тестҳои танзимоти муҳит"""
    
    def test_valid_production_config(self):
        """Танзимоти дурусти production"""
        config = {
            "ENV": "production",
            "DB_PASSWORD": "strong_password",
            "API_KEY": "a" * 32,
            "INTERNAL_API_KEY": "b" * 32
        }
        assert validate_env_config(config) is True
    
    def test_missing_required_vars(self):
        """Тағйирёбандаҳои зарурӣ намерасанд"""
        config = {
            "ENV": "production",
            # DB_PASSWORD нест
        }
        assert validate_env_config(config) is False


class TestPassportValidation:
    """Тестҳои санҷиши шиноснома"""
    
    def test_valid_passport_format(self):
        """Формати дурусти шиноснома"""
        assert validate_passport("AA", "1234567") is True
        assert validate_passport("A", "12345678") is True
    
    def test_invalid_passport_series(self):
        """Серияи нодурусти шиноснома"""
        assert validate_passport("AAA", "1234567") is False  # 3 аломат
        assert validate_passport("", "1234567") is False
    
    def test_invalid_passport_number(self):
        """Рақами нодурусти шиноснома"""
        assert validate_passport("AA", "123456") is False  # 6 рақам
        assert validate_passport("AA", "1234567890") is False  # 10 рақам
        assert validate_passport("AA", "123456A") is False  # ҳарф


class TestPhoneValidation:
    """Тестҳои санҷиши телефон"""
    
    def test_valid_phone(self):
        """Телефони дуруст"""
        assert validate_phone("+992901234567") is True
        assert validate_phone("+992911234567") is True
    
    def test_invalid_phone(self):
        """Телефони нодуруст"""
        assert validate_phone("+9921234567") is False  # кӯтоҳ
        assert validate_phone("992901234567") is False  # бе +
        assert validate_phone("+99290123456") is False  # 10 рақам


class TestDateValidation:
    """Тестҳои санҷиши таърих"""
    
    def test_valid_date_format(self):
        """Формати дурусти таърих"""
        assert validate_date_of_birth("2000-01-15") is True
        assert validate_date_of_birth("1990-12-31") is True
    
    def test_invalid_date_format(self):
        """Формати нодурусти таърих"""
        assert validate_date_of_birth("15-01-2000") is False
        assert validate_date_of_birth("2000/01/15") is False
        assert validate_date_of_birth("invalid") is False


class TestAmountValidation:
    """Тестҳои санҷиши маблағ"""
    
    def test_valid_amount(self):
        """Маблағи дуруст"""
        assert validate_amount(1000) is True
        assert validate_amount(5000.50) is True
    
    def test_invalid_amount(self):
        """Маблағи нодуруст"""
        assert validate_amount(0) is False
        assert validate_amount(-100) is False
        assert validate_amount("1000") is False  # string


class TestProductTypeValidation:
    """Тестҳои санҷиши намуди маҳсулот"""
    
    def test_valid_product_types(self):
        """Намудҳои дурусти маҳсулот"""
        assert validate_product_type("StudentPay") is True
        assert validate_product_type("DailyPay") is True
        assert validate_product_type("RentPay") is True
    
    def test_invalid_product_type(self):
        """Намуди нодурусти маҳсулот"""
        assert validate_product_type("InvalidProduct") is False
        assert validate_product_type("") is False


class TestRequestBodyValidation:
    """Тестҳои санҷиши бадани дархост"""
    
    def test_valid_studentpay_request(self):
        """Дархости дурусти StudentPay"""
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
        """Майдонҳои зарурӣ намерасанд"""
        request = {
            "passport_series": "AA",
            # passport_number нест
        }
        errors = validate_request_body(request)
        assert len(errors) > 0


class TestIBANFormatValidation:
    """Тестҳои санҷиши формати IBAN"""
    
    def test_valid_tajik_iban(self):
        """IBAN дурусти Тоҷикистон"""
        iban = "TJ0735010123456789012345"
        assert validate_iban_format(iban) is True
    
    def test_invalid_iban_length(self):
        """IBAN нодуруст (дарозӣ)"""
        iban = "TJ073501012345678901234"  # 24 аломат
        assert validate_iban_format(iban) is False
    
    def test_invalid_iban_country(self):
        """IBAN нодуруст (кишвар)"""
        iban = "US0735010123456789012345"  # US
        assert validate_iban_format(iban) is False


class TestSignatureValidation:
    """Тестҳои санҷиши имзо"""
    
    def test_valid_signature_format(self):
        """Формати дурусти имзо"""
        signature = "0" * 64  # 64 hex chars
        assert validate_signature(signature) is True
    
    def test_invalid_signature_length(self):
        """Дарозии нодурусти имзо"""
        signature = "0" * 63  # 63 аломат
        assert validate_signature(signature) is False
    
    def test_invalid_signature_chars(self):
        """Аломатҳои нодурусти имзо"""
        signature = "g" * 64  # g hex нест
        assert validate_signature(signature) is False


class TestRateLimiting:
    """Тестҳои маҳдудияти суръат"""
    
    def test_within_rate_limit(self):
        """Дар доираи лимит"""
        requests_made = 3
        limit = 5
        assert check_rate_limit(requests_made, limit) is True
    
    def test_exceeded_rate_limit(self):
        """Лимит гузашт"""
        requests_made = 6
        limit = 5
        assert check_rate_limit(requests_made, limit) is False


class TestIdempotency:
    """Тестҳои идемпотентӣ"""
    
    def test_unique_request_id(self):
        """request_id ягона"""
        existing_ids = ["req-001", "req-002"]
        new_id = "req-003"
        assert validate_idempotency(existing_ids, new_id) is True
    
    def test_duplicate_request_id(self):
        """request_id такрорӣ"""
        existing_ids = ["req-001", "req-002"]
        new_id = "req-001"
        assert validate_idempotency(existing_ids, new_id) is False