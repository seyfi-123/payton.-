"""Unit Tests for Cryptography Functions"""
import pytest
import hashlib
import hmac
from credit_engine.crypto import (
    encrypt_pii,
    decrypt_pii,
    generate_hmac,
    verify_hmac,
    generate_master_key,
    derive_key,
    mask_passport,
    mask_phone,
    validate_iban,
    calculate_checksum
)


class TestEncryptionDecryption:
    """Тестҳои рамзгузорӣ ва рамзкушоӣ"""
    
    def test_encrypt_decrypt_passport(self):
        """Рамзгузорӣ ва рамзкушоии шиноснома"""
        original = "AA1234567"
        encrypted = encrypt_pii(original, field="passport")
        decrypted = decrypt_pii(encrypted, field="passport")
        assert decrypted == original
    
    def test_encrypt_decrypt_phone(self):
        """Рамзгузорӣ ва рамзкушоии телефон"""
        original = "+992901234567"
        encrypted = encrypt_pii(original, field="phone")
        decrypted = decrypt_pii(encrypted, field="phone")
        assert decrypted == original
    
    def test_encrypt_decrypt_iban(self):
        """Рамзгузорӣ ва рамзкушоии IBAN"""
        original = "TJ0735010123456789012345"
        encrypted = encrypt_pii(original, field="iban")
        decrypted = decrypt_pii(encrypted, field="iban")
        assert decrypted == original
    
    def test_encrypt_different_outputs(self):
        """ар маротиба рамзгузорӣ гуногун аст"""
        original = "test_data"
        encrypted1 = encrypt_pii(original, field="passport")
        encrypted2 = encrypt_pii(original, field="passport")
        assert encrypted1 != encrypted2  # Nonce гуногун
    
    def test_decrypt_wrong_field_fails(self):
        """Рамзкушоӣ бо майдони нодуруст ноком мешавад"""
        original = "AA1234567"
        encrypted = encrypt_pii(original, field="passport")
        with pytest.raises(Exception):
            decrypt_pii(encrypted, field="phone")  # Майдони дигар


class TestHMAC:
    """Тестҳои HMAC-SHA256"""
    
    def test_generate_hmac(self):
        """Тавлиди HMAC"""
        data = "test_data"
        signature = generate_hmac(data)
        assert len(signature) == 64  # 64 hex chars
    
    def test_verify_hmac_valid(self):
        """Тасдиқи HMAC дуруст"""
        data = "test_data"
        signature = generate_hmac(data)
        assert verify_hmac(data, signature) is True
    
    def test_verify_hmac_invalid(self):
        """Тасдиқи HMAC нодуруст"""
        data = "test_data"
        signature = generate_hmac(data)
        tampered_data = "tampered_data"
        assert verify_hmac(tampered_data, signature) is False
    
    def test_hmac_consistency(self):
        """HMAC барои ҳамон додаҳо якхела аст"""
        data = "test_data"
        sig1 = generate_hmac(data)
        sig2 = generate_hmac(data)
        assert sig1 == sig2


class TestKeyManagement:
    """Тестҳои идоракунии калидҳо"""
    
    def test_generate_master_key(self):
        """Тавлиди калиди асосӣ"""
        key = generate_master_key()
        assert len(key) == 64  # 64 hex chars = 32 bytes
        assert all(c in '0123456789abcdef' for c in key)
    
    def test_derive_key(self):
        """Ҳосил кардани калиди фаръӣ"""
        master_key = "0" * 64
        derived1 = derive_key(master_key, context="encryption")
        derived2 = derive_key(master_key, context="signing")
        assert derived1 != derived2
        assert len(derived1) == 64


class TestMasking:
    """Тестҳои пинҳон кардан"""
    
    def test_mask_passport(self):
        """Пинҳон кардани шиноснома"""
        passport = "AA1234567"
        masked = mask_passport(passport)
        assert masked == "AA*****567"
    
    def test_mask_phone(self):
        """Пинҳон кардани телефон"""
        phone = "+992901234567"
        masked = mask_phone(phone)
        assert masked.startswith("+992")
        assert masked.endswith("567")
        assert "*" in masked


class TestIBANValidation:
    """Тестҳои санҷиши IBAN"""
    
    def test_validate_valid_iban(self):
        """Санҷиши IBAN дуруст"""
        iban = "TJ0735010123456789012345"
        assert validate_iban(iban) is True
    
    def test_validate_invalid_iban_format(self):
        """Санҷиши IBAN нодуруст (формат)"""
        iban = "INVALID_IBAN"
        assert validate_iban(iban) is False
    
    def test_validate_invalid_iban_checksum(self):
        """Санҷиши IBAN нодуруст (checksum)"""
        iban = "TJ9935010123456789012345"  # Checksum нодуруст
        assert validate_iban(iban) is False
    
    def test_calculate_checksum(self):
        """Ҳисоб кардани checksum"""
        iban = "TJ0735010123456789012345"
        checksum = calculate_checksum(iban)
        assert isinstance(checksum, int)
        assert 0 <= checksum <= 97