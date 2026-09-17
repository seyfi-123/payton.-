# -*- coding: utf-8 -*-
"""Crypto unit tests — 25 tests."""

import base64
import hashlib
import hmac
import sys

from credit_engine import CryptoService

M = 'a' * 64
K = 'b' * 64
C = 'c' * 64

c = CryptoService(M, K, C)

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


def raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


# 1. Round-trip encryption
check("encrypt/decrypt passport",
      c.decrypt(c.encrypt("AB1234567")) == "AB1234567")
check("encrypt/decrypt unicode",
      c.decrypt(c.encrypt("Аликулов")) == "Аликулов")
check("encrypt/decrypt with aad",
      c.decrypt(c.encrypt("+992901234567", aad='p:x'), aad='p:x')
      == "+992901234567")
check("encrypt empty", c.encrypt('') == '')
check("nonce random", c.encrypt("x") != c.encrypt("x"))
check("aad mismatch rejected",
      raises(lambda: c.decrypt(c.encrypt("s", aad='a'), aad='b')))
check("large plaintext",
      c.decrypt(c.encrypt("x" * 10000)) == "x" * 10000)
check("ciphertext longer than 12 bytes",
      len(base64.b64decode(c.encrypt("t"))) > 12)

# 2. Blind index
check("blind index length 64", len(c.blind_index("AB1234567")) == 64)
check("blind index deterministic",
      c.blind_index("A") == c.blind_index("A"))
check("blind index differs",
      c.blind_index("a") != c.blind_index("b"))
check("blind index empty", c.blind_index('') == '')
check("blind index hex only",
      all(x in '0123456789abcdef' for x in c.blind_index("A")))

# 3. OTP hash
check("otp_hash length 64", len(c.otp_hash('123456', 1)) == 64)
check("otp_hash deterministic",
      c.otp_hash('1', 1) == c.otp_hash('1', 1))
check("otp_hash differs by id",
      c.otp_hash('1', 1) != c.otp_hash('1', 2))

# 4. Signature hash
check("signature_hash length 64",
      len(c.signature_hash(1, '1', 'a')) == 64)
check("signature_hash deterministic",
      c.signature_hash(1, '1', 'a') == c.signature_hash(1, '1', 'a'))

# 5. Idempotency key
check("idempotency_key length 64",
      len(CryptoService.idempotency_key('a', 'b')) == 64)
check("idempotency_key deterministic",
      CryptoService.idempotency_key('a', 'b')
      == CryptoService.idempotency_key('a', 'b'))
check("idempotency_key differs",
      CryptoService.idempotency_key('a', 'b')
      != CryptoService.idempotency_key('a', 'c'))

# 6. Key validation
check("short key rejected", raises(lambda: CryptoService('short', K)))
check("non-hex key rejected",
      raises(lambda: CryptoService('x' * 64, K)))
check("bad hmac key rejected",
      raises(lambda: CryptoService(M, 'y' * 64)))

# 7. Card signature
ph = c.blind_index('A')
expected = hmac.new(
    bytes.fromhex(C),
    f'card:{ph}:tok_x'.encode('utf-8'),
    hashlib.sha256).hexdigest()
check("card signature valid",
      c.verify_card_signature(ph, 'tok_x', expected))
check("card signature invalid",
      not c.verify_card_signature(ph, 'tok_x', 'wrong' * 16))

print(f"\nCrypto: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)