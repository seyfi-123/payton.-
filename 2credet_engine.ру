# -*- coding: utf-8 -*-
# ============================================================================
# TAJIK FINTECH CREDIT ENGINE
# Version: 3.8.1 | Target: PostgreSQL 13+ | Python 3.9+
# ============================================================================

import asyncio
import base64
import concurrent.futures
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Optional, Tuple, Dict, Any, Set, List

try:
    import httpx
except ImportError:
    raise ImportError("Install: pip install httpx")

try:
    from psycopg2 import (
        pool, IntegrityError, OperationalError, DataError,
    )
except ImportError:
    raise ImportError("Install: pip install psycopg2-binary")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError("Install: pip install cryptography")

try:
    from tenacity import (
        retry, stop_after_attempt, wait_exponential, retry_if_exception_type,
    )
except ImportError:
    raise ImportError("Install: pip install tenacity")

try:
    import aiobreaker
except ImportError:
    raise ImportError("Install: pip install aiobreaker")

try:
    from fastapi import FastAPI, HTTPException, Request, Depends, status
    from fastapi.responses import JSONResponse
    from fastapi.security import APIKeyHeader
    from pydantic import BaseModel, Field, ConfigDict
    import uvicorn
except ImportError:
    raise ImportError("Install: pip install fastapi uvicorn[standard] pydantic")

try:
    import hvac
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False


# ============================================================================
# PII SCRUBBING / МАХФИИ МАЪЛУМОТИ ШАХСӢ
# ============================================================================
PII_SCRUB_PATTERNS = [
    (re.compile(r'\b[A-Z]{2}\d{7,9}\b'), '[PASSPORT]'),
    (re.compile(r'\+?992\d{9}\b'), '[PHONE]'),
    (re.compile(r'\bTJ\d{2}[A-Z0-9]{16,20}\b'), '[IBAN]'),
    (re.compile(r'\btok_[A-Za-z0-9]+\b'), '[CARD_TOKEN]'),
    (re.compile(r'\b\d{16}\b'), '[CARD_NUM]'),
]


def scrub_pii(text) -> str:
    if text is None:
        return ''
    text = str(text)
    for pattern, replacement in PII_SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ============================================================================
# LOGGING / ЛОГГИРКУНӢ
# ============================================================================
class JSONFormatter(logging.Formatter):
    RESERVED = {
        'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
        'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
        'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
        'thread', 'threadName', 'processName', 'process', 'message',
        'asctime', 'taskName',
    }
    PII_KEYS = {
        'passport_sn', 'passport', 'passport_series', 'passport_number',
        'face_id_data', 'face_image', 'face_data', 'phone', 'user_phone',
        'guarantor_phone', 'card_token', 'self_iban', 'landlord_iban',
        'university_iban', 'master_key', 'hmac_key', 'api_key', 'password',
        'landlord_name', 'university_name', 'signature', 'internal_api_key',
    }

    def format(self, record):
        log_obj = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': scrub_pii(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith('_'):
                if key.lower() in self.PII_KEYS:
                    log_obj[key] = (
                        None if value is None
                        else f'***[len={len(str(value))}]'
                    )
                else:
                    try:
                        json.dumps(value)
                        log_obj[key] = (
                            scrub_pii(value) if isinstance(value, str)
                            else value
                        )
                    except (TypeError, ValueError):
                        log_obj[key] = scrub_pii(str(value))
        if record.exc_info:
            log_obj['exception'] = scrub_pii(
                self.formatException(record.exc_info)
            )
        return json.dumps(log_obj, ensure_ascii=False, default=str)


def setup_logging():
    logger = logging.getLogger('credit_engine')
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get('LOG_FORMAT') == 'json':
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))
    logger.handlers = [handler]
    logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))
    return logger


logger = setup_logging()


# ============================================================================
# DATE HELPERS / ЁРИРАСОНҲОИ САНА
# ============================================================================
def add_months(d: date, months: int) -> date:
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1
    leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
    days_in_month = [31, 29 if leap else 28, 31, 30, 31, 30,
                     31, 31, 30, 31, 30, 31][month - 1]
    day = min(d.day, days_in_month)
    return date(year, month, day)


def add_days(d: date, days: int) -> date:
    """v3.8.1: Барои DailyPay (7 рӯз) ва RentPay (15 рӯз)."""
    return d + timedelta(days=int(days))


# ============================================================================
# KEY MANAGER / ИДОРАИ КАЛИДҲО
# ============================================================================
class KeyManager:
    def __init__(self):
        self._vault_url = os.environ.get('VAULT_URL')
        self._vault_token = os.environ.get('VAULT_TOKEN')
        self._vault_path = os.environ.get('VAULT_PATH', 'credit-engine/keys')

    def load(self) -> Dict[str, str]:
        if self._vault_url and self._vault_token and VAULT_AVAILABLE:
            return self._load_from_vault()
        return self._load_from_env()

    def _load_from_vault(self) -> Dict[str, str]:
        client = hvac.Client(url=self._vault_url, token=self._vault_token)
        if not client.is_authenticated():
            raise ValueError('Vault auth failed')
        secret = client.secrets.kv.v2.read_secret_version(path=self._vault_path)
        data = secret['data']['data']
        master = data.get('master_key')
        hmac_key = data.get('hmac_key')
        if not master or not hmac_key:
            raise ValueError('Keys not found in Vault')
        if len(master) != 64 or len(hmac_key) != 64:
            raise ValueError('Keys must be 64 hex chars')
        logger.info('Keys loaded from Vault')
        return {'master_key': master, 'hmac_key': hmac_key}

    def _load_from_env(self) -> Dict[str, str]:
        master = os.environ.get('MASTER_KEY_HEX')
        hmac_key = os.environ.get('HMAC_KEY_HEX')
        if not master or not hmac_key:
            raise ValueError('MASTER_KEY_HEX and HMAC_KEY_HEX required')
        if len(master) != 64 or len(hmac_key) != 64:
            raise ValueError('Keys must be 64 hex chars')
        logger.info('Keys loaded from environment')
        return {'master_key': master, 'hmac_key': hmac_key}


# ============================================================================
# CRYPTO SERVICE / ХИЗМАТИ КРИПТОГРАФӢ
# ============================================================================
def _validate_hex_key(key: str, name: str) -> None:
    if not key:
        raise ValueError(f'{name} is required')
    if not isinstance(key, str):
        raise ValueError(f'{name} must be a string')
    if len(key) != 64:
        raise ValueError(
            f'{name} must be 64 hex characters (32 bytes), '
            f'got {len(key)} characters')
    try:
        bytes.fromhex(key)
    except ValueError:
        raise ValueError(
            f'{name} must contain only hex characters (0-9, a-f)')


class CryptoService:
    def __init__(self, master_key_hex: str, hmac_key_hex: str,
                 card_signature_key_hex: Optional[str] = None):
        _validate_hex_key(master_key_hex, 'MASTER_KEY')
        _validate_hex_key(hmac_key_hex, 'HMAC_KEY')
        if card_signature_key_hex is not None:
            _validate_hex_key(card_signature_key_hex, 'CARD_SIGNATURE_KEY')
        self._aesgcm = AESGCM(bytes.fromhex(master_key_hex))
        self._hmac_key = bytes.fromhex(hmac_key_hex)
        if card_signature_key_hex:
            self._card_sig_key = bytes.fromhex(card_signature_key_hex)
        else:
            self._card_sig_key = None

    def encrypt(self, plain_text: str, aad: str = '') -> str:
        if not plain_text:
            return ''
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(
            nonce, plain_text.encode('utf-8'),
            aad.encode('utf-8') if aad else None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt(self, cipher_text: str, aad: str = '') -> str:
        if not cipher_text:
            return ''
        data = base64.b64decode(cipher_text.encode('utf-8'))
        nonce, ciphertext = data[:12], data[12:]
        return self._aesgcm.decrypt(
            nonce, ciphertext,
            aad.encode('utf-8') if aad else None).decode('utf-8')

    def blind_index(self, plain_text: str) -> str:
        if not plain_text:
            return ''
        return hmac.new(
            self._hmac_key, plain_text.encode('utf-8'), hashlib.sha256,
        ).hexdigest()

    def otp_hash(self, otp: str, app_guarantor_id: int) -> str:
        return hmac.new(
            self._hmac_key,
            f'otp:{app_guarantor_id}:{otp}'.encode('utf-8'),
            hashlib.sha256).hexdigest()

    def signature_hash(self, app_guarantor_id: int, otp_code: str,
                       passport_hmac: str) -> str:
        return hmac.new(
            self._hmac_key,
            f'sig:{app_guarantor_id}:{otp_code}:{passport_hmac}'.encode('utf-8'),
            hashlib.sha256).hexdigest()

    def verify_card_signature(self, passport_hmac: str, card_token: str,
                               provided_signature: str) -> bool:
        if not self._card_sig_key:
            return False
        expected = hmac.new(
            self._card_sig_key,
            f'card:{passport_hmac}:{card_token}'.encode('utf-8'),
            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, provided_signature or '')

    @staticmethod
    def idempotency_key(*parts) -> str:
        return hashlib.sha256(
            ':'.join(str(p) for p in parts).encode('utf-8')
        ).hexdigest()


# ============================================================================
# EXTERNAL CLIENTS / МИЗОҶОНИ БЕРУНА
# ============================================================================
class ServiceUnavailable(Exception):
    pass


class BaseAsyncClient:
    def __init__(self, name: str, base_url: str, api_key: str,
                 timeout: int = 10, client_cert: Optional[str] = None,
                 client_key: Optional[str] = None,
                 ca_cert: Optional[str] = None,
                 fail_max: int = 5, reset_timeout: int = 60):
        self.name = name
        self.base_url = base_url
        limits = httpx.Limits(
            max_keepalive_connections=50,
            max_connections=200,
            keepalive_expiry=30.0)
        verify = ca_cert if ca_cert else True
        if client_cert and client_key:
            cert = (client_cert, client_key)
        else:
            cert = None
        self._client = httpx.AsyncClient(
            timeout=timeout, verify=verify, cert=cert, limits=limits,
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'User-Agent': f'credit-engine/{name}',
            })
        self._breaker = aiobreaker.CircuitBreaker(
            fail_max=fail_max,
            timeout_duration=timedelta(seconds=reset_timeout),
            name=name)

    async def _do_request(self, method: str, path: str,
                           **kwargs) -> httpx.Response:
        try:
            response = await self._client.request(
                method, f'{self.base_url}{path}', **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            logger.error(f'{self.name} HTTP {e.response.status_code} on {path}')
            raise ServiceUnavailable(f'{self.name} HTTP {e.response.status_code}')

    async def _call(self, method: str, path: str, **kwargs) -> httpx.Response:
        return await self._breaker.call_async(
            self._do_request, method, path, **kwargs)

    async def close(self):
        await self._client.aclose()


class CIBClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('CIB', base_url, api_key,
                         timeout=kwargs.pop('timeout', 5), **kwargs)

    @retry(stop=stop_after_attempt(2),
           wait=wait_exponential(multiplier=1, min=1, max=3),
           retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
           reraise=True)
    async def _do_check(self, passport_sn: str) -> Dict:
        r = await self._call('POST', '/api/check', json={'passport': passport_sn})
        return r.json()

    async def check(self, passport_sn: str) -> Tuple[int, Decimal]:
        try:
            data = await self._do_check(passport_sn)
            score = data.get('score')
            limit = data.get('limit')
            if score is None or limit is None:
                logger.error('CIB returned None score/limit')
                raise ServiceUnavailable('CIB invalid response')
            try:
                score_int = int(score)
                limit_dec = Decimal(str(limit))
            except (ValueError, TypeError, InvalidOperation) as e:
                logger.error(f'CIB parse error: {scrub_pii(str(e))}')
                raise ServiceUnavailable('CIB invalid response')
            return score_int, limit_dec
        except aiobreaker.CircuitBreakerError:
            raise ServiceUnavailable('CIB circuit open')
        except ServiceUnavailable:
            raise
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f'CIB failed: {scrub_pii(str(e))}')
            raise ServiceUnavailable('CIB unavailable')


class FaceIDClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('Face-ID', base_url, api_key,
                         timeout=kwargs.pop('timeout', 10), **kwargs)

    @retry(stop=stop_after_attempt(2),
           wait=wait_exponential(multiplier=1, min=1, max=3),
           retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
           reraise=True)
    async def _do_verify(self, face_image: str, passport_sn: str) -> Dict:
        r = await self._call('POST', '/api/verify',
                             json={'image': face_image, 'passport': passport_sn})
        return r.json()

    async def verify(self, face_image: str, passport_sn: str) -> bool:
        try:
            data = await self._do_verify(face_image, passport_sn)
            return bool(data.get('verified', False))
        except aiobreaker.CircuitBreakerError:
            raise ServiceUnavailable('Face-ID circuit open')
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f'Face-ID failed: {scrub_pii(str(e))}')
            raise ServiceUnavailable('Face-ID unavailable')


class ABSClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('ABS', base_url, api_key,
                         timeout=kwargs.pop('timeout', 15), **kwargs)

    @retry(stop=stop_after_attempt(2),
           wait=wait_exponential(multiplier=1, min=2, max=5),
           retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
           reraise=True)
    async def _do_create(self, payload: Dict, idem: str) -> Dict:
        if not idem:
            raise ValueError('idempotency_key required')
        r = await self._call('POST', '/api/contracts', json=payload,
                             headers={'X-Idempotency-Key': idem})
        return r.json()

    async def create_contract(self, passport_sn, amount, product,
                              target_iban, target_name, idem) -> str:
        try:
            payload = {
                'passport': passport_sn, 'amount': str(amount),
                'product': product, 'target_iban': target_iban,
                'target_name': target_name,
            }
            data = await self._do_create(payload, idem)
            return data['contract_id']
        except aiobreaker.CircuitBreakerError:
            raise ServiceUnavailable('ABS circuit open')
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f'ABS failed: {scrub_pii(str(e))}')
            raise ServiceUnavailable('ABS unavailable')


class PaymentGatewayClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('Payment', base_url, api_key,
                         timeout=kwargs.pop('timeout', 10),
                         fail_max=kwargs.pop('fail_max', 3), **kwargs)

    @retry(stop=stop_after_attempt(2),
           wait=wait_exponential(multiplier=1, min=1, max=2),
           retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
           reraise=True)
    async def _do_debit(self, payload: Dict, idem: str) -> Dict:
        if not idem:
            raise ValueError('idempotency_key required')
        r = await self._call('POST', '/api/debit', json=payload,
                             headers={'X-Idempotency-Key': idem})
        return r.json()

    async def debit(self, card_token, amount, idem) -> Dict:
        try:
            payload = {'card_token': card_token, 'amount': str(amount),
                       'no_accept': True}
            return await self._do_debit(payload, idem)
        except aiobreaker.CircuitBreakerError:
            raise ServiceUnavailable('Payment circuit open')
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f'Payment failed: {scrub_pii(str(e))}')
            raise ServiceUnavailable('Payment unavailable')

    async def query_debit(self, idem: str) -> Optional[Dict]:
        try:
            r = await self._call('GET', f'/api/debit/status/{idem}')
            return r.json()
        except (aiobreaker.CircuitBreakerError, httpx.RequestError, httpx.HTTPStatusError):
            return None


class SMSClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('SMS', base_url, api_key,
                         timeout=kwargs.pop('timeout', 5),
                         fail_max=kwargs.pop('fail_max', 10), **kwargs)

    async def send(self, phone: str, message: str) -> bool:
        try:
            await self._call('POST', '/api/send',
                             json={'phone': phone, 'message': message})
            return True
        except (aiobreaker.CircuitBreakerError, httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f'SMS failed: {scrub_pii(str(e))}')
            return False


# ============================================================================
# CONFIG / КОНФИГУРАТСИЯ
# ============================================================================
class Config:
    ENV = os.environ.get('ENV', 'production')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 5432))
    DB_NAME = os.environ.get('DB_NAME', 'bank_db')
    DB_USER = os.environ.get('DB_USER', 'bank_user')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')
    DB_POOL_MIN = int(os.environ.get('DB_POOL_MIN', 2))
    DB_POOL_MAX = int(os.environ.get('DB_POOL_MAX', 20))
    DB_CONNECT_TIMEOUT = int(os.environ.get('DB_CONNECT_TIMEOUT', 10))
    DB_RETRY_MAX = int(os.environ.get('DB_RETRY_MAX', 3))
    GUARANTOR_TTL_HOURS = 24
    OTP_TTL_MINUTES = 10
    OTP_MAX_ATTEMPTS = 3
    OTP_MAX_RESENDS = 3
    OTP_RESEND_COOLDOWN_SEC = 60
    OTP_RATE_LIMIT_PER_HOUR = 10
    RATE_LIMIT_PER_HOUR = int(os.environ.get('RATE_LIMIT_PER_HOUR', 5))
    MIN_AGE_YEARS = 18
    AUTO_DEBIT_MAX_ATTEMPTS = 3
    AUTO_DEBIT_RETRY_HOURS = 24
    AUTO_DEBIT_SCAN_INTERVAL_SEC = 3600
    AUTO_DEBIT_STUCK_THRESHOLD_SEC = 3600
    AUTO_DEBIT_RECOVERY_THRESHOLD_SEC = 600
    TTL_SCAN_INTERVAL_SEC = 600
    OVERDUE_SCAN_INTERVAL_SEC = 3600
    CLEANUP_SCAN_INTERVAL_SEC = 3600
    THREAD_POOL_WORKERS = int(os.environ.get('THREAD_POOL_WORKERS', 64))
    LEADER_ELECTION_ENABLED = (
        os.environ.get('LEADER_ELECTION_ENABLED', 'true').lower() == 'true'
    )
    TRUSTED_PROXY_IPS: Set[str] = set(
        ip.strip() for ip in
        os.environ.get('TRUSTED_PROXY_IPS', '').split(',')
        if ip.strip()
    )

    REQUIRED_ENV = (
        'DB_PASSWORD', 'API_KEY',
        'CIB_URL', 'CIB_API_KEY',
        'FACE_ID_URL', 'FACE_ID_API_KEY',
        'ABS_URL', 'ABS_API_KEY',
        'PAYMENT_URL', 'PAYMENT_API_KEY',
        'SMS_URL', 'SMS_API_KEY',
        'CARD_SIGNATURE_KEY_HEX',
    )

    @classmethod
    def validate(cls):
        missing = [v for v in cls.REQUIRED_ENV if not os.environ.get(v)]
        if missing:
            raise ValueError(f'Missing required env vars: {missing}')
        if cls.MIN_AGE_YEARS < 18:
            raise ValueError('MIN_AGE_YEARS must be >= 18')
        if cls.DB_RETRY_MAX < 1:
            raise ValueError('DB_RETRY_MAX must be >= 1')
        if cls.DB_POOL_MAX < cls.DB_POOL_MIN:
            raise ValueError('DB_POOL_MAX must be >= DB_POOL_MIN')
        sig_key = os.environ.get('CARD_SIGNATURE_KEY_HEX', '')
        if len(sig_key) != 64:
            raise ValueError('CARD_SIGNATURE_KEY_HEX must be 64 hex chars')

        if cls.ENV == 'production':
            api_key = os.environ.get('API_KEY', '')
            if len(api_key) < 32:
                raise ValueError(
                    'API_KEY must be at least 32 characters in production')

            internal_api_key = os.environ.get('INTERNAL_API_KEY', '')
            if not internal_api_key:
                raise ValueError(
                    'INTERNAL_API_KEY is required in production')
            if internal_api_key == api_key:
                raise ValueError(
                    'INTERNAL_API_KEY must differ from API_KEY')
            if len(internal_api_key) < 32:
                raise ValueError(
                    'INTERNAL_API_KEY must be at least 32 characters')

            for path_var in ('INTERNAL_CLIENT_CERT', 'INTERNAL_CLIENT_KEY',
                             'INTERNAL_CA_CERT'):
                path = os.environ.get(path_var)
                if not path:
                    raise ValueError(
                        f'{path_var} is required in production (mTLS)')
                if not os.path.isfile(path):
                    raise ValueError(
                        f'{path_var} file not found: {path}')

            if not cls.TRUSTED_PROXY_IPS:
                logger.warning(
                    'TRUSTED_PROXY_IPS is empty — '
                    'X-Forwarded-For will be ignored')


class DatabasePool:
    def __init__(self, config):
        self._config = config
        self._pool = None

    def initialize(self):
        self._pool = pool.ThreadedConnectionPool(
            minconn=self._config.DB_POOL_MIN,
            maxconn=self._config.DB_POOL_MAX,
            host=self._config.DB_HOST, port=self._config.DB_PORT,
            database=self._config.DB_NAME, user=self._config.DB_USER,
            password=self._config.DB_PASSWORD,
            connect_timeout=self._config.DB_CONNECT_TIMEOUT,
            application_name='credit_engine',
            options='-c statement_timeout=30000')
        logger.info('Database pool initialized')

    @contextmanager
    def get_connection(self):
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            try:
                conn.rollback()
            except Exception:
                pass
            self._pool.putconn(conn)

    @contextmanager
    def transaction(self):
        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def close_all(self):
        if self._pool:
            self._pool.closeall()
            logger.info('Database pool closed')


# ============================================================================
# EXCEPTIONS / ИСТИСНОҲО
# ============================================================================
class GuarantorBusyError(Exception):
    pass


class GuarantorError(Exception):
    pass


class WrongOTPError(GuarantorError):
    pass


class TTLExpiredError(GuarantorError):
    pass


class IdempotencyConflict(Exception):
    pass


class RateLimitError(Exception):
    pass


class OpsRecoveryError(Exception):
    pass


class Product:
    STUDENT_PAY = 'STUDENT_PAY'
    DAILY_PAY = 'DAILY_PAY'
    RENT_PAY = 'RENT_PAY'


# ============================================================================
# LEADER ELECTION / ИНТИХОБИ ЛИДЕР
# ============================================================================
class LeaderElection:
    BASE_LOCK_ID = 0x5A1D3F0C7B2E4A00

    def __init__(self, db_pool, name: str, slot: int, enabled: bool = True):
        self.db = db_pool
        self.name = name
        self.slot = slot
        self.enabled = enabled
        self.lock_id = self.BASE_LOCK_ID + slot
        self._is_leader = not enabled
        self._lock_conn = None

    def try_acquire(self) -> bool:
        if not self.enabled:
            return True
        if self._is_leader and self._check_alive():
            return True
        if self._is_leader and not self._check_alive():
            self._release()
        try:
            conn = self.db._pool.getconn()
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'SELECT pg_try_advisory_lock(%s) AS acquired',
                    (self.lock_id,))
                row = cursor.fetchone()
                acquired = bool(row and row[0])
            finally:
                cursor.close()
            if acquired:
                self._lock_conn = conn
                self._is_leader = True
                logger.info(f'Leader elected: {self.name}')
                return True
            self.db._pool.putconn(conn)
            self._is_leader = False
            return False
        except Exception as e:
            logger.warning(
                f'Leader election error [{self.name}]: {scrub_pii(str(e))}')
            self._is_leader = False
            return False

    def _check_alive(self) -> bool:
        if self._lock_conn is None:
            return False
        try:
            cursor = self._lock_conn.cursor()
            try:
                cursor.execute('SELECT 1')
                cursor.fetchone()
            finally:
                cursor.close()
            return True
        except Exception:
            self._release()
            return False

    def _release(self):
        if self._lock_conn is not None:
            try:
                self.db._pool.putconn(self._lock_conn)
            except Exception:
                pass
            self._lock_conn = None
        if self._is_leader:
            logger.info(f'Leader released: {self.name}')
        self._is_leader = False

    def release(self):
        if self._lock_conn is not None:
            try:
                cursor = self._lock_conn.cursor()
                try:
                    cursor.execute(
                        'SELECT pg_advisory_unlock(%s)', (self.lock_id,))
                finally:
                    cursor.close()
            except Exception:
                pass
        self._release()

    @property
    def is_leader(self) -> bool:
        return self._is_leader


# ============================================================================
# CREDIT ENGINE / МОҲИЯТИ ҚАРЗДИҲӢ (v3.8.1)
# ============================================================================
class CreditEngine:
    def __init__(self, db_pool, crypto, cib_client, face_client,
                 abs_client, payment_client, sms_client):
        self.db = db_pool
        self.crypto = crypto
        self.cib = cib_client
        self.face = face_client
        self.abs = abs_client
        self.payment = payment_client
        self.sms = sms_client
        self._bg_tasks: Set[asyncio.Task] = set()
        self._auto_debit_task: Optional[asyncio.Task] = None
        self._ttl_task: Optional[asyncio.Task] = None
        self._overdue_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._config_cache: Dict[str, Dict] = {}
        self._config_cache_ts: float = 0.0
        self._config_cache_ttl: float = 60.0

        self._leader_auto_debit = LeaderElection(
            db_pool, 'auto_debit', slot=1,
            enabled=Config.LEADER_ELECTION_ENABLED)
        self._leader_ttl = LeaderElection(
            db_pool, 'ttl_expiry', slot=2,
            enabled=Config.LEADER_ELECTION_ENABLED)
        self._leader_overdue = LeaderElection(
            db_pool, 'overdue', slot=3,
            enabled=Config.LEADER_ELECTION_ENABLED)
        self._leader_cleanup = LeaderElection(
            db_pool, 'cleanup', slot=4,
            enabled=Config.LEADER_ELECTION_ENABLED)

    @staticmethod
    def money_round(val) -> Decimal:
        return Decimal(str(val)).quantize(
            Decimal('0.01'), rounding=ROUND_HALF_UP)

    async def _db_call_with_retry(self, fn, *args, **kwargs):
        last_exc = None
        for attempt in range(Config.DB_RETRY_MAX):
            try:
                return await asyncio.to_thread(fn, *args, **kwargs)
            except OperationalError as e:
                last_exc = e
                if attempt == Config.DB_RETRY_MAX - 1:
                    logger.error(
                        f'DB OperationalError after '
                        f'{Config.DB_RETRY_MAX} attempts: '
                        f'{scrub_pii(str(e))}')
                    raise
                wait = 0.5 * (2 ** attempt)
                logger.warning(
                    f'DB OperationalError (attempt {attempt+1}), '
                    f'retry in {wait}s')
                await asyncio.sleep(wait)
        if last_exc:
            raise last_exc

    # ------------------------------------------------------------------------
    # product_config
    # ------------------------------------------------------------------------
    def _fetch_product_configs_sync(self) -> List[Tuple]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT product_type, min_amount, max_amount,
                           no_guarantor_limit, commission_rate,
                           insurance_rate, transfer_comm_rate,
                           term_months, pti_max_ratio,
                           grace_days, daily_penalty_rate, interest_rate,
                           term_days
                    FROM product_config
                """)
                return cursor.fetchall()
            finally:
                cursor.close()

    async def _load_product_config(self, product: str) -> Optional[Dict]:
        now = time.time()
        if (now - self._config_cache_ts) < self._config_cache_ttl:
            return self._config_cache.get(product)
        rows = await self._db_call_with_retry(self._fetch_product_configs_sync)
        cache = {}
        for r in rows:
            cache[r[0]] = {
                'min_amount': Decimal(str(r[1])),
                'max_amount': Decimal(str(r[2])),
                'no_guarantor_limit': Decimal(str(r[3])),
                'commission_rate': Decimal(str(r[4])),
                'insurance_rate': Decimal(str(r[5])),
                'transfer_comm_rate': Decimal(str(r[6])),
                'term_months': int(r[7]) if r[7] is not None else 0,
                'pti_max_ratio': Decimal(str(r[8])),
                'grace_days': int(r[9]) if len(r) > 9 and r[9] is not None else 0,
                'daily_penalty_rate': (
                    Decimal(str(r[10])) if len(r) > 10 and r[10] is not None
                    else Decimal('0')),
                'interest_rate': (
                    Decimal(str(r[11])) if len(r) > 11 and r[11] is not None
                    else Decimal('0')),
                'term_days': int(r[12]) if len(r) > 12 and r[12] is not None else 0,
            }
        self._config_cache = cache
        self._config_cache_ts = time.time()
        return cache.get(product)

    @staticmethod
    def _iban_format_ok(iban: str) -> bool:
        iban = iban.replace(' ', '').upper()
        if len(iban) < 15 or len(iban) > 34:
            return False
        if not iban[:2].isalpha() or not iban[2:4].isdigit():
            return False
        if not iban[4:].isalnum():
            return False
        rearranged = iban[4:] + iban[:4]
        converted = ''.join(str(int(c, 36)) for c in rearranged)
        try:
            return int(converted) % 97 == 1
        except Exception:
            return False

    def _validate_product_requirements(self, product_type, extra_data):
        if product_type == Product.RENT_PAY:
            iban = extra_data.get('landlord_iban', '')
            if not iban:
                return False, 'Landlord IBAN required.'
            if not self._iban_format_ok(iban):
                return False, 'Invalid landlord IBAN format.'
        elif product_type == Product.STUDENT_PAY:
            iban = extra_data.get('university_iban', '')
            if not iban:
                return False, 'University IBAN required.'
            if not self._iban_format_ok(iban):
                return False, 'Invalid university IBAN format.'
        elif product_type == Product.DAILY_PAY:
            iban = extra_data.get('self_iban')
            if iban and not self._iban_format_ok(iban):
                return False, 'Invalid self IBAN format.'
        return True, ''

    def _check_pti(self, user_income, guarantor_income, monthly_payment, max_ratio):
        total_income = (Decimal(str(user_income or 0)) + Decimal(str(guarantor_income or 0)))
        if total_income <= Decimal('0'):
            return False, 'Total income insufficient.'
        pti = (Decimal(str(monthly_payment)) / total_income).quantize(
            Decimal('0.0001'), rounding=ROUND_HALF_UP)
        if pti > max_ratio:
            return False, f'PTI {pti:.2%} exceeds {max_ratio:.0%}'
        return True, ''

    async def process_loan_application(
        self, passport_sn, face_id_data, guarantor_phone,
        product_type, amount_val, user_phone, date_of_birth,
        relation_type=None, extra_data=None, request_id=None,
    ):
        start = time.time()
        amount = Decimal(str(amount_val))
        extra_data = extra_data or {}
        request_id = request_id or str(uuid.uuid4())

        logger.info('Processing loan', extra={
            'product': product_type, 'amount': float(amount), 'request_id': request_id})

        try:
            dob = (date.fromisoformat(date_of_birth)
                   if isinstance(date_of_birth, str) else date_of_birth)
        except Exception:
            return self._error('E1012', 'Invalid date of birth.', 400)
        age = (date.today() - dob).days // 365
        if age < Config.MIN_AGE_YEARS:
            return self._error('E1012', f'Age must be >= {Config.MIN_AGE_YEARS}.', 400)

        cfg = await self._load_product_config(product_type)
        if not cfg:
            return self._error('E1001', 'Unknown product.', 400)
        if not (cfg['min_amount'] <= amount <= cfg['max_amount']):
            return self._error('E1001',
                f"Amount must be {cfg['min_amount']}-{cfg['max_amount']} TJS.", 400)

        valid, err = self._validate_product_requirements(product_type, extra_data)
        if not valid:
            return self._error('E1006', err, 400)

        passport_hmac = self.crypto.blind_index(passport_sn)

        try:
            application_id = await self._db_call_with_retry(
                self._stage1_create_pending,
                passport_hmac, product_type, amount, request_id)
            if application_id is None:
                return self._error('E1010', 'Too many requests.', 429)
            if isinstance(application_id, dict):
                return application_id
        except IntegrityError:
            logger.warning(f'Idempotency race: {request_id}')
            return self._error('E0002', 'Duplicate request.', 409)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Stage 1 failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

        stage2 = await self._run_face_and_cib(passport_sn, face_id_data, amount)
        if stage2['status'] != 'OK':
            if stage2['status'] == 'REJECTED':
                await self._db_call_with_retry(
                    self._mark_status, application_id,
                    stage2['reason_code'], passport_hmac, stage2['reason'])
                return stage2['response']
            await self._db_call_with_retry(
                self._mark_error, application_id, 'ERROR_EXTERNAL',
                'external service unavailable')
            return stage2['response']

        try:
            abs_id = await self._call_abs(
                passport_sn, amount, product_type, extra_data, request_id)
        except ServiceUnavailable as e:
            logger.error(f'Stage 3 ABS failed: {scrub_pii(str(e))}')
            await self._db_call_with_retry(
                self._mark_error, application_id, 'ABS_FAILED', 'ABS unavailable')
            return self._error('E2001', 'ABS unavailable.', 503)

        try:
            result = await self._db_call_with_retry(
                self._stage4_finalize,
                application_id, passport_sn, passport_hmac,
                amount, product_type, user_phone, guarantor_phone,
                relation_type, dob, extra_data, abs_id,
                stage2['cib_result'], cfg)
            logger.info(f'Done: app_id={application_id}, '
                        f'status={result.get("status")}, '
                        f'duration={time.time() - start:.2f}s')
        except GuarantorBusyError:
            await self._db_call_with_retry(
                self._mark_error, application_id, 'ERROR_PHASE3', 'guarantor busy')
            return self._error('E1011', 'Guarantor already has an active guarantee.', 409)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except DataError as e:
            logger.error(f'DataError: {scrub_pii(str(e))}')
            return self._error('E2004', 'Invalid data format.', 400)
        except Exception as e:
            logger.exception(f'Stage 4 failed: {scrub_pii(str(e))}')
            await self._db_call_with_retry(
                self._mark_error, application_id, 'ERROR_PHASE3', 'stage4 failure')
            return self._error('E2002', 'Database error.', 500)

        if result.get('_notify_phone'):
            phone = result.pop('_notify_phone')
            otp = result.pop('_otp_code', None)
            ag_id = result.pop('_app_guarantor_id', None)
            if otp and ag_id:
                msg = f'Credit guarantee request. OTP: {otp}'
                task = asyncio.create_task(self._deliver_otp_sms(phone, msg, ag_id))
                self._bg_tasks.add(task)
                task.add_done_callback(self._bg_tasks.discard)

        return result

    def _stage1_create_pending(self, passport_hmac, product_type, amount, request_id):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT id FROM applications WHERE request_id = %s', (request_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'code': 'E0002', 'status': 'DUPLICATE',
                        'application_id': row[0],
                        'reason': 'Request already processed.',
                        'http_status': 409,
                    }
                lock_key = int(passport_hmac[:15], 16) & 0x7FFFFFFFFFFFFFFF
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', (lock_key,))
                cursor.execute(
                    "SELECT COUNT(*) FROM applications WHERE passport_sn_hmac = %s "
                    "AND created_at > NOW() - INTERVAL '1 hour'", (passport_hmac,))
                count = cursor.fetchone()[0]
                if count >= Config.RATE_LIMIT_PER_HOUR:
                    return None
                now = datetime.now(timezone.utc)
                cursor.execute(
                    "INSERT INTO applications (passport_sn_hmac, product_type, amount, "
                    "status, request_id, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (passport_hmac, product_type, str(amount),
                     'PENDING_CHECKS', request_id, now, now))
                return cursor.fetchone()[0]
            finally:
                cursor.close()

    async def _run_face_and_cib(self, passport_sn, face_id_data, amount):
        try:
            if not await self.face.verify(face_id_data, passport_sn):
                return self._reject('E1008', 'BIOMETRIC_FAILED', 'Biometric verification failed.')
        except ServiceUnavailable:
            return self._ext_error('Face-ID unavailable')

        try:
            cib_score, cib_limit = await self.cib.check(passport_sn)
            if cib_score < 500:
                return self._reject('E1009', 'CIB_REJECTED', f'CIB score too low: {cib_score}')
        except ServiceUnavailable:
            return self._ext_error('CIB unavailable')

        return {'status': 'OK', 'cib_result': {'score': cib_score, 'limit': cib_limit}}

    async def _call_abs(self, passport_sn, amount, product_type, extra_data, request_id):
        idem = self.crypto.idempotency_key(request_id, 'abs')
        if product_type == Product.RENT_PAY:
            iban = extra_data.get('landlord_iban')
            name = extra_data.get('landlord_name', 'Landlord')
        elif product_type == Product.STUDENT_PAY:
            iban = extra_data.get('university_iban')
            name = extra_data.get('university_name', 'University')
        else:
            iban = extra_data.get('self_iban', '')
            name = 'Customer'
        return await self.abs.create_contract(
            passport_sn, amount, product_type, iban, name, idem)

    def _fail_app(self, conn, app_id, passport_hmac, err_dict):
        hs = err_dict.get('http_status', 500)
        if 400 <= hs < 500:
            reason = err_dict.get('reason', '')
            self._update_status(conn, app_id, 'REJECTED', reason)
            self._cancel_pending_loan(conn, app_id, reason)
            self._audit(conn, 'APP_REJECTED', app_id, passport_hmac, reason)
        return err_dict

    def _cancel_pending_loan(self, conn, app_id, reason):
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE loan_disbursements SET status = 'CANCELLED'::loan_status_enum, "
                "cancelled_at = NOW(), cancellation_reason = %s, closed_at = NOW() "
                "WHERE application_id = %s AND status = 'PENDING_DISBURSEMENT'",
                (scrub_pii(str(reason))[:500], app_id))
            if cursor.rowcount > 0:
                logger.info(f'Cancelled pending loan for app_id={app_id}: {reason}')
        finally:
            cursor.close()

    def _stage4_finalize(self, app_id, passport_sn, passport_hmac,
                          amount, product_type, user_phone, guarantor_phone,
                          relation_type, dob, extra_data, abs_id, cib_result, cfg):
        with self.db.transaction() as conn:
            lock_key = int(passport_hmac[:15], 16) & 0x7FFFFFFFFFFFFFFF
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', (lock_key,))
            finally:
                cursor.close()

            user_id = self._upsert_user(
                conn, passport_sn, passport_hmac, user_phone,
                dob, cib_result['score'], cib_result['limit'])

            cursor = conn.cursor()
            try:
                cursor.execute('UPDATE applications SET user_id = %s WHERE id = %s',
                               (user_id, app_id))
            finally:
                cursor.close()

            if self._is_user_blocked(conn, user_id):
                return self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1015', 'User is blocked. Contact support.', 403))

            if self._has_active_loan(conn, passport_hmac):
                return self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1013', 'User already has an active loan.', 409))

            user = self._find_user_by_id(conn, user_id)
            user_income = user['monthly_income'] if user else Decimal('0')

            if product_type == Product.RENT_PAY:
                result = self._finalize_rent_pay(
                    conn, app_id, passport_sn, passport_hmac, amount,
                    user_id, user_income, guarantor_phone, relation_type,
                    extra_data, abs_id, cfg)
            elif product_type == Product.STUDENT_PAY:
                result = self._finalize_student_pay(
                    conn, app_id, passport_sn, passport_hmac, amount,
                    user_id, user_income, guarantor_phone, relation_type,
                    extra_data, abs_id, cfg)
            elif product_type == Product.DAILY_PAY:
                result = self._finalize_daily_pay(
                    conn, app_id, passport_sn, passport_hmac, amount,
                    user_id, user_income, guarantor_phone, relation_type,
                    extra_data, abs_id, cfg)
            else:
                return self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1002', 'Unknown product.', 400))

            if (isinstance(result, dict) and result.get('http_status', 200) >= 400):
                self._fail_app(conn, app_id, passport_hmac, result)
            return result

    # ------------------------------------------------------------------------
    # RentPay: 15 РӮЗ, 8% комиссия, ФОИЗИ ИЛОВАГӢ НЕСТ
    # ------------------------------------------------------------------------
    def _finalize_rent_pay(self, conn, app_id, passport_sn, passport_hmac,
                            amount, user_id, user_income, guarantor_phone,
                            relation_type, extra_data, abs_id, cfg):
        if not guarantor_phone:
            return self._error('E1003', 'Guarantor required for RentPay.', 400)
        guarantor = self._find_user_by_phone(conn, guarantor_phone, for_update=True)
        if not guarantor:
            return self._error('E1004', 'Guarantor not found.', 404)
        if guarantor['id'] == user_id:
            return self._error('E1014', 'Guarantor cannot be the same as user.', 400)
        if guarantor['turnover'] < Decimal('1000'):
            return self._error('E1005', 'Guarantor turnover insufficient.', 400)

        pti_ok, pti_err = self._check_pti(
            user_income, guarantor['monthly_income'], amount, cfg['pti_max_ratio'])
        if not pti_ok:
            return self._error('E1007', pti_err, 400)

        landlord_iban = extra_data.get('landlord_iban')
        # RentPay: 8% комиссияи яквақтаина, ФОИЗИ ИЛОВАГӢ НЕСТ
        commission = self.money_round(amount * cfg['commission_rate'])
        net = self.money_round(amount - commission)

        loan_id = self._create_loan(
            conn, app_id, passport_hmac, guarantor['id'], amount,
            commission, net, abs_id, 'RENT_PAY', 'LANDLORD', landlord_iban,
            extra_data.get('landlord_name', 'Landlord'))
        # RentPay = 15 рӯз (аз product_config)
        rent_days = cfg.get('term_days') or 15
        self._create_repayment_schedule(conn, loan_id, amount, days=rent_days)
        ag_id, otp = self._create_guarantee(
            conn, app_id, guarantor['id'], guarantor_phone, relation_type)
        self._update_status(conn, app_id, 'PENDING_GUARANTOR')
        self._audit(conn, 'RENT_PAY_PENDING', app_id, passport_hmac,
                    f'Amount={amount} days={rent_days}')

        return {
            'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
            'application_id': app_id, 'loan_id': loan_id,
            'commission': str(commission), 'net': str(net),
            'target_iban': landlord_iban, 'abs_contract_id': abs_id,
            'guarantor_id': ag_id, 'term_days': rent_days,
            'interest_rate': '0', 'http_status': 200,
            '_notify_phone': guarantor_phone,
            '_otp_code': otp, '_app_guarantor_id': ag_id,
        }

    def _finalize_student_pay(self, conn, app_id, passport_sn, passport_hmac,
                               amount, user_id, user_income, guarantor_phone,
                               relation_type, extra_data, abs_id, cfg):
        if not guarantor_phone:
            return self._error('E1003', 'Guarantor required for StudentPay.', 400)
        guarantor = self._find_user_by_phone(conn, guarantor_phone, for_update=True)
        if not guarantor:
            return self._error('E1004', 'Guarantor not found.', 404)
        if guarantor['id'] == user_id:
            return self._error('E1014', 'Guarantor cannot be the same as user.', 400)

        insurance = self.money_round(amount * cfg['insurance_rate'])
        margin = self.money_round(insurance * Decimal('0.50'))
        comm = self.money_round(amount * cfg['transfer_comm_rate'])
        interest = self.money_round(amount * cfg['interest_rate'])
        net = self.money_round(amount - comm)
        total = self.money_round(amount + insurance + interest)
        months = cfg.get('term_months') or 10
        monthly = self.money_round(total / Decimal(str(months)))

        pti_ok, pti_err = self._check_pti(
            user_income, guarantor['monthly_income'], monthly, cfg['pti_max_ratio'])
        if not pti_ok:
            return self._error('E1007', pti_err, 400)

        university_iban = extra_data.get('university_iban')
        self._create_insurance(conn, app_id, passport_hmac, insurance, margin, interest)
        loan_id = self._create_loan(
            conn, app_id, passport_hmac, guarantor['id'], amount,
            comm, net, abs_id, 'STUDENT_PAY', 'UNIVERSITY', university_iban,
            extra_data.get('university_name', 'University'))
        # StudentPay = 10 моҳ
        self._create_repayment_schedule(conn, loan_id, total, months=months)
        ag_id, otp = self._create_guarantee(
            conn, app_id, guarantor['id'], guarantor_phone, relation_type)
        self._update_status(conn, app_id, 'PENDING_GUARANTOR')
        self._audit(conn, 'STUDENT_PAY_PENDING', app_id, passport_hmac, f'Amount={amount}')

        return {
            'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
            'application_id': app_id, 'loan_id': loan_id,
            'gross_loan': str(total), 'insurance': str(insurance),
            'interest': str(interest),
            'transfer_commission': str(comm), 'net_transferred': str(net),
            'target_iban': university_iban, 'abs_contract_id': abs_id,
            'guarantor_id': ag_id, 'http_status': 200,
            '_notify_phone': guarantor_phone,
            '_otp_code': otp, '_app_guarantor_id': ag_id,
        }

    # ------------------------------------------------------------------------
    # DailyPay: 7 РӮЗ, 4% комиссия, ФОИЗИ ИЛОВАГӢ НЕСТ
    # ------------------------------------------------------------------------
    def _finalize_daily_pay(self, conn, app_id, passport_sn, passport_hmac,
                             amount, user_id, user_income, guarantor_phone,
                             relation_type, extra_data, abs_id, cfg):
        target_iban = extra_data.get('self_iban', '')
        commission = self.money_round(amount * cfg['commission_rate'])
        net = self.money_round(amount - commission)
        # DailyPay = 7 рӯз (аз product_config)
        daily_days = cfg.get('term_days') or 7

        if amount > cfg['no_guarantor_limit']:
            if not guarantor_phone:
                return self._error('E1003',
                    f'Amount > {cfg["no_guarantor_limit"]} requires guarantor.', 400)
            guarantor = self._find_user_by_phone(conn, guarantor_phone, for_update=True)
            if not guarantor:
                return self._error('E1004', 'Guarantor not found.', 404)
            if guarantor['id'] == user_id:
                return self._error('E1014', 'Guarantor cannot be the same as user.', 400)

            pti_ok, pti_err = self._check_pti(
                user_income, guarantor['monthly_income'], amount, cfg['pti_max_ratio'])
            if not pti_ok:
                return self._error('E1007', pti_err, 400)

            loan_id = self._create_loan(
                conn, app_id, passport_hmac, guarantor['id'], amount,
                commission, net, abs_id, 'DAILY_PAY', 'SELF',
                target_iban, 'Customer')
            self._create_repayment_schedule(
                conn, loan_id, amount, days=daily_days)
            ag_id, otp = self._create_guarantee(
                conn, app_id, guarantor['id'], guarantor_phone, relation_type)
            self._update_status(conn, app_id, 'PENDING_GUARANTOR')
            self._audit(conn, 'DAILY_PAY_PENDING', app_id, passport_hmac,
                        f'Amount={amount} days={daily_days}')
            return {
                'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
                'application_id': app_id, 'loan_id': loan_id,
                'commission': str(commission), 'net': str(net),
                'abs_contract_id': abs_id, 'guarantor_id': ag_id,
                'term_days': daily_days, 'http_status': 200,
                '_notify_phone': guarantor_phone,
                '_otp_code': otp, '_app_guarantor_id': ag_id,
            }

        if user_income > Decimal('0'):
            pti_ok, pti_err = self._check_pti(
                user_income, Decimal('0'), amount, cfg['pti_max_ratio'])
            if not pti_ok:
                return self._error('E1007', pti_err, 400)

        loan_id = self._create_loan(
            conn, app_id, passport_hmac, None, amount, commission,
            net, abs_id, 'DAILY_PAY', 'SELF', target_iban, 'Customer')
        self._create_repayment_schedule(
            conn, loan_id, amount, days=daily_days)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE loan_disbursements SET status='ACTIVE', "
                "disbursed_at=NOW() WHERE id=%s", (loan_id,))
        finally:
            cursor.close()
        self._update_status(conn, app_id, 'APPROVED')
        self._audit(conn, 'DAILY_PAY_APPROVED', app_id, passport_hmac,
                    f'Amount={amount} days={daily_days}')
        return {
            'code': 'E0000', 'status': 'APPROVED',
            'application_id': app_id, 'loan_id': loan_id,
            'gross_loan': str(amount),
            'commission': str(commission), 'net': str(net),
            'abs_contract_id': abs_id, 'term_days': daily_days,
            'http_status': 200,
        }

    def _upsert_user(self, conn, passport_sn, passport_hmac, phone,
                      date_of_birth, cib_score, cib_limit):
        phone_hmac = self.crypto.blind_index(phone)
        enc_passport = self.crypto.encrypt(passport_sn, aad=f'passport:{passport_hmac}')
        enc_phone = self.crypto.encrypt(phone, aad=f'phone:{phone_hmac}')
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (passport_sn_hmac, passport_sn_encrypted,
                     phone_hmac, phone_encrypted, date_of_birth,
                     cib_score, approved_limit, cib_checked_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (passport_sn_hmac) DO UPDATE SET
                    phone_hmac = EXCLUDED.phone_hmac,
                    phone_encrypted = EXCLUDED.phone_encrypted,
                    date_of_birth = COALESCE(EXCLUDED.date_of_birth, users.date_of_birth),
                    cib_score = EXCLUDED.cib_score,
                    approved_limit = EXCLUDED.approved_limit,
                    cib_checked_at = EXCLUDED.cib_checked_at
                RETURNING id
                """,
                (passport_hmac, enc_passport, phone_hmac, enc_phone,
                 date_of_birth, cib_score, str(cib_limit),
                 datetime.now(timezone.utc)))
            return cursor.fetchone()[0]
        finally:
            cursor.close()

    def _is_user_blocked(self, conn, user_id) -> bool:
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT is_blocked FROM users WHERE id = %s', (user_id,))
            row = cursor.fetchone()
            return bool(row and row[0])
        finally:
            cursor.close()

    def _has_active_loan(self, conn, passport_hmac) -> bool:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM loan_disbursements "
                "WHERE passport_sn_hmac = %s "
                "AND status IN ('ACTIVE','PENDING_DISBURSEMENT')", (passport_hmac,))
            return cursor.fetchone()[0] > 0
        finally:
            cursor.close()

    def _find_user_by_id(self, conn, user_id):
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT id, card_turnover_3m, monthly_income '
                           'FROM users WHERE id = %s', (user_id,))
            row = cursor.fetchone()
            if row:
                return {'id': row[0],
                        'turnover': Decimal(str(row[1] or 0)),
                        'monthly_income': Decimal(str(row[2] or 0))}
            return None
        finally:
            cursor.close()

    def _find_user_by_phone(self, conn, phone, for_update=False):
        if not phone:
            return None
        phone_hmac = self.crypto.blind_index(phone)
        cursor = conn.cursor()
        try:
            query = ('SELECT id, card_turnover_3m, monthly_income '
                     'FROM users WHERE phone_hmac = %s')
            if for_update:
                query += ' FOR UPDATE'
            cursor.execute(query, (phone_hmac,))
            row = cursor.fetchone()
            if row:
                return {'id': row[0],
                        'turnover': Decimal(str(row[1] or 0)),
                        'monthly_income': Decimal(str(row[2] or 0))}
            return None
        finally:
            cursor.close()

    def _get_guarantor_phone_sync(self, app_guarantor_id: int) -> Optional[str]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT u.phone_encrypted, u.phone_hmac "
                    "FROM application_guarantors ag "
                    "JOIN users u ON u.id = ag.guarantor_user_id "
                    "WHERE ag.id = %s", (app_guarantor_id,))
                row = cursor.fetchone()
                if not row or not row[0]:
                    return None
                return self.crypto.decrypt(row[0], aad=f'phone:{row[1]}')
            except Exception as e:
                logger.warning(f'Phone decrypt failed for ag_id={app_guarantor_id}: {scrub_pii(str(e))}')
                return None
            finally:
                cursor.close()

    # ------------------------------------------------------------------------
    # ИСЛОҲ: Гирифтани phone_hmac ва passport_hmac-и КАФИЛ
    # ------------------------------------------------------------------------
    def _get_guarantor_phone_hmac_sync(self, app_guarantor_id: int) -> Optional[str]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT phone_hmac FROM application_guarantors WHERE id = %s",
                    (app_guarantor_id,))
                row = cursor.fetchone()
                return row[0] if row else None
            finally:
                cursor.close()

    def _get_guarantor_passport_hmac_sync(self, app_guarantor_id: int) -> Optional[str]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT u.passport_sn_hmac
                    FROM application_guarantors ag
                    JOIN users u ON u.id = ag.guarantor_user_id
                    WHERE ag.id = %s
                    """, (app_guarantor_id,))
                row = cursor.fetchone()
                return row[0] if row else None
            finally:
                cursor.close()

    def _create_guarantee(self, conn, app_id, guarantor_user_id,
                           guarantor_phone, relation_type):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=Config.GUARANTOR_TTL_HOURS)
        otp_expires = now + timedelta(minutes=Config.OTP_TTL_MINUTES)
        phone_hmac = (self.crypto.blind_index(guarantor_phone)
                      if guarantor_phone else None)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO guarantors (user_id, phone_hmac, relation_default)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE
                    SET phone_hmac = EXCLUDED.phone_hmac,
                        relation_default = COALESCE(EXCLUDED.relation_default,
                                                    guarantors.relation_default)
                """, (guarantor_user_id, phone_hmac, relation_type))

            cursor.execute(
                "SELECT active_guarantee_id FROM guarantors WHERE user_id = %s FOR UPDATE",
                (guarantor_user_id,))
            row = cursor.fetchone()
            if row is None:
                raise GuarantorBusyError('Guarantor profile not found')
            if row[0] is not None:
                raise GuarantorBusyError(f'Guarantor already has active guarantee id={row[0]}')

            otp_code = f'{int.from_bytes(os.urandom(3), "big") % 1000000:06d}'

            cursor.execute("""
                INSERT INTO application_guarantors
                    (application_id, guarantor_user_id, relation_type,
                     phone_hmac, approval_status, otp_expires_at,
                     otp_last_sent_at, otp_send_count, ttl_expires_at)
                VALUES (%s, %s, %s, %s, 'PENDING', %s, %s, 1, %s)
                RETURNING id
                """, (app_id, guarantor_user_id, relation_type,
                      phone_hmac, otp_expires, now, expires))
            app_guarantor_id = cursor.fetchone()[0]

            otp_hash = self.crypto.otp_hash(otp_code, app_guarantor_id)
            cursor.execute(
                "UPDATE application_guarantors SET otp_code_hash = %s WHERE id = %s",
                (otp_hash, app_guarantor_id))
            cursor.execute(
                "UPDATE guarantors SET active_guarantee_id = %s, updated_at = %s "
                "WHERE user_id = %s",
                (app_guarantor_id, now, guarantor_user_id))
            cursor.execute(
                "INSERT INTO guarantor_ttl_log (application_id, "
                "application_guarantor_id, sent_at, expires_at, status, "
                "sms_status, sms_attempts) VALUES (%s, %s, %s, %s, 'SENT', 'PENDING', 0)",
                (app_id, app_guarantor_id, now, expires))
            return app_guarantor_id, otp_code
        finally:
            cursor.close()

    def _close_guarantee(self, conn, app_guarantor_id, new_status):
        now = datetime.now(timezone.utc)
        cursor = conn.cursor()
        try:
            if new_status == 'REJECTED':
                cursor.execute("""
                    UPDATE application_guarantors
                    SET approval_status = 'REJECTED', closed_at = %s, rejected_at = %s
                    WHERE id = %s AND approval_status IN ('PENDING', 'APPROVED')
                    RETURNING guarantor_user_id
                    """, (now, now, app_guarantor_id))
            else:
                cursor.execute("""
                    UPDATE application_guarantors
                    SET approval_status = %s, closed_at = %s
                    WHERE id = %s AND approval_status IN ('PENDING', 'APPROVED')
                    RETURNING guarantor_user_id
                    """, (new_status, now, app_guarantor_id))
            row = cursor.fetchone()
            if row is None:
                logger.warning(f'Guarantee {app_guarantor_id} already closed or not found')
                return
            guarantor_user_id = row[0]
            cursor.execute("""
                UPDATE guarantors SET active_guarantee_id = NULL, updated_at = %s
                WHERE user_id = %s AND active_guarantee_id = %s
                """, (now, guarantor_user_id, app_guarantor_id))
            logger.info(f'Guarantee {app_guarantor_id} closed as {new_status}')
        finally:
            cursor.close()

    def _check_otp_rate_limit_sync(self, phone_hmac: str, client_ip: Optional[str]) -> bool:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM otp_rate_limit
                    WHERE phone_hmac = %s AND attempted_at > NOW() - INTERVAL '1 hour'
                    """, (phone_hmac,))
                phone_count = cursor.fetchone()[0]
                if phone_count >= Config.OTP_RATE_LIMIT_PER_HOUR:
                    return False
                if client_ip:
                    cursor.execute("""
                        SELECT COUNT(*) FROM otp_rate_limit
                        WHERE client_ip = %s AND attempted_at > NOW() - INTERVAL '1 hour'
                        """, (client_ip,))
                    ip_count = cursor.fetchone()[0]
                    if ip_count >= Config.OTP_RATE_LIMIT_PER_HOUR:
                        return False
                return True
            finally:
                cursor.close()

    def _record_otp_attempt_sync(self, phone_hmac: str, client_ip: Optional[str], success: bool) -> None:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO otp_rate_limit (phone_hmac, client_ip, success) "
                    "VALUES (%s, %s, %s)", (phone_hmac, client_ip, success))
            finally:
                cursor.close()

    def _cleanup_otp_rate_limit_sync(self) -> int:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM otp_rate_limit WHERE attempted_at < NOW() - INTERVAL '24 hours'")
                return cursor.rowcount
            finally:
                cursor.close()

    # ------------------------------------------------------------------------
    # ИСЛОҲ: signature бо шиносномаи КАФИЛ, на қарзгир
    # ------------------------------------------------------------------------
    def _approve_guarantee_sync(self, app_guarantor_id, otp_code):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT ag.application_id, ag.guarantor_user_id,
                           ag.approval_status, ag.otp_code_hash,
                           ag.otp_expires_at, ag.otp_attempts, ag.ttl_expires_at,
                           u.passport_sn_hmac AS guarantor_passport_hmac
                    FROM application_guarantors ag
                    JOIN users u ON u.id = ag.guarantor_user_id
                    WHERE ag.id = %s FOR UPDATE
                    """, (app_guarantor_id,))
                row = cursor.fetchone()
                if not row:
                    raise GuarantorError('Guarantee not found')

                (app_id, g_user_id, status, otp_hash, otp_exp,
                 attempts, ttl_exp, g_passport_hmac) = row

                if status != 'PENDING':
                    raise GuarantorError(f'Guarantee status is {status}')

                now = datetime.now(timezone.utc)
                if ttl_exp and ttl_exp < now:
                    raise TTLExpiredError('Guarantee TTL expired')
                if otp_exp and otp_exp < now:
                    raise GuarantorError('OTP expired')
                if attempts >= Config.OTP_MAX_ATTEMPTS:
                    raise GuarantorError('Too many OTP attempts')

                expected = self.crypto.otp_hash(otp_code, app_guarantor_id)
                if not hmac.compare_digest(expected, otp_hash or ''):
                    raise WrongOTPError('Invalid OTP')

                # ИСЛОҲ: signature бо шиносномаи КАФИЛ ҳисоб мешавад
                signature_hash = self.crypto.signature_hash(
                    app_guarantor_id, otp_code, g_passport_hmac)

                cursor.execute("""
                    UPDATE application_guarantors
                    SET approval_status = 'APPROVED', approved_at = %s,
                        signature_hash = %s WHERE id = %s
                    """, (now, signature_hash, app_guarantor_id))
                cursor.execute("""
                    UPDATE guarantors SET face_id_passed = TRUE,
                        sms_otp_confirmed = TRUE, guarantee_signature = %s,
                        signature_signed_at = %s WHERE user_id = %s
                    """, (signature_hash, now, g_user_id))
                cursor.execute("""
                    UPDATE guarantor_ttl_log SET approved_at = %s, status = 'APPROVED'
                    WHERE application_guarantor_id = %s
                    """, (now, app_guarantor_id))
                cursor.execute("""
                    UPDATE applications SET status = 'APPROVED',
                        error_reason = NULL, updated_at = %s WHERE id = %s
                    """, (now, app_id))
                cursor.execute("""
                    UPDATE loan_disbursements SET status='ACTIVE',
                        disbursed_at=NOW() WHERE application_id = %s
                    """, (app_id,))
                self._audit(conn, 'GUARANTEE_APPROVED', app_id,
                            g_passport_hmac, f'ag_id={app_guarantor_id}')
                return {'application_id': app_id, 'status': 'APPROVED'}
            finally:
                cursor.close()

    def _force_expire_guarantee_sync(self, app_guarantor_id: int) -> None:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT application_id, approval_status "
                    "FROM application_guarantors WHERE id = %s FOR UPDATE",
                    (app_guarantor_id,))
                row = cursor.fetchone()
                if not row:
                    return
                app_id, status = row
                if status != 'PENDING':
                    return
                self._close_guarantee(conn, app_guarantor_id, 'EXPIRED')
                cursor.execute("""
                    UPDATE applications SET status='REJECTED',
                        error_reason='Guarantee TTL expired', updated_at=NOW()
                    WHERE id=%s AND status IN ('PENDING_GUARANTOR','PENDING_CHECKS')
                    """, (app_id,))
                self._cancel_pending_loan(conn, app_id, 'Guarantee TTL expired')
                cursor.execute("""
                    UPDATE guarantor_ttl_log SET expired_at=NOW(), status='EXPIRED'
                    WHERE application_guarantor_id=%s
                    """, (app_guarantor_id,))
                self._audit(conn, 'GUARANTEE_EXPIRED', app_id, '',
                            f'ag_id={app_guarantor_id} (on approve)')
                logger.info(f'Guarantee {app_guarantor_id} force-expired')
            finally:
                cursor.close()

    def _increment_otp_attempts_sync(self, app_guarantor_id: int) -> None:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "UPDATE application_guarantors SET otp_attempts = otp_attempts + 1 "
                    "WHERE id = %s", (app_guarantor_id,))
            finally:
                cursor.close()

    # ------------------------------------------------------------------------
    # ИСЛОҲ: Face ID бо шиносномаи КАФИЛ муқоиса мешавад
    #        OTP rate limit бо phone_hmac
    # ------------------------------------------------------------------------
    async def approve_guarantee(self, app_guarantor_id, otp_code,
                                  face_id_data, passport_sn,
                                  client_ip: Optional[str] = None):
        # 1. Шиносномаи кафилро аз база гиред
        try:
            expected_passport_hmac = await self._db_call_with_retry(
                self._get_guarantor_passport_hmac_sync, app_guarantor_id)
            if not expected_passport_hmac:
                return self._error('E1004', 'Guarantee not found.', 404)
        except Exception as e:
            logger.exception(f'Get guarantor passport failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

        provided_passport_hmac = self.crypto.blind_index(passport_sn)
        if not hmac.compare_digest(provided_passport_hmac, expected_passport_hmac):
            logger.warning(
                f'Face ID passport mismatch for ag_id={app_guarantor_id}')
            return self._error('E1014',
                'Passport does not match the guarantor.', 400)

        # 2. Face ID санҷиш
        try:
            ok = await self.face.verify(face_id_data, passport_sn)
            if not ok:
                return self._error('E1008', 'Biometric failed.', 400)
        except ServiceUnavailable:
            return self._error('E2001', 'Face-ID unavailable.', 503)

        # 3. OTP rate limit бо phone_hmac-и кафил
        try:
            phone_hmac = await self._db_call_with_retry(
                self._get_guarantor_phone_hmac_sync, app_guarantor_id)
            if not phone_hmac:
                return self._error('E1004', 'Guarantee not found.', 404)
            allowed = await self._db_call_with_retry(
                self._check_otp_rate_limit_sync, phone_hmac, client_ip)
            if not allowed:
                return self._error('E1021', 'Too many OTP attempts. Try later.', 429)
        except Exception as e:
            logger.warning(f'Rate limit check failed: {scrub_pii(str(e))}')

        try:
            result = await self._db_call_with_retry(
                self._approve_guarantee_sync, app_guarantor_id, otp_code)
            try:
                await self._db_call_with_retry(
                    self._record_otp_attempt_sync, phone_hmac, client_ip, True)
            except Exception:
                pass
            return {**result, 'http_status': 200}
        except TTLExpiredError:
            try:
                await self._db_call_with_retry(
                    self._force_expire_guarantee_sync, app_guarantor_id)
            except Exception as exp_err:
                logger.error(f'Force expire failed: {scrub_pii(str(exp_err))}')
            return self._error('E1020', 'Guarantee expired.', 400)
        except WrongOTPError:
            try:
                await self._db_call_with_retry(
                    self._increment_otp_attempts_sync, app_guarantor_id)
            except Exception as inc_err:
                logger.error(f'OTP attempts increment failed: {scrub_pii(str(inc_err))}')
            try:
                await self._db_call_with_retry(
                    self._record_otp_attempt_sync, phone_hmac, client_ip, False)
            except Exception:
                pass
            return self._error('E1020', 'Invalid OTP.', 400)
        except GuarantorError as e:
            return self._error('E1020', str(e), 400)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Approve failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    def _reject_guarantee_sync(self, app_guarantor_id, reason):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT application_id, approval_status "
                    "FROM application_guarantors WHERE id = %s FOR UPDATE",
                    (app_guarantor_id,))
                row = cursor.fetchone()
                if not row:
                    raise GuarantorError('Guarantee not found')
                app_id, status = row
                if status != 'PENDING':
                    raise GuarantorError(f'Status is {status}')
                self._close_guarantee(conn, app_guarantor_id, 'REJECTED')
                reason_str = scrub_pii(reason or 'guarantor rejected')
                cursor.execute("""
                    UPDATE applications SET status = 'REJECTED',
                        error_reason = %s, updated_at = %s WHERE id = %s
                    """, (reason_str, datetime.now(timezone.utc), app_id))
                self._cancel_pending_loan(conn, app_id, 'guarantor rejected')
                self._audit(conn, 'GUARANTEE_REJECTED', app_id, '',
                            reason or 'no reason')
                return {'application_id': app_id, 'status': 'REJECTED'}
            finally:
                cursor.close()

    async def reject_guarantee(self, app_guarantor_id, reason=None):
        try:
            result = await self._db_call_with_retry(
                self._reject_guarantee_sync, app_guarantor_id, reason)
            return {**result, 'http_status': 200}
        except GuarantorError as e:
            return self._error('E1020', str(e), 400)
        except Exception as e:
            logger.exception(f'Reject failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    def _resend_otp_sync(self, app_guarantor_id: int) -> Dict:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT application_id, approval_status,
                           otp_send_count, otp_last_sent_at,
                           ttl_expires_at, otp_attempts
                    FROM application_guarantors WHERE id = %s FOR UPDATE
                    """, (app_guarantor_id,))
                row = cursor.fetchone()
                if not row:
                    raise GuarantorError('Guarantee not found')
                (app_id, status, send_count, last_sent, ttl_exp, attempts) = row
                if status != 'PENDING':
                    raise GuarantorError(f'Status is {status}')
                now = datetime.now(timezone.utc)
                if ttl_exp and ttl_exp < now:
                    raise GuarantorError('Guarantee expired')
                if send_count >= Config.OTP_MAX_RESENDS:
                    raise GuarantorError('Max resends reached')
                if attempts >= Config.OTP_MAX_ATTEMPTS:
                    raise GuarantorError('Too many failed attempts')
                if (last_sent and (now - last_sent).total_seconds()
                        < Config.OTP_RESEND_COOLDOWN_SEC):
                    raise GuarantorError(
                        f'Cooldown active. Try after {Config.OTP_RESEND_COOLDOWN_SEC}s')

                otp_code = f'{int.from_bytes(os.urandom(3), "big") % 1000000:06d}'
                otp_hash = self.crypto.otp_hash(otp_code, app_guarantor_id)
                otp_expires = now + timedelta(minutes=Config.OTP_TTL_MINUTES)

                cursor.execute("""
                    UPDATE application_guarantors
                    SET otp_code_hash = %s, otp_expires_at = %s,
                        otp_last_sent_at = %s, otp_send_count = otp_send_count + 1
                    WHERE id = %s
                    """, (otp_hash, otp_expires, now, app_guarantor_id))
                cursor.execute("""
                    UPDATE guarantor_ttl_log SET sms_status = 'PENDING', sms_attempts = 0
                    WHERE application_guarantor_id = %s
                    """, (app_guarantor_id,))
                self._audit(conn, 'OTP_RESENT', app_id, '',
                            f'ag_id={app_guarantor_id} count={send_count + 1}')
                return {
                    'application_id': app_id,
                    'app_guarantor_id': app_guarantor_id,
                    '_otp_code': otp_code,
                    'send_count': send_count + 1,
                }
            finally:
                cursor.close()

    async def resend_otp(self, app_guarantor_id: int,
                          client_ip: Optional[str] = None):
        try:
            result = await self._db_call_with_retry(
                self._resend_otp_sync, app_guarantor_id)
        except GuarantorError as e:
            return self._error('E1022', str(e), 400)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Resend OTP failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

        otp_code = result.pop('_otp_code', None)
        if otp_code:
            try:
                phone = await self._db_call_with_retry(
                    self._get_guarantor_phone_sync, app_guarantor_id)
                if phone:
                    msg = f'Credit guarantee request. New OTP: {otp_code}'
                    task = asyncio.create_task(
                        self._deliver_otp_sms(phone, msg, app_guarantor_id))
                    self._bg_tasks.add(task)
                    task.add_done_callback(self._bg_tasks.discard)
            except Exception as e:
                logger.warning(f'Resend phone lookup: {scrub_pii(str(e))}')
        return {**result, 'status': 'SENT', 'http_status': 200}

    def _register_card_sync(self, passport_hmac: str, card_token: str,
                             card_masked: str, signature: str) -> Dict:
        if not self.crypto.verify_card_signature(
                passport_hmac, card_token, signature):
            raise GuarantorError('Invalid card signature.')
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT g.id, g.user_id FROM guarantors g
                    JOIN users u ON u.id = g.user_id
                    WHERE u.passport_sn_hmac = %s FOR UPDATE
                    """, (passport_hmac,))
                row = cursor.fetchone()
                if not row:
                    raise GuarantorError('Guarantor profile not found')
                now = datetime.now(timezone.utc)
                cursor.execute("""
                    UPDATE guarantors SET card_token = %s, card_masked = %s,
                        card_registered_at = %s, auto_debit_enabled = TRUE,
                        updated_at = %s WHERE user_id = %s
                    """, (card_token, card_masked, now, now, row[1]))
                self._audit(conn, 'CARD_REGISTERED', None, passport_hmac,
                            f'card={card_masked}')
                return {'user_id': row[1], 'card_masked': card_masked,
                        'auto_debit_enabled': True}
            finally:
                cursor.close()

    async def register_card(self, passport_series: str, passport_number: str,
                             card_token: str, card_masked: str, signature: str):
        passport_sn = f'{passport_series}{passport_number}'
        passport_hmac = self.crypto.blind_index(passport_sn)
        try:
            result = await self._db_call_with_retry(
                self._register_card_sync, passport_hmac,
                card_token, card_masked, signature)
            return {**result, 'status': 'OK', 'http_status': 200}
        except GuarantorError as e:
            return self._error('E1040', str(e), 400)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Register card failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    def _expire_ttl_sync(self) -> int:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT ag.id, ag.application_id
                    FROM application_guarantors ag
                    WHERE ag.approval_status = 'PENDING' AND ag.ttl_expires_at < NOW()
                    FOR UPDATE SKIP LOCKED
                    """)
                rows = cursor.fetchall()
                for ag_id, app_id in rows:
                    self._close_guarantee(conn, ag_id, 'EXPIRED')
                    cursor.execute("""
                        UPDATE applications SET status='REJECTED',
                            error_reason='Guarantee TTL expired', updated_at=NOW()
                        WHERE id=%s AND status='PENDING_GUARANTOR'
                        """, (app_id,))
                    self._cancel_pending_loan(conn, app_id, 'Guarantee TTL expired')
                    cursor.execute("""
                        UPDATE guarantor_ttl_log SET expired_at=NOW(), status='EXPIRED'
                        WHERE application_guarantor_id=%s
                        """, (ag_id,))
                return len(rows)
            finally:
                cursor.close()

    # ------------------------------------------------------------------------
    # ИСЛОҲ: Ҷарима ТАНҲО ба principal_due (compounding нест)
    # ------------------------------------------------------------------------
    def _mark_overdue_sync(self) -> int:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE repayment_schedule SET status = 'OVERDUE'
                    WHERE status IN ('PENDING','PARTIAL') AND due_date < CURRENT_DATE
                    """)
                marked = cursor.rowcount

                # Ҷарима ба PRINCIPAL_DUE, на ба AMOUNT_DUE (compounding нест)
                cursor.execute("""
                    UPDATE repayment_schedule rs
                    SET penalty_amount = rs.penalty_amount + ROUND(
                            rs.principal_due * pc.daily_penalty_rate, 2),
                        amount_due = rs.principal_due + rs.penalty_amount + ROUND(
                            rs.principal_due * pc.daily_penalty_rate, 2),
                        last_penalty_date = CURRENT_DATE
                    FROM loan_disbursements ld
                    JOIN product_config pc ON pc.product_type = ld.product_type
                    WHERE rs.loan_id = ld.id
                      AND rs.status = 'OVERDUE'
                      AND pc.daily_penalty_rate > 0
                      AND (CURRENT_DATE - rs.due_date) > pc.grace_days
                      AND (rs.last_penalty_date IS NULL
                           OR rs.last_penalty_date < CURRENT_DATE)
                    """)
                penalized = cursor.rowcount
                if penalized:
                    logger.info(f'Applied penalty (non-compounding) to {penalized} installments')
                return marked
            finally:
                cursor.close()

    def _cleanup_idempotency_sync(self) -> int:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM repayment_idempotency WHERE expires_at < NOW()")
                return cursor.rowcount
            finally:
                cursor.close()

    def _pay_installment_impl(self, conn, installment_id, amount_paid, idempotency_key):
        cursor = conn.cursor()
        try:
            if idempotency_key:
                cursor.execute("""
                    SELECT response_body, installment_id FROM repayment_idempotency
                    WHERE idempotency_key = %s AND expires_at > NOW()
                    """, (idempotency_key,))
                cached = cursor.fetchone()
                if cached:
                    if cached[1] != installment_id:
                        raise GuarantorError('Idempotency key reused for different installment')
                    return json.loads(cached[0])

            cursor.execute("""
                SELECT rs.loan_id, rs.amount_due, rs.amount_paid,
                       rs.status, ld.guarantor_id, ld.status
                FROM repayment_schedule rs
                JOIN loan_disbursements ld ON ld.id = rs.loan_id
                WHERE rs.id = %s FOR UPDATE
                """, (installment_id,))
            row = cursor.fetchone()
            if not row:
                raise GuarantorError('Installment not found')

            (loan_id, amount_due, already_paid, rs_status, _g_id, loan_status) = row

            if rs_status == 'PAID':
                response = {'status': 'ALREADY_PAID', 'installment_id': installment_id}
            else:
                total_paid = Decimal(str(already_paid)) + Decimal(str(amount_paid))
                amount_due = Decimal(str(amount_due))
                if Decimal(str(amount_paid)) > (amount_due - Decimal(str(already_paid))
                                                + Decimal('0.01')):
                    raise GuarantorError('Amount exceeds remaining due')

                if total_paid >= amount_due:
                    new_status = 'PAID'
                    paid_at = datetime.now(timezone.utc)
                elif total_paid > 0:
                    new_status = 'PARTIAL'
                    paid_at = None
                else:
                    new_status = 'PENDING'
                    paid_at = None

                cursor.execute("""
                    UPDATE repayment_schedule SET amount_paid = %s,
                        status = %s, paid_at = %s WHERE id = %s
                    """, (str(total_paid), new_status, paid_at, installment_id))

                cursor.execute("""
                    SELECT COUNT(*) FROM repayment_schedule
                    WHERE loan_id = %s AND status != 'PAID'
                    """, (loan_id,))
                remaining = cursor.fetchone()[0]

                if remaining == 0:
                    cursor.execute("""
                        UPDATE loan_disbursements SET status='CLOSED', closed_at=%s
                        WHERE id=%s
                        """, (datetime.now(timezone.utc), loan_id))
                    cursor.execute("""
                        UPDATE applications SET status='CLOSED', updated_at=%s
                        WHERE id=(SELECT application_id FROM loan_disbursements
                                  WHERE id=%s)
                        """, (datetime.now(timezone.utc), loan_id))
                    cursor.execute("""
                        SELECT ag.id FROM application_guarantors ag
                        JOIN loan_disbursements ld ON ld.application_id = ag.application_id
                        WHERE ld.id = %s AND ag.approval_status = 'APPROVED'
                        """, (loan_id,))
                    ag_row = cursor.fetchone()
                    if ag_row:
                        self._close_guarantee(conn, ag_row[0], 'CLOSED')
                    logger.info(f'Loan {loan_id} CLOSED, guarantee released')

                response = {
                    'status': new_status, 'installment_id': installment_id,
                    'amount_paid': str(total_paid), 'loan_closed': remaining == 0,
                }

                cursor.execute("SELECT application_id FROM loan_disbursements WHERE id=%s",
                               (loan_id,))
                app_row = cursor.fetchone()
                app_id_for_audit = app_row[0] if app_row else None
                self._audit(conn, 'REPAYMENT', app_id_for_audit, '',
                            f'installment={installment_id} amount={amount_paid}')

            if idempotency_key:
                cursor.execute("""
                    INSERT INTO repayment_idempotency (idempotency_key,
                        installment_id, response_body) VALUES (%s, %s, %s)
                    ON CONFLICT (idempotency_key) DO NOTHING
                    """, (idempotency_key, installment_id, json.dumps(response)))
            return response
        finally:
            cursor.close()

    def _pay_installment_sync(self, installment_id, amount_paid, idempotency_key):
        with self.db.transaction() as conn:
            return self._pay_installment_impl(conn, installment_id, amount_paid, idempotency_key)

    async def pay_installment(self, installment_id, amount, idempotency_key):
        try:
            result = await self._db_call_with_retry(
                self._pay_installment_sync, installment_id, amount, idempotency_key)
            return {**result, 'http_status': 200}
        except GuarantorError as e:
            return self._error('E1030', str(e), 400)
        except DataError as e:
            logger.error(f'DataError: {scrub_pii(str(e))}')
            return self._error('E2004', 'Invalid data format.', 400)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Pay failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    def _find_due_installments(self) -> List[Dict]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT rs.id, rs.loan_id, rs.amount_due, rs.amount_paid,
                           ld.guarantor_id, g.card_token, ld.application_id
                    FROM repayment_schedule rs
                    JOIN loan_disbursements ld ON ld.id = rs.loan_id
                    JOIN guarantors g ON g.user_id = ld.guarantor_id
                    WHERE rs.status IN ('PENDING','PARTIAL','OVERDUE')
                      AND rs.due_date <= CURRENT_DATE
                      AND ld.status = 'ACTIVE'
                      AND ld.guarantor_id IS NOT NULL
                      AND g.auto_debit_enabled = TRUE
                      AND g.card_token IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM auto_debit_transactions adt
                          WHERE adt.installment_id = rs.id
                            AND adt.status IN ('FAILED','PENDING')
                            AND adt.next_retry_at IS NOT NULL
                            AND adt.next_retry_at > NOW()
                      )
                    ORDER BY rs.due_date LIMIT 50
                    """)
                rows = cursor.fetchall()
                return [{
                    'installment_id': r[0], 'loan_id': r[1],
                    'amount_due': Decimal(str(r[2])),
                    'amount_paid': Decimal(str(r[3] or 0)),
                    'guarantor_id': r[4], 'card_token': r[5],
                    'application_id': r[6],
                } for r in rows]
            finally:
                cursor.close()

    def _record_debit_attempt(self, inst, amount, idem):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO auto_debit_transactions
                        (loan_id, guarantor_id, installment_id, amount,
                         card_token, status, idempotency_key,
                         last_attempt_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 'PENDING', %s, NOW(), NOW())
                    ON CONFLICT (idempotency_key) DO UPDATE
                    SET status = CASE
                            WHEN auto_debit_transactions.status
                                 IN ('SUCCESS','EXHAUSTED','NEEDS_RECOVERY')
                                THEN auto_debit_transactions.status
                            ELSE 'PENDING'::debit_status_enum
                        END,
                        last_attempt_at = CASE
                            WHEN auto_debit_transactions.status
                                 IN ('SUCCESS','EXHAUSTED','NEEDS_RECOVERY')
                                THEN auto_debit_transactions.last_attempt_at
                            ELSE NOW()
                        END,
                        next_retry_at = CASE
                            WHEN auto_debit_transactions.status
                                 IN ('SUCCESS','EXHAUSTED','NEEDS_RECOVERY')
                                THEN auto_debit_transactions.next_retry_at
                            ELSE NULL
                        END,
                        updated_at = NOW()
                    RETURNING id, status
                    """, (inst['loan_id'], inst['guarantor_id'],
                          inst['installment_id'], str(amount),
                          inst['card_token'], idem))
                tx_id, status = cursor.fetchone()
                if status in ('SUCCESS', 'EXHAUSTED', 'NEEDS_RECOVERY'):
                    return None
                return tx_id
            finally:
                cursor.close()

    def _mark_debit_success(self, tx_id):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE auto_debit_transactions SET status='SUCCESS',
                        last_attempt_at=NOW(), updated_at=NOW(), next_retry_at=NULL
                    WHERE id=%s
                    """, (tx_id,))
            finally:
                cursor.close()

    def _mark_debit_failed(self, tx_id, error):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE auto_debit_transactions
                    SET status = CASE
                            WHEN attempt_count + 1 >= %s
                                THEN 'EXHAUSTED'::debit_status_enum
                            ELSE 'FAILED'::debit_status_enum
                        END,
                        attempt_count = attempt_count + 1,
                        last_attempt_at = NOW(), updated_at = NOW(),
                        next_retry_at = CASE
                            WHEN attempt_count + 1 >= %s THEN NULL
                            ELSE NOW() + INTERVAL '24 hours'
                        END,
                        error_message = %s
                    WHERE id = %s
                    """, (Config.AUTO_DEBIT_MAX_ATTEMPTS,
                          Config.AUTO_DEBIT_MAX_ATTEMPTS, error[:500], tx_id))
            finally:
                cursor.close()

    def _mark_debit_needs_recovery(self, tx_id, reason):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE auto_debit_transactions
                    SET status = 'NEEDS_RECOVERY'::debit_status_enum,
                        last_attempt_at = NOW(), updated_at = NOW(),
                        next_retry_at = NULL, error_message = %s
                    WHERE id = %s
                    """, (reason[:500], tx_id))
            finally:
                cursor.close()

    def _recover_orphan_debits(self) -> int:
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE auto_debit_transactions adt
                    SET status = 'SUCCESS'::debit_status_enum,
                        last_attempt_at = NOW(), updated_at = NOW(),
                        next_retry_at = NULL,
                        error_message = 'auto-recovered: installment PAID'
                    WHERE adt.status = 'PENDING'
                      AND adt.last_attempt_at < NOW() - make_interval(secs => %s::int)
                      AND EXISTS (
                          SELECT 1 FROM repayment_schedule rs
                          WHERE rs.id = adt.installment_id
                            AND rs.amount_paid >= rs.amount_due
                      )
                    """, (Config.AUTO_DEBIT_RECOVERY_THRESHOLD_SEC,))
                recovered = cursor.rowcount

                cursor.execute("""
                    UPDATE auto_debit_transactions
                    SET status = 'NEEDS_RECOVERY'::debit_status_enum,
                        updated_at = NOW(), next_retry_at = NULL,
                        error_message = COALESCE(error_message, '') ||
                            ' | stuck PENDING > threshold, ops review'
                    WHERE status = 'PENDING'
                      AND last_attempt_at < NOW() - make_interval(secs => %s::int)
                    """, (Config.AUTO_DEBIT_STUCK_THRESHOLD_SEC,))
                stuck = cursor.rowcount
                if stuck:
                    logger.warning(f'{stuck} auto-debit tx marked NEEDS_RECOVERY')
                return recovered + stuck
            finally:
                cursor.close()

    async def _process_auto_debit_batch(self):
        try:
            await self._db_call_with_retry(self._recover_orphan_debits)
        except Exception as e:
            logger.exception(f'Orphan debit recovery failed: {scrub_pii(str(e))}')

        try:
            installments = await self._db_call_with_retry(self._find_due_installments)
        except Exception as e:
            logger.exception(f'Auto-debit scan failed: {scrub_pii(str(e))}')
            return

        for inst in installments:
            remaining = inst['amount_due'] - inst['amount_paid']
            if remaining <= 0:
                continue
            idem = self.crypto.idempotency_key(
                'autodebit', str(inst['loan_id']), str(inst['installment_id']))

            try:
                tx_id = await self._db_call_with_retry(
                    self._record_debit_attempt, inst, remaining, idem)
            except Exception as e:
                logger.exception(f'Record debit failed: {scrub_pii(str(e))}')
                continue
            if tx_id is None:
                continue

            try:
                result = await self.payment.debit(inst['card_token'], remaining, idem)
                if result.get('success'):
                    try:
                        await self._db_call_with_retry(
                            self._pay_installment_sync,
                            inst['installment_id'], remaining, idem)
                    except Exception as db_err:
                        logger.critical(f'Gateway OK but DB FAILED: tx_id={tx_id}')
                        try:
                            await self._db_call_with_retry(
                                self._mark_debit_needs_recovery, tx_id,
                                f'DB failure after gateway success: {scrub_pii(str(db_err))[:200]}')
                        except Exception as rec_err:
                            logger.critical(f'Failed to mark NEEDS_RECOVERY: {scrub_pii(str(rec_err))}')
                        continue
                    try:
                        await self._db_call_with_retry(self._mark_debit_success, tx_id)
                    except Exception as mark_err:
                        logger.warning(f'Mark success failed: {scrub_pii(str(mark_err))}')
                    logger.info(f'Auto-debit OK: inst={inst["installment_id"]}')
                else:
                    await self._db_call_with_retry(
                        self._mark_debit_failed, tx_id, result.get('error', 'unknown'))
            except ServiceUnavailable:
                try:
                    queried = await self.payment.query_debit(idem)
                except Exception:
                    queried = None
                if queried and queried.get('success'):
                    logger.warning(f'Timeout but query confirms SUCCESS: tx_id={tx_id}')
                    try:
                        await self._db_call_with_retry(
                            self._pay_installment_sync,
                            inst['installment_id'], remaining, idem)
                        await self._db_call_with_retry(self._mark_debit_success, tx_id)
                    except Exception as rec_err:
                        logger.critical(f'Post-timeout recovery failed: {scrub_pii(str(rec_err))}')
                        try:
                            await self._db_call_with_retry(
                                self._mark_debit_needs_recovery, tx_id,
                                'timeout + query SUCCESS but DB failed')
                        except Exception:
                            pass
                else:
                    await self._db_call_with_retry(
                        self._mark_debit_failed, tx_id,
                        'service_unavailable (timeout, query=none)')
            except Exception as e:
                logger.exception(f'Auto-debit error for tx_id={tx_id}: {scrub_pii(str(e))}')
                try:
                    await self._db_call_with_retry(
                        self._mark_debit_needs_recovery, tx_id,
                        f'unknown error: {scrub_pii(str(e))[:200]}')
                except Exception:
                    pass

    # ------------------------------------------------------------------------
    # ИСЛОҲ: Ops recovery SUCCESS — хато сарфи назар НАМЕШАВАД
    # ------------------------------------------------------------------------
    def _ops_resolve_recovery_sync(self, tx_id: int, resolution: str, note: str) -> Dict:
        if resolution not in ('SUCCESS', 'FAILED'):
            raise OpsRecoveryError('resolution must be SUCCESS or FAILED')
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT adt.id, adt.installment_id, adt.loan_id,
                           adt.amount, adt.status, adt.idempotency_key
                    FROM auto_debit_transactions adt WHERE adt.id = %s FOR UPDATE
                    """, (tx_id,))
                row = cursor.fetchone()
                if not row:
                    raise OpsRecoveryError('Transaction not found')
                (_id, inst_id, loan_id, amount, st, idem) = row
                if st != 'NEEDS_RECOVERY':
                    raise OpsRecoveryError(f'Status is {st}, expected NEEDS_RECOVERY')

                if resolution == 'SUCCESS':
                    # Агар pay_installment_impl хато диҳад — тамом кунем
                    self._pay_installment_impl(conn, inst_id, amount, idem)
                    cursor.execute("""
                        UPDATE auto_debit_transactions
                        SET status='SUCCESS', updated_at=NOW(), next_retry_at=NULL,
                            error_message=COALESCE(error_message,'') ||
                                ' | ops-resolved SUCCESS: ' || %s
                        WHERE id = %s
                        """, (note[:200], tx_id))
                else:
                    cursor.execute("""
                        UPDATE auto_debit_transactions
                        SET status='FAILED', updated_at=NOW(),
                            next_retry_at=NOW() + INTERVAL '24 hours',
                            error_message=COALESCE(error_message,'') ||
                                ' | ops-resolved FAILED: ' || %s
                        WHERE id = %s
                        """, (note[:200], tx_id))

                cursor.execute("SELECT application_id FROM loan_disbursements WHERE id=%s",
                               (loan_id,))
                arow = cursor.fetchone()
                app_id = arow[0] if arow else None
                self._audit(conn, f'OPS_RECOVERY_{resolution}', app_id, '',
                            f'tx_id={tx_id} note={note[:200]}')
                return {'tx_id': tx_id, 'installment_id': inst_id, 'resolution': resolution}
            finally:
                cursor.close()

    async def ops_resolve_recovery(self, tx_id: int, resolution: str, note: str = ''):
        try:
            result = await self._db_call_with_retry(
                self._ops_resolve_recovery_sync, tx_id, resolution, note)
            return {**result, 'http_status': 200, 'status': 'OK'}
        except OpsRecoveryError as e:
            return self._error('E1050', str(e), 400)
        except OperationalError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Ops recovery failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    def _list_needs_recovery_sync(self, limit: int = 100) -> List[Dict]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT adt.id, adt.loan_id, adt.installment_id, adt.amount,
                           adt.attempt_count, adt.last_attempt_at,
                           adt.error_message, ld.application_id
                    FROM auto_debit_transactions adt
                    JOIN loan_disbursements ld ON ld.id = adt.loan_id
                    WHERE adt.status = 'NEEDS_RECOVERY'
                    ORDER BY adt.last_attempt_at LIMIT %s
                    """, (limit,))
                rows = cursor.fetchall()
                return [{
                    'tx_id': r[0], 'loan_id': r[1], 'installment_id': r[2],
                    'amount': str(r[3]), 'attempt_count': r[4],
                    'last_attempt_at': (r[5].isoformat() if r[5] else None),
                    'error_message': r[6], 'application_id': r[7],
                } for r in rows]
            finally:
                cursor.close()

    async def list_needs_recovery(self, limit: int = 100):
        try:
            result = await self._db_call_with_retry(self._list_needs_recovery_sync, limit)
            return {'transactions': result, 'http_status': 200}
        except Exception as e:
            logger.exception(f'List recovery failed: {scrub_pii(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def _auto_debit_loop(self):
        while not self._shutdown_event.is_set():
            try:
                has_lock = await self._db_call_with_retry(
                    self._leader_auto_debit.try_acquire)
                if has_lock:
                    await self._process_auto_debit_batch()
            except Exception as e:
                logger.exception(f'Auto-debit loop error: {scrub_pii(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.AUTO_DEBIT_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _ttl_expiry_loop(self):
        while not self._shutdown_event.is_set():
            try:
                has_lock = await self._db_call_with_retry(
                    self._leader_ttl.try_acquire)
                if has_lock:
                    count = await self._db_call_with_retry(self._expire_ttl_sync)
                    if count:
                        logger.info(f'Expired {count} guarantees')
            except Exception as e:
                logger.exception(f'TTL loop error: {scrub_pii(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.TTL_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _overdue_loop(self):
        while not self._shutdown_event.is_set():
            try:
                has_lock = await self._db_call_with_retry(
                    self._leader_overdue.try_acquire)
                if has_lock:
                    count = await self._db_call_with_retry(self._mark_overdue_sync)
                    if count:
                        logger.info(f'Marked {count} installments OVERDUE')
            except Exception as e:
                logger.exception(f'Overdue loop error: {scrub_pii(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.OVERDUE_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _cleanup_loop(self):
        while not self._shutdown_event.is_set():
            try:
                has_lock = await self._db_call_with_retry(
                    self._leader_cleanup.try_acquire)
                if has_lock:
                    count = await self._db_call_with_retry(
                        self._cleanup_idempotency_sync)
                    if count:
                        logger.info(f'Cleaned up {count} idempotency records')
                    await self._db_call_with_retry(
                        self._cleanup_otp_rate_limit_sync)
            except Exception as e:
                logger.exception(f'Cleanup loop error: {scrub_pii(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.CLEANUP_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    def start_background_workers(self):
        if self._auto_debit_task is None:
            self._auto_debit_task = asyncio.create_task(self._auto_debit_loop())
        if self._ttl_task is None:
            self._ttl_task = asyncio.create_task(self._ttl_expiry_loop())
        if self._overdue_task is None:
            self._overdue_task = asyncio.create_task(self._overdue_loop())
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_background_workers(self):
        self._shutdown_event.set()
        for task in (self._auto_debit_task, self._ttl_task,
                     self._overdue_task, self._cleanup_task):
            if task:
                try:
                    await asyncio.wait_for(task, timeout=10)
                except (asyncio.TimeoutError, Exception):
                    task.cancel()
        for leader in (self._leader_auto_debit, self._leader_ttl,
                       self._leader_overdue, self._leader_cleanup):
            try:
                leader.release()
            except Exception:
                pass

    def _create_loan(self, conn, app_id, passport_hmac, guarantor_id,
                     gross, comm, net, abs_id, product,
                     target_type, target_iban, target_name):
        target_hmac = (self.crypto.blind_index(target_iban) if target_iban else '')
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO loan_disbursements
                    (application_id, passport_sn_hmac, guarantor_id,
                     gross_amount, transfer_commission, net_transferred,
                     abs_contract_id, product_type, target_account_type,
                     target_account_iban, target_account_hmac, target_name,
                     status, disbursed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        'PENDING_DISBURSEMENT', NULL)
                ON CONFLICT (application_id) DO NOTHING RETURNING id
                """, (app_id, passport_hmac, guarantor_id,
                      str(gross), str(comm), str(net), abs_id, product,
                      target_type, target_iban, target_hmac, target_name))
            row = cursor.fetchone()
            if row is None:
                cursor.execute('SELECT id FROM loan_disbursements WHERE application_id = %s',
                               (app_id,))
                row = cursor.fetchone()
            return row[0]
        finally:
            cursor.close()

    # ------------------------------------------------------------------------
    # ИСЛОҲ: principal_due низ пур карда мешавад
    #   days > 0  → як installment (DailyPay=7, RentPay=15)
    #   months > 0 → months-то installment моҳона (StudentPay=10)
    # ------------------------------------------------------------------------
    def _create_repayment_schedule(self, conn, loan_id, total,
                                    months=0, days=0):
        total = Decimal(str(total))
        now = datetime.now(timezone.utc)
        today = now.date()
        cursor = conn.cursor()
        try:
            if days and int(days) > 0:
                due_date = add_days(today, int(days)).isoformat()
                cursor.execute("""
                    INSERT INTO repayment_schedule
                        (loan_id, installment_number, due_date,
                         principal_due, amount_due, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, 'PENDING', %s)
                    ON CONFLICT (loan_id, installment_number) DO NOTHING
                    """, (loan_id, 1, due_date, str(total), str(total), now))
                return

            if not months or int(months) <= 0:
                months = 1
            months = int(months)
            monthly = self.money_round(total / Decimal(str(months)))
            paid = Decimal('0')
            for i in range(1, months + 1):
                if i == months:
                    amount_due = total - paid
                else:
                    amount_due = monthly
                    paid += monthly
                due_date = add_months(today, i).isoformat()
                cursor.execute("""
                    INSERT INTO repayment_schedule
                        (loan_id, installment_number, due_date,
                         principal_due, amount_due, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, 'PENDING', %s)
                    ON CONFLICT (loan_id, installment_number) DO NOTHING
                    """, (loan_id, i, due_date, str(amount_due),
                          str(amount_due), now))
        finally:
            cursor.close()

    def _create_insurance(self, conn, app_id, passport_hmac, insurance, margin,
                          interest=Decimal('0')):
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO insurance_policies
                    (application_id, passport_sn_hmac, fee_amount,
                     bank_margin, interest_amount, issued_at, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'ACTIVE')
                """, (app_id, passport_hmac, str(insurance), str(margin),
                      str(interest), datetime.now(timezone.utc)))
        finally:
            cursor.close()

    def _update_status(self, conn, app_id, status, error_reason=None):
        cursor = conn.cursor()
        try:
            if error_reason:
                cursor.execute("""
                    UPDATE applications SET status = %s, error_reason = %s,
                        updated_at = %s WHERE id = %s
                    """, (status, scrub_pii(str(error_reason))[:2000],
                          datetime.now(timezone.utc), app_id))
            else:
                cursor.execute("""
                    UPDATE applications SET status = %s, updated_at = %s WHERE id = %s
                    """, (status, datetime.now(timezone.utc), app_id))
        finally:
            cursor.close()

    def _mark_status(self, app_id, st, passport_hmac, reason):
        with self.db.transaction() as conn:
            self._update_status(conn, app_id, st, reason)
            self._audit(conn, st, app_id, passport_hmac, reason)

    def _mark_error(self, app_id, st, reason=''):
        try:
            with self.db.transaction() as conn:
                self._update_status(conn, app_id, st, reason)
                if st in ('ERROR_PHASE3', 'ERROR_EXTERNAL', 'ABS_FAILED'):
                    self._cancel_pending_loan(conn, app_id, reason)
        except Exception as e:
            logger.exception(f'Mark error failed: {scrub_pii(str(e))}')

    def _audit(self, conn, action, application_id, passport_hmac='', details=''):
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO audit_log (action, application_id,
                    passport_sn_hmac, details, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """, (action, application_id, passport_hmac,
                      scrub_pii(details[:2000]), datetime.now(timezone.utc)))
        finally:
            cursor.close()

    async def _deliver_otp_sms(self, phone: str, message: str, app_guarantor_id: int):
        sent = False
        error = None
        try:
            sent = await self.sms.send(phone, message)
        except Exception as e:
            error = scrub_pii(str(e))
            logger.warning(f'OTP SMS failed: {error}')
        try:
            await self._db_call_with_retry(
                self._update_sms_status, app_guarantor_id,
                'SENT' if sent else 'FAILED', error)
        except Exception as e:
            logger.warning(f'SMS status update failed: {scrub_pii(str(e))}')

    def _update_sms_status(self, app_guarantor_id: int, status: str, error: Optional[str]):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE guarantor_ttl_log
                    SET sms_status = %s::sms_status_enum,
                        sms_attempts = sms_attempts + 1, sms_last_error = %s
                    WHERE application_guarantor_id = %s
                    """, (status, (error or '')[:500], app_guarantor_id))
            finally:
                cursor.close()

    async def close_clients(self):
        for client in (self.cib, self.face, self.abs, self.payment, self.sms):
            try:
                await client.close()
            except Exception as e:
                logger.warning(f'Error closing {client.name}: {scrub_pii(str(e))}')

    async def shutdown(self):
        await self.stop_background_workers()
        if self._bg_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._bg_tasks, return_exceptions=True),
                    timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning(f'{len(self._bg_tasks)} bg tasks timed out')
                for t in self._bg_tasks:
                    t.cancel()

    async def health_check(self):
        checks = {}
        healthy = True
        try:
            await asyncio.to_thread(self._db_ping)
            checks['database'] = 'OK'
        except Exception as e:
            checks['database'] = f'FAIL: {scrub_pii(str(e))}'
            healthy = False
        try:
            test = 'health'
            enc = self.crypto.encrypt(test)
            dec = self.crypto.decrypt(enc)
            if dec != test:
                raise ValueError('Round-trip failed')
            checks['encryption'] = 'OK'
        except Exception as e:
            checks['encryption'] = f'FAIL: {scrub_pii(str(e))}'
            healthy = False
        checks['version'] = '3.8.1'
        checks['env'] = Config.ENV
        checks['leader_election_enabled'] = Config.LEADER_ELECTION_ENABLED
        checks['auto_debit_worker'] = (
            'RUNNING' if self._auto_debit_task
            and not self._auto_debit_task.done() else 'STOPPED')
        checks['ttl_worker'] = (
            'RUNNING' if self._ttl_task
            and not self._ttl_task.done() else 'STOPPED')
        checks['overdue_worker'] = (
            'RUNNING' if self._overdue_task
            and not self._overdue_task.done() else 'STOPPED')
        checks['cleanup_worker'] = (
            'RUNNING' if self._cleanup_task
            and not self._cleanup_task.done() else 'STOPPED')
        return {
            'status': 'HEALTHY' if healthy else 'UNHEALTHY',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checks': checks,
        }

    def _db_ping(self):
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            cursor.fetchone()
            cursor.close()

    @staticmethod
    def _error(code, reason, http_status=400):
        return {
            'code': code,
            'status': 'ERROR' if code.startswith('E2') else 'REJECTED',
            'reason': reason, 'http_status': http_status,
        }

    @staticmethod
    def _reject(code, st, reason):
        return {
            'status': 'REJECTED', 'reason_code': st, 'reason': reason,
            'response': {'code': code, 'status': 'REJECTED',
                         'reason': reason, 'http_status': 400},
        }

    @staticmethod
    def _ext_error(msg):
        return {
            'status': 'ERROR',
            'response': {'code': 'E2001', 'status': 'ERROR',
                         'reason': msg, 'http_status': 503},
        }


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================
_application_ref: Optional["Application"] = None
_executor_ref: Optional[concurrent.futures.ThreadPoolExecutor] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _executor_ref
    _executor_ref = concurrent.futures.ThreadPoolExecutor(
        max_workers=Config.THREAD_POOL_WORKERS,
        thread_name_prefix='credit_engine')
    asyncio.get_running_loop().set_default_executor(_executor_ref)
    if _application_ref and _application_ref.engine:
        _application_ref.engine.start_background_workers()
    yield
    if _application_ref is not None:
        try:
            if _application_ref.engine is not None:
                await _application_ref.engine.shutdown()
                await _application_ref.engine.close_clients()
            _application_ref.db_pool.close_all()
            logger.info('Application shutdown complete')
        except Exception as e:
            logger.exception(f'Shutdown error: {scrub_pii(str(e))}')
    if _executor_ref:
        _executor_ref.shutdown(wait=True)

# ============================================================================
# FASTAPI LIFESPAN & INITIALIZATION / ИНИЦИАЛИЗАТСИЯИ ТИЗИМ
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, db_pool, crypto_service
    
    # 1. Ҳангоми оғози сервер: Боркунии базаи маълумот ва CreditEngine ба хотира
    if db_pool:
        db_pool.initialize()
    
    engine = CreditEngine(
        db_pool=db_pool,
        crypto=crypto_service,
        cib_client=cib_client,
        face_client=face_client,
        abs_client=abs_client,
        payment_client=payment_client,
        sms_client=sms_client
    )
    
    if engine:
        await engine.start_background_tasks()
        
    yield  # Сервер ба кор сар мекунад ва дархостҳоро қабул менамояд
    
    # 2. Ҳангоми хомӯш шудани сервер: Бобустани бехатари ресурско
    if engine:
        await engine.stop_background_tasks()
    if db_pool:
        db_pool.close_all()


# ============================================================================
# FASTAPI APP CREATION / СОХТОРИ АСОСИИ API
# ============================================================================
app = FastAPI(
    title="Fintech Enterprise Microcredit Engine API",
    version="3.8.1",
    docs_url=None if os.environ.get('ENV') == 'production' else '/docs',
    redoc_url=None if os.environ.get('ENV') == 'production' else '/redoc',
    lifespan=lifespan,
)

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

_API_KEY_CACHE: Optional[str] = None
_INTERNAL_API_KEY_CACHE: Optional[str] = None


def _constant_time_compare(a: str, b: str) -> bool:
    a = str(a or '')
    b = str(b or '')
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, '\0')
    b_padded = b.ljust(max_len, '\0')
    return hmac.compare_digest(a_padded, b_padded)


def _get_expected_api_key() -> str:
    global _API_KEY_CACHE
    if _API_KEY_CACHE is None:
        _API_KEY_CACHE = os.getenv("API_KEY")
        if not _API_KEY_CACHE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API_KEY not configured.")
    return _API_KEY_CACHE


def _get_expected_internal_api_key() -> str:
    global _INTERNAL_API_KEY_CACHE
    if _INTERNAL_API_KEY_CACHE is None:
        _INTERNAL_API_KEY_CACHE = os.getenv("INTERNAL_API_KEY")
        if not _INTERNAL_API_KEY_CACHE:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="INTERNAL_API_KEY not configured.")
    return _INTERNAL_API_KEY_CACHE


async def verify_api_key(api_key: str = Depends(api_key_header)):
    expected = _get_expected_api_key()
    provided = str(api_key or '')
    if not _constant_time_compare(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.")
    return api_key


async def verify_internal_api_key(api_key: str = Depends(api_key_header)):
    expected = _get_expected_internal_api_key()
    provided = str(api_key or '')
    if not _constant_time_compare(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid internal API key.")
    return api_key


_engine: Optional[CreditEngine] = None


def get_engine() -> CreditEngine:
    if _engine is None:
        raise HTTPException(500, 'Engine not initialized')
    return _engine


def set_engine(engine: CreditEngine):
    global _engine
    _engine = engine


def _client_ip(request: Request) -> Optional[str]:
    direct_ip = request.client.host if request.client else None
    if direct_ip and direct_ip in Config.TRUSTED_PROXY_IPS:
        fwd = request.headers.get('x-forwarded-for')
        if fwd:
            first = fwd.split(',')[0].strip()
            if first:
                return first[:45]
    return direct_ip[:45] if direct_ip else None


class ProductTypeEnum(str, Enum):
    STUDENT_PAY = "StudentPay"
    DAILY_PAY = "DailyPay"
    RENT_PAY = "RentPay"


class RelationEnum(str, Enum):
    FATHER = "FATHER"
    MOTHER = "MOTHER"
    UNCLE_PATERNAL = "UNCLE_PATERNAL"
    AUNT_MATERNAL = "AUNT_MATERNAL"
    BROTHER = "BROTHER"
    SISTER = "SISTER"
    SPOUSE = "SPOUSE"
    OTHER = "OTHER"


class CreditApplicationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    passport_series: str = Field(..., min_length=1, max_length=2)
    passport_number: str = Field(..., min_length=7, max_length=9)
    date_of_birth: str = Field(..., description="YYYY-MM-DD")
    amount: Decimal = Field(..., gt=0, le=50000)
    product_type: ProductTypeEnum
    face_id_data: str = Field(..., min_length=10)
    user_phone: str = Field(..., min_length=9, max_length=15)
    guarantor_phone: Optional[str] = Field(None, max_length=15)
    guarantor_relation: Optional[RelationEnum] = None
    request_id: Optional[str] = Field(None, max_length=100)
    university_iban: Optional[str] = None
    university_name: Optional[str] = None
    landlord_iban: Optional[str] = None
    landlord_name: Optional[str] = None
    self_iban: Optional[str] = None


class CreditApplicationResponse(BaseModel):
    code: str
    status: str
    application_id: Optional[int] = None
    loan_id: Optional[int] = None
    abs_contract_id: Optional[str] = None
    reason: Optional[str] = None
    http_status: int = 200
    commission: Optional[str] = None
    net: Optional[str] = None
    gross_loan: Optional[str] = None
    insurance: Optional[str] = None
    interest: Optional[str] = None
    transfer_commission: Optional[str] = None
    net_transferred: Optional[str] = None
    target_iban: Optional[str] = None
    guarantor_id: Optional[int] = None


class GuarantorApproveRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    application_guarantor_id: int = Field(..., gt=0)
    otp_code: str = Field(..., min_length=6, max_length=6)
    face_id_data: str = Field(..., min_length=10)
    passport_series: str = Field(..., min_length=1, max_length=2)
    passport_number: str = Field(..., min_length=7, max_length=9)


class GuarantorRejectRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    application_guarantor_id: int = Field(..., gt=0)
    reason: Optional[str] = Field(None, max_length=500)


class GuarantorResendOTPRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    application_guarantor_id: int = Field(..., gt=0)


class CardRegisterRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    passport_series: str = Field(..., min_length=1, max_length=2)
    passport_number: str = Field(..., min_length=7, max_length=9)
    card_token: str = Field(..., min_length=8, max_length=200)
    card_masked: str = Field(..., min_length=4, max_length=20)
    signature: str = Field(..., min_length=64, max_length=64)


class PaymentRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    installment_id: int = Field(..., gt=0)
    amount: Decimal = Field(..., gt=0)
    idempotency_key: str = Field(..., min_length=8, max_length=64)


class OpsRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tx_id: int = Field(..., gt=0)
    resolution: str = Field(..., pattern='^(SUCCESS|FAILED)$')
    note: str = Field('', max_length=500)


def _product_to_engine(pt: ProductTypeEnum) -> str:
    return {
        ProductTypeEnum.STUDENT_PAY: 'STUDENT_PAY',
        ProductTypeEnum.DAILY_PAY: 'DAILY_PAY',
        ProductTypeEnum.RENT_PAY: 'RENT_PAY',
    }[pt]


@app.post("/api/v1/credit/apply",
          response_model=CreditApplicationResponse,
          tags=["Core Microcredit Engine"])
async def apply_for_credit(payload: CreditApplicationRequest,
                            api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    passport_sn = f"{payload.passport_series}{payload.passport_number}"
    extra_data = {
        'university_iban': payload.university_iban,
        'university_name': payload.university_name,
        'landlord_iban': payload.landlord_iban,
        'landlord_name': payload.landlord_name,
        'self_iban': payload.self_iban,
    }
    extra_data = {k: v for k, v in extra_data.items() if v is not None}
    result = await engine.process_loan_application(
        passport_sn=passport_sn,
        face_id_data=payload.face_id_data,
        guarantor_phone=payload.guarantor_phone,
        product_type=_product_to_engine(payload.product_type),
        amount_val=payload.amount,
        user_phone=payload.user_phone,
        date_of_birth=payload.date_of_birth,
        relation_type=(payload.guarantor_relation.value
                       if payload.guarantor_relation else None),
        extra_data=extra_data,
        request_id=payload.request_id)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/guarantor/approve", tags=["Guarantor"])
async def guarantor_approve(payload: GuarantorApproveRequest,
                              request: Request,
                              api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    passport_sn = f"{payload.passport_series}{payload.passport_number}"
    result = await engine.approve_guarantee(
        app_guarantor_id=payload.application_guarantor_id,
        otp_code=payload.otp_code,
        face_id_data=payload.face_id_data,
        passport_sn=passport_sn,
        client_ip=_client_ip(request))
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/guarantor/reject", tags=["Guarantor"])
async def guarantor_reject(payload: GuarantorRejectRequest,
                             api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    result = await engine.reject_guarantee(
        app_guarantor_id=payload.application_guarantor_id,
        reason=payload.reason)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/guarantor/resend-otp", tags=["Guarantor"])
async def guarantor_resend_otp(payload: GuarantorResendOTPRequest,
                                 request: Request,
                                 api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    result = await engine.resend_otp(
        app_guarantor_id=payload.application_guarantor_id,
        client_ip=_client_ip(request))
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/guarantor/register-card", tags=["Guarantor"])
async def guarantor_register_card(payload: CardRegisterRequest,
                                    api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    result = await engine.register_card(
        passport_series=payload.passport_series,
        passport_number=payload.passport_number,
        card_token=payload.card_token,
        card_masked=payload.card_masked,
        signature=payload.signature)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/repayment/pay", tags=["Repayment"])
async def repay(payload: PaymentRequest,
                 api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    result = await engine.pay_installment(
        installment_id=payload.installment_id,
        amount=payload.amount,
        idempotency_key=payload.idempotency_key)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/internal/guarantees/expire", tags=["Internal"])
async def expire_guarantees(
        api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    count = await engine._db_call_with_retry(engine._expire_ttl_sync)
    return {'expired': count, 'status': 'OK'}


@app.post("/api/v1/internal/auto-debit/run", tags=["Internal"])
async def run_auto_debit(
        api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    await engine._process_auto_debit_batch()
    return {'status': 'OK'}


@app.post("/api/v1/internal/auto-debit/recover", tags=["Internal"])
async def ops_recover(payload: OpsRecoveryRequest,
                        api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    result = await engine.ops_resolve_recovery(
        tx_id=payload.tx_id,
        resolution=payload.resolution,
        note=payload.note)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.get("/api/v1/internal/auto-debit/needs-recovery", tags=["Internal"])
async def list_needs_recovery(limit: int = 100,
                                api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    result = await engine.list_needs_recovery(limit=min(limit, 500))
    return result


@app.post("/api/v1/internal/overdue/run", tags=["Internal"])
async def run_overdue(
        api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    count = await engine._db_call_with_retry(engine._mark_overdue_sync)
    return {'marked': count, 'status': 'OK'}


@app.post("/api/v1/internal/cleanup/run", tags=["Internal"])
async def run_cleanup(
        api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    count = await engine._db_call_with_retry(engine._cleanup_idempotency_sync)
    otp_cleaned = await engine._db_call_with_retry(
        engine._cleanup_otp_rate_limit_sync)
    return {'cleaned': count, 'otp_cleaned': otp_cleaned, 'status': 'OK'}


@app.get("/api/v1/system/health", tags=["System"])
async def health():
    return await get_engine().health_check()


@app.get("/api/v1/system/ready", tags=["System"])
async def ready():
    result = await get_engine().health_check()
    if result['status'] != 'HEALTHY':
        raise HTTPException(503, detail=result)
    return result


@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    logger.exception(f'Unhandled: {scrub_pii(str(exc))}')
    return JSONResponse(
        status_code=500,
        content={'code': 'E2003', 'status': 'ERROR',
                 'reason': 'Internal server error.'})


class Application:
    def __init__(self):
        self.db_pool = DatabasePool(Config)
        self.engine: Optional[CreditEngine] = None

    def start(self):
        global _application_ref
        _application_ref = self

        Config.validate()

        keys = KeyManager().load()
        crypto = CryptoService(
            keys['master_key'], keys['hmac_key'],
            os.environ.get('CARD_SIGNATURE_KEY_HEX'))
        self.db_pool.initialize()

        client_cert = os.environ.get('INTERNAL_CLIENT_CERT')
        client_key = os.environ.get('INTERNAL_CLIENT_KEY')
        ca_cert = os.environ.get('INTERNAL_CA_CERT')

        if Config.ENV == 'production':
            common = {
                'client_cert': client_cert,
                'client_key': client_key,
                'ca_cert': ca_cert,
            }
        else:
            common = {
                'client_cert': client_cert if client_cert and client_key else None,
                'client_key': client_key if client_cert and client_key else None,
                'ca_cert': ca_cert,
            }

        cib = CIBClient(os.environ['CIB_URL'],
                        os.environ['CIB_API_KEY'], **common)
        face = FaceIDClient(os.environ['FACE_ID_URL'],
                            os.environ['FACE_ID_API_KEY'], **common)
        abs_client = ABSClient(os.environ['ABS_URL'],
                               os.environ['ABS_API_KEY'], **common)
        payment = PaymentGatewayClient(os.environ['PAYMENT_URL'],
                                       os.environ['PAYMENT_API_KEY'],
                                       **common)
        sms = SMSClient(os.environ['SMS_URL'],
                        os.environ['SMS_API_KEY'], **common)

        self.engine = CreditEngine(
            db_pool=self.db_pool, crypto=crypto,
            cib_client=cib, face_client=face,
            abs_client=abs_client, payment_client=payment,
            sms_client=sms)
        set_engine(self.engine)

        logger.info(
            f'Application initialized v3.8.1 (ENV={Config.ENV}, '
            f'leader_election={Config.LEADER_ELECTION_ENABLED})')

    def run(self):
        self.start()
        uvicorn.run(app, host='0.0.0.0',
                    port=int(os.environ.get('API_PORT', 8000)),
                    log_level='info')


if __name__ == '__main__':
    logging.basicConfig(
        level=os.environ.get('LOG_LEVEL', 'INFO'),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    Application().run()