
# -*- coding: utf-8 -*-
# ============================================================================
# TAJIK FINTECH CREDIT ENGINE
# Version: 3.8.1 (Security Patch) | PostgreSQL 13+ | Python 3.9+
# ============================================================================

import asyncio, base64, hashlib, hmac, json, logging, os, re, sys, time, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Optional, Tuple, Dict, Any, Set, List

import httpx
import asyncpg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import aiobreaker
from fastapi import FastAPI, HTTPException, Request, Depends, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, ConfigDict, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as StarletteJSON
import uvicorn

try:
    import hvac
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False


# ============================================================================
# PII SCRUBBING / ТОЗА КАРДАНИ PII
# ============================================================================
PII_KEYS = frozenset({
    'passport_sn', 'passport', 'passport_series', 'passport_number',
    'face_id_data', 'face_image', 'face_data', 'phone', 'user_phone',
    'guarantor_phone', 'card_token', 'self_iban', 'landlord_iban',
    'university_iban', 'master_key', 'hmac_key', 'api_key', 'password',
    'landlord_name', 'university_name', 'signature', 'internal_api_key',
})


def scrub_value(key, value):
    if value is None:
        return None
    if key and key.lower() in PII_KEYS:
        return '***'
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + '...'
    return value


def scrub_text(text):
    if text is None:
        return ''
    s = str(text)
    return s[:1000] + '...' if len(s) > 1000 else s


# ============================================================================
# LOGGING
# ============================================================================
class JSONFormatter(logging.Formatter):
    RESERVED = {
        'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
        'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
        'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
        'thread', 'threadName', 'processName', 'process', 'message',
        'asctime', 'taskName',
    }

    def format(self, record):
        obj = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': scrub_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith('_'):
                obj[key] = scrub_value(key, value)
        if record.exc_info:
            obj['exception'] = scrub_text(self.formatException(record.exc_info))
        return json.dumps(obj, ensure_ascii=False, default=str)


def setup_logging():
    log = logging.getLogger('credit_engine')
    handler = logging.StreamHandler(sys.stdout)
    if os.environ.get('LOG_FORMAT') == 'json':
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    log.handlers = [handler]
    log.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))
    return log


logger = setup_logging()

_START_TIME = time.time()


# ============================================================================
# DATE HELPERS
# ============================================================================
def add_months(d, months):
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1
    leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
    days_in_month = [31, 29 if leap else 28, 31, 30, 31, 30,
                     31, 31, 30, 31, 30, 31][month - 1]
    return date(year, month, min(d.day, days_in_month))


def add_days(d, days):
    return d + timedelta(days=int(days))


# ============================================================================
# KEY MANAGER
# ============================================================================
class KeyManager:
    def __init__(self):
        self._vault_url = os.environ.get('VAULT_URL')
        self._vault_token = os.environ.get('VAULT_TOKEN')
        self._vault_path = os.environ.get('VAULT_PATH', 'credit-engine/keys')

    def load(self):
        if self._vault_url and self._vault_token and VAULT_AVAILABLE:
            return self._load_vault()
        return self._load_env()

    def _load_vault(self):
        client = hvac.Client(url=self._vault_url, token=self._vault_token)
        if not client.is_authenticated():
            raise ValueError('Vault auth failed')
        secret = client.secrets.kv.v2.read_secret_version(path=self._vault_path)
        data = secret['data']['data']
        master, hmac_key = data.get('master_key'), data.get('hmac_key')
        if not master or not hmac_key:
            raise ValueError('Keys not found in Vault')
        if len(master) != 64 or len(hmac_key) != 64:
            raise ValueError('Keys must be 64 hex chars')
        return {'master_key': master, 'hmac_key': hmac_key}

    def _load_env(self):
        master = os.environ.get('MASTER_KEY_HEX')
        hmac_key = os.environ.get('HMAC_KEY_HEX')
        if not master or not hmac_key:
            raise ValueError('MASTER_KEY_HEX and HMAC_KEY_HEX required')
        if len(master) != 64 or len(hmac_key) != 64:
            raise ValueError('Keys must be 64 hex chars')
        return {'master_key': master, 'hmac_key': hmac_key}


# ============================================================================
# CRYPTO
# ============================================================================
def _validate_hex(key, name):
    if not key or not isinstance(key, str):
        raise ValueError(f'{name} is required')
    if len(key) != 64:
        raise ValueError(f'{name} must be 64 hex chars')
    try:
        bytes.fromhex(key)
    except ValueError:
        raise ValueError(f'{name} must contain only hex chars')


class CryptoService:
    def __init__(self, master_key_hex, hmac_key_hex, card_signature_key_hex=None):
        _validate_hex(master_key_hex, 'MASTER_KEY')
        _validate_hex(hmac_key_hex, 'HMAC_KEY')
        if card_signature_key_hex is not None:
            _validate_hex(card_signature_key_hex, 'CARD_SIGNATURE_KEY')
        self._aesgcm = AESGCM(bytes.fromhex(master_key_hex))
        self._hmac_key = bytes.fromhex(hmac_key_hex)
        self._card_sig_key = (bytes.fromhex(card_signature_key_hex)
                              if card_signature_key_hex else None)

    def encrypt(self, plain, aad=''):
        if not plain:
            return ''
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plain.encode('utf-8'),
                                  aad.encode('utf-8') if aad else None)
        return base64.b64encode(nonce + ct).decode('utf-8')

    def decrypt(self, cipher, aad=''):
        if not cipher:
            return ''
        data = base64.b64decode(cipher.encode('utf-8'))
        return self._aesgcm.decrypt(
            data[:12], data[12:],
            aad.encode('utf-8') if aad else None).decode('utf-8')

    def blind_index(self, plain):
        if not plain:
            return ''
        return hmac.new(self._hmac_key, plain.encode('utf-8'),
                        hashlib.sha256).hexdigest()

    def otp_hash(self, otp, ag_id):
        return hmac.new(self._hmac_key, f'otp:{ag_id}:{otp}'.encode(),
                        hashlib.sha256).hexdigest()

    def signature_hash(self, ag_id, otp, passport_hmac):
        return hmac.new(self._hmac_key,
                        f'sig:{ag_id}:{otp}:{passport_hmac}'.encode(),
                        hashlib.sha256).hexdigest()

    def verify_card_signature(self, passport_hmac, card_token, signature):
        if not self._card_sig_key:
            return False
        expected = hmac.new(self._card_sig_key,
                            f'card:{passport_hmac}:{card_token}'.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature or '')

    @staticmethod
    def idempotency_key(*parts):
        return hashlib.sha256(':'.join(str(p) for p in parts).encode()).hexdigest()


# ============================================================================
# DATABASE POOL
# ============================================================================
class DatabasePool:
    def __init__(self, config):
        self._config = config
        self._pool = None

    async def initialize(self):
        self._pool = await asyncpg.create_pool(
            host=self._config.DB_HOST, port=self._config.DB_PORT,
            database=self._config.DB_NAME, user=self._config.DB_USER,
            password=self._config.DB_PASSWORD,
            min_size=self._config.DB_POOL_MIN,
            max_size=self._config.DB_POOL_MAX,
            timeout=self._config.DB_CONNECT_TIMEOUT, command_timeout=30,
            server_settings={'application_name': 'credit_engine',
                             'statement_timeout': '30000', 'jit': 'off'},
            statement_cache_size=100, max_inactive_connection_lifetime=300)

    @asynccontextmanager
    async def acquire(self):
        async with self._pool.acquire() as conn:
            yield conn

    @asynccontextmanager
    async def transaction(self):
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def close(self):
        if self._pool:
            await self._pool.close()


# ============================================================================
# EXTERNAL CLIENTS
# ============================================================================
class ServiceUnavailable(Exception):
    pass


class BaseAsyncClient:
    def __init__(self, name, base_url, api_key, timeout=10,
                 client_cert=None, client_key=None, ca_cert=None,
                 fail_max=5, reset_timeout=60):
        self.name = name
        self.base_url = base_url
        limits = httpx.Limits(max_keepalive_connections=50,
                              max_connections=200, keepalive_expiry=30.0)
        verify = ca_cert if ca_cert else True
        cert = (client_cert, client_key) if (client_cert and client_key) else None
        self._client = httpx.AsyncClient(
            timeout=timeout, verify=verify, cert=cert, limits=limits,
            headers={'Authorization': f'Bearer {api_key}',
                     'Content-Type': 'application/json',
                     'User-Agent': f'credit-engine/{name}'})
        self._breaker = aiobreaker.CircuitBreaker(
            fail_max=fail_max,
            timeout_duration=timedelta(seconds=reset_timeout), name=name)

    async def _do_request(self, method, path, **kwargs):
        try:
            r = await self._client.request(method, f'{self.base_url}{path}', **kwargs)
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as e:
            logger.error(f'{self.name} HTTP {e.response.status_code} on {path}')
            raise ServiceUnavailable(f'{self.name} HTTP {e.response.status_code}')

    async def _call(self, method, path, **kwargs):
        return await self._breaker.call_async(self._do_request, method, path, **kwargs)

    async def close(self):
        await self._client.aclose()


class CIBClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('CIB', base_url, api_key,
                         timeout=kwargs.pop('timeout', 5), **kwargs)

    async def check(self, passport_sn):
        try:
            r = await self._call('POST', '/api/check',
                                 json={'passport': passport_sn})
            data = r.json()
            score, limit = data.get('score'), data.get('limit')
            if score is None or limit is None:
                raise ServiceUnavailable('CIB invalid response')
            return int(score), Decimal(str(limit))
        except aiobreaker.CircuitBreakerError:
            raise ServiceUnavailable('CIB circuit open')
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
            raise ServiceUnavailable('CIB unavailable')


class FaceIDClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('Face-ID', base_url, api_key,
                         timeout=kwargs.pop('timeout', 10), **kwargs)

    async def verify(self, face_image, passport_sn):
        try:
            r = await self._call('POST', '/api/verify',
                                 json={'image': face_image, 'passport': passport_sn})
            return bool(r.json().get('verified', False))
        except (aiobreaker.CircuitBreakerError, httpx.RequestError, httpx.HTTPStatusError):
            raise ServiceUnavailable('Face-ID unavailable')


class ABSClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('ABS', base_url, api_key,
                         timeout=kwargs.pop('timeout', 15), **kwargs)

    async def create_contract(self, passport_sn, amount, product,
                              target_iban, target_name, idem):
        try:
            r = await self._call('POST', '/api/contracts',
                json={'passport': passport_sn, 'amount': str(amount),
                      'product': product, 'target_iban': target_iban,
                      'target_name': target_name},
                headers={'X-Idempotency-Key': idem})
            return r.json()['contract_id']
        except (aiobreaker.CircuitBreakerError, httpx.RequestError, httpx.HTTPStatusError):
            raise ServiceUnavailable('ABS unavailable')


class PaymentGatewayClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('Payment', base_url, api_key,
                         timeout=kwargs.pop('timeout', 10),
                         fail_max=kwargs.pop('fail_max', 3), **kwargs)

    async def debit(self, card_token, amount, idem):
        try:
            r = await self._call('POST', '/api/debit',
                json={'card_token': card_token, 'amount': str(amount), 'no_accept': True},
                headers={'X-Idempotency-Key': idem})
            return r.json()
        except (aiobreaker.CircuitBreakerError, httpx.RequestError, httpx.HTTPStatusError):
            raise ServiceUnavailable('Payment unavailable')

    async def query_debit(self, idem):
        try:
            r = await self._call('GET', f'/api/debit/status/{idem}')
            return r.json()
        except Exception:
            return None


class SMSClient(BaseAsyncClient):
    def __init__(self, base_url, api_key, **kwargs):
        super().__init__('SMS', base_url, api_key,
                         timeout=kwargs.pop('timeout', 5),
                         fail_max=kwargs.pop('fail_max', 10), **kwargs)

    async def send(self, phone, message):
        try:
            await self._call('POST', '/api/send',
                             json={'phone': phone, 'message': message})
            return True
        except Exception:
            return False


# ============================================================================
# CONFIG
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
    MAX_REQUEST_SIZE = 1_048_576

    LEADER_ELECTION_ENABLED = os.environ.get(
        'LEADER_ELECTION_ENABLED', 'true').lower() == 'true'
    TRUSTED_PROXY_IPS = set(
        ip.strip() for ip in os.environ.get('TRUSTED_PROXY_IPS', '').split(',')
        if ip.strip())

    REQUIRED_ENV = (
        'DB_PASSWORD', 'API_KEY', 'CIB_URL', 'CIB_API_KEY',
        'FACE_ID_URL', 'FACE_ID_API_KEY', 'ABS_URL', 'ABS_API_KEY',
        'PAYMENT_URL', 'PAYMENT_API_KEY', 'SMS_URL', 'SMS_API_KEY',
        'CARD_SIGNATURE_KEY_HEX',
        # ИСЛОҲ (v3.8.2): SIGNING_SECRET пештар дар ин рӯйхат набуд,
        # бинобар ин сервер бе он ҳам бемалол оғоз мешуд ва ҳимояи
        # HMAC/X-Signature ба таври хомӯш ғайрифаъол мемонд.
        'SIGNING_SECRET')

    @classmethod
    def validate(cls):
        missing = [v for v in cls.REQUIRED_ENV if not os.environ.get(v)]
        if missing:
            raise ValueError(f'Missing env: {missing}')
        if cls.MIN_AGE_YEARS < 18:
            raise ValueError('MIN_AGE_YEARS >= 18')
        if cls.DB_POOL_MAX < cls.DB_POOL_MIN:
            raise ValueError('DB_POOL_MAX >= DB_POOL_MIN')
        if len(os.environ.get('CARD_SIGNATURE_KEY_HEX', '')) != 64:
            raise ValueError('CARD_SIGNATURE_KEY_HEX must be 64 hex')
        if len(os.environ.get('SIGNING_SECRET', '')) < 32:
            raise ValueError('SIGNING_SECRET must be >= 32 chars '
                              '(тавсия: 64 hex, openssl rand -hex 32)')
        if cls.ENV == 'production':
            api_key = os.environ.get('API_KEY', '')
            internal = os.environ.get('INTERNAL_API_KEY', '')
            if len(api_key) < 32:
                raise ValueError('API_KEY >= 32 chars')
            if not internal or len(internal) < 32:
                raise ValueError('INTERNAL_API_KEY >= 32 chars')
            if internal == api_key:
                raise ValueError('INTERNAL_API_KEY must differ from API_KEY')


# ============================================================================
# EXCEPTIONS
# ============================================================================
class GuarantorBusyError(Exception): pass
class GuarantorError(Exception): pass
class WrongOTPError(GuarantorError): pass
class TTLExpiredError(GuarantorError): pass


class Product:
    STUDENT_PAY = 'STUDENT_PAY'
    DAILY_PAY = 'DAILY_PAY'
    RENT_PAY = 'RENT_PAY'


# ============================================================================
# LEADER ELECTION
# ============================================================================
class LeaderElection:
    BASE_LOCK_ID = 0x5A1D3F0C7B2E4A00

    def __init__(self, db_pool, name, slot, enabled=True):
        self.db = db_pool
        self.name = name
        self.lock_id = self.BASE_LOCK_ID + slot
        self.enabled = enabled
        self._is_leader = not enabled
        self._lock_conn = None

    async def try_acquire(self):
        if not self.enabled:
            return True
        if self._is_leader and await self._check_alive():
            return True
        if self._is_leader and not await self._check_alive():
            await self._release()
        try:
            conn = await self.db._pool.acquire()
            row = await conn.fetchrow(
                'SELECT pg_try_advisory_lock($1) AS acquired', self.lock_id)
            if row and row['acquired']:
                self._lock_conn = conn
                self._is_leader = True
                logger.info(f'Leader elected: {self.name}')
                return True
            await self.db._pool.release(conn)
            self._is_leader = False
            return False
        except Exception as e:
            logger.warning(f'Leader election error [{self.name}]: {scrub_text(str(e))}')
            self._is_leader = False
            return False

    async def _check_alive(self):
        if self._lock_conn is None:
            return False
        try:
            await self._lock_conn.fetchrow('SELECT 1')
            return True
        except Exception:
            await self._release()
            return False

    async def _release(self):
        if self._lock_conn is not None:
            try:
                await self.db._pool.release(self._lock_conn)
            except Exception:
                pass
            self._lock_conn = None
        self._is_leader = False

    async def release(self):
        if self._lock_conn is not None:
            try:
                await self._lock_conn.fetchrow(
                    'SELECT pg_advisory_unlock($1)', self.lock_id)
            except Exception:
                pass
        await self._release()

    @property
    def is_leader(self):
        return self._is_leader


# ============================================================================
# CREDIT ENGINE
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
        self._bg_tasks = set()
        self._auto_debit_task = None
        self._ttl_task = None
        self._overdue_task = None
        self._cleanup_task = None
        self._shutdown_event = asyncio.Event()
        self._config_cache = {}
        self._config_cache_ts = 0.0
        self._config_cache_ttl = 60.0

        self._leader_auto_debit = LeaderElection(db_pool, 'auto_debit', 1,
                                                  Config.LEADER_ELECTION_ENABLED)
        self._leader_ttl = LeaderElection(db_pool, 'ttl_expiry', 2,
                                           Config.LEADER_ELECTION_ENABLED)
        self._leader_overdue = LeaderElection(db_pool, 'overdue', 3,
                                               Config.LEADER_ELECTION_ENABLED)
        self._leader_cleanup = LeaderElection(db_pool, 'cleanup', 4,
                                               Config.LEADER_ELECTION_ENABLED)

    @staticmethod
    def money_round(val):
        return Decimal(str(val)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    async def _load_product_config(self, product):
        now = time.time()
        if (now - self._config_cache_ts) < self._config_cache_ttl:
            return self._config_cache.get(product)
        async with self.db.acquire() as conn:
            rows = await conn.fetch("""
                SELECT product_type, min_amount, max_amount,
                       no_guarantor_limit, commission_rate,
                       insurance_rate, transfer_comm_rate,
                       term_months, pti_max_ratio,
                       grace_days, daily_penalty_rate, interest_rate, term_days
                FROM product_config
            """)
        cache = {}
        for r in rows:
            cache[r['product_type']] = {
                'min_amount': Decimal(str(r['min_amount'])),
                'max_amount': Decimal(str(r['max_amount'])),
                'no_guarantor_limit': Decimal(str(r['no_guarantor_limit'])),
                'commission_rate': Decimal(str(r['commission_rate'])),
                'insurance_rate': Decimal(str(r['insurance_rate'])),
                'transfer_comm_rate': Decimal(str(r['transfer_comm_rate'])),
                'term_months': int(r['term_months'] or 0),
                'pti_max_ratio': Decimal(str(r['pti_max_ratio'])),
                'grace_days': int(r['grace_days'] or 0),
                'daily_penalty_rate': Decimal(str(r['daily_penalty_rate'] or 0)),
                'interest_rate': Decimal(str(r['interest_rate'] or 0)),
                'term_days': int(r['term_days'] or 0)}
        self._config_cache = cache
        self._config_cache_ts = time.time()
        return cache.get(product)

    @staticmethod
    def _iban_ok(iban):
        iban = iban.replace(' ', '').upper()
        if len(iban) < 15 or len(iban) > 34:
            return False
        if not iban[:2].isalpha() or not iban[2:4].isdigit():
            return False
        if not iban[4:].isalnum():
            return False
        rearranged = iban[4:] + iban[:4]
        try:
            converted = ''.join(str(int(c, 36)) for c in rearranged)
            return int(converted) % 97 == 1
        except Exception:
            return False

    def _validate_product(self, product_type, extra_data):
        if product_type == Product.RENT_PAY:
            iban = extra_data.get('landlord_iban', '')
            if not iban:
                return False, 'Landlord IBAN required.'
            if not self._iban_ok(iban):
                return False, 'Invalid landlord IBAN format.'
        elif product_type == Product.STUDENT_PAY:
            iban = extra_data.get('university_iban', '')
            if not iban:
                return False, 'University IBAN required.'
            if not self._iban_ok(iban):
                return False, 'Invalid university IBAN format.'
        elif product_type == Product.DAILY_PAY:
            iban = extra_data.get('self_iban')
            if iban and not self._iban_ok(iban):
                return False, 'Invalid self IBAN format.'
        return True, ''

    def _check_pti(self, user_income, guarantor_income, monthly_payment, max_ratio):
        total = Decimal(str(user_income or 0)) + Decimal(str(guarantor_income or 0))
        if total <= Decimal('0'):
            return False, 'Total income insufficient.'
        pti = (Decimal(str(monthly_payment)) / total).quantize(
            Decimal('0.0001'), rounding=ROUND_HALF_UP)
        if pti > max_ratio:
            return False, f'PTI {pti:.2%} exceeds {max_ratio:.0%}'
        return True, ''

    async def process_loan_application(self, passport_sn, face_id_data,
                                        guarantor_phone, product_type,
                                        amount_val, user_phone, date_of_birth,
                                        relation_type=None, extra_data=None,
                                        request_id=None, client_ip=None):
        start = time.time()
        amount = Decimal(str(amount_val))
        extra_data = extra_data or {}
        request_id = request_id or str(uuid.uuid4())

        logger.info('Processing loan', extra={
            'product': product_type, 'amount': float(amount),
            'request_id': request_id})

        try:
            dob = (date.fromisoformat(date_of_birth)
                   if isinstance(date_of_birth, str) else date_of_birth)
        except Exception:
            return self._error('E1012', 'Invalid date of birth.', 400)

        age = (date.today() - dob).days // 365
        if age < Config.MIN_AGE_YEARS:
            return self._error('E1012',
                f'Age must be >= {Config.MIN_AGE_YEARS}.', 400)

        cfg = await self._load_product_config(product_type)
        if not cfg:
            return self._error('E1001', 'Unknown product.', 400)
        if not (cfg['min_amount'] <= amount <= cfg['max_amount']):
            return self._error('E1001',
                f"Amount must be {cfg['min_amount']}-{cfg['max_amount']} TJS.", 400)

        valid, err = self._validate_product(product_type, extra_data)
        if not valid:
            return self._error('E1006', err, 400)

        passport_hmac = self.crypto.blind_index(passport_sn)

        try:
            application_id = await self._stage1_create_pending(
                passport_hmac, product_type, amount, request_id, client_ip)
            if application_id is None:
                return self._error('E1010', 'Too many requests.', 429)
            if isinstance(application_id, dict):
                return application_id
        except asyncpg.UniqueViolationError:
            return self._error('E0002', 'Duplicate request.', 409)
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Stage 1 failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

        stage2 = await self._run_face_and_cib(passport_sn, face_id_data)
        if stage2['status'] != 'OK':
            if stage2['status'] == 'REJECTED':
                await self._mark_status(application_id, stage2['reason_code'],
                                        passport_hmac, stage2['reason'])
                return stage2['response']
            await self._mark_error(application_id, 'ERROR_EXTERNAL',
                                   'external service unavailable')
            return stage2['response']

        try:
            abs_id = await self._call_abs(passport_sn, amount, product_type,
                                           extra_data, request_id)
        except ServiceUnavailable:
            await self._mark_error(application_id, 'ABS_FAILED', 'ABS unavailable')
            return self._error('E2001', 'ABS unavailable.', 503)

        try:
            result = await self._stage4_finalize(
                application_id, passport_sn, passport_hmac, amount,
                product_type, user_phone, guarantor_phone, relation_type,
                dob, extra_data, abs_id, stage2['cib_result'], cfg)
            logger.info(f'Done: app_id={application_id}, '
                        f'status={result.get("status")}, '
                        f'duration={time.time() - start:.2f}s')
        except GuarantorBusyError:
            await self._mark_error(application_id, 'ERROR_PHASE3', 'guarantor busy')
            return self._error('E1011', 'Guarantor already has an active guarantee.', 409)
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except asyncpg.DataError:
            return self._error('E2004', 'Invalid data format.', 400)
        except Exception as e:
            logger.exception(f'Stage 4 failed: {scrub_text(str(e))}')
            await self._mark_error(application_id, 'ERROR_PHASE3', 'stage4 failure')
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

    async def _stage1_create_pending(self, passport_hmac, product_type,
                                      amount, request_id, client_ip=None):
        async with self.db.transaction() as conn:
            existing = await conn.fetchrow(
                'SELECT id FROM applications WHERE request_id = $1', request_id)
            if existing:
                return {'code': 'E0002', 'status': 'DUPLICATE',
                        'application_id': existing['id'],
                        'reason': 'Request already processed.',
                        'http_status': 409}
            lock_key = int(passport_hmac[:15], 16) & 0x7FFFFFFFFFFFFFFF
            await conn.execute('SELECT pg_advisory_xact_lock($1)', lock_key)

            # ИСЛОҲ (v3.8.2): пештар _check_velocity/_record_velocity
            # (VelocityMixin, extensions_v381.py) дар ин ҷо ҳаргиз даъват
            # намешуданд — яъне лимитҳои 5/сония, 20/соат, 10,000 TJS/рӯз,
            # 100,000 TJS/моҳ амалан ҳеҷ гоҳ иҷро намешуданд. Ҳоло, агар
            # extensions бор шуда бошанд, пеш аз сабти ариза санҷиш иҷро
            # мешавад ва баъд аз сабт дархост дар velocity_log қайд мешавад.
            if hasattr(self, '_check_velocity'):
                ok, err_code, reason = await self._check_velocity(
                    conn, passport_hmac, amount, client_ip)
                if not ok:
                    return {'code': err_code, 'status': 'VELOCITY_BLOCKED',
                            'reason': reason, 'http_status': 429}

            count_row = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt FROM applications
                WHERE passport_sn_hmac = $1
                  AND created_at > NOW() - INTERVAL '1 hour'
            """, passport_hmac)
            if count_row['cnt'] >= Config.RATE_LIMIT_PER_HOUR:
                return None
            now = datetime.now(timezone.utc)
            row = await conn.fetchrow("""
                INSERT INTO applications
                    (passport_sn_hmac, product_type, amount, status,
                     request_id, created_at, updated_at)
                VALUES ($1, $2, $3, 'PENDING_CHECKS', $4, $5, $6)
                RETURNING id
            """, passport_hmac, product_type, str(amount), request_id, now, now)

            if hasattr(self, '_record_velocity'):
                await self._record_velocity(conn, passport_hmac, amount,
                                             client_ip)

            return row['id']

    async def _run_face_and_cib(self, passport_sn, face_id_data):
        try:
            if not await self.face.verify(face_id_data, passport_sn):
                return self._reject('E1008', 'BIOMETRIC_FAILED',
                                    'Biometric verification failed.')
        except ServiceUnavailable:
            return self._ext_error('Face-ID unavailable')
        try:
            cib_score, cib_limit = await self.cib.check(passport_sn)
            if cib_score < 500:
                return self._reject('E1009', 'CIB_REJECTED',
                                    f'CIB score too low: {cib_score}')
        except ServiceUnavailable:
            return self._ext_error('CIB unavailable')
        return {'status': 'OK',
                'cib_result': {'score': cib_score, 'limit': cib_limit}}

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

    async def _stage4_finalize(self, app_id, passport_sn, passport_hmac,
                                amount, product_type, user_phone, guarantor_phone,
                                relation_type, dob, extra_data, abs_id, cib_result, cfg):
        async with self.db.transaction() as conn:
            lock_key = int(passport_hmac[:15], 16) & 0x7FFFFFFFFFFFFFFF
            await conn.execute('SELECT pg_advisory_xact_lock($1)', lock_key)
            user_id = await self._upsert_user(conn, passport_sn, passport_hmac,
                                              user_phone, dob,
                                              cib_result['score'], cib_result['limit'])
            await conn.execute('UPDATE applications SET user_id = $1 WHERE id = $2',
                               user_id, app_id)
            blocked = await conn.fetchrow(
                'SELECT is_blocked FROM users WHERE id = $1', user_id)
            if blocked and blocked['is_blocked']:
                return await self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1015', 'User is blocked. Contact support.', 403))
            active = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt FROM loan_disbursements
                WHERE passport_sn_hmac = $1
                  AND status IN ('ACTIVE','PENDING_DISBURSEMENT')
            """, passport_hmac)
            if active['cnt'] > 0:
                return await self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1013', 'User already has an active loan.', 409))
            user = await conn.fetchrow(
                'SELECT id, card_turnover_3m, monthly_income FROM users WHERE id = $1',
                user_id)
            user_income = (Decimal(str(user['monthly_income'] or 0))
                           if user else Decimal('0'))

            if product_type == Product.RENT_PAY:
                result = await self._finalize_rent_pay(
                    conn, app_id, passport_sn, passport_hmac, amount, user_id,
                    user_income, guarantor_phone, relation_type, extra_data, abs_id, cfg)
            elif product_type == Product.STUDENT_PAY:
                result = await self._finalize_student_pay(
                    conn, app_id, passport_sn, passport_hmac, amount, user_id,
                    user_income, guarantor_phone, relation_type, extra_data, abs_id, cfg)
            elif product_type == Product.DAILY_PAY:
                result = await self._finalize_daily_pay(
                    conn, app_id, passport_sn, passport_hmac, amount, user_id,
                    user_income, guarantor_phone, relation_type, extra_data, abs_id, cfg)
            else:
                return await self._fail_app(conn, app_id, passport_hmac,
                    self._error('E1002', 'Unknown product.', 400))

            if isinstance(result, dict) and result.get('http_status', 200) >= 400:
                await self._fail_app(conn, app_id, passport_hmac, result)
            return result

    async def _fail_app(self, conn, app_id, passport_hmac, err_dict):
        hs = err_dict.get('http_status', 500)
        if 400 <= hs < 500:
            reason = err_dict.get('reason', '')
            await self._update_status(conn, app_id, 'REJECTED', reason)
            await self._cancel_pending_loan(conn, app_id, reason)
            await self._audit(conn, 'APP_REJECTED', app_id, passport_hmac, reason)
        return err_dict

    async def _cancel_pending_loan(self, conn, app_id, reason):
        result = await conn.execute("""
            UPDATE loan_disbursements
            SET status = 'CANCELLED'::loan_status_enum,
                cancelled_at = NOW(), cancellation_reason = $1, closed_at = NOW()
            WHERE application_id = $2 AND status = 'PENDING_DISBURSEMENT'
        """, scrub_text(reason)[:500], app_id)
        if result and result.split()[-1] != '0':
            logger.info(f'Cancelled pending loan app_id={app_id}')

    async def _finalize_rent_pay(self, conn, app_id, passport_sn, passport_hmac,
                                  amount, user_id, user_income, guarantor_phone,
                                  relation_type, extra_data, abs_id, cfg):
        if not guarantor_phone:
            return self._error('E1003', 'Guarantor required for RentPay.', 400)
        guarantor = await self._find_user_by_phone(conn, guarantor_phone, for_update=True)
        if not guarantor:
            return self._error('E1004', 'Guarantor not found.', 404)
        if guarantor['id'] == user_id:
            return self._error('E1014', 'Guarantor cannot be same as user.', 400)
        if guarantor['turnover'] < Decimal('1000'):
            return self._error('E1005', 'Guarantor turnover insufficient.', 400)
        pti_ok, pti_err = self._check_pti(
            user_income, guarantor['monthly_income'], amount, cfg['pti_max_ratio'])
        if not pti_ok:
            return self._error('E1007', pti_err, 400)

        landlord_iban = extra_data.get('landlord_iban')
        commission = self.money_round(amount * cfg['commission_rate'])
        net = self.money_round(amount - commission)
        loan_id = await self._create_loan(
            conn, app_id, passport_hmac, guarantor['id'], amount, commission, net,
            abs_id, 'RENT_PAY', 'LANDLORD', landlord_iban,
            extra_data.get('landlord_name', 'Landlord'))
        rent_days = cfg.get('term_days') or 15
        await self._create_repayment_schedule(conn, loan_id, amount, days=rent_days)
        ag_id, otp = await self._create_guarantee(
            conn, app_id, guarantor['id'], guarantor_phone, relation_type)
        await self._update_status(conn, app_id, 'PENDING_GUARANTOR')
        await self._audit(conn, 'RENT_PAY_PENDING', app_id, passport_hmac,
                          f'Amount={amount} days={rent_days}')
        return {'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
                'application_id': app_id, 'loan_id': loan_id,
                'commission': str(commission), 'net': str(net),
                'target_iban': landlord_iban, 'abs_contract_id': abs_id,
                'guarantor_id': ag_id, 'term_days': rent_days,
                'interest_rate': '0', 'http_status': 200,
                '_notify_phone': guarantor_phone,
                '_otp_code': otp, '_app_guarantor_id': ag_id}

    async def _finalize_student_pay(self, conn, app_id, passport_sn, passport_hmac,
                                     amount, user_id, user_income, guarantor_phone,
                                     relation_type, extra_data, abs_id, cfg):
        if not guarantor_phone:
            return self._error('E1003', 'Guarantor required for StudentPay.', 400)
        guarantor = await self._find_user_by_phone(conn, guarantor_phone, for_update=True)
        if not guarantor:
            return self._error('E1004', 'Guarantor not found.', 404)
        if guarantor['id'] == user_id:
            return self._error('E1014', 'Guarantor cannot be same as user.', 400)
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
        await self._create_insurance(conn, app_id, passport_hmac, insurance, margin, interest)
        loan_id = await self._create_loan(
            conn, app_id, passport_hmac, guarantor['id'], amount, comm, net,
            abs_id, 'STUDENT_PAY', 'UNIVERSITY', university_iban,
            extra_data.get('university_name', 'University'))
        await self._create_repayment_schedule(conn, loan_id, total, months=months)
        ag_id, otp = await self._create_guarantee(
            conn, app_id, guarantor['id'], guarantor_phone, relation_type)
        await self._update_status(conn, app_id, 'PENDING_GUARANTOR')
        await self._audit(conn, 'STUDENT_PAY_PENDING', app_id, passport_hmac,
                          f'Amount={amount}')
        return {'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
                'application_id': app_id, 'loan_id': loan_id,
                'gross_loan': str(total), 'insurance': str(insurance),
                'interest': str(interest), 'transfer_commission': str(comm),
                'net_transferred': str(net), 'target_iban': university_iban,
                'abs_contract_id': abs_id, 'guarantor_id': ag_id,
                'http_status': 200, '_notify_phone': guarantor_phone,
                '_otp_code': otp, '_app_guarantor_id': ag_id}

    async def _finalize_daily_pay(self, conn, app_id, passport_sn, passport_hmac,
                                   amount, user_id, user_income, guarantor_phone,
                                   relation_type, extra_data, abs_id, cfg):
        target_iban = extra_data.get('self_iban', '')
        commission = self.money_round(amount * cfg['commission_rate'])
        net = self.money_round(amount - commission)
        daily_days = cfg.get('term_days') or 7

        if amount > cfg['no_guarantor_limit']:
            if not guarantor_phone:
                return self._error('E1003',
                    f'Amount > {cfg["no_guarantor_limit"]} requires guarantor.', 400)
            guarantor = await self._find_user_by_phone(conn, guarantor_phone, for_update=True)
            if not guarantor:
                return self._error('E1004', 'Guarantor not found.', 404)
            if guarantor['id'] == user_id:
                return self._error('E1014', 'Guarantor cannot be same as user.', 400)
            pti_ok, pti_err = self._check_pti(
                user_income, guarantor['monthly_income'], amount, cfg['pti_max_ratio'])
            if not pti_ok:
                return self._error('E1007', pti_err, 400)
            loan_id = await self._create_loan(
                conn, app_id, passport_hmac, guarantor['id'], amount, commission, net,
                abs_id, 'DAILY_PAY', 'SELF', target_iban, 'Customer')
            await self._create_repayment_schedule(conn, loan_id, amount, days=daily_days)
            ag_id, otp = await self._create_guarantee(
                conn, app_id, guarantor['id'], guarantor_phone, relation_type)
            await self._update_status(conn, app_id, 'PENDING_GUARANTOR')
            await self._audit(conn, 'DAILY_PAY_PENDING', app_id, passport_hmac,
                              f'Amount={amount} days={daily_days}')
            return {'code': 'E0001', 'status': 'PENDING_GUARANTOR_APPROVAL',
                    'application_id': app_id, 'loan_id': loan_id,
                    'commission': str(commission), 'net': str(net),
                    'abs_contract_id': abs_id, 'guarantor_id': ag_id,
                    'term_days': daily_days, 'http_status': 200,
                    '_notify_phone': guarantor_phone,
                    '_otp_code': otp, '_app_guarantor_id': ag_id}

        if user_income > Decimal('0'):
            pti_ok, pti_err = self._check_pti(
                user_income, Decimal('0'), amount, cfg['pti_max_ratio'])
            if not pti_ok:
                return self._error('E1007', pti_err, 400)

        loan_id = await self._create_loan(
            conn, app_id, passport_hmac, None, amount, commission, net,
            abs_id, 'DAILY_PAY', 'SELF', target_iban, 'Customer')
        await self._create_repayment_schedule(conn, loan_id, amount, days=daily_days)
        await conn.execute("""
            UPDATE loan_disbursements SET status='ACTIVE', disbursed_at=NOW() WHERE id=$1
        """, loan_id)
        await self._update_status(conn, app_id, 'APPROVED')
        await self._audit(conn, 'DAILY_PAY_APPROVED', app_id, passport_hmac,
                          f'Amount={amount} days={daily_days}')
        return {'code': 'E0000', 'status': 'APPROVED',
                'application_id': app_id, 'loan_id': loan_id,
                'gross_loan': str(amount), 'commission': str(commission),
                'net': str(net), 'abs_contract_id': abs_id,
                'term_days': daily_days, 'http_status': 200}

    async def _upsert_user(self, conn, passport_sn, passport_hmac, phone, dob,
                           cib_score, cib_limit):
        phone_hmac = self.crypto.blind_index(phone)
        enc_passport = self.crypto.encrypt(passport_sn, aad=f'passport:{passport_hmac}')
        enc_phone = self.crypto.encrypt(phone, aad=f'phone:{phone_hmac}')
        row = await conn.fetchrow("""
            INSERT INTO users
                (passport_sn_hmac, passport_sn_encrypted, phone_hmac,
                 phone_encrypted, date_of_birth, cib_score,
                 approved_limit, cib_checked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (passport_sn_hmac) DO UPDATE SET
                phone_hmac = EXCLUDED.phone_hmac,
                phone_encrypted = EXCLUDED.phone_encrypted,
                date_of_birth = COALESCE(EXCLUDED.date_of_birth, users.date_of_birth),
                cib_score = EXCLUDED.cib_score,
                approved_limit = EXCLUDED.approved_limit,
                cib_checked_at = EXCLUDED.cib_checked_at
            RETURNING id
        """, passport_hmac, enc_passport, phone_hmac, enc_phone,
            dob, cib_score, str(cib_limit), datetime.now(timezone.utc))
        return row['id']

    async def _find_user_by_phone(self, conn, phone, for_update=False):
        if not phone:
            return None
        phone_hmac = self.crypto.blind_index(phone)
        q = ('SELECT id, card_turnover_3m, monthly_income '
             'FROM users WHERE phone_hmac = $1')
        if for_update:
            q += ' FOR UPDATE'
        row = await conn.fetchrow(q, phone_hmac)
        if row:
            return {'id': row['id'],
                    'turnover': Decimal(str(row['card_turnover_3m'] or 0)),
                    'monthly_income': Decimal(str(row['monthly_income'] or 0))}
        return None

    async def _create_guarantee(self, conn, app_id, guarantor_user_id,
                                 guarantor_phone, relation_type):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=Config.GUARANTOR_TTL_HOURS)
        otp_expires = now + timedelta(minutes=Config.OTP_TTL_MINUTES)
        phone_hmac = (self.crypto.blind_index(guarantor_phone)
                      if guarantor_phone else None)

        await conn.execute("""
            INSERT INTO guarantors (user_id, phone_hmac, relation_default)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id) DO UPDATE
                SET phone_hmac = EXCLUDED.phone_hmac,
                    relation_default = COALESCE(EXCLUDED.relation_default,
                                                guarantors.relation_default)
        """, guarantor_user_id, phone_hmac, relation_type)

        row = await conn.fetchrow(
            'SELECT active_guarantee_id FROM guarantors WHERE user_id = $1 FOR UPDATE',
            guarantor_user_id)
        if row is None:
            raise GuarantorBusyError('Guarantor profile not found')
        if row['active_guarantee_id'] is not None:
            raise GuarantorBusyError('Guarantor already has active guarantee')

        otp_code = f'{int.from_bytes(os.urandom(3), "big") % 1000000:06d}'
        ag_row = await conn.fetchrow("""
            INSERT INTO application_guarantors
                (application_id, guarantor_user_id, relation_type, phone_hmac,
                 approval_status, otp_expires_at, otp_last_sent_at,
                 otp_send_count, ttl_expires_at)
            VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, 1, $7)
            RETURNING id
        """, app_id, guarantor_user_id, relation_type, phone_hmac,
            otp_expires, now, expires)
        ag_id = ag_row['id']

        otp_hash = self.crypto.otp_hash(otp_code, ag_id)
        await conn.execute(
            'UPDATE application_guarantors SET otp_code_hash = $1 WHERE id = $2',
            otp_hash, ag_id)
        await conn.execute("""
            UPDATE guarantors SET active_guarantee_id = $1, updated_at = $2
            WHERE user_id = $3
        """, ag_id, now, guarantor_user_id)
        await conn.execute("""
            INSERT INTO guarantor_ttl_log
                (application_id, application_guarantor_id, sent_at, expires_at,
                 status, sms_status, sms_attempts)
            VALUES ($1, $2, $3, $4, 'SENT', 'PENDING', 0)
        """, app_id, ag_id, now, expires)
        return ag_id, otp_code

    async def _close_guarantee(self, conn, ag_id, new_status):
        now = datetime.now(timezone.utc)
        if new_status == 'REJECTED':
            row = await conn.fetchrow("""
                UPDATE application_guarantors
                SET approval_status = 'REJECTED', closed_at = $1, rejected_at = $1
                WHERE id = $2 AND approval_status IN ('PENDING', 'APPROVED')
                RETURNING guarantor_user_id
            """, now, ag_id)
        else:
            row = await conn.fetchrow("""
                UPDATE application_guarantors
                SET approval_status = $1, closed_at = $2
                WHERE id = $3 AND approval_status IN ('PENDING', 'APPROVED')
                RETURNING guarantor_user_id
            """, new_status, now, ag_id)
        if row is None:
            return
        await conn.execute("""
            UPDATE guarantors SET active_guarantee_id = NULL, updated_at = $1
            WHERE user_id = $2 AND active_guarantee_id = $3
        """, now, row['guarantor_user_id'], ag_id)

    async def approve_guarantee(self, ag_id, otp_code, face_id_data,
                                 passport_sn, client_ip=None):
        try:
            expected_hmac = await self._get_guarantor_passport_hmac(ag_id)
            if not expected_hmac:
                return self._error('E1004', 'Guarantee not found.', 404)
        except Exception:
            return self._error('E2002', 'Database error.', 500)

        provided = self.crypto.blind_index(passport_sn)
        if not hmac.compare_digest(provided, expected_hmac):
            return self._error('E1014', 'Passport does not match the guarantor.', 400)

        try:
            ok = await self.face.verify(face_id_data, passport_sn)
            if not ok:
                return self._error('E1008', 'Biometric failed.', 400)
        except ServiceUnavailable:
            return self._error('E2001', 'Face-ID unavailable.', 503)

        try:
            phone_hmac = await self._get_guarantor_phone_hmac(ag_id)
            if not phone_hmac:
                return self._error('E1004', 'Guarantee not found.', 404)
            allowed = await self._check_otp_rate_limit(phone_hmac, client_ip)
            if not allowed:
                return self._error('E1021', 'Too many OTP attempts. Try later.', 429)
        except Exception:
            pass

        try:
            result = await self._approve_guarantee_tx(ag_id, otp_code)
            try:
                await self._record_otp_attempt(phone_hmac, client_ip, True)
            except Exception:
                pass
            return {**result, 'http_status': 200}
        except TTLExpiredError:
            try:
                await self._force_expire(ag_id)
            except Exception:
                pass
            return self._error('E1020', 'Guarantee expired.', 400)
        except WrongOTPError:
            try:
                await self._increment_otp_attempts(ag_id)
            except Exception:
                pass
            try:
                await self._record_otp_attempt(phone_hmac, client_ip, False)
            except Exception:
                pass
            return self._error('E1020', 'Invalid OTP.', 400)
        except GuarantorError as e:
            return self._error('E1020', str(e), 400)
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Approve failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def _get_guarantor_passport_hmac(self, ag_id):
        async with self.db.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT u.passport_sn_hmac FROM application_guarantors ag
                JOIN users u ON u.id = ag.guarantor_user_id
                WHERE ag.id = $1
            """, ag_id)
            return row['passport_sn_hmac'] if row else None

    async def _get_guarantor_phone_hmac(self, ag_id):
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT phone_hmac FROM application_guarantors WHERE id = $1', ag_id)
            return row['phone_hmac'] if row else None

    async def _get_guarantor_phone(self, ag_id):
        async with self.db.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT u.phone_encrypted, u.phone_hmac
                FROM application_guarantors ag
                JOIN users u ON u.id = ag.guarantor_user_id
                WHERE ag.id = $1
            """, ag_id)
            if not row or not row['phone_encrypted']:
                return None
            return self.crypto.decrypt(
                row['phone_encrypted'], aad=f'phone:{row["phone_hmac"]}')

    async def _check_otp_rate_limit(self, phone_hmac, client_ip):
        async with self.db.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt FROM otp_rate_limit
                WHERE phone_hmac = $1 AND attempted_at > NOW() - INTERVAL '1 hour'
            """, phone_hmac)
            if row['cnt'] >= Config.OTP_RATE_LIMIT_PER_HOUR:
                return False
            if client_ip:
                r2 = await conn.fetchrow("""
                    SELECT COUNT(*) AS cnt FROM otp_rate_limit
                    WHERE client_ip = $1 AND attempted_at > NOW() - INTERVAL '1 hour'
                """, client_ip)
                if r2['cnt'] >= Config.OTP_RATE_LIMIT_PER_HOUR:
                    return False
            return True

    async def _record_otp_attempt(self, phone_hmac, client_ip, success):
        async with self.db.transaction() as conn:
            await conn.execute("""
                INSERT INTO otp_rate_limit (phone_hmac, client_ip, success)
                VALUES ($1, $2, $3)
            """, phone_hmac, client_ip, success)

    async def _approve_guarantee_tx(self, ag_id, otp_code):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT ag.application_id, ag.guarantor_user_id,
                       ag.approval_status, ag.otp_code_hash,
                       ag.otp_expires_at, ag.otp_attempts, ag.ttl_expires_at,
                       u.passport_sn_hmac AS g_hmac
                FROM application_guarantors ag
                JOIN users u ON u.id = ag.guarantor_user_id
                WHERE ag.id = $1 FOR UPDATE
            """, ag_id)
            if not row:
                raise GuarantorError('Guarantee not found')
            if row['approval_status'] != 'PENDING':
                raise GuarantorError(f'Status is {row["approval_status"]}')
            now = datetime.now(timezone.utc)
            if row['ttl_expires_at'] and row['ttl_expires_at'] < now:
                raise TTLExpiredError('Guarantee TTL expired')
            if row['otp_expires_at'] and row['otp_expires_at'] < now:
                raise GuarantorError('OTP expired')
            if row['otp_attempts'] >= Config.OTP_MAX_ATTEMPTS:
                raise GuarantorError('Too many OTP attempts')
            expected = self.crypto.otp_hash(otp_code, ag_id)
            if not hmac.compare_digest(expected, row['otp_code_hash'] or ''):
                raise WrongOTPError('Invalid OTP')
            sig = self.crypto.signature_hash(ag_id, otp_code, row['g_hmac'])
            app_id = row['application_id']
            g_user_id = row['guarantor_user_id']
            await conn.execute("""
                UPDATE application_guarantors
                SET approval_status = 'APPROVED', approved_at = $1, signature_hash = $2
                WHERE id = $3
            """, now, sig, ag_id)
            await conn.execute("""
                UPDATE guarantors
                SET face_id_passed = TRUE, sms_otp_confirmed = TRUE,
                    guarantee_signature = $1, signature_signed_at = $2
                WHERE user_id = $3
            """, sig, now, g_user_id)
            await conn.execute("""
                UPDATE guarantor_ttl_log SET approved_at = $1, status = 'APPROVED'
                WHERE application_guarantor_id = $2
            """, now, ag_id)
            await conn.execute("""
                UPDATE applications SET status = 'APPROVED', error_reason = NULL,
                    updated_at = $1 WHERE id = $2
            """, now, app_id)
            await conn.execute("""
                UPDATE loan_disbursements SET status='ACTIVE', disbursed_at=NOW()
                WHERE application_id = $1
            """, app_id)
            await self._audit(conn, 'GUARANTEE_APPROVED', app_id, row['g_hmac'],
                              f'ag_id={ag_id}')
            return {'application_id': app_id, 'status': 'APPROVED'}

    async def _increment_otp_attempts(self, ag_id):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE application_guarantors SET otp_attempts = otp_attempts + 1
                WHERE id = $1
            """, ag_id)

    async def _force_expire(self, ag_id):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT application_id, approval_status
                FROM application_guarantors WHERE id = $1 FOR UPDATE
            """, ag_id)
            if not row or row['approval_status'] != 'PENDING':
                return
            app_id = row['application_id']
            await self._close_guarantee(conn, ag_id, 'EXPIRED')
            await conn.execute("""
                UPDATE applications SET status='REJECTED',
                    error_reason='Guarantee TTL expired', updated_at=NOW()
                WHERE id=$1 AND status IN ('PENDING_GUARANTOR','PENDING_CHECKS')
            """, app_id)
            await self._cancel_pending_loan(conn, app_id, 'Guarantee TTL expired')
            await conn.execute("""
                UPDATE guarantor_ttl_log SET expired_at=NOW(), status='EXPIRED'
                WHERE application_guarantor_id=$1
            """, ag_id)
            await self._audit(conn, 'GUARANTEE_EXPIRED', app_id, '', f'ag_id={ag_id}')

    async def reject_guarantee(self, ag_id, reason=None):
        try:
            async with self.db.transaction() as conn:
                row = await conn.fetchrow("""
                    SELECT application_id, approval_status
                    FROM application_guarantors WHERE id = $1 FOR UPDATE
                """, ag_id)
                if not row:
                    raise GuarantorError('Guarantee not found')
                if row['approval_status'] != 'PENDING':
                    raise GuarantorError(f'Status is {row["approval_status"]}')
                app_id = row['application_id']
                await self._close_guarantee(conn, ag_id, 'REJECTED')
                reason_str = scrub_text(reason or 'guarantor rejected')
                await conn.execute("""
                    UPDATE applications SET status = 'REJECTED', error_reason = $1,
                        updated_at = $2 WHERE id = $3
                """, reason_str, datetime.now(timezone.utc), app_id)
                await self._cancel_pending_loan(conn, app_id, 'guarantor rejected')
                await self._audit(conn, 'GUARANTEE_REJECTED', app_id, '',
                                  reason or 'no reason')
                return {'application_id': app_id, 'status': 'REJECTED',
                        'http_status': 200}
        except GuarantorError as e:
            return self._error('E1020', str(e), 400)
        except Exception as e:
            logger.exception(f'Reject failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def resend_otp(self, ag_id, client_ip=None):
        try:
            result = await self._resend_otp_tx(ag_id)
        except GuarantorError as e:
            return self._error('E1022', str(e), 400)
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Resend OTP failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)
        otp_code = result.pop('_otp_code', None)
        if otp_code:
            try:
                phone = await self._get_guarantor_phone(ag_id)
                if phone:
                    msg = f'Credit guarantee request. New OTP: {otp_code}'
                    task = asyncio.create_task(self._deliver_otp_sms(phone, msg, ag_id))
                    self._bg_tasks.add(task)
                    task.add_done_callback(self._bg_tasks.discard)
            except Exception:
                pass
        return {**result, 'status': 'SENT', 'http_status': 200}

    async def _resend_otp_tx(self, ag_id):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT application_id, approval_status, otp_send_count,
                       otp_last_sent_at, ttl_expires_at, otp_attempts
                FROM application_guarantors WHERE id = $1 FOR UPDATE
            """, ag_id)
            if not row:
                raise GuarantorError('Guarantee not found')
            if row['approval_status'] != 'PENDING':
                raise GuarantorError(f'Status is {row["approval_status"]}')
            now = datetime.now(timezone.utc)
            if row['ttl_expires_at'] and row['ttl_expires_at'] < now:
                raise GuarantorError('Guarantee expired')
            if row['otp_send_count'] >= Config.OTP_MAX_RESENDS:
                raise GuarantorError('Max resends reached')
            if row['otp_attempts'] >= Config.OTP_MAX_ATTEMPTS:
                raise GuarantorError('Too many failed attempts')
            if (row['otp_last_sent_at'] and
                    (now - row['otp_last_sent_at']).total_seconds()
                    < Config.OTP_RESEND_COOLDOWN_SEC):
                raise GuarantorError(
                    f'Cooldown active. Try after {Config.OTP_RESEND_COOLDOWN_SEC}s')
            otp_code = f'{int.from_bytes(os.urandom(3), "big") % 1000000:06d}'
            otp_hash = self.crypto.otp_hash(otp_code, ag_id)
            otp_expires = now + timedelta(minutes=Config.OTP_TTL_MINUTES)
            await conn.execute("""
                UPDATE application_guarantors
                SET otp_code_hash = $1, otp_expires_at = $2,
                    otp_last_sent_at = $3, otp_send_count = otp_send_count + 1
                WHERE id = $4
            """, otp_hash, otp_expires, now, ag_id)
            await conn.execute("""
                UPDATE guarantor_ttl_log SET sms_status = 'PENDING', sms_attempts = 0
                WHERE application_guarantor_id = $1
            """, ag_id)
            await self._audit(conn, 'OTP_RESENT', row['application_id'], '',
                              f'ag_id={ag_id}')
            return {'application_id': row['application_id'],
                    'app_guarantor_id': ag_id, '_otp_code': otp_code,
                    'send_count': row['otp_send_count'] + 1}

    async def register_card(self, passport_series, passport_number,
                            card_token, card_masked, signature):
        passport_sn = f'{passport_series}{passport_number}'
        passport_hmac = self.crypto.blind_index(passport_sn)
        try:
            async with self.db.transaction() as conn:
                if not self.crypto.verify_card_signature(
                        passport_hmac, card_token, signature):
                    return self._error('E1040', 'Invalid card signature.', 400)
                row = await conn.fetchrow("""
                    SELECT g.id, g.user_id FROM guarantors g
                    JOIN users u ON u.id = g.user_id
                    WHERE u.passport_sn_hmac = $1 FOR UPDATE
                """, passport_hmac)
                if not row:
                    return self._error('E1040', 'Guarantor profile not found.', 400)
                now = datetime.now(timezone.utc)
                await conn.execute("""
                    UPDATE guarantors SET card_token = $1, card_masked = $2,
                        card_registered_at = $3, auto_debit_enabled = TRUE,
                        updated_at = $4 WHERE user_id = $5
                """, card_token, card_masked, now, now, row['user_id'])
                await self._audit(conn, 'CARD_REGISTERED', None, passport_hmac,
                                  f'card={card_masked}')
                return {'user_id': row['user_id'], 'card_masked': card_masked,
                        'auto_debit_enabled': True, 'status': 'OK',
                        'http_status': 200}
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Register card failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def pay_installment(self, installment_id, amount, idem_key):
        try:
            async with self.db.transaction() as conn:
                result = await self._pay_impl(conn, installment_id, amount, idem_key)
            return {**result, 'http_status': 200}
        except GuarantorError as e:
            return self._error('E1030', str(e), 400)
        except asyncpg.DataError:
            return self._error('E2004', 'Invalid data format.', 400)
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Pay failed: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def _pay_impl(self, conn, installment_id, amount_paid, idem_key):
        if idem_key:
            cached = await conn.fetchrow("""
                SELECT response_body, installment_id FROM repayment_idempotency
                WHERE idempotency_key = $1 AND expires_at > NOW()
            """, idem_key)
            if cached:
                if cached['installment_id'] != installment_id:
                    raise GuarantorError('Idempotency key reused')
                return json.loads(cached['response_body'])

        row = await conn.fetchrow("""
            SELECT rs.loan_id, rs.amount_due, rs.amount_paid, rs.status,
                   ld.guarantor_id, ld.status AS loan_status
            FROM repayment_schedule rs
            JOIN loan_disbursements ld ON ld.id = rs.loan_id
            WHERE rs.id = $1 FOR UPDATE
        """, installment_id)
        if not row:
            raise GuarantorError('Installment not found')

        loan_id = row['loan_id']
        amount_due = Decimal(str(row['amount_due']))
        already_paid = Decimal(str(row['amount_paid'] or 0))

        if row['status'] == 'PAID':
            response = {'status': 'ALREADY_PAID', 'installment_id': installment_id}
        else:
            total_paid = already_paid + Decimal(str(amount_paid))
            if Decimal(str(amount_paid)) > (amount_due - already_paid + Decimal('0.01')):
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
            await conn.execute("""
                UPDATE repayment_schedule SET amount_paid = $1, status = $2,
                    paid_at = $3 WHERE id = $4
            """, str(total_paid), new_status, paid_at, installment_id)
            remaining = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt FROM repayment_schedule
                WHERE loan_id = $1 AND status != 'PAID'
            """, loan_id)
            rem_cnt = remaining['cnt']
            if rem_cnt == 0:
                now = datetime.now(timezone.utc)
                await conn.execute("""
                    UPDATE loan_disbursements SET status='CLOSED', closed_at=$1
                    WHERE id=$2
                """, now, loan_id)
                await conn.execute("""
                    UPDATE applications SET status='CLOSED', updated_at=$1
                    WHERE id=(SELECT application_id FROM loan_disbursements WHERE id=$2)
                """, now, loan_id)
                ag_row = await conn.fetchrow("""
                    SELECT ag.id FROM application_guarantors ag
                    JOIN loan_disbursements ld ON ld.application_id = ag.application_id
                    WHERE ld.id = $1 AND ag.approval_status = 'APPROVED'
                """, loan_id)
                if ag_row:
                    await self._close_guarantee(conn, ag_row['id'], 'CLOSED')
            response = {'status': new_status, 'installment_id': installment_id,
                        'amount_paid': str(total_paid), 'loan_closed': rem_cnt == 0}
            app_row = await conn.fetchrow(
                'SELECT application_id FROM loan_disbursements WHERE id=$1', loan_id)
            await self._audit(conn, 'REPAYMENT',
                              app_row['application_id'] if app_row else None, '',
                              f'installment={installment_id} amount={amount_paid}')

        if idem_key:
            await conn.execute("""
                INSERT INTO repayment_idempotency
                    (idempotency_key, installment_id, response_body)
                VALUES ($1, $2, $3) ON CONFLICT (idempotency_key) DO NOTHING
            """, idem_key, installment_id, json.dumps(response))
        return response

    async def _process_auto_debit_batch(self):
        try:
            await self._recover_orphans()
        except Exception as e:
            logger.exception(f'Orphan recovery: {scrub_text(str(e))}')
        try:
            async with self.db.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT rs.id AS installment_id, rs.loan_id, rs.amount_due,
                           rs.amount_paid, ld.guarantor_id, g.card_token,
                           ld.application_id
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
                            AND adt.next_retry_at > NOW())
                    ORDER BY rs.due_date LIMIT 50
                """)
        except Exception as e:
            logger.exception(f'Auto-debit scan: {scrub_text(str(e))}')
            return
        for r in rows:
            remaining = Decimal(str(r['amount_due'])) - Decimal(str(r['amount_paid'] or 0))
            if remaining <= 0:
                continue
            idem = self.crypto.idempotency_key(
                'autodebit', str(r['loan_id']), str(r['installment_id']))
            await self._process_one_debit(r, remaining, idem)

    async def _process_one_debit(self, r, remaining, idem):
        try:
            async with self.db.transaction() as conn:
                tx = await conn.fetchrow("""
                    INSERT INTO auto_debit_transactions
                        (loan_id, guarantor_id, installment_id, amount, card_token,
                         status, idempotency_key, last_attempt_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, 'PENDING', $6, NOW(), NOW())
                    ON CONFLICT (idempotency_key) DO UPDATE
                    SET status = CASE
                            WHEN auto_debit_transactions.status
                                 IN ('SUCCESS','EXHAUSTED','NEEDS_RECOVERY')
                                THEN auto_debit_transactions.status
                            ELSE 'PENDING'::debit_status_enum END,
                        last_attempt_at = NOW(), updated_at = NOW()
                    RETURNING id, status
                """, r['loan_id'], r['guarantor_id'], r['installment_id'],
                    str(remaining), r['card_token'], idem)
                if tx['status'] in ('SUCCESS', 'EXHAUSTED', 'NEEDS_RECOVERY'):
                    return
                tx_id = tx['id']
        except Exception as e:
            logger.exception(f'Record debit: {scrub_text(str(e))}')
            return
        try:
            result = await self.payment.debit(r['card_token'], remaining, idem)
            if result.get('success'):
                try:
                    async with self.db.transaction() as conn:
                        await self._pay_impl(conn, r['installment_id'],
                                              remaining, idem)
                except Exception as e:
                    logger.critical(f'GW ok DB fail tx={tx_id}')
                    await self._mark_recovery(tx_id, f'DB fail: {scrub_text(str(e))[:200]}')
                    return
                await self._mark_debit_success(tx_id)
            else:
                await self._mark_debit_failed(tx_id, result.get('error', 'unknown'))
        except ServiceUnavailable:
            queried = await self.payment.query_debit(idem)
            if queried and queried.get('success'):
                try:
                    async with self.db.transaction() as conn:
                        await self._pay_impl(conn, r['installment_id'],
                                              remaining, idem)
                    await self._mark_debit_success(tx_id)
                except Exception:
                    await self._mark_recovery(tx_id, 'timeout+query ok db fail')
            else:
                await self._mark_debit_failed(tx_id, 'service_unavailable')
        except Exception as e:
            logger.exception(f'Debit error tx={tx_id}: {scrub_text(str(e))}')
            await self._mark_recovery(tx_id, f'unknown: {scrub_text(str(e))[:200]}')

    async def _mark_debit_success(self, tx_id):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE auto_debit_transactions SET status='SUCCESS',
                    last_attempt_at=NOW(), updated_at=NOW(), next_retry_at=NULL
                WHERE id=$1
            """, tx_id)

    async def _mark_debit_failed(self, tx_id, error):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE auto_debit_transactions
                SET status = CASE WHEN attempt_count + 1 >= $1
                        THEN 'EXHAUSTED'::debit_status_enum
                        ELSE 'FAILED'::debit_status_enum END,
                    attempt_count = attempt_count + 1,
                    last_attempt_at = NOW(), updated_at = NOW(),
                    next_retry_at = CASE WHEN attempt_count + 1 >= $2 THEN NULL
                        ELSE NOW() + INTERVAL '24 hours' END,
                    error_message = $3
                WHERE id = $4
            """, Config.AUTO_DEBIT_MAX_ATTEMPTS, Config.AUTO_DEBIT_MAX_ATTEMPTS,
                error[:500], tx_id)

    async def _mark_recovery(self, tx_id, reason):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE auto_debit_transactions
                SET status = 'NEEDS_RECOVERY'::debit_status_enum,
                    last_attempt_at = NOW(), updated_at = NOW(),
                    next_retry_at = NULL, error_message = $1
                WHERE id = $2
            """, reason[:500], tx_id)

    async def _recover_orphans(self):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE auto_debit_transactions adt
                SET status = 'SUCCESS'::debit_status_enum,
                    last_attempt_at = NOW(), updated_at = NOW(),
                    next_retry_at = NULL,
                    error_message = 'auto-recovered: installment PAID'
                WHERE adt.status = 'PENDING'
                  AND adt.last_attempt_at < NOW() - make_interval(secs => $1::int)
                  AND EXISTS (SELECT 1 FROM repayment_schedule rs
                              WHERE rs.id = adt.installment_id
                                AND rs.amount_paid >= rs.amount_due)
            """, Config.AUTO_DEBIT_RECOVERY_THRESHOLD_SEC)
            await conn.execute("""
                UPDATE auto_debit_transactions
                SET status = 'NEEDS_RECOVERY'::debit_status_enum,
                    updated_at = NOW(), next_retry_at = NULL,
                    error_message = COALESCE(error_message, '') || ' | stuck'
                WHERE status = 'PENDING'
                  AND last_attempt_at < NOW() - make_interval(secs => $1::int)
            """, Config.AUTO_DEBIT_STUCK_THRESHOLD_SEC)

    async def ops_resolve_recovery(self, tx_id, resolution, note=''):
        if resolution not in ('SUCCESS', 'FAILED'):
            return self._error('E1050', 'resolution must be SUCCESS or FAILED', 400)
        try:
            async with self.db.transaction() as conn:
                row = await conn.fetchrow("""
                    SELECT adt.id, adt.installment_id, adt.loan_id, adt.amount,
                           adt.status, adt.idempotency_key
                    FROM auto_debit_transactions adt
                    WHERE adt.id = $1 FOR UPDATE
                """, tx_id)
                if not row:
                    return self._error('E1050', 'Transaction not found', 400)
                if row['status'] != 'NEEDS_RECOVERY':
                    return self._error('E1050', f'Status is {row["status"]}', 400)
                if resolution == 'SUCCESS':
                    await self._pay_impl(conn, row['installment_id'],
                                          row['amount'], row['idempotency_key'])
                    await conn.execute("""
                        UPDATE auto_debit_transactions SET status='SUCCESS',
                            updated_at=NOW(), next_retry_at=NULL,
                            error_message=COALESCE(error_message,'') ||
                                ' | ops: ' || $1
                        WHERE id = $2
                    """, note[:200], tx_id)
                else:
                    await conn.execute("""
                        UPDATE auto_debit_transactions SET status='FAILED',
                            updated_at=NOW(),
                            next_retry_at=NOW() + INTERVAL '24 hours',
                            error_message=COALESCE(error_message,'') ||
                                ' | ops: ' || $1
                        WHERE id = $2
                    """, note[:200], tx_id)
                return {'tx_id': tx_id, 'installment_id': row['installment_id'],
                        'resolution': resolution, 'status': 'OK', 'http_status': 200}
        except asyncpg.PostgresConnectionError:
            return self._error('E2006', 'Database unavailable.', 503)
        except Exception as e:
            logger.exception(f'Ops recovery: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def list_needs_recovery(self, limit=100):
        try:
            async with self.db.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT adt.id, adt.loan_id, adt.installment_id, adt.amount,
                           adt.attempt_count, adt.last_attempt_at,
                           adt.error_message, ld.application_id
                    FROM auto_debit_transactions adt
                    JOIN loan_disbursements ld ON ld.id = adt.loan_id
                    WHERE adt.status = 'NEEDS_RECOVERY'
                    ORDER BY adt.last_attempt_at LIMIT $1
                """, limit)
                return {'transactions': [
                    {'tx_id': r['id'], 'loan_id': r['loan_id'],
                     'installment_id': r['installment_id'],
                     'amount': str(r['amount']),
                     'attempt_count': r['attempt_count'],
                     'error_message': r['error_message'],
                     'application_id': r['application_id']} for r in rows],
                    'http_status': 200}
        except Exception as e:
            logger.exception(f'List recovery: {scrub_text(str(e))}')
            return self._error('E2002', 'Database error.', 500)

    async def _auto_debit_loop(self):
        while not self._shutdown_event.is_set():
            try:
                if await self._leader_auto_debit.try_acquire():
                    await self._process_auto_debit_batch()
            except Exception as e:
                logger.exception(f'Auto-debit loop: {scrub_text(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.AUTO_DEBIT_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _ttl_loop(self):
        while not self._shutdown_event.is_set():
            try:
                if await self._leader_ttl.try_acquire():
                    await self._expire_ttl()
            except Exception as e:
                logger.exception(f'TTL loop: {scrub_text(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.TTL_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _overdue_loop(self):
        while not self._shutdown_event.is_set():
            try:
                if await self._leader_overdue.try_acquire():
                    await self._mark_overdue()
            except Exception as e:
                logger.exception(f'Overdue loop: {scrub_text(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.OVERDUE_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _cleanup_loop(self):
        while not self._shutdown_event.is_set():
            try:
                if await self._leader_cleanup.try_acquire():
                    await self._cleanup()
            except Exception as e:
                logger.exception(f'Cleanup loop: {scrub_text(str(e))}')
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=Config.CLEANUP_SCAN_INTERVAL_SEC)
                return
            except asyncio.TimeoutError:
                continue

    async def _expire_ttl(self):
        async with self.db.transaction() as conn:
            rows = await conn.fetch("""
                SELECT ag.id, ag.application_id FROM application_guarantors ag
                WHERE ag.approval_status = 'PENDING' AND ag.ttl_expires_at < NOW()
                FOR UPDATE SKIP LOCKED
            """)
            for r in rows:
                await self._close_guarantee(conn, r['id'], 'EXPIRED')
                await conn.execute("""
                    UPDATE applications SET status='REJECTED',
                        error_reason='Guarantee TTL expired', updated_at=NOW()
                    WHERE id=$1 AND status='PENDING_GUARANTOR'
                """, r['application_id'])
                await self._cancel_pending_loan(conn, r['application_id'],
                                                 'Guarantee TTL expired')
                await conn.execute("""
                    UPDATE guarantor_ttl_log SET expired_at=NOW(), status='EXPIRED'
                    WHERE application_guarantor_id=$1
                """, r['id'])

    async def _mark_overdue(self):
        async with self.db.transaction() as conn:
            await conn.execute("""
                UPDATE repayment_schedule SET status = 'OVERDUE'
                WHERE status IN ('PENDING','PARTIAL') AND due_date < CURRENT_DATE
            """)
            await conn.execute("""
                UPDATE repayment_schedule rs
                SET penalty_amount = rs.penalty_amount + ROUND(
                        rs.principal_due * pc.daily_penalty_rate, 2),
                    amount_due = rs.principal_due + rs.penalty_amount + ROUND(
                        rs.principal_due * pc.daily_penalty_rate, 2),
                    last_penalty_date = CURRENT_DATE
                FROM loan_disbursements ld
                JOIN product_config pc ON pc.product_type = ld.product_type
                WHERE rs.loan_id = ld.id AND rs.status = 'OVERDUE'
                  AND pc.daily_penalty_rate > 0
                  AND (CURRENT_DATE - rs.due_date) > pc.grace_days
                  AND (rs.last_penalty_date IS NULL
                       OR rs.last_penalty_date < CURRENT_DATE)
            """)

    async def _cleanup(self):
        async with self.db.transaction() as conn:
            await conn.execute('DELETE FROM repayment_idempotency WHERE expires_at < NOW()')
            await conn.execute("""
                DELETE FROM otp_rate_limit
                WHERE attempted_at < NOW() - INTERVAL '24 hours'
            """)

    def start_background_workers(self):
        if self._auto_debit_task is None:
            self._auto_debit_task = asyncio.create_task(self._auto_debit_loop())
        if self._ttl_task is None:
            self._ttl_task = asyncio.create_task(self._ttl_loop())
        if self._overdue_task is None:
            self._overdue_task = asyncio.create_task(self._overdue_loop())
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_background_workers(self):
        self._shutdown_event.set()
        for t in (self._auto_debit_task, self._ttl_task,
                  self._overdue_task, self._cleanup_task):
            if t:
                try:
                    await asyncio.wait_for(t, timeout=10)
                except (asyncio.TimeoutError, Exception):
                    t.cancel()
        for leader in (self._leader_auto_debit, self._leader_ttl,
                       self._leader_overdue, self._leader_cleanup):
            try:
                await leader.release()
            except Exception:
                pass

    async def _create_loan(self, conn, app_id, passport_hmac, guarantor_id,
                            gross, comm, net, abs_id, product, target_type,
                            target_iban, target_name):
        target_hmac = (self.crypto.blind_index(target_iban) if target_iban else '')
        row = await conn.fetchrow("""
            INSERT INTO loan_disbursements
                (application_id, passport_sn_hmac, guarantor_id, gross_amount,
                 transfer_commission, net_transferred, abs_contract_id,
                 product_type, target_account_type, target_account_iban,
                 target_account_hmac, target_name, status, disbursed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    'PENDING_DISBURSEMENT', NULL)
            ON CONFLICT (application_id) DO NOTHING
            RETURNING id
        """, app_id, passport_hmac, guarantor_id, str(gross), str(comm),
            str(net), abs_id, product, target_type, target_iban,
            target_hmac, target_name)
        if row is None:
            row = await conn.fetchrow(
                'SELECT id FROM loan_disbursements WHERE application_id = $1', app_id)
        return row['id']

    async def _create_repayment_schedule(self, conn, loan_id, total, months=0, days=0):
        total = Decimal(str(total))
        now = datetime.now(timezone.utc)
        today = now.date()
        if days and int(days) > 0:
            due_date = add_days(today, int(days)).isoformat()
            await conn.execute("""
                INSERT INTO repayment_schedule
                    (loan_id, installment_number, due_date, principal_due,
                     amount_due, status, created_at)
                VALUES ($1, 1, $2, $3, $4, 'PENDING', $5)
                ON CONFLICT (loan_id, installment_number) DO NOTHING
            """, loan_id, due_date, str(total), str(total), now)
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
            await conn.execute("""
                INSERT INTO repayment_schedule
                    (loan_id, installment_number, due_date, principal_due,
                     amount_due, status, created_at)
                VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)
                ON CONFLICT (loan_id, installment_number) DO NOTHING
            """, loan_id, i, due_date, str(amount_due), str(amount_due), now)

    async def _create_insurance(self, conn, app_id, passport_hmac,
                                 insurance, margin, interest=Decimal('0')):
        await conn.execute("""
            INSERT INTO insurance_policies
                (application_id, passport_sn_hmac, fee_amount, bank_margin,
                 interest_amount, issued_at, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
        """, app_id, passport_hmac, str(insurance), str(margin),
            str(interest), datetime.now(timezone.utc))

    async def _update_status(self, conn, app_id, status, error_reason=None):
        if error_reason:
            await conn.execute("""
                UPDATE applications SET status = $1, error_reason = $2, updated_at = $3
                WHERE id = $4
            """, status, scrub_text(str(error_reason))[:2000],
                datetime.now(timezone.utc), app_id)
        else:
            await conn.execute("""
                UPDATE applications SET status = $1, updated_at = $2 WHERE id = $3
            """, status, datetime.now(timezone.utc), app_id)

    async def _mark_status(self, app_id, st, passport_hmac, reason):
        async with self.db.transaction() as conn:
            await self._update_status(conn, app_id, st, reason)
            await self._audit(conn, st, app_id, passport_hmac, reason)

    async def _mark_error(self, app_id, st, reason=''):
        try:
            async with self.db.transaction() as conn:
                await self._update_status(conn, app_id, st, reason)
                if st in ('ERROR_PHASE3', 'ERROR_EXTERNAL', 'ABS_FAILED'):
                    await self._cancel_pending_loan(conn, app_id, reason)
        except Exception as e:
            logger.exception(f'Mark error: {scrub_text(str(e))}')

    async def _audit(self, conn, action, app_id, passport_hmac='', details=''):
        await conn.execute("""
            INSERT INTO audit_log (action, application_id, passport_sn_hmac,
                                    details, created_at)
            VALUES ($1, $2, $3, $4, $5)
        """, action, app_id, passport_hmac,
            scrub_text(details)[:2000], datetime.now(timezone.utc))

    async def _deliver_otp_sms(self, phone, message, ag_id):
        sent = False
        error = None
        try:
            sent = await self.sms.send(phone, message)
        except Exception as e:
            error = scrub_text(str(e))
        try:
            async with self.db.transaction() as conn:
                await conn.execute("""
                    UPDATE guarantor_ttl_log
                    SET sms_status = $1::sms_status_enum,
                        sms_attempts = sms_attempts + 1, sms_last_error = $2
                    WHERE application_guarantor_id = $3
                """, 'SENT' if sent else 'FAILED', (error or '')[:500], ag_id)
        except Exception:
            pass

    async def health_check(self):
        checks = {}
        healthy = True
        try:
            async with self.db.acquire() as conn:
                await conn.fetchrow('SELECT 1')
            checks['database'] = 'OK'
        except Exception as e:
            checks['database'] = f'FAIL: {scrub_text(str(e))}'
            healthy = False
        try:
            test = 'health'
            enc = self.crypto.encrypt(test)
            dec = self.crypto.decrypt(enc)
            if dec != test:
                raise ValueError('Round-trip failed')
            checks['encryption'] = 'OK'
        except Exception as e:
            checks['encryption'] = f'FAIL: {scrub_text(str(e))}'
            healthy = False
        checks['version'] = '3.8.1'
        checks['env'] = Config.ENV
        checks['leader_election_enabled'] = Config.LEADER_ELECTION_ENABLED
        checks['auto_debit_worker'] = ('RUNNING' if self._auto_debit_task
                                        and not self._auto_debit_task.done()
                                        else 'STOPPED')
        checks['ttl_worker'] = ('RUNNING' if self._ttl_task
                                 and not self._ttl_task.done() else 'STOPPED')
        checks['overdue_worker'] = ('RUNNING' if self._overdue_task
                                     and not self._overdue_task.done()
                                     else 'STOPPED')
        checks['cleanup_worker'] = ('RUNNING' if self._cleanup_task
                                     and not self._cleanup_task.done()
                                     else 'STOPPED')
        return {'status': 'HEALTHY' if healthy else 'UNHEALTHY',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'checks': checks}

    async def close_clients(self):
        for client in (self.cib, self.face, self.abs, self.payment, self.sms):
            try:
                await client.close()
            except Exception:
                pass

    async def shutdown(self):
        await self.stop_background_workers()
        if self._bg_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._bg_tasks, return_exceptions=True),
                    timeout=5.0)
            except asyncio.TimeoutError:
                for t in self._bg_tasks:
                    t.cancel()

    @staticmethod
    def _error(code, reason, http_status=400):
        return {'code': code,
                'status': 'ERROR' if code.startswith('E2') else 'REJECTED',
                'reason': reason, 'http_status': http_status}

    @staticmethod
    def _reject(code, st, reason):
        return {'status': 'REJECTED', 'reason_code': st, 'reason': reason,
                'response': {'code': code, 'status': 'REJECTED',
                             'reason': reason, 'http_status': 400}}

    @staticmethod
    def _ext_error(msg):
        return {'status': 'ERROR',
                'response': {'code': 'E2001', 'status': 'ERROR',
                             'reason': msg, 'http_status': 503}}


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================
_application_ref = None


@asynccontextmanager
async def lifespan(app):
    global _application_ref
    if _application_ref is None:
        _application_ref = Application()
        await _application_ref.start()
    if _application_ref and _application_ref.engine:
        _application_ref.engine.start_background_workers()
    yield
    if _application_ref is not None:
        try:
            if _application_ref.engine is not None:
                await _application_ref.engine.shutdown()
                await _application_ref.engine.close_clients()
            if _application_ref.db_pool:
                await _application_ref.db_pool.close()
        except Exception as e:
            logger.exception(f'Shutdown error: {scrub_text(str(e))}')


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size=1_048_576):
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request, call_next):
        cl = request.headers.get('content-length')
        if cl:
            try:
                if int(cl) > self.max_size:
                    return StarletteJSON(
                        status_code=413,
                        content={'code': 'E2004', 'status': 'ERROR',
                                 'reason': 'Request body too large (max 1 MB)'})
            except (ValueError, TypeError):
                return StarletteJSON(
                    status_code=400,
                    content={'code': 'E2004', 'status': 'ERROR',
                             'reason': 'Invalid Content-Length header'})
        return await call_next(request)


_ENV = os.environ.get('ENV', 'production')
_IS_PROD = (_ENV == 'production')

app = FastAPI(
    title="Fintech Enterprise Microcredit Engine API",
    version="3.8.1",
    docs_url=None if _IS_PROD else '/docs',
    redoc_url=None if _IS_PROD else '/redoc',
    openapi_url=None if _IS_PROD else '/openapi.json',
    lifespan=lifespan)

app.add_middleware(RequestSizeLimitMiddleware, max_size=1_048_576)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Window",
    ],
)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    for err in errors:
        loc = ".".join(str(x) for x in err.get('loc', []))
        if 'date_of_birth' in loc:
            return JSONResponse(
                status_code=400,
                content={
                    'code': 'E1012',
                    'status': 'REJECTED',
                    'reason': 'Invalid date of birth or age < 18',
                    'field': 'date_of_birth',
                })
    return JSONResponse(
        status_code=400,
        content={
            'code': 'E1001',
            'status': 'REJECTED',
            'reason': 'Validation error',
            'details': [
                {'field': ".".join(str(x) for x in e.get('loc', [])),
                 'message': e.get('msg', '')}
                for e in errors
            ],
        })


@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto == "http":
        url = request.url.replace(scheme="https")
        return RedirectResponse(url=str(url), status_code=301)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request, call_next):
    if request.method in ('POST', 'PUT', 'PATCH'):
        ct = request.headers.get('content-type', '')
        if 'application/json' not in ct.lower():
            return StarletteJSON(
                status_code=415,
                content={'code': 'E2004', 'status': 'ERROR',
                         'reason': 'Content-Type must be application/json'})
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    return response


API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

_API_KEY_CACHE = None
_INTERNAL_API_KEY_CACHE = None


def _constant_time_compare(a, b):
    a, b = str(a or ''), str(b or '')
    max_len = max(len(a), len(b))
    return hmac.compare_digest(a.ljust(max_len, '\0'), b.ljust(max_len, '\0'))


def _get_expected_api_key():
    global _API_KEY_CACHE
    if _API_KEY_CACHE is None:
        _API_KEY_CACHE = os.getenv("API_KEY")
        if not _API_KEY_CACHE:
            raise HTTPException(500, "API_KEY not configured.")
    return _API_KEY_CACHE


def _get_expected_internal_api_key():
    global _INTERNAL_API_KEY_CACHE
    if _INTERNAL_API_KEY_CACHE is None:
        _INTERNAL_API_KEY_CACHE = os.getenv("INTERNAL_API_KEY")
        if not _INTERNAL_API_KEY_CACHE:
            raise HTTPException(500, "INTERNAL_API_KEY not configured.")
    return _INTERNAL_API_KEY_CACHE


async def verify_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or not api_key.strip():
        raise HTTPException(401, "Invalid API key.")
    if not _constant_time_compare(str(api_key), _get_expected_api_key()):
        raise HTTPException(401, "Invalid API key.")
    return api_key


async def verify_internal_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or not api_key.strip():
        raise HTTPException(401, "Invalid internal API key.")
    if not _constant_time_compare(str(api_key),
                                   _get_expected_internal_api_key()):
        raise HTTPException(401, "Invalid internal API key.")
    return api_key


_engine = None


def get_engine():
    if _engine is None:
        raise HTTPException(500, 'Engine not initialized')
    return _engine


def set_engine(engine):
    global _engine
    _engine = engine


def _client_ip(request):
    direct = request.client.host if request.client else None
    if direct and direct in Config.TRUSTED_PROXY_IPS:
        fwd = request.headers.get('x-forwarded-for')
        if fwd:
            first = fwd.split(',')[0].strip()
            if first:
                return first[:45]
    return direct[:45] if direct else None


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

    @field_validator('passport_series')
    @classmethod
    def validate_passport_series(cls, v):
        if not v:
            raise ValueError('passport_series is required')
        v = v.strip().upper()
        if not re.fullmatch(r'[A-Z]{1,2}', v):
            raise ValueError('passport_series must be 1-2 Latin letters')
        return v

    @field_validator('passport_number')
    @classmethod
    def validate_passport_number(cls, v):
        if not v:
            raise ValueError('passport_number is required')
        v = v.strip()
        if not re.fullmatch(r'\d{7,9}', v):
            raise ValueError('passport_number must be 7-9 digits')
        return v

    @field_validator('date_of_birth')
    @classmethod
    def validate_dob(cls, v):
        try:
            d = date.fromisoformat(v)
        except (ValueError, TypeError):
            raise ValueError('date_of_birth must be YYYY-MM-DD')
        age = (date.today() - d).days // 365
        if age < 18:
            raise ValueError('Age must be >= 18')
        if age > 120:
            raise ValueError('Age must be <= 120')
        return v

    @field_validator('user_phone', 'guarantor_phone')
    @classmethod
    def validate_phone(cls, v):
        if v is None:
            return v
        clean = v.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if not re.fullmatch(r'\+\d{9,15}', clean):
            raise ValueError('phone must be +XXXXXXXXXXX')
        return clean

    @field_validator('university_iban', 'landlord_iban', 'self_iban')
    @classmethod
    def validate_iban(cls, v):
        if v is None or v == '':
            return v
        clean = v.replace(' ', '').upper()
        if not re.fullmatch(r'[A-Z]{2}\d{2}[A-Z0-9]{11,30}', clean):
            raise ValueError('IBAN format invalid')
        return clean

    @field_validator('face_id_data')
    @classmethod
    def validate_face_id(cls, v):
        if not v:
            raise ValueError('face_id_data is required')
        if len(v) > 10_000_000:
            raise ValueError('face_id_data too large (max 10 MB)')
        return v

    @field_validator('request_id')
    @classmethod
    def validate_request_id(cls, v):
        if v is None:
            return v
        if not re.fullmatch(r'[a-zA-Z0-9_\-]{1,100}', v):
            raise ValueError('request_id must be alphanumeric')
        return v


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


def _pt_to_engine(pt):
    return {'StudentPay': 'STUDENT_PAY', 'DailyPay': 'DAILY_PAY',
            'RentPay': 'RENT_PAY'}[pt.value]


@app.post("/api/v1/credit/apply", tags=["Core"])
async def apply_for_credit(payload: CreditApplicationRequest,
                            request: Request,
                            response: Response,
                            api_key: str = Depends(verify_api_key)):
    engine = get_engine()

    response.headers["X-RateLimit-Limit"] = str(Config.RATE_LIMIT_PER_HOUR)
    response.headers["X-RateLimit-Window"] = "3600"

    idem_key = request.headers.get('X-Idempotency-Key')
    if idem_key:
        payload.request_id = idem_key
    elif not payload.request_id:
        payload.request_id = str(uuid.uuid4())

    passport_sn = f"{payload.passport_series}{payload.passport_number}"
    extra = {k: v for k, v in {
        'university_iban': payload.university_iban,
        'university_name': payload.university_name,
        'landlord_iban': payload.landlord_iban,
        'landlord_name': payload.landlord_name,
        'self_iban': payload.self_iban}.items() if v is not None}
    result = await engine.process_loan_application(
        passport_sn=passport_sn, face_id_data=payload.face_id_data,
        guarantor_phone=payload.guarantor_phone,
        product_type=_pt_to_engine(payload.product_type),
        amount_val=payload.amount, user_phone=payload.user_phone,
        date_of_birth=payload.date_of_birth,
        relation_type=(payload.guarantor_relation.value
                       if payload.guarantor_relation else None),
        extra_data=extra, request_id=payload.request_id,
        client_ip=_client_ip(request))
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/guarantor/approve", tags=["Guarantor"])
async def guarantor_approve(payload: GuarantorApproveRequest, request: Request,
                              api_key: str = Depends(verify_api_key)):
    engine = get_engine()
    passport_sn = f"{payload.passport_series}{payload.passport_number}"
    result = await engine.approve_guarantee(
        ag_id=payload.application_guarantor_id, otp_code=payload.otp_code,
        face_id_data=payload.face_id_data, passport_sn=passport_sn,
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
        ag_id=payload.application_guarantor_id, reason=payload.reason)
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
        ag_id=payload.application_guarantor_id, client_ip=_client_ip(request))
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
        card_token=payload.card_token, card_masked=payload.card_masked,
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
        installment_id=payload.installment_id, amount=payload.amount,
        idem_key=payload.idempotency_key)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.post("/api/v1/internal/guarantees/expire", tags=["Internal"])
async def expire_guarantees(api_key: str = Depends(verify_internal_api_key)):
    await get_engine()._expire_ttl()
    return {'status': 'OK'}


@app.post("/api/v1/internal/auto-debit/run", tags=["Internal"])
async def run_auto_debit(api_key: str = Depends(verify_internal_api_key)):
    await get_engine()._process_auto_debit_batch()
    return {'status': 'OK'}


@app.post("/api/v1/internal/auto-debit/recover", tags=["Internal"])
async def ops_recover(payload: OpsRecoveryRequest,
                       api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    result = await engine.ops_resolve_recovery(
        tx_id=payload.tx_id, resolution=payload.resolution, note=payload.note)
    hs = result.get('http_status', 200)
    if hs >= 400:
        raise HTTPException(status_code=hs, detail=result)
    return result


@app.get("/api/v1/internal/auto-debit/needs-recovery", tags=["Internal"])
async def list_needs_recovery(limit: int = 100,
                                api_key: str = Depends(verify_internal_api_key)):
    return await get_engine().list_needs_recovery(limit=min(limit, 500))


@app.post("/api/v1/internal/overdue/run", tags=["Internal"])
async def run_overdue(api_key: str = Depends(verify_internal_api_key)):
    await get_engine()._mark_overdue()
    return {'status': 'OK'}


@app.post("/api/v1/internal/cleanup/run", tags=["Internal"])
async def run_cleanup(api_key: str = Depends(verify_internal_api_key)):
    await get_engine()._cleanup()
    return {'status': 'OK'}


@app.get("/api/v1/system/health", tags=["System"])
async def health():
    return await get_engine().health_check()


@app.get("/api/v1/system/ready", tags=["System"])
async def ready():
    result = await get_engine().health_check()
    if result['status'] != 'HEALTHY':
        raise HTTPException(503, detail=result)
    return result


@app.get("/api/v1/system/metrics", tags=["System"])
async def metrics(api_key: str = Depends(verify_internal_api_key)):
    engine = get_engine()
    return {
        'version': '3.8.1',
        'uptime_seconds': round(time.time() - _START_TIME, 2),
        'workers': {
            'auto_debit': ('RUNNING' if engine._auto_debit_task
                           and not engine._auto_debit_task.done()
                           else 'STOPPED'),
            'ttl': ('RUNNING' if engine._ttl_task
                    and not engine._ttl_task.done() else 'STOPPED'),
            'overdue': ('RUNNING' if engine._overdue_task
                        and not engine._overdue_task.done() else 'STOPPED'),
            'cleanup': ('RUNNING' if engine._cleanup_task
                        and not engine._cleanup_task.done() else 'STOPPED'),
        },
        'env': Config.ENV,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    logger.exception(f'Unhandled: {scrub_text(str(exc))}')
    return JSONResponse(
        status_code=500,
        content={'code': 'E2003', 'status': 'ERROR',
                 'reason': 'Internal server error.'})


class Application:
    def __init__(self):
        self.db_pool = DatabasePool(Config)
        self.engine = None

    async def start(self):
        global _application_ref
        _application_ref = self
        Config.validate()
        keys = KeyManager().load()
        crypto = CryptoService(keys['master_key'], keys['hmac_key'],
                                os.environ.get('CARD_SIGNATURE_KEY_HEX'))
        await self.db_pool.initialize()
        client_cert = os.environ.get('INTERNAL_CLIENT_CERT')
        client_key = os.environ.get('INTERNAL_CLIENT_KEY')
        ca_cert = os.environ.get('INTERNAL_CA_CERT')
        if Config.ENV == 'production':
            common = {'client_cert': client_cert, 'client_key': client_key,
                      'ca_cert': ca_cert}
        else:
            common = {'client_cert': client_cert if (client_cert and client_key) else None,
                      'client_key': client_key if (client_cert and client_key) else None,
                      'ca_cert': ca_cert}
        cib = CIBClient(os.environ['CIB_URL'], os.environ['CIB_API_KEY'], **common)
        face = FaceIDClient(os.environ['FACE_ID_URL'],
                             os.environ['FACE_ID_API_KEY'], **common)
        abs_client = ABSClient(os.environ['ABS_URL'],
                                os.environ['ABS_API_KEY'], **common)
        payment = PaymentGatewayClient(os.environ['PAYMENT_URL'],
                                        os.environ['PAYMENT_API_KEY'], **common)
        sms = SMSClient(os.environ['SMS_URL'], os.environ['SMS_API_KEY'], **common)
        self.engine = CreditEngine(
            db_pool=self.db_pool, crypto=crypto, cib_client=cib,
            face_client=face, abs_client=abs_client,
            payment_client=payment, sms_client=sms)
        set_engine(self.engine)
        logger.info(f'Application initialized v3.8.1 (ENV={Config.ENV})')

# ============================================================================
# EXTENSIONS v3.8.1 — 5 ҷузъ
# ============================================================================
try:
    from extensions_v381 import apply_extensions, patch_payment_client
    patch_payment_client(PaymentGatewayClient)
    apply_extensions(CreditEngine, app, get_engine,
                     verify_api_key, verify_internal_api_key)
    logger.info('Extensions loaded: lifecycle, refund, velocity, '
                'reconciliation, hmac')
except ImportError as e:
    logger.warning(f'Extensions not loaded: {e}')

if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'),
                        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    uvicorn.run(app, host='0.0.0.0',
                port=int(os.environ.get('API_PORT', 8000)),
                log_level='info')