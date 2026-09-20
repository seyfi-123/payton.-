# -*- coding: utf-8 -*-
"""
Tajik Fintech Credit Engine v3.8.1 — Extensions
5 ҷузъи иловагӣ:
  1. Transaction Lifecycle (HOLD/CAPTURE/CANCEL)
  2. Refund / Partial Refund
  3. Reconciliation (Ҳар рӯз 00:00)
  4. HMAC Request Signing (X-Signature)
  5. Velocity Check / Anti-Fraud

Истифода дар 2credit_engine.py:
    try:
        from extensions_v381 import apply_extensions
        apply_extensions(CreditEngine, app, get_engine,
                         verify_api_key, verify_internal_api_key)
    except ImportError as e:
        logger.warning(f'Extensions not loaded: {e}')
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from fastapi import Request, HTTPException, Depends
from starlette.responses import JSONResponse as StarletteJSON

logger = logging.getLogger('credit_engine')

SIGNING_SECRET = os.environ.get('SIGNING_SECRET', '')
EXTENSION_VERSION = '3.8.1'


# ============================================================================
# ҶУЗЪИ 4: HMAC REQUEST SIGNING — ФУНКСИЯҲО
# ============================================================================

def _canonical_request(method, path, body_bytes, timestamp):
    body_hash = hashlib.sha256(body_bytes or b'').hexdigest()
    return f'{method}\n{path}\n{timestamp}\n{body_hash}'


def hmac_sign(method, path, body_bytes, timestamp=None):
    """Сохтани X-Signature"""
    if not SIGNING_SECRET:
        return None
    ts = timestamp or str(int(time.time()))
    canonical = _canonical_request(method, path, body_bytes, ts)
    sig = hmac.new(
        SIGNING_SECRET.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f'{ts}.{sig}'


def hmac_verify(method, path, body_bytes, signature, max_age=300):
    """Санҷиши X-Signature

    ИСЛОҲ (патчи амниятӣ): пештар дар ин ҷо ҳангоми набудани SIGNING_SECRET
    `return True` навишта шуда буд — яъне агар калид танзим карда
    нашавад, ҳама дархостҳо БЕ САНҶИШ қабул мешуданд (fail-open).
    Ҳоло система fail-closed аст: агар калид набошад — дархост рад
    мешавад ва хатогӣ дар лог сабт мешавад.
    """
    if not SIGNING_SECRET:
        logger.error(
            'SIGNING_SECRET танзим нашудааст — ҳама дархостҳои '
            'имзошаванда рад карда мешаванд (fail-closed).')
        return False
    if not signature:
        return False
    try:
        ts_str, sig = signature.split('.', 1)
        ts = int(ts_str)
    except (ValueError, AttributeError):
        return False
    if abs(time.time() - ts) > max_age:
        return False
    expected = hmac_sign(method, path, body_bytes, ts_str)
    if not expected:
        return True
    expected_sig = expected.split('.', 1)[1]
    return hmac.compare_digest(sig, expected_sig)


# ============================================================================
# ҶУЗЪИ 1: TRANSACTION LIFECYCLE — MIXIN
# ============================================================================

class PaymentLifecycleMixin:
    """HOLD / CAPTURE / CANCEL"""

    async def payment_hold(self, installment_id, amount, idem_key,
                            client_ip=None):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT rs.loan_id, rs.amount_due, rs.amount_paid,
                       ld.guarantor_id, g.card_token, ld.application_id,
                       a.passport_sn_hmac
                FROM repayment_schedule rs
                JOIN loan_disbursements ld ON ld.id = rs.loan_id
                JOIN guarantors g ON g.user_id = ld.guarantor_id
                JOIN applications a ON a.id = ld.application_id
                WHERE rs.id = $1 AND rs.status != 'PAID'
                FOR UPDATE
            """, installment_id)
            if not row:
                return self._error('E1031',
                                   'Installment not found or paid.', 404)

            existing = await conn.fetchrow("""
                SELECT transaction_id, status, amount
                FROM payment_transactions
                WHERE idempotency_key = $1
            """, idem_key)
            if existing:
                return {
                    'code': 'E0000', 'status': existing['status'],
                    'transaction_id': existing['transaction_id'],
                    'amount': str(existing['amount']),
                    'http_status': 200,
                }

            # ИСЛОҲ (патчи амниятӣ): пештар HOLD ягон санҷиши суръат надошт —
            # мизоҷ метавонист даҳҳо HOLD-ро зуд-зуд эҷод кунад.
            # Ҳоло ҳамон VelocityMixin (агар бор шуда бошад) истифода
            # мешавад, бо passport_sn_hmac-и мизоҷи ҳамин installment.
            if hasattr(self, '_check_velocity'):
                ok, err_code, reason = await self._check_velocity(
                    conn, row['passport_sn_hmac'], amount, client_ip)
                if not ok:
                    return {'code': err_code, 'status': 'VELOCITY_BLOCKED',
                            'reason': reason, 'http_status': 429}

            try:
                result = await self.payment.hold(
                    row['card_token'], amount, idem_key)
            except Exception:
                return self._error('E2001',
                                   'Payment gateway unavailable.', 503)

            if not result.get('success'):
                return self._error('E1031',
                    f"HOLD failed: {result.get('error', 'unknown')}", 400)

            tx_id = result.get('transaction_id') or f'TX-{uuid.uuid4().hex[:16]}'
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

            await conn.execute("""
                INSERT INTO payment_transactions
                    (transaction_id, application_id, loan_id, installment_id,
                     amount, card_token, status, expires_at, idempotency_key,
                     gateway_response)
                VALUES ($1, $2, $3, $4, $5, $6, 'HOLD', $7, $8, $9)
            """, tx_id, row['application_id'], row['loan_id'],
                installment_id, str(amount), row['card_token'],
                expires_at, idem_key, json.dumps(result))

            if hasattr(self, '_record_velocity'):
                await self._record_velocity(
                    conn, row['passport_sn_hmac'], amount, client_ip)

            await self._audit(conn, 'PAYMENT_HOLD',
                              row['application_id'], '',
                              f'tx={tx_id} amount={amount}')

            return {
                'code': 'E0000', 'status': 'HOLD',
                'transaction_id': tx_id,
                'amount': str(amount),
                'expires_at': expires_at.isoformat(),
                'http_status': 200,
            }

    async def payment_capture(self, transaction_id, idem_key):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT pt.id, pt.installment_id, pt.amount, pt.card_token,
                       pt.status, a.passport_sn_hmac
                FROM payment_transactions pt
                LEFT JOIN applications a ON a.id = pt.application_id
                WHERE pt.transaction_id = $1 FOR UPDATE
            """, transaction_id)
            if not row:
                return self._error('E1032', 'Transaction not found.', 404)
            if row['status'] == 'CAPTURED':
                return {'code': 'E0000', 'status': 'ALREADY_CAPTURED',
                        'transaction_id': transaction_id, 'http_status': 200}
            if row['status'] != 'HOLD':
                return self._error('E1032',
                    f'Cannot capture: {row["status"]}', 400)

            # Заифии #5: Capture низ velocity дорад (ҳамон гурӯҳи паспорт).
            if hasattr(self, '_check_velocity') and row['passport_sn_hmac']:
                ok, err_code, reason = await self._check_velocity(
                    conn, row['passport_sn_hmac'], row['amount'], None)
                if not ok:
                    return {'code': err_code, 'status': 'VELOCITY_BLOCKED',
                            'reason': reason, 'http_status': 429}

            try:
                result = await self.payment.capture(
                    transaction_id, row['amount'], idem_key)
            except Exception:
                return self._error('E2001',
                                   'Gateway unavailable.', 503)

            if not result.get('success'):
                return self._error('E1031',
                    f"Capture failed: {result.get('error')}", 400)

            await conn.execute("""
                UPDATE payment_transactions
                SET status = 'CAPTURED', captured_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
            """, row['id'])

            await self._pay_impl(conn, row['installment_id'],
                                  row['amount'],
                                  f'capture-{transaction_id}')
            await self._audit(conn, 'PAYMENT_CAPTURED', None, '',
                              f'tx={transaction_id}')

            if hasattr(self, '_record_velocity') and row['passport_sn_hmac']:
                await self._record_velocity(
                    conn, row['passport_sn_hmac'], row['amount'], None)

            return {
                'code': 'E0000', 'status': 'CAPTURED',
                'transaction_id': transaction_id, 'http_status': 200,
            }

    async def payment_cancel(self, transaction_id, idem_key):
        async with self.db.transaction() as conn:
            row = await conn.fetchrow("""
                SELECT pt.id, pt.amount, pt.status, a.passport_sn_hmac
                FROM payment_transactions pt
                LEFT JOIN applications a ON a.id = pt.application_id
                WHERE pt.transaction_id = $1 FOR UPDATE
            """, transaction_id)
            if not row:
                return self._error('E1032', 'Transaction not found.', 404)
            if row['status'] == 'CANCELLED':
                return {'code': 'E0000', 'status': 'ALREADY_CANCELLED',
                        'transaction_id': transaction_id, 'http_status': 200}
            if row['status'] != 'HOLD':
                return self._error('E1032',
                    f'Cannot cancel: {row["status"]}', 400)

            try:
                await self.payment.cancel(transaction_id, idem_key)
            except Exception:
                return self._error('E2001',
                                   'Gateway unavailable.', 503)

            await conn.execute("""
                UPDATE payment_transactions
                SET status = 'CANCELLED', cancelled_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
            """, row['id'])
            await self._audit(conn, 'PAYMENT_CANCELLED', None, '',
                              f'tx={transaction_id}')

            return {
                'code': 'E0000', 'status': 'CANCELLED',
                'transaction_id': transaction_id, 'http_status': 200,
            }


# ============================================================================
# ҶУЗЪИ 2: REFUND — MIXIN
# ============================================================================

class RefundMixin:
    """Refund / Partial Refund"""

    async def payment_refund(self, transaction_id, amount, reason,
                              idem_key, initiated_by='api'):
        async with self.db.transaction() as conn:
            existing = await conn.fetchrow("""
                SELECT refund_id, status, refund_amount, remaining_amount
                FROM refunds WHERE idempotency_key = $1
            """, idem_key)
            if existing:
                return {
                    'code': 'E0000', 'refund_id': existing['refund_id'],
                    'status': existing['status'],
                    'refund_amount': str(existing['refund_amount']),
                    'remaining_amount': str(existing['remaining_amount']),
                    'http_status': 200,
                }

            tx = await conn.fetchrow("""
                SELECT pt.id, pt.amount, pt.refunded_amount, pt.status,
                       a.passport_sn_hmac
                FROM payment_transactions pt
                LEFT JOIN applications a ON a.id = pt.application_id
                WHERE pt.transaction_id = $1 FOR UPDATE
            """, transaction_id)
            if not tx:
                return self._error('E1032', 'Transaction not found.', 404)
            if tx['status'] not in ('CAPTURED', 'REFUNDED'):
                return self._error('E1033',
                    f'Cannot refund: {tx["status"]}', 400)

            # Заифии #4: Refund пештар ягон санҷиши суръат надошт.
            if hasattr(self, '_check_velocity') and tx['passport_sn_hmac']:
                ok, err_code, reason = await self._check_velocity(
                    conn, tx['passport_sn_hmac'], Decimal(str(amount)), None)
                if not ok:
                    return {'code': err_code, 'status': 'VELOCITY_BLOCKED',
                            'reason': reason, 'http_status': 429}

            original = Decimal(str(tx['amount']))
            already = Decimal(str(tx['refunded_amount'] or 0))
            amount = Decimal(str(amount))

            if amount <= 0:
                return self._error('E1033', 'Refund must be > 0', 400)
            if amount > original - already:
                return self._error('E1033',
                    f'Exceeds remaining: {original - already}', 400)

            try:
                result = await self.payment.refund(
                    transaction_id, amount, idem_key, reason)
            except Exception:
                return self._error('E2001', 'Gateway unavailable.', 503)

            refund_id = result.get('refund_id') or f'RF-{uuid.uuid4().hex[:16]}'

            if not result.get('success'):
                await conn.execute("""
                    INSERT INTO refunds
                        (refund_id, transaction_id, original_amount,
                         refund_amount, remaining_amount, reason, status,
                         initiated_by, idempotency_key, error_message)
                    VALUES ($1, $2, $3, $4, $5, $6, 'FAILED', $7, $8, $9)
                """, refund_id, transaction_id, str(original), str(amount),
                    str(original - already), reason[:500], initiated_by,
                    idem_key, result.get('error', 'unknown'))
                return self._error('E1033',
                    f"Refund failed: {result.get('error')}", 400)

            new_refunded = already + amount
            remaining = original - new_refunded

            await conn.execute("""
                INSERT INTO refunds
                    (refund_id, transaction_id, original_amount,
                     refund_amount, remaining_amount, reason, status,
                     initiated_by, idempotency_key, completed_at,
                     gateway_response)
                VALUES ($1, $2, $3, $4, $5, $6, 'SUCCESS', $7, $8, NOW(), $9)
            """, refund_id, transaction_id, str(original), str(amount),
                str(remaining), reason[:500], initiated_by, idem_key,
                json.dumps(result))

            new_status = 'REFUNDED' if remaining == 0 else 'CAPTURED'
            await conn.execute("""
                UPDATE payment_transactions
                SET refunded_amount = $1, status = $2, updated_at = NOW()
                WHERE id = $3
            """, str(new_refunded), new_status, tx['id'])

            if hasattr(self, '_record_velocity') and tx['passport_sn_hmac']:
                await self._record_velocity(
                    conn, tx['passport_sn_hmac'], Decimal(str(amount)), None)

            await self._audit(conn, 'REFUND', None, '',
                              f'tx={transaction_id} amount={amount} '
                              f'remaining={remaining}')

            return {
                'code': 'E0000', 'status': 'SUCCESS',
                'refund_id': refund_id,
                'transaction_id': transaction_id,
                'original_amount': str(original),
                'refund_amount': str(amount),
                'remaining_amount': str(remaining),
                'http_status': 200,
            }

    async def get_refund(self, refund_id):
        async with self.db.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT refund_id, transaction_id, original_amount,
                       refund_amount, remaining_amount, status, reason,
                       created_at, completed_at
                FROM refunds WHERE refund_id = $1
            """, refund_id)
            if not row:
                return self._error('E1035', 'Refund not found.', 404)
            return {
                'code': 'E0000',
                'refund_id': row['refund_id'],
                'transaction_id': row['transaction_id'],
                'original_amount': str(row['original_amount']),
                'refund_amount': str(row['refund_amount']),
                'remaining_amount': str(row['remaining_amount']),
                'status': row['status'],
                'reason': row['reason'],
                'created_at': row['created_at'].isoformat(),
                'completed_at': (row['completed_at'].isoformat()
                                 if row['completed_at'] else None),
                'http_status': 200,
            }


# ============================================================================
# ҶУЗЪИ 5: VELOCITY CHECK — MIXIN
# ============================================================================

class VelocityMixin:
    """Anti-Fraud: суръат ва лимитҳо"""

    async def _check_velocity(self, conn, passport_hmac, amount,
                                client_ip=None):
        # 5 дархост дар 1 сония
        row = await conn.fetchrow("""
            SELECT COUNT(*) AS cnt FROM velocity_log
            WHERE passport_hmac = $1
              AND created_at > NOW() - INTERVAL '1 second'
        """, passport_hmac)
        if row['cnt'] >= 5:
            return False, 'E1023', 'Too many requests (1 sec)'

        # 20 дархост дар 1 соат
        row = await conn.fetchrow("""
            SELECT COUNT(*) AS cnt FROM velocity_log
            WHERE passport_hmac = $1
              AND created_at > NOW() - INTERVAL '1 hour'
        """, passport_hmac)
        if row['cnt'] >= 20:
            return False, 'E1023', 'Too many requests (1 hour)'

        # Кунлик лимит
        row = await conn.fetchrow("""
            SELECT COALESCE(SUM(amount), 0) AS total FROM velocity_log
            WHERE passport_hmac = $1
              AND created_at > NOW() - INTERVAL '1 day'
        """, passport_hmac)
        if Decimal(str(row['total'])) + Decimal(str(amount)) > Decimal('10000'):
            return False, 'E1024', 'Daily limit exceeded'

        # Моҳона лимит
        row = await conn.fetchrow("""
            SELECT COALESCE(SUM(amount), 0) AS total FROM velocity_log
            WHERE passport_hmac = $1
              AND created_at > NOW() - INTERVAL '30 days'
        """, passport_hmac)
        if Decimal(str(row['total'])) + Decimal(str(amount)) > Decimal('100000'):
            return False, 'E1024', 'Monthly limit exceeded'

        # IP лимит
        if client_ip:
            row = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt FROM velocity_log
                WHERE client_ip = $1
                  AND created_at > NOW() - INTERVAL '1 hour'
            """, client_ip)
            if row['cnt'] >= 50:
                return False, 'E1023', 'IP rate limit'

        return True, '', ''

    async def _record_velocity(self, conn, passport_hmac, amount,
                                 client_ip=None):
        await conn.execute("""
            INSERT INTO velocity_log (passport_hmac, amount, client_ip)
            VALUES ($1, $2, $3)
        """, passport_hmac, str(amount), client_ip)


# ============================================================================
# ҶУЗЪИ 3: RECONCILIATION — MIXIN
# ============================================================================

class ReconciliationMixin:
    """Ҳар рӯз 00:00 солиштирӣ бо бонк"""

    async def run_reconciliation(self):
        async with self.db.acquire() as conn:
            period_end = datetime.now(timezone.utc)
            period_start = period_end - timedelta(days=1)

            local = await conn.fetchrow("""
                SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total
                FROM payment_transactions
                WHERE status IN ('CAPTURED', 'REFUNDED')
                  AND captured_at >= $1 AND captured_at < $2
            """, period_start, period_end)

            local_total = Decimal(str(local['total']))
            local_count = local['cnt']

            try:
                remote = await self.payment.get_reconciliation(
                    period_start.isoformat(), period_end.isoformat())
                remote_total = Decimal(str(remote.get('total', 0)))
                remote_count = int(remote.get('count', 0))
            except Exception as e:
                logger.exception(f'Recon remote: {e}')
                remote_total = Decimal('0')
                remote_count = 0

            matched = min(local_count, remote_count)
            mismatch = abs(local_count - remote_count)
            status = 'OK' if (local_total == remote_total
                              and mismatch == 0) else 'MISMATCH'

            await conn.execute("""
                INSERT INTO reconciliation_log
                    (period_start, period_end, total_local, total_remote,
                     matched_count, mismatch_count, status, details)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, period_start, period_end, str(local_total),
                str(remote_total), matched, mismatch, status,
                json.dumps({'local': local_count, 'remote': remote_count}))

            if status == 'MISMATCH':
                logger.error(
                    f'RECONCILIATION MISMATCH: local={local_total} '
                    f'remote={remote_total}')

            return {
                'status': status,
                'local_total': str(local_total),
                'remote_total': str(remote_total),
                'mismatch_count': mismatch,
            }


# ============================================================================
# ҶУЗЪИ 4: HMAC MIDDLEWARE
# ============================================================================

class HMACSigningMixin:

    @staticmethod
    def register_signature_middleware(app):
        @app.middleware("http")
        async def signature_middleware(request: Request, call_next):
            if not SIGNING_SECRET:
                return await call_next(request)
            if request.method not in ('POST', 'PUT', 'PATCH'):
                return await call_next(request)

            signature = request.headers.get('X-Signature', '')
            body = await request.body()
            path = request.url.path

            if not hmac_verify(request.method, path, body, signature):
                logger.warning(f'Invalid signature: {path}')
                return StarletteJSON(
                    status_code=401,
                    content={'code': 'E1022', 'status': 'REJECTED',
                             'reason': 'Invalid or missing X-Signature'})
            return await call_next(request)


# ============================================================================
# ENDPOINTS
# ============================================================================

def register_endpoints(app, get_engine, verify_api_key,
                        verify_internal_api_key):
    from pydantic import BaseModel, Field, ConfigDict
    from decimal import Decimal

    class PaymentHoldRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        installment_id: int = Field(..., gt=0)
        amount: Decimal = Field(..., gt=0)
        idempotency_key: str = Field(..., min_length=8, max_length=64)

    class PaymentCaptureRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        transaction_id: str = Field(..., min_length=8, max_length=64)
        idempotency_key: str = Field(..., min_length=8, max_length=64)

    class PaymentCancelRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        transaction_id: str = Field(..., min_length=8, max_length=64)
        idempotency_key: str = Field(..., min_length=8, max_length=64)

    class RefundRequest(BaseModel):
        model_config = ConfigDict(extra='forbid')
        transaction_id: str = Field(..., min_length=8, max_length=64)
        amount: Decimal = Field(..., gt=0)
        reason: str = Field('', max_length=500)
        idempotency_key: str = Field(..., min_length=8, max_length=64)

    @app.post("/api/v1/payment/hold", tags=["Payment"])
    async def payment_hold(payload: PaymentHoldRequest, request: Request,
                            api_key: str = Depends(verify_api_key)):
        engine = get_engine()
        client_ip = request.client.host if request.client else None
        result = await engine.payment_hold(
            payload.installment_id, payload.amount,
            payload.idempotency_key, client_ip=client_ip)
        hs = result.get('http_status', 200)
        if hs >= 400:
            raise HTTPException(status_code=hs, detail=result)
        return result

    @app.post("/api/v1/payment/capture", tags=["Payment"])
    async def payment_capture(payload: PaymentCaptureRequest,
                               api_key: str = Depends(verify_api_key)):
        engine = get_engine()
        result = await engine.payment_capture(
            payload.transaction_id, payload.idempotency_key)
        hs = result.get('http_status', 200)
        if hs >= 400:
            raise HTTPException(status_code=hs, detail=result)
        return result

    @app.post("/api/v1/payment/cancel", tags=["Payment"])
    async def payment_cancel(payload: PaymentCancelRequest,
                              api_key: str = Depends(verify_api_key)):
        engine = get_engine()
        result = await engine.payment_cancel(
            payload.transaction_id, payload.idempotency_key)
        hs = result.get('http_status', 200)
        if hs >= 400:
            raise HTTPException(status_code=hs, detail=result)
        return result

    @app.post("/api/v1/payment/refund", tags=["Payment"])
    async def payment_refund(payload: RefundRequest,
                              api_key: str = Depends(verify_api_key)):
        engine = get_engine()
        result = await engine.payment_refund(
            payload.transaction_id, payload.amount, payload.reason,
            payload.idempotency_key)
        hs = result.get('http_status', 200)
        if hs >= 400:
            raise HTTPException(status_code=hs, detail=result)
        return result

    @app.get("/api/v1/payment/refund/{refund_id}", tags=["Payment"])
    async def get_refund(refund_id: str,
                          api_key: str = Depends(verify_api_key)):
        engine = get_engine()
        result = await engine.get_refund(refund_id)
        hs = result.get('http_status', 200)
        if hs >= 400:
            raise HTTPException(status_code=hs, detail=result)
        return result

    @app.post("/api/v1/internal/reconciliation/run", tags=["Internal"])
    async def run_recon(api_key: str = Depends(verify_internal_api_key)):
        engine = get_engine()
        return await engine.run_reconciliation()


# ============================================================================
# PAYMENT GATEWAY — МЕТОДҲОИ НАВ
# ============================================================================

def patch_payment_client(PaymentClass):
    """Илова кардани hold/capture/cancel/refund ба PaymentGatewayClient"""

    async def hold(self, card_token, amount, idem):
        try:
            r = await self._call('POST', '/api/hold',
                json={'card_token': card_token, 'amount': str(amount)},
                headers={'X-Idempotency-Key': idem})
            return r.json()
        except Exception as e:
            logger.error(f'Payment hold failed: {e}')
            return {'success': False, 'error': str(e)}

    async def capture(self, transaction_id, amount, idem):
        try:
            r = await self._call('POST', '/api/capture',
                json={'transaction_id': transaction_id,
                      'amount': str(amount)},
                headers={'X-Idempotency-Key': idem})
            return r.json()
        except Exception as e:
            logger.error(f'Payment capture failed: {e}')
            return {'success': False, 'error': str(e)}

    async def cancel(self, transaction_id, idem):
        try:
            r = await self._call('POST', '/api/cancel',
                json={'transaction_id': transaction_id},
                headers={'X-Idempotency-Key': idem})
            return r.json()
        except Exception as e:
            logger.error(f'Payment cancel failed: {e}')
            return {'success': False, 'error': str(e)}

    async def refund(self, transaction_id, amount, idem, reason=''):
        try:
            r = await self._call('POST', '/api/refund',
                json={'transaction_id': transaction_id,
                      'amount': str(amount),
                      'reason': reason},
                headers={'X-Idempotency-Key': idem})
            return r.json()
        except Exception as e:
            logger.error(f'Payment refund failed: {e}')
            return {'success': False, 'error': str(e)}

    async def get_reconciliation(self, start, end):
        try:
            r = await self._call('GET',
                f'/api/reconciliation?start={start}&end={end}')
            return r.json()
        except Exception as e:
            logger.error(f'Reconciliation failed: {e}')
            return {'total': 0, 'count': 0}

    PaymentClass.hold = hold
    PaymentClass.capture = capture
    PaymentClass.cancel = cancel
    PaymentClass.refund = refund
    PaymentClass.get_reconciliation = get_reconciliation


# ============================================================================
# APPLY — ЯК ФУНКСИЯ
# ============================================================================

def apply_extensions(engine_class, app, get_engine,
                     verify_api_key, verify_internal_api_key):
    """Ҳама 5 ҷузъро муттаҳид мекунад"""
    # Mixin-ҳо ба engine
    for mixin in (PaymentLifecycleMixin, RefundMixin, VelocityMixin,
                  ReconciliationMixin):
        for name in dir(mixin):
            if name.startswith('_') and name not in (
                '_check_velocity', '_record_velocity'):
                continue
            attr = getattr(mixin, name)
            if callable(attr):
                setattr(engine_class, name, attr)

    # Middleware
    HMACSigningMixin.register_signature_middleware(app)

    # Endpoints
    register_endpoints(app, get_engine, verify_api_key,
                       verify_internal_api_key)

    logger.info(f'Extensions v{EXTENSION_VERSION} applied: '
                f'lifecycle, refund, velocity, reconciliation, hmac')