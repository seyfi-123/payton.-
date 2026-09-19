-- ============================================================================
-- Tajik Fintech Credit Engine v3.8.1 — Migrations
-- 4 ҷадвали нав барои 5 ҷузъ
-- ============================================================================

-- 1. payment_transactions (Ҷузъи 1: Lifecycle)
CREATE TABLE IF NOT EXISTS payment_transactions (
    id BIGSERIAL PRIMARY KEY,
    transaction_id VARCHAR(64) NOT NULL UNIQUE,
    application_id BIGINT REFERENCES applications(id) ON DELETE CASCADE,
    loan_id BIGINT REFERENCES loan_disbursements(id) ON DELETE CASCADE,
    installment_id BIGINT REFERENCES repayment_schedule(id) ON DELETE CASCADE,
    amount NUMERIC(12,2) NOT NULL,
    refunded_amount NUMERIC(12,2) NOT NULL DEFAULT 0.00,
    card_token TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'HOLD',
    hold_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    captured_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    gateway_response JSONB,
    error_message TEXT,
    idempotency_key VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT payment_transactions_status_check CHECK (
        status IN ('HOLD','CAPTURED','CANCELLED','REFUNDED','EXPIRED')
    )
);

CREATE INDEX IF NOT EXISTS idx_ptx_status
    ON payment_transactions(status);
CREATE INDEX IF NOT EXISTS idx_ptx_expires
    ON payment_transactions(expires_at) WHERE status = 'HOLD';
CREATE INDEX IF NOT EXISTS idx_ptx_installment
    ON payment_transactions(installment_id);


-- 2. refunds (Ҷузъи 2: Refund)
CREATE TABLE IF NOT EXISTS refunds (
    id BIGSERIAL PRIMARY KEY,
    refund_id VARCHAR(64) NOT NULL UNIQUE,
    transaction_id VARCHAR(64) NOT NULL,
    original_amount NUMERIC(12,2) NOT NULL,
    refund_amount NUMERIC(12,2) NOT NULL,
    remaining_amount NUMERIC(12,2) NOT NULL,
    reason TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    initiated_by VARCHAR(50) NOT NULL DEFAULT 'system',
    gateway_response JSONB,
    idempotency_key VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    CONSTRAINT refunds_amount_check CHECK (
        refund_amount > 0 AND refund_amount <= original_amount
    )
);

CREATE INDEX IF NOT EXISTS idx_refunds_tx
    ON refunds(transaction_id);
CREATE INDEX IF NOT EXISTS idx_refunds_status
    ON refunds(status);


-- 3. velocity_log (Ҷузъи 5: Anti-Fraud)
CREATE TABLE IF NOT EXISTS velocity_log (
    id BIGSERIAL PRIMARY KEY,
    passport_hmac VARCHAR(64) NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    client_ip VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_velocity_passport_time
    ON velocity_log(passport_hmac, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_velocity_ip_time
    ON velocity_log(client_ip, created_at DESC)
    WHERE client_ip IS NOT NULL;


-- 4. reconciliation_log (Ҷузъи 3: Reconciliation)
CREATE TABLE IF NOT EXISTS reconciliation_log (
    id BIGSERIAL PRIMARY KEY,
    run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    total_local NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_remote NUMERIC(14,2) NOT NULL DEFAULT 0,
    matched_count INT NOT NULL DEFAULT 0,
    mismatch_count INT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'OK',
    details JSONB,
    CONSTRAINT recon_status_check CHECK (
        status IN ('OK','MISMATCH','ERROR')
    )
);

CREATE INDEX IF NOT EXISTS idx_recon_run
    ON reconciliation_log(run_at DESC);

-- ============================================================================
-- END MIGRATION v3.8.1
-- ============================================================================
