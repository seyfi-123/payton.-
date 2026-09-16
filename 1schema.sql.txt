-- ============================================================================
-- TAJIK FINTECH CREDIT ENGINE — DATABASE SCHEMA
-- Version: 3.8.1 | Target: PostgreSQL 13+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN
    CREATE TYPE product_type_enum AS ENUM ('STUDENT_PAY','DAILY_PAY','RENT_PAY');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE application_status_enum AS ENUM (
        'PENDING_CHECKS','APPROVED','REJECTED','CIB_REJECTED',
        'BIOMETRIC_FAILED','PENDING_GUARANTOR','ERROR_EXTERNAL',
        'ABS_FAILED','ERROR_PHASE3','ACTIVE','CLOSED','CANCELLED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE target_account_type_enum AS ENUM ('SELF','LANDLORD','UNIVERSITY');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE relation_type_enum AS ENUM (
        'FATHER','MOTHER','UNCLE_PATERNAL','AUNT_MATERNAL',
        'BROTHER','SISTER','SPOUSE','OTHER'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE guarantee_status_enum AS ENUM (
        'PENDING','APPROVED','REJECTED','EXPIRED','CLOSED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE installment_status_enum AS ENUM (
        'PENDING','PAID','PARTIAL','OVERDUE','FAILED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE loan_status_enum AS ENUM (
        'PENDING_DISBURSEMENT','ACTIVE','CLOSED','DEFAULTED','CANCELLED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE debit_status_enum AS ENUM (
        'PENDING','SUCCESS','FAILED','EXHAUSTED','NEEDS_RECOVERY'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE sms_status_enum AS ENUM (
        'PENDING','SENT','FAILED','DELIVERED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'loan_status_enum') THEN
        BEGIN ALTER TYPE loan_status_enum ADD VALUE IF NOT EXISTS 'CANCELLED';
        EXCEPTION WHEN duplicate_object THEN NULL; END;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'debit_status_enum') THEN
        BEGIN ALTER TYPE debit_status_enum ADD VALUE IF NOT EXISTS 'NEEDS_RECOVERY';
        EXCEPTION WHEN duplicate_object THEN NULL; END;
    END IF;
END $$;

-- ============================================================================
-- PRODUCT CONFIG
-- ============================================================================
CREATE TABLE IF NOT EXISTS product_config (
    product_type product_type_enum PRIMARY KEY,
    min_amount NUMERIC(12,2) NOT NULL,
    max_amount NUMERIC(12,2) NOT NULL,
    no_guarantor_limit NUMERIC(12,2) NOT NULL DEFAULT 0,
    commission_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    insurance_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    transfer_comm_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    term_months INT NOT NULL DEFAULT 0,
    term_days INT NOT NULL DEFAULT 0,
    pti_max_ratio NUMERIC(6,4) NOT NULL DEFAULT 0.50,
    grace_days INT NOT NULL DEFAULT 0,
    daily_penalty_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    interest_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT product_config_term_check CHECK (
        (term_months > 0 AND term_days = 0)
        OR (term_months = 0 AND term_days > 0)
    )
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='product_config' AND column_name='grace_days') THEN
        ALTER TABLE product_config ADD COLUMN grace_days INT NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='product_config' AND column_name='daily_penalty_rate') THEN
        ALTER TABLE product_config ADD COLUMN daily_penalty_rate NUMERIC(6,4) NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='product_config' AND column_name='interest_rate') THEN
        ALTER TABLE product_config ADD COLUMN interest_rate NUMERIC(6,4) NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='product_config' AND column_name='term_days') THEN
        ALTER TABLE product_config ADD COLUMN term_days INT NOT NULL DEFAULT 0;
    END IF;
END $$;

-- ============================================================================
-- МАҲСУЛОТҲО (v3.8.1)
--   StudentPay: 10 моҳ, 12% фоиз, 2% суғурта, 0% комиссияи интиқол
--   DailyPay:   7 рӯз,  4% комиссия, penalty 0.5%/рӯз (баъд аз 7 рӯз)
--   RentPay:    15 рӯз, 8% комиссия, penalty 0.5%/рӯз (баъд аз 15 рӯз)
--   Фоизи иловагӣ барои DailyPay/RentPay НЕСТ (interest_rate = 0)
-- ============================================================================
INSERT INTO product_config
    (product_type, min_amount, max_amount, no_guarantor_limit,
     commission_rate, insurance_rate, transfer_comm_rate,
     term_months, term_days,
     grace_days, daily_penalty_rate, interest_rate)
VALUES
    ('STUDENT_PAY', 3000, 12000, 0,    0,    0.02, 0,    10, 0,  0,  0,     0.12),
    ('DAILY_PAY',   200,  2000,  1000, 0.04, 0,    0,    0,  7,  0,  0.005, 0),
    ('RENT_PAY',    500,  5000,  0,    0.08, 0,    0,    0,  15, 0,  0.005, 0)
ON CONFLICT (product_type) DO UPDATE SET
    min_amount = EXCLUDED.min_amount,
    max_amount = EXCLUDED.max_amount,
    no_guarantor_limit = EXCLUDED.no_guarantor_limit,
    commission_rate = EXCLUDED.commission_rate,
    insurance_rate = EXCLUDED.insurance_rate,
    transfer_comm_rate = EXCLUDED.transfer_comm_rate,
    term_months = EXCLUDED.term_months,
    term_days = EXCLUDED.term_days,
    grace_days = EXCLUDED.grace_days,
    daily_penalty_rate = EXCLUDED.daily_penalty_rate,
    interest_rate = EXCLUDED.interest_rate,
    updated_at = NOW();

-- ============================================================================
-- USERS
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    passport_sn_hmac VARCHAR(64) NOT NULL UNIQUE,
    passport_sn_encrypted TEXT,
    phone_hmac VARCHAR(64) NOT NULL UNIQUE,
    phone_encrypted TEXT,
    date_of_birth DATE,
    monthly_income NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    card_turnover_3m NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    cib_score INT DEFAULT 0,
    approved_limit NUMERIC(12, 2) DEFAULT 0.00,
    cib_checked_at TIMESTAMPTZ,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_age_check CHECK (
        date_of_birth IS NULL OR date_of_birth <= CURRENT_DATE - INTERVAL '18 years'
    )
);

CREATE INDEX IF NOT EXISTS idx_users_passport_hmac ON users(passport_sn_hmac);
CREATE INDEX IF NOT EXISTS idx_users_phone_hmac ON users(phone_hmac);
CREATE INDEX IF NOT EXISTS idx_users_cib_checked ON users(cib_checked_at);
CREATE INDEX IF NOT EXISTS idx_users_blocked ON users(is_blocked) WHERE is_blocked = TRUE;

-- ============================================================================
-- APPLICATIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS applications (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE,
    passport_sn_hmac VARCHAR(64) NOT NULL,
    user_id BIGINT REFERENCES users(id),
    product_type product_type_enum NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    status application_status_enum NOT NULL DEFAULT 'PENDING_CHECKS',
    error_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_applications_rate_limit ON applications (passport_sn_hmac, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications (status);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);

-- ============================================================================
-- GUARANTORS
-- ============================================================================
CREATE TABLE IF NOT EXISTS guarantors (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    phone_hmac VARCHAR(64),
    relation_default relation_type_enum,
    face_id_passed BOOLEAN NOT NULL DEFAULT FALSE,
    sms_otp_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    card_token TEXT,
    card_masked VARCHAR(20),
    card_registered_at TIMESTAMPTZ,
    auto_debit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    guarantee_signature TEXT,
    signature_signed_at TIMESTAMPTZ,
    active_guarantee_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_guarantors_phone_hmac ON guarantors(phone_hmac);
CREATE INDEX IF NOT EXISTS idx_guarantors_active ON guarantors(active_guarantee_id) WHERE active_guarantee_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_guarantors_auto_debit ON guarantors(user_id) WHERE auto_debit_enabled = TRUE AND card_token IS NOT NULL;

-- ============================================================================
-- APPLICATION_GUARANTORS
-- ============================================================================
CREATE TABLE IF NOT EXISTS application_guarantors (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    guarantor_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    relation_type relation_type_enum,
    phone_hmac VARCHAR(64),
    approval_status guarantee_status_enum NOT NULL DEFAULT 'PENDING',
    otp_code_hash VARCHAR(64),
    otp_expires_at TIMESTAMPTZ,
    otp_attempts INT NOT NULL DEFAULT 0,
    otp_last_sent_at TIMESTAMPTZ,
    otp_send_count INT NOT NULL DEFAULT 0,
    ttl_expires_at TIMESTAMPTZ,
    signature_hash VARCHAR(64),
    approved_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT app_guarantor_unique UNIQUE (application_id, guarantor_user_id)
);

CREATE INDEX IF NOT EXISTS idx_app_guarantors_app ON application_guarantors(application_id);
CREATE INDEX IF NOT EXISTS idx_app_guarantors_user_status ON application_guarantors(guarantor_user_id, approval_status);
CREATE INDEX IF NOT EXISTS idx_app_guarantors_ttl ON application_guarantors(ttl_expires_at) WHERE approval_status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_app_guarantors_ttl_status ON application_guarantors(approval_status, ttl_expires_at) WHERE approval_status = 'PENDING';

ALTER TABLE guarantors DROP CONSTRAINT IF EXISTS guarantors_active_guarantee_fk;
ALTER TABLE guarantors ADD CONSTRAINT guarantors_active_guarantee_fk
    FOREIGN KEY (active_guarantee_id) REFERENCES application_guarantors(id) ON DELETE SET NULL;

-- ============================================================================
-- GUARANTOR TTL LOG
-- ============================================================================
CREATE TABLE IF NOT EXISTS guarantor_ttl_log (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    application_guarantor_id BIGINT NOT NULL REFERENCES application_guarantors(id) ON DELETE CASCADE,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'SENT',
    sms_status sms_status_enum NOT NULL DEFAULT 'PENDING',
    sms_attempts INT NOT NULL DEFAULT 0,
    sms_last_error TEXT,
    CONSTRAINT ttl_unique UNIQUE (application_guarantor_id)
);

CREATE INDEX IF NOT EXISTS idx_ttl_status ON guarantor_ttl_log(status);
CREATE INDEX IF NOT EXISTS idx_ttl_expires ON guarantor_ttl_log(expires_at);
CREATE INDEX IF NOT EXISTS idx_ttl_sms_status ON guarantor_ttl_log(sms_status) WHERE sms_status IN ('PENDING','FAILED');

-- ============================================================================
-- OTP RATE LIMIT
-- ============================================================================
CREATE TABLE IF NOT EXISTS otp_rate_limit (
    id BIGSERIAL PRIMARY KEY,
    phone_hmac VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_otp_rl_phone ON otp_rate_limit (phone_hmac, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_otp_rl_ip ON otp_rate_limit (client_ip, attempted_at DESC) WHERE client_ip IS NOT NULL;

-- ============================================================================
-- LOAN DISBURSEMENTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS loan_disbursements (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    passport_sn_hmac VARCHAR(64) NOT NULL,
    guarantor_id BIGINT REFERENCES users(id),
    gross_amount NUMERIC(12, 2) NOT NULL,
    transfer_commission NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    net_transferred NUMERIC(12, 2) NOT NULL,
    abs_contract_id VARCHAR(100) NOT NULL UNIQUE,
    product_type product_type_enum NOT NULL,
    target_account_type target_account_type_enum NOT NULL,
    target_account_iban VARCHAR(34) NOT NULL,
    target_account_hmac VARCHAR(64) NOT NULL,
    target_name VARCHAR(150) NOT NULL,
    status loan_status_enum NOT NULL DEFAULT 'PENDING_DISBURSEMENT',
    disbursed_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    cancellation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_disbursements_app ON loan_disbursements(application_id);
CREATE INDEX IF NOT EXISTS idx_disbursements_passport_status ON loan_disbursements(passport_sn_hmac, status);
CREATE INDEX IF NOT EXISTS idx_disbursements_guarantor ON loan_disbursements(guarantor_id) WHERE guarantor_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_loan_per_passport
    ON loan_disbursements (passport_sn_hmac)
    WHERE status IN ('ACTIVE','PENDING_DISBURSEMENT');

-- ============================================================================
-- REPAYMENT SCHEDULE (v3.8.1: principal_due илова шуд)
-- ============================================================================
CREATE TABLE IF NOT EXISTS repayment_schedule (
    id BIGSERIAL PRIMARY KEY,
    loan_id BIGINT NOT NULL REFERENCES loan_disbursements(id) ON DELETE CASCADE,
    installment_number INT NOT NULL,
    due_date DATE NOT NULL,
    principal_due NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    amount_due NUMERIC(12, 2) NOT NULL,
    amount_paid NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    penalty_amount NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    last_penalty_date DATE,
    status installment_status_enum NOT NULL DEFAULT 'PENDING',
    paid_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT repayment_schedule_loan_installment_key UNIQUE (loan_id, installment_number)
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='repayment_schedule' AND column_name='penalty_amount') THEN
        ALTER TABLE repayment_schedule ADD COLUMN penalty_amount NUMERIC(12,2) NOT NULL DEFAULT 0.00;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='repayment_schedule' AND column_name='last_penalty_date') THEN
        ALTER TABLE repayment_schedule ADD COLUMN last_penalty_date DATE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='repayment_schedule' AND column_name='principal_due') THEN
        ALTER TABLE repayment_schedule ADD COLUMN principal_due NUMERIC(12,2) NOT NULL DEFAULT 0.00;
    END IF;
END $$;

-- Маълумоти кӯҳнаро пур кунед
UPDATE repayment_schedule
SET principal_due = amount_due - penalty_amount
WHERE principal_due = 0 AND amount_due > 0;

CREATE INDEX IF NOT EXISTS idx_schedule_loan ON repayment_schedule(loan_id);
CREATE INDEX IF NOT EXISTS idx_schedule_status_due ON repayment_schedule(status, due_date);

-- ============================================================================
-- REPAYMENT IDEMPOTENCY
-- ============================================================================
CREATE TABLE IF NOT EXISTS repayment_idempotency (
    idempotency_key VARCHAR(64) PRIMARY KEY,
    installment_id BIGINT NOT NULL REFERENCES repayment_schedule(id) ON DELETE CASCADE,
    response_body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP + INTERVAL '7 days'
);

CREATE INDEX IF NOT EXISTS idx_repay_idem_expires ON repayment_idempotency(expires_at);

-- ============================================================================
-- INSURANCE POLICIES
-- ============================================================================
CREATE TABLE IF NOT EXISTS insurance_policies (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    passport_sn_hmac VARCHAR(64) NOT NULL,
    fee_amount NUMERIC(12, 2) NOT NULL,
    bank_margin NUMERIC(12, 2) NOT NULL,
    interest_amount NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='insurance_policies' AND column_name='interest_amount') THEN
        ALTER TABLE insurance_policies ADD COLUMN interest_amount NUMERIC(12,2) NOT NULL DEFAULT 0.00;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_insurance_app ON insurance_policies(application_id);

-- ============================================================================
-- AUTO-DEBIT TRANSACTIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS auto_debit_transactions (
    id BIGSERIAL PRIMARY KEY,
    loan_id BIGINT NOT NULL REFERENCES loan_disbursements(id) ON DELETE CASCADE,
    guarantor_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    installment_id BIGINT NOT NULL REFERENCES repayment_schedule(id) ON DELETE CASCADE,
    amount NUMERIC(12, 2) NOT NULL,
    card_token TEXT,
    status debit_status_enum NOT NULL DEFAULT 'PENDING',
    attempt_count INT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    error_message TEXT,
    idempotency_key VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_debit_loan ON auto_debit_transactions(loan_id);
CREATE INDEX IF NOT EXISTS idx_debit_status ON auto_debit_transactions(status);
CREATE INDEX IF NOT EXISTS idx_debit_installment ON auto_debit_transactions(installment_id);
CREATE INDEX IF NOT EXISTS idx_debit_next_retry ON auto_debit_transactions(next_retry_at) WHERE status IN ('FAILED','PENDING');
CREATE INDEX IF NOT EXISTS idx_debit_needs_recovery ON auto_debit_transactions(last_attempt_at) WHERE status = 'NEEDS_RECOVERY';

-- ============================================================================
-- AUDIT LOG
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    application_id BIGINT,
    passport_sn_hmac VARCHAR(64),
    details TEXT,
    request_id VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_log(application_id);
CREATE INDEX IF NOT EXISTS idx_audit_passport ON audit_log(passport_sn_hmac, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- ============================================================================
-- MIGRATIONS
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='loan_disbursements' AND column_name='guarantor_id') THEN
        ALTER TABLE loan_disbursements ADD COLUMN guarantor_id BIGINT REFERENCES users(id);
        CREATE INDEX idx_disbursements_guarantor ON loan_disbursements(guarantor_id) WHERE guarantor_id IS NOT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='loan_disbursements' AND column_name='cancelled_at') THEN
        ALTER TABLE loan_disbursements ADD COLUMN cancelled_at TIMESTAMPTZ;
        ALTER TABLE loan_disbursements ADD COLUMN cancellation_reason TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='guarantors' AND column_name='card_registered_at') THEN
        ALTER TABLE guarantors ADD COLUMN card_registered_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='guarantors' AND column_name='signature_signed_at') THEN
        ALTER TABLE guarantors ADD COLUMN signature_signed_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='application_guarantors' AND column_name='otp_last_sent_at') THEN
        ALTER TABLE application_guarantors ADD COLUMN otp_last_sent_at TIMESTAMPTZ;
        ALTER TABLE application_guarantors ADD COLUMN otp_send_count INT NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='application_guarantors' AND column_name='signature_hash') THEN
        ALTER TABLE application_guarantors ADD COLUMN signature_hash VARCHAR(64);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='guarantor_ttl_log' AND column_name='sms_status') THEN
        ALTER TABLE guarantor_ttl_log ADD COLUMN sms_status sms_status_enum NOT NULL DEFAULT 'PENDING';
        ALTER TABLE guarantor_ttl_log ADD COLUMN sms_attempts INT NOT NULL DEFAULT 0;
        ALTER TABLE guarantor_ttl_log ADD COLUMN sms_last_error TEXT;
    END IF;
END $$;

UPDATE loan_disbursements ld
SET status = 'CANCELLED'::loan_status_enum,
    cancelled_at = NOW(),
    cancellation_reason = 'migration: orphaned pending loan'
WHERE ld.status = 'PENDING_DISBURSEMENT'
  AND EXISTS (
      SELECT 1 FROM applications a
      WHERE a.id = ld.application_id
        AND a.status IN ('REJECTED','ERROR_EXTERNAL','ERROR_PHASE3',
                         'ABS_FAILED','BIOMETRIC_FAILED','CIB_REJECTED','CLOSED')
  );

-- ============================================================================
-- END OF SCHEMA — v3.8.1
-- ============================================================================