-- ============================================================================
-- Tajik Fintech Credit Engine — Migration: PENDING_REVIEW status
-- Илова мешавад ба application_status_enum, бо ҳамон усуле, ки 1schema.sql
-- аллакай барои loan_status_enum ('CANCELLED') ва debit_status_enum
-- ('NEEDS_RECOVERY') истифода кардааст. Ҳеҷ сутуни нав, ҳеҷ ҷадвали нав —
-- бинобар ин ҳеҷ маълумоти шахсии (PII) иловагӣ дар DB нигоҳ дошта намешавад.
-- ============================================================================

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'application_status_enum') THEN
        BEGIN
            ALTER TYPE application_status_enum ADD VALUE IF NOT EXISTS 'PENDING_REVIEW';
        EXCEPTION WHEN duplicate_object THEN NULL; END;
    END IF;
END $$;

-- ============================================================================
-- END MIGRATION — PENDING_REVIEW
-- ============================================================================
