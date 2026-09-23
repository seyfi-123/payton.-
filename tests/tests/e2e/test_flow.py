"""End-to-End Flow Tests"""
import pytest
from credit_engine.e2e import (
    submit_application,
    approve_guarantor,
    create_loan,
    disburse_funds,
    make_payment,
    close_loan
)


class TestCompleteFlow:
    """Тестҳои ҷараёни пурра"""
    
    @pytest.mark.asyncio
    async def test_dailypay_complete_flow(self):
        """Ҷараёни пурраи DailyPay"""
        # 1. Submit application
        application = await submit_application(
            passport_series="AA",
            passport_number="1234567",
            amount=1000,
            product_type="DailyPay"
        )
        assert application["status"] == "PENDING_GUARANTOR_APPROVAL"
        
        # 2. Approve guarantor
        approval = await approve_guarantor(
            application_id=application["id"],
            otp_code="123456"
        )
        assert approval["status"] == "APPROVED"
        
        # 3. Create loan
        loan = await create_loan(application_id=application["id"])
        assert loan["status"] == "ACTIVE"
        
        # 4. Disburse funds
        disbursement = await disburse_funds(loan_id=loan["id"])
        assert disbursement["status"] == "DISBURSED"
        
        # 5. Make payment
        payment = await make_payment(
            loan_id=loan["id"],
            amount=1040  # 1000 + 4% commission
        )
        assert payment["status"] == "PAID"
        
        # 6. Close loan
        closure = await close_loan(loan_id=loan["id"])
        assert closure["status"] == "CLOSED"
    
    @pytest.mark.asyncio
    async def test_rentpay_complete_flow(self):
        """Ҷараёни пурраи RentPay"""
        application = await submit_application(
            passport_series="BB",
            passport_number="7654321",
            amount=3000,
            product_type="RentPay",
            landlord_iban="TJ0500030000000000000003"
        )
        assert application["status"] == "PENDING_GUARANTOR_APPROVAL"
    
    @pytest.mark.asyncio
    async def test_studentpay_complete_flow(self):
        """Ҷараёни пурраи StudentPay"""
        application = await submit_application(
            passport_series="CC",
            passport_number="9876543",
            amount=10000,
            product_type="StudentPay",
            university_iban="TJ3200020000000000000002"
        )
        assert application["status"] == "PENDING_GUARANTOR_APPROVAL"
    
    @pytest.mark.asyncio
    async def test_application_rejection_flow(self):
        """Ҷараёни рад кардан"""
        application = await submit_application(...)
        rejection = await reject_application(
            application_id=application["id"],
            reason="Invalid documents"
        )
        assert rejection["status"] == "REJECTED"
    
    @pytest.mark.asyncio
    async def test_guarantor_rejection_flow(self):
        """Ҷараёни рад кардани гарантор"""
        application = await submit_application(...)
        rejection = await guarantor_reject(
            application_id=application["id"],
            reason="Cannot be guarantor"
        )
        assert rejection["status"] == "GUARANTOR_REJECTED"


class TestErrorHandling:
    """Тестҳои идоракунии хато"""
    
    @pytest.mark.asyncio
    async def test_duplicate_application_handling(self):
        """Идоракунии дархости такрорӣ"""
        # First application
        app1 = await submit_application(
            passport_series="AA",
            passport_number="1111111",
            request_id="req-unique-001"
        )
        
        # Duplicate application
        with pytest.raises(Exception) as exc_info:
            await submit_application(
                passport_series="AA",
                passport_number="1111111",
                request_id="req-unique-001"  # Same ID
            )
        assert "duplicate" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_rate_limit_handling(self):
        """Идоракунии rate limit"""
        # Make 5 applications (limit)
        for i in range(5):
            await submit_application(
                passport_series="AA",
                passport_number=f"222222{i}",
                amount=1000
            )
        
        # 6th application should fail
        with pytest.raises(Exception) as exc_info:
            await submit_application(
                passport_series="AA",
                passport_number="2222226",
                amount=1000
            )
        assert "rate limit" in str(exc_info.value).lower()