"""Load and Performance Tests"""
import pytest
import asyncio
import time
from locust import HttpUser, task, between


class TestPerformance:
    """Тестҳои иҷро"""
    
    @pytest.mark.asyncio
    async def test_response_time_under_load(self):
        """Вақти ҷавоб дар зери бор"""
        start = time.time()
        
        # 100 дархости ҳамзамон
        tasks = [
            submit_application(
                passport_series="AA",
                passport_number=f"{1000000 + i}",
                amount=1000
            )
            for i in range(100)
        ]
        
        await asyncio.gather(*tasks)
        elapsed = time.time() - start
        
        # Ҳар дархост бояд < 500ms бошад
        avg_time = elapsed / 100
        assert avg_time < 0.5  # 500ms
    
    @pytest.mark.asyncio
    async def test_database_connection_pool(self):
        """Connection pool дуруст кор мекунад"""
        pool = await create_pool(..., min_size=10, max_size=100)
        
        # 200 дархости ҳамзамон
        tasks = [
            execute_query(pool, "SELECT 1")
            for _ in range(200)
        ]
        
        start = time.time()
        await asyncio.gather(*tasks)
        elapsed = time.time() - start
        
        # Pool бояд 200 дархостро идора кунад
        assert elapsed < 10  # 10 секунд
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self):
        """Истифодаи хотира дар зери бор"""
        import psutil
        process = psutil.Process()
        
        initial_memory = process.memory_info().rss
        
        # 1000 дархост
        for i in range(1000):
            await submit_application(...)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Хотира бояд < 100MB афзоиш ёбад
        assert memory_increase < 100 * 1024 * 1024


class LocustLoadTest(HttpUser):
    """Load test бо Locust"""
    wait_time = between(0.1, 0.5)
    
    @task(5)
    def credit_apply(self):
        """Дархости кредит"""
        self.client.post(
            "/api/v1/credit/apply",
            json={
                "passport_series": "AA",
                "passport_number": "1234567",
                "amount": 1000,
                "product_type": "DailyPay"
            }
        )
    
    @task(3)
    def health_check(self):
        """Health check"""
        self.client.get("/api/v1/system/health")
    
    @task(2)
    def guarantor_approve(self):
        """Тасдиқи гарантор"""
        self.client.post(
            "/api/v1/guarantor/approve",
            json={
                "application_guarantor_id": 1,
                "otp_code": "123456"
            }
        )