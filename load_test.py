from locust import HttpUser, task, between
import json
import uuid
import time

class CreditUser(HttpUser):
    wait_time = between(0.1, 0.5)
    
    def on_start(self):
        self.api_key = "test_api_key_for_load_testing_32_chars!"
        self.headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }
    
    @task(5)
    def credit_apply_daily(self):
        """DailyPay - 200-2000 TJS"""
        payload = {
            "passport_series": "AA",
            "passport_number": f"{1000000 + self.environment.runner.user_count:08d}",
            "date_of_birth": "2000-01-15",
            "amount": 1000,
            "product_type": "DailyPay",
            "face_id_data": "TEST_FACE_ID_LIVE_001",
            "user_phone": f"+99290{1000000 + self.environment.runner.user_count:07d}",
            "self_iban": "TJ5900010000000000000001",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            json=payload,
            headers=self.headers,
            catch_response=True,
            name="/api/v1/credit/apply [DailyPay]"
        ) as response:
            if response.status_code in [200, 429, 400]:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}")
    
    @task(3)
    def credit_apply_rent(self):
        """RentPay - 500-5000 TJS"""
        payload = {
            "passport_series": "BB",
            "passport_number": f"{2000000 + self.environment.runner.user_count:08d}",
            "date_of_birth": "1995-05-20",
            "amount": 3000,
            "product_type": "RentPay",
            "face_id_data": "TEST_FACE_ID_LIVE_002",
            "user_phone": f"+99290{2000000 + self.environment.runner.user_count:07d}",
            "landlord_iban": "TJ0500030000000000000003",
            "landlord_name": "Test Landlord",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            json=payload,
            headers=self.headers,
            catch_response=True,
            name="/api/v1/credit/apply [RentPay]"
        ) as response:
            if response.status_code in [200, 429, 400]:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}")
    
    @task(2)
    def credit_apply_student(self):
        """StudentPay - 3000-12000 TJS"""
        payload = {
            "passport_series": "CC",
            "passport_number": f"{3000000 + self.environment.runner.user_count:08d}",
            "date_of_birth": "2002-09-01",
            "amount": 5000,
            "product_type": "StudentPay",
            "face_id_data": "TEST_FACE_ID_LIVE_003",
            "user_phone": f"+99290{3000000 + self.environment.runner.user_count:07d}",
            "university_iban": "TJ3200020000000000000002",
            "university_name": "Test University",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            json=payload,
            headers=self.headers,
            catch_response=True,
            name="/api/v1/credit/apply [StudentPay]"
        ) as response:
            if response.status_code in [200, 429, 400]:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}")
    
    @task(1)
    def health_check(self):
        """Health check endpoint"""
        with self.client.get(
            "/api/v1/system/health",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}")