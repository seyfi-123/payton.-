from locust import HttpUser, task, between
import json
import uuid
import time
import hashlib
import hmac
import os

API_KEY = os.environ.get("PAYTON_API_KEY", "")
SIGNING_SECRET = os.environ.get("PAYTON_SIGNING_SECRET", "")

def sign_request(body: str) -> str:
    timestamp = str(int(time.time()))
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical = f"POST\n/api/v1/credit/apply\n{timestamp}\n{body_hash}"
    digest = hmac.new(
        SIGNING_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{timestamp}.{digest}"


class CreditUser(HttpUser):
    wait_time = between(0.01, 0.05)  # Уменьшено для увеличения скорости
    host = os.environ.get("PAYTON_BASE_URL", "http://localhost:8000")

    def on_start(self):
        if not API_KEY or not SIGNING_SECRET:
            raise Exception("PAYTON_API_KEY и PAYTON_SIGNING_SECRET обязательны!")

    @task(5)
    def credit_apply_daily(self):
        """DailyPay - 200-2000 TJS"""
        # Уникальный паспорт для каждого запроса
        passport_num = str(uuid.uuid4().int)[:8]
        
        payload = {
            "passport_series": "AA",
            "passport_number": passport_num,
            "date_of_birth": "2000-01-15",
            "amount": 1000,
            "product_type": "DailyPay",
            "face_id_data": "TEST_FACE_ID_LIVE_001",
            "user_phone": f"+99290{passport_num[:7]}",
            "self_iban": "TJ5900010000000000000001",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        body = json.dumps(payload)
        headers = {
            "X-API-KEY": API_KEY,
            "X-Signature": sign_request(body),
            "Content-Type": "application/json"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            data=body,
            headers=headers,
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
        passport_num = str(uuid.uuid4().int)[:8]
        
        payload = {
            "passport_series": "BB",
            "passport_number": passport_num,
            "date_of_birth": "1995-05-20",
            "amount": 3000,
            "product_type": "RentPay",
            "face_id_data": "TEST_FACE_ID_LIVE_002",
            "user_phone": f"+99290{passport_num[:7]}",
            "landlord_iban": "TJ0500030000000000000003",
            "landlord_name": "Test Landlord",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        body = json.dumps(payload)
        headers = {
            "X-API-KEY": API_KEY,
            "X-Signature": sign_request(body),
            "Content-Type": "application/json"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            data=body,
            headers=headers,
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
        passport_num = str(uuid.uuid4().int)[:8]
        
        payload = {
            "passport_series": "CC",
            "passport_number": passport_num,
            "date_of_birth": "2002-09-01",
            "amount": 5000,
            "product_type": "StudentPay",
            "face_id_data": "TEST_FACE_ID_LIVE_003",
            "user_phone": f"+99290{passport_num[:7]}",
            "university_iban": "TJ3200020000000000000002",
            "university_name": "Test University",
            "request_id": f"load-{uuid.uuid4().hex[:12]}"
        }
        
        body = json.dumps(payload)
        headers = {
            "X-API-KEY": API_KEY,
            "X-Signature": sign_request(body),
            "Content-Type": "application/json"
        }
        
        with self.client.post(
            "/api/v1/credit/apply",
            data=body,
            headers=headers,
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