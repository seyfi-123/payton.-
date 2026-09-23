"""Integration Tests for PostgreSQL"""
import pytest
import asyncpg
from credit_engine.database import (
    create_pool,
    get_connection,
    execute_query,
    fetch_one,
    fetch_all
)


class TestDatabaseConnection:
    """Тестҳои пайвастшавӣ ба база"""
    
    @pytest.mark.asyncio
    async def test_create_pool(self):
        """Эҷоди connection pool"""
        pool = await create_pool(
            host="localhost",
            port=5432,
            database="bank_db_test",
            user="test_user",
            password="test_password",
            min_size=2,
            max_size=10
        )
        assert pool is not None
        await pool.close()
    
    @pytest.mark.asyncio
    async def test_get_connection(self):
        """Гирифтани connection"""
        pool = await create_pool(...)
        async with get_connection(pool) as conn:
            assert conn is not None
    
    @pytest.mark.asyncio
    async def test_connection_pool_size(self):
        """Андозаи pool дуруст аст"""
        pool = await create_pool(..., min_size=2, max_size=10)
        assert pool.get_size() >= 2
        assert pool.get_size() <= 10


class TestDatabaseOperations:
    """Тестҳои амалиётҳои база"""
    
    @pytest.mark.asyncio
    async def test_insert_user(self):
        """Ворид кардани корбар"""
        async with get_connection(pool) as conn:
            await execute_query(
                conn,
                "INSERT INTO users (passport_series, passport_number) VALUES ($1, $2)",
                "AA", "1234567"
            )
            user = await fetch_one(
                conn,
                "SELECT * FROM users WHERE passport_series = $1 AND passport_number = $2",
                "AA", "1234567"
            )
            assert user is not None
            assert user["passport_series"] == "AA"
    
    @pytest.mark.asyncio
    async def test_insert_loan(self):
        """Ворид кардани қарз"""
        async with get_connection(pool) as conn:
            await execute_query(
                conn,
                """INSERT INTO loans 
                   (user_id, product_type, amount, status) 
                   VALUES ($1, $2, $3, $4)""",
                1, "DailyPay", 1000, "PENDING"
            )
            loan = await fetch_one(
                conn,
                "SELECT * FROM loans WHERE product_type = $1",
                "DailyPay"
            )
            assert loan is not None
            assert loan["amount"] == 1000
    
    @pytest.mark.asyncio
    async def test_fetch_multiple_records(self):
        """Гирифтани чанд сабт"""
        async with get_connection(pool) as conn:
            loans = await fetch_all(conn, "SELECT * FROM loans")
            assert isinstance(loans, list)
    
    @pytest.mark.asyncio
    async def test_transaction_commit(self):
        """Transaction commit"""
        async with get_connection(pool) as conn:
            async with conn.transaction():
                await execute_query(
                    conn,
                    "INSERT INTO test_table (value) VALUES ($1)",
                    "test"
                )
            # Transaction commit шуд
    
    @pytest.mark.asyncio
    async def test_transaction_rollback(self):
        """Transaction rollback"""
        async with get_connection(pool) as conn:
            try:
                async with conn.transaction():
                    await execute_query(
                        conn,
                        "INSERT INTO test_table (value) VALUES ($1)",
                        "test"
                    )
                    raise Exception("Force rollback")
            except Exception:
                pass
            # Transaction rollback шуд
    
    @pytest.mark.asyncio
    async def test_advisory_lock(self):
        """PostgreSQL advisory lock"""
        async with get_connection(pool) as conn:
            # Гирифтани lock
            await conn.execute("SELECT pg_advisory_lock(12345)")
            # Lock гирифта шуд
            await conn.execute("SELECT pg_advisory_unlock(12345)")
            # Lock озод шуд