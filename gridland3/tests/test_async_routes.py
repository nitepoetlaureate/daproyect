"""
Phase 2 Async Route Tests.

All scan dispatch now goes through Celery tasks. These tests mock
celery_run_scan.delay / celery_run_discover.delay so that no real
worker or Redis connection is needed.

Job status lookups are tested by mocking AsyncResult to return
controlled state / info from simulated Redis.
"""
import pytest
import asyncio
import time
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport
from server import app
from itsdangerous import URLSafeSerializer
import secrets
import os

pytestmark = pytest.mark.asyncio


# ── Helpers ──────────────────────────────────────────────────────────

def _make_mock_async_result(task_id="fake-task-id"):
    """Return a mock object that behaves like Celery's AsyncResult."""
    mock = MagicMock()
    mock.id = task_id
    return mock


# ── CSRF / Template Tests ───────────────────────────────────────────

async def test_jinja2_context_fix():
    """
    Test that GET / no longer crashes due to the unhashable dict/lambda issue
    introduced in the previous commit.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200, f"Expected 200, got {response.status_code} - Jinja syntax might still be broken."
        assert "Gridland" in response.text or "aegis" in response.text.lower(), "Expected HTML response."


async def test_forged_csrf_using_default_key():
    """
    Test if the application is running with the default insecure secret key.
    If it is, the 'cryptographically secure' CSRF is trivially bypassed.
    """
    secret_key = 'default-insecure-key-for-dev'
    serializer = URLSafeSerializer(secret_key)
    forged_token = serializer.dumps("hacked_raw_token")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.cookies.set("csrf_token", forged_token)
        response = await client.post(
            "/scan",
            json={"target": "192.168.1.1"},
            headers={"X-CSRFToken": forged_token}
        )

        assert response.status_code == 403, f"Expected 403 Forbidden for forged token, got {response.status_code}."


# ── Celery Dispatch: /scan ───────────────────────────────────────────

@patch("server.celery_run_scan")
async def test_scan_dispatches_to_celery(mock_scan):
    """POST /scan should call celery_run_scan.delay and return 202 + task ID."""
    mock_scan.delay.return_value = _make_mock_async_result("scan-task-001")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/")
        csrf_cookie = r1.cookies.get("csrf_token")

        response = await client.post(
            "/scan",
            json={"target": "10.0.0.1"},
            headers={"X-CSRFToken": csrf_cookie},
        )

    assert response.status_code == 202
    body = response.json()
    assert body["job_id"] == "scan-task-001"
    assert body["action"] == "scan"
    mock_scan.delay.assert_called_once_with("10.0.0.1", True, 100)


# ── Celery Dispatch: /discover ───────────────────────────────────────

@patch("server.celery_run_discover")
async def test_discover_dispatches_to_celery(mock_discover):
    """POST /discover should call celery_run_discover.delay and return 202 + task ID."""
    mock_discover.delay.return_value = _make_mock_async_result("discover-task-001")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/")
        csrf_cookie = r1.cookies.get("csrf_token")

        response = await client.post(
            "/discover",
            json={"target": "10.0.0.1/24"},
            headers={"X-CSRFToken": csrf_cookie},
        )

    assert response.status_code == 202
    body = response.json()
    assert body["job_id"] == "discover-task-001"
    assert body["action"] == "discover"
    mock_discover.delay.assert_called_once_with("10.0.0.1/24", 100)


# ── Celery Dispatch: /api/jobs (POST) ────────────────────────────────

@patch("server.celery_run_scan")
async def test_api_jobs_post_dispatches_to_celery(mock_scan):
    """POST /api/jobs should dispatch to Celery and return 202 + task ID."""
    mock_scan.delay.return_value = _make_mock_async_result("api-task-001")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/")
        csrf_cookie = r1.cookies.get("csrf_token")

        response = await client.post(
            "/api/jobs",
            json={"target": "192.168.1.0/24"},
            headers={"X-CSRFToken": csrf_cookie},
        )

    assert response.status_code == 202
    body = response.json()
    assert body["job_id"] == "api-task-001"
    mock_scan.delay.assert_called_once_with("192.168.1.0/24", True, 100)


# ── Job Status: AsyncResult from Redis ───────────────────────────────

@patch("server.AsyncResult")
async def test_job_status_pending(mock_ar_cls):
    """GET /api/jobs/{id} should return pending for unknown tasks."""
    mock_ar = MagicMock()
    mock_ar.state = "PENDING"
    mock_ar_cls.return_value = mock_ar

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/jobs/nonexistent-id")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pending"
    assert body["logs"] == []
    assert body["results"] == []


@patch("server.AsyncResult")
async def test_job_status_progress(mock_ar_cls):
    """GET /api/jobs/{id} should return running + logs for PROGRESS state."""
    mock_ar = MagicMock()
    mock_ar.state = "PROGRESS"
    mock_ar.info = {"status": "running", "logs": ["[12:00:00] Scanning 10.0.0.1..."]}
    mock_ar_cls.return_value = mock_ar

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/jobs/progress-task-id")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "running"
    assert len(body["logs"]) == 1
    assert "Scanning" in body["logs"][0]


@patch("server.AsyncResult")
async def test_job_status_success(mock_ar_cls):
    """GET /api/jobs/{id} should return completed + results for SUCCESS state."""
    mock_ar = MagicMock()
    mock_ar.state = "SUCCESS"
    mock_ar.result = {
        "status": "completed",
        "logs": ["[12:00:00] Done"],
        "results": [{"ip": "10.0.0.1", "open_ports": []}],
    }
    mock_ar_cls.return_value = mock_ar

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/jobs/success-task-id")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert len(body["results"]) == 1
    assert body["results"][0]["ip"] == "10.0.0.1"


@patch("server.AsyncResult")
async def test_job_status_failure(mock_ar_cls):
    """GET /api/jobs/{id} should return 500 for FAILURE state."""
    mock_ar = MagicMock()
    mock_ar.state = "FAILURE"
    mock_ar.info = Exception("worker crashed")
    mock_ar_cls.return_value = mock_ar

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/jobs/failed-task-id")

    assert response.status_code == 500
    body = response.json()
    assert body["status"] == "failed"
    assert "worker crashed" in body["error"]


# ── Concurrency: No event-loop blocking ─────────────────────────────

@patch("server.celery_run_scan")
async def test_hammer_scan_with_valid_csrf_no_deadlock(mock_scan):
    """
    Fetch a valid CSRF token, then hammer /scan concurrently.
    Now that scans are dispatched to Celery (non-blocking .delay()),
    the event loop must NEVER block.
    """
    mock_scan.delay.return_value = _make_mock_async_result()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/")
        csrf_cookie = r1.cookies.get("csrf_token")

        start_time = time.perf_counter()

        tasks = [
            client.post(
                "/scan",
                json={"target": "10.0.0.1"},
                headers={"X-CSRFToken": csrf_cookie}
            )
            for _ in range(100)
        ]
        try:
            responses = await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        except asyncio.TimeoutError:
            pytest.fail("Event loop blocked! Celery dispatch should be non-blocking.")

        elapsed = time.perf_counter() - start_time

        for response in responses:
            assert response.status_code == 202, f"Expected 202, got {response.status_code}."

        assert elapsed < 2.0, f"Blocking detected: /scan took {elapsed:.2f}s for 100 requests."


@patch("server.celery_run_discover")
async def test_hammer_discover_with_valid_csrf_no_deadlock(mock_discover):
    """
    Fetch a valid CSRF token, then hammer /discover concurrently.
    Celery dispatch must be fully non-blocking.
    """
    mock_discover.delay.return_value = _make_mock_async_result()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/")
        csrf_cookie = r1.cookies.get("csrf_token")

        start_time = time.perf_counter()

        tasks = [
            client.post(
                "/discover",
                json={"target": "10.0.0.1/24"},
                headers={"X-CSRFToken": csrf_cookie}
            )
            for _ in range(100)
        ]
        try:
            responses = await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        except asyncio.TimeoutError:
            pytest.fail("Event loop blocked! Celery dispatch should be non-blocking.")

        elapsed = time.perf_counter() - start_time

        for response in responses:
            assert response.status_code == 202, f"Expected 202, got {response.status_code}."

        assert elapsed < 2.0, f"Blocking detected: /discover took {elapsed:.2f}s for 100 requests."
